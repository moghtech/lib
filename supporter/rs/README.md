# Mogh Supporter

Mogh Supporter schema and embedded API.

The [typescript package](../ts) verifies the key offline in the browser,
and [mogh_ui](../../ui) renders the badge and the settings section.

Nothing talks to mogh.tech at runtime.

```rust,ignore
// With the `server` feature. On the app's `AuthImpl` of
// mogh_auth_server:
impl mogh_supporter::server::SupporterImpl for MyAuthImpl {
  fn supporter_app(&self) -> &'static str {
    "komodo"
  }
  // The app's own root keys of mogh.tech, hardcoded.
  fn supporter_root_keys(&self) -> &'static [&'static str] {
    &["<public key>"]
  }
  fn supporter_config_key(&self) -> &str {
    &config().supporter_key
  }
  // The key holds the instance private key: handed over as
  // `Zeroizing<String>`, kept encrypted.
  fn load_stored_supporter_key(&self) -> DynFuture<mogh_error::Result<Option<Zeroizing<String>>>> {
    Box::pin(async { db::load_supporter_key().await })
  }
  fn store_supporter_key(&self, key: Option<Zeroizing<String>>) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move { db::store_supporter_key(key.as_deref()).await })
  }
  fn load_supporter_branding(&self) -> DynFuture<mogh_error::Result<Option<SupporterBranding>>> {
    Box::pin(async { db::load_supporter_branding().await })
  }
  fn store_supporter_branding(&self, branding: SupporterBranding) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move { db::store_supporter_branding(branding).await })
  }
}

// At startup, once the database is up: the stored key, else the
// config's, logged, and the branding.
mogh_supporter::server::init::<MyAuthImpl>().await?;

// Next to the auth api.
let app = Router::new()
  .nest("/auth", mogh_auth_server::api::router::<MyAuthImpl>())
  .nest("/supporter", mogh_supporter::server::router::<MyAuthImpl>());
```

## The key

```text
key = base64url(P) "." base64url(SP) "." base64url(I1)
```

base64url without padding everywhere, whitespace anywhere (the key
is long, and wrapped in config files and emails) is removed
(`compact_key`).

- `P`: the payload, a CBOR map. Kept as decoded, these bytes are what
  the root key signed. At most 4 KiB.
- `SP`: the root key's Ed25519 signature over `P || I2`, 64 bytes.
- `I1`: the Ed25519 seed of the key's instance key pair, 32 bytes,
  from which `I2`, the instance public key, is derived. The only
  secret in the key. Parsed, it is kept in `SupporterKey`, whose
  `Debug` is redacted, and wiped from memory on drop. The key as
  text, `I1` in it, goes to the app to keep and comes back from it
  (`SupporterImpl::store_supporter_key` /
  `load_stored_supporter_key`) as a `Zeroizing<String>`, wiped once
  dropped, which the app stores encrypted. The `key` of a
  `SetSupporterKey` is wiped once handled and left out of its
  `Debug`, but the body of the request it arrived in is read like
  any request body: that copy isn't wiped.

The payload (`Payload`): `v` the format version (1), `k` the id of
the root key which signed it, `i` the key's id (a UUID, what the
revocation list names), `a` the app (`komodo`, `cicada`), `n` the
name on the badge, `t` the tier (`individual`, `organization`,
`sponsor`), `s` supporter since and `c` the last release date the
key covers, both `YYYY-MM-DD`. Keys of the map this version does not
know are ignored. The decoder (`decode_cbor`) reads the subset the
payload uses: definite length integers, byte and text strings, arrays
and maps (whose keys are text or integers), `false`, `true` and
`null`; everything else is refused. The typescript package's decoder
and checks are the same, to the error message: both run the vectors
of `../test_vectors.json` (a case goes there, not to one side).

`SupporterKey::parse` parses a key, `SupporterKey::respond` answers a
nonce, `SupporterKey::verify` checks the root signature, the format
version and the app under given root keys. The api below is built on
them.

## The api

Mounted at `/supporter` by the app (`server::router`), and posted to
like the app's own api: `POST /supporter/read` and
`POST /supporter/write` with `{ "type": "<request>", "params": <request> }`,
or `POST /supporter/read/<request>` with the params alone as the
body (an unknown request, or params of the wrong shape, is a 422 which
names the field, never the value). Every request is authenticated
like the requests the app's UI makes, by mogh_auth_server's
`middleware::authenticate_user` as its management api is: a jwt, api
key or signing key, the cidr whitelists, the rate limit, the app's
`accept_signed_request`. A disabled user is refused every request,
also the ones for every user (the management api still tells them
who they are). "Admins" below are `AuthUserImpl::is_admin`, and no
workload: a CI identity whose trusted issuer rule makes it an admin
reads what every user reads, and manages nothing.

| Request | Who | Does |
| --- | --- | --- |
| `GetSupporterKey { nonce }` | every user | Signs the browser's nonce (32 bytes, base64url without padding, else a 400) with the key in use: `SignedSupporterKey`. `null` without a key, and for a key which does not verify on the server. What the badge verifies. |
| `GetSupporterKeyInfo {}` | admins | `SupporterKeyInfo`: where the key in use comes from (`None`, `Config`, `Stored`), whether the config sets one, the supporter it names, and `problem`, why it does not verify and is not served. Never the key. |
| `SetSupporterKey { key }` | admins | Parses and verifies the key (a 400 with the reason otherwise, and nothing changes), hands it to the app to keep, and uses it from now on, over the config's. Answers the info. |
| `DeleteSupporterKey {}` | admins | Removes the stored key; the config's is used again. Answers the info. |
| `GetSupporterBranding {}` | every user | The `SupporterBranding` in use, the default while none is set. What the topbar shows an organization's key with. |
| `SetSupporterBranding { branding }` | admins | Checks the branding (a 400 with the reason otherwise), hands it to the app to keep, and serves it from now on. Answers it as kept. |

The answer to `GetSupporterKey` is `P`, `SP`, `I2` and `SN`, the
instance key's signature over

```text
UTF-8("{app}-supporter-v1") || nonce || SHA-256(P)
```

(`nonce_message`). The server only ever signs a fixed domain string,
32 bytes it did not choose and a hash, so the request is no signing
oracle. Signing is deterministic, the same nonce gets the same
answer. The browser then verifies `SP` under the root key `k` names,
`SN` under `I2` for the nonce it drew (a captured answer, or a proxy
without `I1`, verifies for no other nonce), and that `a` is its app,
`v` is 1, the build's release date is at most `c`, and `i` is not
revoked.

Both sides verify. The server verifies the key in use under the root
keys the app hardcodes (`SupporterKey::verify`: the root signature,
the format version, the app), and serves it only when it verifies:
nothing is signed with the instance key of another key, and such a key
brands nothing. `SetSupporterKey` refuses a key which does not verify
like one which does not parse, so only the key of the app's config, or
a stored key which verified under another release (eg. before a root
key was removed), can be in use without verifying: it stays where it
is, and `SupporterKeyInfo::problem` (also the startup log) says why it
is not served. The browser verifies what it is served again, under the
same root keys hardcoded in the app's UI, with what only it checks:
the nonce signature, the release date of the build, and the revocation
list.

Clients: `MoghSupporterClient` of the typescript package, and in
mogh_ui `setSupporterUrl`, `useSupporterBrand` + `SupporterBadge` for
the topbar and `SupporterKeyConfig` for the settings. This crate has
no http client: a Rust client posts the requests of `api` with its
own, with its own credentials (eg. the example app's client).

## Branding

The key of an organization or sponsor can be shown the organization's
way. `SupporterBranding`, set by admins and the same for every user:

| Field | Is |
| --- | --- |
| `icon` | Shown in place of the heart: an image url (`https://` or `http://`), a path on the app (`/...`), or an uploaded image, kept as a `data:image/...;base64,` url (png, jpeg, gif, webp or svg, at most `MAX_ICON_BYTES`, 256 KiB). Unset: the heart. |
| `icon_height` | The height the icon is shown at, in pixels: `MIN_ICON_SIZE` (8) to `MAX_ICON_HEIGHT` (56, what fits the topbar of the Mogh apps). Unset: 20 (`DEFAULT_ICON_HEIGHT`), on the badge and as the home button alike. |
| `icon_width` | The width the icon is shown at, in pixels: `MIN_ICON_SIZE` (8) to `MAX_ICON_WIDTH` (240). Unset: as wide as the image is at that height. The image keeps its proportions either way. |
| `link` | Where a click on the badge leads, opened in a new tab: a web address (`https://` or `http://`), eg. the organization's own site. Unset: the supporter page of mogh.tech. Not used while the brand is the home button, which leads home. |
| `replace_home` | Show the icon and the supporter's name in place of the app's home button, which still leads to `/`, instead of as a badge. |
| `hide_name` | Leave the name out where the brand shows, on the badge and as the home button: for an icon which includes it. Only with an icon, which then stands for the name: kept `false` without one, and the name shows again when the icon fails to load. |
| `uppercase_name` | Show the name in capital letters where the brand shows, on the badge and as the home button, like the apps write their own names. The name itself stays as the key has it. |

`SupporterBranding::validated` is the check (`check_icon` for the
icon, `check_link` for the link), with `BrandingError` as the reason,
which never echoes the icon or the link. Whitespace and control
characters, other schemes, `//host` paths and other media types are
refused: the icon is only ever the `src` of an `<img>`, where neither
a url nor an svg runs a script, and the link is only ever a web
address, the `href` of a new tab.

The branding is no secret and not part of the key, and it decides
nothing: the browser applies it only for a key it verified as an
organization's or sponsor's (`supporterBrand` of the typescript
package), so without such a key it shows nowhere. The server refuses
to set one unless the key in use verifies, the check it serves the
key by, and is an organization's or sponsor's. The default
(`SupporterBranding::default()`) is always accepted: it clears.
Removing the key keeps the branding for the next one.

An uploaded icon is the whole image: it is never logged (the log
says `icon uploaded`), and a request carrying the largest one is
about 350 KB, within axum's default body limit of 2 MB and the
default `signed_request_body_limit` of mogh_auth_server.

An app which sends a `Content-Security-Policy` has to let the icon
through: `img-src` needs `data:` for an uploaded icon, and the host
of an icon given as a url. An icon the browser does not load shows
as if none was set (the heart, or the app's own logo).

## Serving it

The `server` feature. `SupporterImpl`, implemented on the app's
`AuthImpl`:

- `supporter_app`: this app, as the `a` of its keys names it.
- `supporter_config_key`: the key the app's config sets, empty for
  none. Follow the app's conventions for secret settings (config
  file, environment variable, `_FILE` variant).
- `load_stored_supporter_key` / `store_supporter_key`: where a key
  set over the api is kept. It holds the instance private key: store
  it like a secret, encrypted at rest. It is handed over both ways as
  a `Zeroizing<String>` (`mogh_supporter::Zeroizing`), wiped from
  memory once dropped: encrypt it from the reference and decrypt it
  into one, without a plain copy (eg. a `to_string()`) which would
  outlive it.
- `load_supporter_branding` / `store_supporter_branding`: where the
  branding is kept, whole (as json, say). Nothing in it is secret.
  With an uploaded icon it is up to about 350 KB of text.
- `supporter_root_keys`: the root public keys which sign this app's
  supporter keys, hardcoded in the app. See Root keys below.

`server::init` loads the key in use once at startup: the stored key,
else the config's. It logs "Supporter key configured for Acme Corp
(organization), covers releases up to 2027-09-30", or at warn level
why the badge will not show, or that there is none. A key which does
not parse is logged with the reason, never the key, and ignored. Then
it loads the branding, checked again: one which is no longer valid is
ignored with a warning. Log target `mogh_supporter`.

## Root keys

A root key is given as its Ed25519 public key in base64 SPKI DER (60
characters starting `MCowBQYDK2VwAyEA`). Its id, the `k` of the
payloads it signed, is never declared: it is derived from the key,
the hex of the first 8 bytes of the SHA-256 of the raw key
(`root_key_id`).

The root keys are app-specific, and this crate ships none: each app
hardcodes the ones which sign its supporter keys, in two places.

- Its server, as `SupporterImpl::supporter_root_keys`: a key is
  served only if it verifies under them.
- Its UI, as the `rootKeys` of the typescript package's verification
  (`useSupporterBrand` of mogh_ui): a served key shows a badge only
  if it verifies under them again.

Keep the two in step. `check_root_keys` checks a list in a unit test
of the app: every entry is a key, listed once, and none is the test
root of the fixture. It returns their ids. Komodo and Cicada also
compare their two lists in a test of Core. Rotation adds an entry and
removes the old one a few releases later; several may be trusted at
once.

A public key copied wrong is another key, or none: no supporter key
verifies under it. So `server::init` logs the ids it derived from the
hardcoded keys ("Supporter keys are verified under the root keys
..."), to compare with the ids the platform published, and warns
about an entry which is no key.

## Fixture

`mogh_supporter::fixture` is test data: a supporter key as a buyer
would paste it, minted by the platform for "Acme Corp" and the app
`komodo` and signed by a test root key rather than one of Mogh's, the
answer a correct `komodo` server gives for it and a nonce of 32 bytes
`0x01`, and the test root (`fixture::ROOT`). The tests of this crate
use it, and an app's tests can: configure `fixture::KEY`, send
`fixture::NONCE`, expect `fixture::response()`.

`fixture::mint(app, name, tier)` mints another key under the test
root, for a test which needs another app, name or tier: the server
serves a key only when it verifies, so the tests of `cicada` need a
key for `cicada`, and trust the test root while under test.

The test root is no root key of an app, so the key shows a badge
only where a test passes `fixture::ROOT` as a trusted root (the
example app does, as a harness). Never do that in a release
(`check_root_keys` refuses it): the key is public, and a build which
trusted its root would show a badge for anyone who configured it.
