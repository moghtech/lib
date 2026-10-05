# Mogh Supporter - Typescript

Verifies Mogh supporter keys in the browser, offline. A key unlocks
nothing, every feature stays free: a valid key only makes the topbar
show a supporter badge instead of the "Become a supporter" button. A
bad key means no badge, never an error. The server side is the
[Rust crate](../rs), which verifies the key in use too and answers
`GetSupporterKey` only for one which verifies; nothing here talks to
mogh.tech at runtime.

[mogh_ui](../../ui) has the React side built on this package:
`setSupporterUrl`, `useSupporterBrand` + `SupporterBadge` for the
topbar, and `SupporterKeyConfig`, the settings section where admins
paste a key and set an organization's branding. The Rust crate serves
the api they talk to.

## The client

```ts
import { MoghSupporterClient } from "mogh_supporter";

const client = MoghSupporterClient(`${origin}/supporter`, jwt);
// Every user, for the badge.
const key = await client.read("GetSupporterKey", { nonce });
// Admins, for the settings.
const info = await client.read("GetSupporterKeyInfo", {});
await client.write("SetSupporterKey", { key: pasted });
await client.write("DeleteSupporterKey", {});
// An organization's branding: read by every user, set by admins.
const branding = await client.read("GetSupporterBranding", {});
await client.write("SetSupporterBranding", {
  branding: { icon: "/logo.png", icon_height: 28, replace_home: true },
});
```

The requests and responses are typed from the Rust crate
(`Types`, generated with typeshare: `node generate_types.mjs` from a
checkout, then `npm run build`), and `SupporterReadResponses` /
`SupporterWriteResponses` map each request to its response. A failed
request rejects with `{ status, result: { error, trace } }`, like
`mogh_auth_client`'s; `status: 1` means the server wasn't reached.
The generated enums are const objects with a union type, so a value
compares with its string: `info.source === "Stored"`.

## Verifying by hand

`useSupporter` of mogh_ui does this. Without it:

```ts
import { newNonce, verifySupporterKey } from "mogh_supporter";

// 1. A fresh nonce for every request: never one from an earlier
//    response or from storage.
const nonce = newNonce();
// 2. The key in use, signed for it.
const response = await client.read("GetSupporterKey", { nonce: nonce.encoded });
// 3. `null` means no badge, whatever the reason (logged with
//    `console.debug`). Keep the result in memory, not in storage.
const supporter = await verifySupporterKey({
  app: "komodo",
  releaseDate: RELEASE_DATE,
  // The app's own root keys of mogh.tech, hardcoded.
  rootKeys: SUPPORTER_ROOT_KEYS,
  nonce,
  response,
});
if (supporter) {
  // supporter.name, supporter.tier (individual / organization /
  // sponsor), supporter.since, supporter.covers, supporter.id
}
```

`verifySupporterKey` checks, in this order, and stops at the first
failure:

1. The response decodes: all four fields base64url without padding,
   `payload_sig` 64 bytes, `instance_public_key` 32, `nonce_sig` 64,
   `payload` at most 4 KiB.
2. The payload's `k` names a root key in `rootKeys`. Nothing else of
   the payload is trusted yet.
3. The root key verifies `payload_sig` over
   `payload || instance_public_key`.
4. The payload, now trusted, has `v` 1 and `a` this app.
5. The instance key verifies `nonce_sig` over
   `UTF-8("{app}-supporter-v1") || nonce || SHA-256(payload)` for the
   nonce this page drew. A captured response, or a proxy without the
   instance private key, verifies for no other nonce.
6. `releaseDate` is at most `c`, the last release date the key covers.
7. `i`, the key's id, is not in `revoked`.

`checkSupporterKey` is the same with the reason thrown instead of
logged, for tests.

## Branding

The key of an organization or sponsor can be shown the organization's
way, with the `SupporterBranding` admins set on the instance: `icon`
(an image url, a path on the app, or an uploaded image as a
`data:image/...;base64,` url), `icon_height` and `icon_width` in
pixels (unset, the height is 20, `DEFAULT_ICON_HEIGHT`, and the width
follows the image's proportions), `replace_home`,
which shows icon and name in place of the app's home button instead
of as a badge, `hide_name`, which leaves the name out for an icon
which includes it, `uppercase_name`, which shows the name in capital
letters, and `link`, a web address a click on the badge opens in a
new tab instead of the Mogh supporter page. `useSupporterBrand` of mogh_ui does this. Without
it:

```ts
import { supporterBrand } from "mogh_supporter";

const branding = await client.read("GetSupporterBranding", {});
// `null` unless `supporter` is a verified organization's or
// sponsor's key: the branding alone shows nothing.
const brand = supporterBrand(supporter, branding);
if (brand) {
  // brand.name, brand.tier, brand.icon, brand.iconWidth,
  // brand.iconHeight, brand.link, brand.replaceHome, brand.hideName,
  // brand.uppercaseName
}
```

`brand.hideName` is only ever set with an icon, which then stands for
the name: keep the name as the icon's text (`alt`), and show it again
if the icon fails to load.

`supporterBrand` checks the branding again and drops an icon or a
size which is not valid, so what it returns can be rendered: the icon
only ever as the `src` of an `<img>`, where neither a url nor an svg
runs a script. For a form, `brandingProblem` (with
`brandingIconProblem` and `brandingSizeProblem` for a single field)
says why the server would refuse a branding, `normalizeBranding` is
the branding as it is sent, and `iconDataUrl(file)` turns an image a
user picked into the `data:` url an icon is kept as, rejecting other
types than `ICON_MEDIA_TYPES` (png, jpeg, gif, webp, svg) and more
than `MAX_ICON_BYTES` (256 KiB). The limits (`MIN_ICON_SIZE`,
`MAX_ICON_WIDTH`, `MAX_ICON_HEIGHT`, `MAX_ICON_URL_LENGTH`) are the
Rust crate's, which checks again.

## What the app embeds

- `rootKeys` (`RootKeys`): the root public keys which sign this
  app's supporter keys, each the Ed25519 public key as base64 SPKI
  DER. The id of a key is derived from it (`rootKeyId`), never
  declared. They are app-specific and this package ships none: the
  app hardcodes its own, eg. as a frozen `SUPPORTER_ROOT_KEYS`. The
  keys are given by Mogh. Rotation adds an entry and removes the
  old one a few releases later; several may be trusted at once. The
  app's server hardcodes the same keys (the Rust crate's
  `supporter_root_keys`) and serves a key only when it verifies under
  them: keep the two in step.
  `checkRootKeys` checks a list in a test of the app: every entry is
  a key, listed once, and none is the fixture's test root. It
  resolves to their ids.
- `REVOKED`, the default `revoked`: key ids as lowercase hyphenated
  UUIDs.
- `releaseDate`: the `YYYY-MM-DD` the build was released, set at
  build time (eg. a Vite `define`). Never the current date: a key
  keeps working on every release it covered, forever, so the
  comparison is against the build, not the clock.
- `app`: `komodo` or `cicada`.

The revocation list ships with this package, so a revocation is a
release of it, picked up by the apps with the bump. A root key
rotation is a change of the app.

## Browser support

The two verifications use WebCrypto Ed25519, which needs Chrome 137,
Safari 17 or Firefox 130. On an older browser the key import throws,
which is no badge. There is no fallback implementation.

## The payload

The payload is a CBOR map (RFC 8949), read with the small decoder of
this package (`decodeCbor`): definite length integers, byte and text
strings, arrays and maps, `false`, `true` and `null`. Indefinite
lengths, tags, floats, other simple values, duplicate map keys and
trailing bytes are refused. Keys of the map this version does not
know are ignored, which is what lets a field be added later without
a new version.

## Rendering

Without a valid key the topbar shows a "Become a supporter" button
with a heart icon, linking to `SUPPORTER_URL`
(`https://mogh.tech/supporter`). With one:

- `individual`: the name next to the heart icon.
- `organization` and `sponsor`: the name and the organization's own
  icon, replacing the heart, at the size its branding sets. The icon
  is not in the key: it comes from the branding, and the heart stays
  while none is set. With `hide_name` the icon shows alone, for an
  icon which includes the name. With `replace_home` the icon and the
  name are the app's home button instead, still leading to `/`, and
  there is no badge next to it.

Don't call the key a licence, say it unlocks anything, or say it
expires: it covers every release published up to `c`, and on those
it works forever.

## Development

```sh
npm install
npm test        # tsc, then the unit tests (node --test)
```

The tests use the fixture the platform's minting code produced with a
test root key (`tests/fixture.ts`, the same as
`mogh_supporter::fixture` in Rust). Never embed that root in a
release: `checkRootKeys` refuses it.
