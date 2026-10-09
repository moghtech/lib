# Mogh Example

A small but complete app built on the libraries of this repository, and the
test suites which run against it. It has two jobs:

- **Reference.** How an app wires the crates together: a resolver based api
  (`/read`, `/write`, `/execute`), the full `mogh_auth_server` integration, and a
  React + react-query UI on `mogh_ui` / `mogh_auth_client`.
- **Audit harness.** The integration tests start the real server binary and drive
  it over http (and a real browser), so changes to the libraries are verified the
  way an app uses them.

## Layout

| Path | What |
| --- | --- |
| [client/rs](client/rs) | `example_client`: the api types (requests, responses, entities) and a rust client. Typeshared to typescript. |
| [client/ts](client/ts) | The typescript client: `read` / `write` / `execute` / `auth`, typed by request name. |
| [server](server) | `example_server`: axum + sqlx (sqlite). `src/auth.rs` is the `AuthImpl`, `src/api` the resolver api, `migrations` the schema. |
| [server/tests/suite](server/tests/suite) | The api test suite (rust), see [Tests](#tests). |
| [mock_idp](mock_idp) | `example_mock_idp`: a mock OIDC provider / token issuer for the tests. ⚠️ Test only, the keys it signs tokens with are in this repo. |
| [ui](ui) | The React UI, and the browser tests in `ui/e2e` (playwright). |

Which crate is used where:

| Crate | Used for |
| --- | --- |
| `mogh_auth_server` / `mogh_auth_client` | Everything under `/auth`: local login, OIDC, passkey + TOTP 2FA, api keys (key + secret) and signing keys (signed requests), stored login providers, token exchange, workload identity. App side in `server/src/auth.rs`. |
| `mogh_resolver` | The request types in `client/rs/src/api`, resolved in `server/src/api`. |
| `mogh_server` | Serving, security headers, CORS, sessions, static UI hosting (`server/src/api/mod.rs`). |
| `mogh_config` / `mogh_secret_file` | Config files + env overrides + `_FILE` secrets (`server/src/config.rs`). |
| `mogh_logger` | Logging (`LogConfig` impl in `server/src/config.rs`). |
| `mogh_error` | Error responses with status codes, everywhere. |
| `mogh_rate_limit` / `mogh_request_ip` | Auth rate limiters (`server/src/state.rs`), client ip, cidr whitelists. |
| `mogh_encryption` | Secrets at rest: TOTP secrets, passkeys, provider client secrets, notes (`server/src/crypto.rs`), and `SealText` / `OpenText`. |
| `mogh_pki` | `GenerateKeyPair` (the Ed25519 keys of signing keys). The auth server verifies signed requests with it. |
| `mogh_cache` | Cached login providers / trusted issuers, and the `GetStats` timeout cache. |
| `mogh_validations` | Note titles, groups, `ValidateString`. |
| `mogh_supporter` | The supporter api under `/supporter`: `SupporterImpl` in `server/src/auth.rs` (the `supporter_key` config, the stored key and an organization's branding in the database), the badge and the branded home button in the topbar (`ui/src/app`) and the settings section (`ui/src/pages/settings.tsx`), from `mogh_ui`. The example plays `komodo`, the app of the crate's fixture key, and trusts the fixture's test root, which a release must not. |

## Run it

```sh
# Server on http://localhost:9220 (database in ./.dev/example)
cargo run -p example_server

# With the mock identity provider as OIDC login (users: alice, bob, mallory)
cargo run -p example_mock_idp            # http://127.0.0.1:9221
EXAMPLE_OIDC_ENABLED=true \
EXAMPLE_OIDC_PROVIDER=http://127.0.0.1:9221 \
EXAMPLE_OIDC_CLIENT_ID=example-client-id \
EXAMPLE_OIDC_CLIENT_SECRET=example-client-secret \
  cargo run -p example_server
```

The first user to sign up is the admin. Everything in `CoreConfig`
(`server/src/config.rs`) can be set in a config file (`EXAMPLE_CONFIG_PATHS`,
toml / yaml / json) or with `EXAMPLE_*` environment variables, which win: one
per field, named after its path (`EXAMPLE_PORT`, `EXAMPLE_OIDC_CLIENT_ID` for
`oidc.client_id`, `EXAMPLE_LOGGING_LEVEL`), each also taking a file with a
`_FILE` variant, eg. `EXAMPLE_JWT_SECRET_FILE`. A blank variable counts as
unset (`mogh_config::EnvSource`, which `server/src/config.rs` builds with
`fields_of`: a field added to `CoreConfig` gets its variable). A
`jwt_secret` must be at least 32 random bytes (`openssl rand -base64 48`), the
server refuses to start with a shorter one (`[FATAL] Invalid 'jwt_secret'`);
without one it uses a random secret, which logs everybody out on restart.

To see the supporter badge, paste the key of `mogh_supporter::fixture`
(`supporter/rs/src/fixture.rs`) into the settings page as the admin, or
set it as `EXAMPLE_SUPPORTER_KEY`. The key is an organization's, so the
settings then also offer its branding: an icon (eg. `/mogh-512x512.png`,
or an uploaded image), its size, hiding the name next to it, and showing
it in place of the "Mogh Example" home button. The UI compares the key
with its release date, the `releaseDate` of `ui/package.json`
(`vite.config.ts` reads it with `mogh_supporter/vite`): a production
build fails without one, the dev server falls back to today.

UI, either with the dev server against the running api:

```sh
cd example/client/ts && npm install && npm run build
cd ../../ui && npm install
VITE_EXAMPLE_HOST=http://localhost:9220 npm run dev   # http://localhost:9222
# The api then has to allow the other origin, start the server with:
# EXAMPLE_CORS_ALLOWED_ORIGINS=http://localhost:9222 EXAMPLE_CORS_ALLOW_CREDENTIALS=true
```

(The tests don't cover this two origin setup, only the one below.)

or built and served by the server itself (one origin, what the browser tests use):

```sh
cd example/ui && npm run build
EXAMPLE_UI_PATH=example/ui/dist cargo run -p example_server
```

The UI uses `mogh_ui`, `mogh_auth_client` and `mogh_supporter` from this
repository (`file:` dependencies), so build them after changing them:
`cd ui && npm run build`, `cd auth/client/ts && npm run build`,
`cd supporter/ts && npm run build`.

After changing the api types, regenerate the typescript types
(needs the `typeshare` cli) and rebuild the client:

```sh
node example/client/ts/generate_types.mjs && (cd example/client/ts && npm run build)
```

## Tests

### Api (rust)

```sh
cargo test -p example_server            # all
cargo test -p example_server oidc       # one module
```

Every test spawns its own server process (own port, temp dir with database,
config and key files) plus an in process mock identity provider, see
`server/tests/suite/common.rs`. The server log is printed when a test fails.

| Module | Covers |
| --- | --- |
| `local_auth` | Signup / login, validation, registration settings, locked usernames, credential updates |
| `two_factor` | TOTP enrollment + login, retries, replay across restarts, recovery codes |
| `api_keys` | Api keys + signing keys, signature binding, expiry, cidr whitelists, ownership |
| `oidc` | Signup / login / linking through the provider, groups, allowed + admin groups, 2FA, callback + redirect checks, failures sent back to the login page |
| `providers` | Admin managed login providers: secrets, validation, static providers, restarts |
| `token_exchange` | RFC 8693 exchange for users, rejected tokens, rate limiting, second factor |
| `workload` | Workload identity: rules, key sources, revocation, static issuers, key caching |
| `reauth` | Credential changes need a recent login, api keys can't make them, disabling the check |
| `security` | Rate limiting, forwarded ips / trusted proxies, user cidr whitelist, headers, CORS, session cookie |
| `app_api` | The resolver api: ownership, validation, encryption at rest, caching, both request forms |
| `supporter` | The supporter api: config forms, the signed answer the fixture pins, nonce checks, invalid keys ignored and logged without the key, admins setting and removing the key (persisted encrypted, used over the config's), an organization's branding (validated, for admins and organization keys, persisted, an uploaded icon never logged) |
| `server` | Static UI hosting, config layering, startup failures, token expiry, json logs |

Passkeys need an authenticator, they are covered by the browser tests.

### UI (playwright)

```sh
cd example/ui
npm run build            # the server serves ui/dist
npx playwright install chromium   # once
npm run test:e2e
```

Playwright builds and starts the mock identity provider and the server (fresh
database in `ui/.e2e`) by itself. Covered: local signup / login, the react-query
read / write / execute hooks (notes, tools), api keys, logging in again for
credential changes, TOTP (retry, recovery code, cancel), passkeys with the virtual authenticator of the browser, OIDC login
/ linking / second factor through the provider's pages, the admin settings
(`LoginProvidersTable`, `TrustedIssuersTable`, users) and the provider / issuer
pages they lead to (`/login-providers/:id`, `/trusted-issuers/:id`: mogh_ui's
`LoginProviderPage` / `TrustedIssuerPage`, as Komodo and Cicada mount them),
and the supporter key
(set and removed in the settings, the badge following without a reload; not
shown for an answer changed on the way or signed for another nonce; verified
in JavaScript on a page without WebCrypto, as over plain http from another
host, or whose WebCrypto lacks Ed25519; an organization's branding: icon url
and upload, size, the icon alone without the name, and the home button).

## Adding to it

1. Request + response types in `client/rs/src/api/{read,write,execute}.rs`
   (`#[derive(Resolve)]`, `#[response(..)]`), add the variant to the request enum in
   `server/src/api/*.rs` and `impl Resolve<..Args>` next to it.
2. Regenerate the typescript types, add the response to `client/ts/src/responses.ts`.
3. Use it in the UI with `useRead("Name", params)` / `useWrite("Name")` / `useExecute("Name")`.
4. Cover it in `server/tests/suite`, and in `ui/e2e` if it has UI.
