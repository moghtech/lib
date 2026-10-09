# Mogh Auth Client

Types and a client for the api of the
[Mogh Auth Server](https://crates.io/crates/mogh_auth_server), which provides:

- Local login with usernames and passwords
- OIDC / social login
- Two factor authentication with webauthn passkey or TOTP code
- JWT token generation and validation utilities
- Request rate limiting by IP for brute force mitigation
- Typescript types / client to layer with app-specific typescript client.

## Usage

`address` is where the app mounts the auth api, eg. `https://example.com/auth`.

```rust,no_run
use mogh_auth_client::{
  api::login::{GetLoginOptions, GetLoginOptionsResponse},
  request,
};

async fn login_options() -> anyhow::Result<GetLoginOptionsResponse> {
  // Follows no redirects, see below.
  let reqwest = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()?;
  request::login(
    &reqwest,
    "https://example.com/auth",
    GetLoginOptions {},
  )
  .await
}
```

- Build the client with `reqwest::redirect::Policy::none()`. reqwest follows
  up to 10 redirects by default, and on one to another host strips only
  `Authorization` and cookies: api key headers (`X-API-KEY` /
  `X-API-SECRET`) go along to wherever the redirect points (the login page
  a proxy in front of the server sends requests to, a domain which moved),
  and a `307` / `308` sends the body again too (the password of
  `LoginLocalUser` / `UpdatePassword`). The request functions take a
  redirect which is not followed as an error.
- A login with a second factor takes more than one request (`LoginLocalUser`
  answers `Totp` / `Passkey`, `CompleteTotpLogin` / `CompletePasskeyLogin`
  finish it), and the server keeps the pending login in the session: send
  them with a client which keeps the session cookie, built with
  `reqwest::ClientBuilder::cookie_store(true)` (reqwest's `cookies` feature),
  as the example app's client does (`example/client/rs` in the repository,
  which also follows no redirects). A client without it keeps none, and the
  second step is refused.
- `request::manage` calls the authenticated management api. It sends no
  credentials itself, give the client default headers with them (eg.
  `Authorization: Bearer <jwt>`). That only works for a JWT or an api key
  (`X-API-KEY` / `X-API-SECRET`): a request with a signing key is signed on
  its own, right before it goes out, over the host of the server and its
  exact path, query and body.
- `request::signed_manage` (`pki` feature) sends a manage request signed
  with a signing key, and `request::signed_post` any signed JSON `POST`
  (a `request::SignedPost`, which can be signed for the host and path the
  server receives behind a proxy, and carry other headers), eg. to the
  app's own api. Both send a request once more, signed anew, when the
  server refused its timestamp (`401`, `signature::SIGNED_AT_ANOTHER_TIME`):
  the time to set up a connection counts against it, so on a slow link
  the first request over a new connection can arrive too late.
- `request::token_exchange` exchanges a token issued by an external login
  provider for an app token (RFC 8693).
- `request::parse_response(status, body)` is how these read a response:
  the value of a successful one, else the error of the server, with the
  status as its context. A successful body which fails to parse (eg. from
  a server of another version) never makes it into the error, whose
  values are redacted: use it for any JSON api whose successful bodies
  hold secrets.
- Bodies are read with a limit: an error body up to 64 KiB (cut there, the
  error says so), a successful one up to 4 MiB. `request::json_response(res,
  max_bytes)` reads and parses the response of any JSON api so, with its own
  limit, `request::error_text(res)` gives the text of an error body, and
  `request::read_body(res, max_bytes)` reads up to a limit (the `blocking`
  module has the same three).
- External login redirects the browser to `/external/{slug}/login` relative
  to the auth api path, using the `slug` of a provider from `GetLoginOptions`.
  The slug is not the provider id.
- `passkey` holds the challenges and credentials of passkey login and
  enrollment, in the JSON form of `webauthn-rs-proto`. The passkey an app
  stores for a user is the server's (`mogh_auth_server::passkey::Passkey`):
  reading it takes `webauthn-rs` and OpenSSL, which a client build of this
  crate doesn't link.

## Features

- `blocking`: adds `request::blocking`, the same functions for a
  `reqwest::blocking::Client`. The async functions stay available, so
  crates using either can be built together.
- `pki`: signing requests with a signing key (an Ed25519 private key
  instead of a secret), see the `signature` module. A client parses the
  private key once (`signature::signing_keys`) and signs each request with
  `signed_request_headers_with_keys` (or `_for_url_with_keys`): the one
  implementation of the five headers, which app clients use rather than
  building them themselves.
- `utoipa`: the OpenAPI schemas of the api types, and the spec
  `openapi::MoghAuthApi`.

```rust,no_run
use mogh_auth_client::{
  api::login::{GetLoginOptions, GetLoginOptionsResponse},
  request,
};

#[cfg(feature = "blocking")]
fn login_options() -> anyhow::Result<GetLoginOptionsResponse> {
  let reqwest = reqwest::blocking::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()?;
  request::blocking::login(
    &reqwest,
    "https://example.com/auth",
    GetLoginOptions {},
  )
}
```
