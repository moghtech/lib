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
  let reqwest = reqwest::Client::new();
  request::login(
    &reqwest,
    "https://example.com/auth",
    GetLoginOptions {},
  )
  .await
}
```

- `request::manage` calls the authenticated management api. It sends no
  credentials itself, give the client default headers with them (eg.
  `Authorization: Bearer <jwt>`). That only works for a JWT or an api key
  (`X-API-KEY` / `X-API-SECRET`): requests with a signing key must be
  signed one at a time with `signature::signed_request_headers_for_url`
  (`pki` feature) over the host of the server and their exact path,
  query and body, so send those yourself (`POST {address}/manage` with
  the JSON body `{"type": "<request>", "params": <request>}`).
- `request::token_exchange` exchanges a token issued by an external login
  provider for an app token (RFC 8693).
- External login redirects the browser to `/external/{slug}/login` relative
  to the auth api path, using the `slug` of a provider from `GetLoginOptions`.
  The slug is not the provider id.

## Features

- `blocking`: adds `request::blocking`, the same functions for a
  `reqwest::blocking::Client`. The async functions stay available, so
  crates using either can be built together.
- `pki`: signing requests with a signing key (an Ed25519 private key
  instead of a secret), see the `signature` module.
- `utoipa`: the OpenAPI schemas of the api types, and the spec
  `openapi::MoghAuthApi`.

```rust,no_run
use mogh_auth_client::{
  api::login::{GetLoginOptions, GetLoginOptionsResponse},
  request,
};

#[cfg(feature = "blocking")]
fn login_options() -> anyhow::Result<GetLoginOptionsResponse> {
  let reqwest = reqwest::blocking::Client::new();
  request::blocking::login(
    &reqwest,
    "https://example.com/auth",
    GetLoginOptions {},
  )
}
```
