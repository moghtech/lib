# Mogh Auth Library

Provides trait-driven server and client implementations for robust application authentication.

- Local login with usernames and passwords
- OIDC / social login
- Two factor authentication with webauthn passkey or TOTP code
- JWT token generation and validation utilities
- Request rate limiting by IP for brute force mitigation
- Typescript types / client to layer with app-specific typescript client.

## Usage (Client)

```rust
let reqwest = Reqwest::default();

let options: mogh_auth_client::api::login::GetLoginOptionsResponse =
  mogh_auth_client::request::login(
    &reqwest,
    "https://example.com/auth",
    mogh_auth_client::api::login::GetLoginOptions {}
  ).await?;
```