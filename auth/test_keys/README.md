# Test keys

RSA keys used only to mint signed tokens in tests. They were generated
for this repository with `openssl genrsa -traditional 2048` and protect
nothing.

They live here, outside the published `mogh_auth_server` crate
(`auth/server`), so its package carries no private key: secret scanners
of the apps' vendored or cached dependencies would flag them. Only test
code includes them, which the published crate doesn't build.

- `rsa_a.pem`: the key the test provider publishes.
- `rsa_b.pem`: a key it doesn't publish, to test rejected signatures.

Used by:

- `auth/server/src/provider/token_exchange.rs` (`test_tokens`, the
  tokens of the unit tests of the token exchange, workload identity and
  the providers),
- `auth/server/src/provider/oidc.rs` (the ID tokens of the login unit
  tests),
- `example/mock_idp` (the identity provider of the example app's
  suites).
