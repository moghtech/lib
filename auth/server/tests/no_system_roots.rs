//! A host without a system CA store (a minimal image without
//! ca-certificates, `SSL_CERT_FILE` naming a missing file): the TLS
//! verifier of the shared http clients can't be built. Loading an OIDC
//! provider or the keys of a trusted issuer fails with the reason,
//! which the server logs and answers as unavailable, and never panics
//! inside the request.
//!
//! A test binary of its own: the environment it changes is the
//! process's, and no other test may build a client meanwhile.

#![allow(unused_crate_dependencies)]

use mogh_auth_client::config::{
  OidcConfig, TrustedIssuer, TrustedIssuerKeys,
};
use mogh_auth_server::provider::{
  oidc::OidcProvider, workload::load_verification_keys,
};

#[test]
fn shared_clients_without_system_roots_fail_without_panicking() {
  let missing = std::env::temp_dir()
    .join("mogh-auth-no-system-roots")
    .join("missing.pem");
  // SAFETY: the only test of this binary, and it runs before any
  // other thread of its own reads the environment.
  unsafe {
    std::env::set_var("SSL_CERT_FILE", &missing);
    std::env::remove_var("SSL_CERT_DIR");
  }
  let runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();

  let config = OidcConfig {
    enabled: true,
    provider: String::from("https://127.0.0.1:1"),
    client_id: String::from("client-id"),
    ..Default::default()
  };
  let issuer = TrustedIssuer {
    id: String::from("no-system-roots"),
    name: String::from("No system roots"),
    enabled: true,
    issuer: String::from("https://127.0.0.1:1"),
    keys: TrustedIssuerKeys::JwksUri(String::from(
      "https://127.0.0.1:1/keys",
    )),
    audiences: vec![String::from("app")],
    max_token_age_secs: 0,
    rules: Vec::new(),
  };

  // Twice: a failed build is not kept, and fails again the same way
  // (a panic in a `OnceLock` initializer would leave it empty, and
  // panic again for every request).
  for _ in 0..2 {
    let error = runtime
      .block_on(OidcProvider::new(
        "test",
        String::from("https://app.example.com/auth/oidc/callback"),
        &config,
      ))
      .err()
      .expect("no OIDC provider without a CA");
    let shown = format!("{error:#}");
    assert!(
      shown.contains("Failed to build the OIDC http client"),
      "{shown}"
    );
    assert!(shown.contains("No CA certificates"), "{shown}");
  }

  let error = runtime
    .block_on(load_verification_keys(&issuer))
    .err()
    .expect("no keys without a CA");
  let shown = format!("{error:#}");
  assert!(
    shown
      .contains("Failed to build the workload identity http client"),
    "{shown}"
  );
  assert!(shown.contains("No CA certificates"), "{shown}");
}
