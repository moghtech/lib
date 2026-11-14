//! A TokenReview source's `ca` replaces the system roots, it is not
//! added to them: a cluster api server whose certificate chains to a
//! system root, but not to the configured `ca`, never receives the
//! reviewer credential and the token.
//!
//! A test binary of its own: it makes a test CA the only system root
//! (`SSL_CERT_FILE`), for the whole process.

#![allow(unused_crate_dependencies)]

use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};

use axum::{Json, Router, routing::post};
use axum_server::tls_rustls::RustlsConfig;
use mogh_auth_client::config::{
  TokenReviewConfig, TrustedIssuer, TrustedIssuerKeys,
};
use mogh_auth_server::provider::workload::direct_token_review;
use rustls::pki_types::{
  CertificateDer, PrivateKeyDer, pem::PemObject as _,
};

/// The test system root, and the api server certificate it issued
/// (for `127.0.0.1`) with its key. Outside the published crate, see
/// `auth/test_keys/README.md`.
const SYSTEM_ROOT: &str = concat!(
  env!("CARGO_MANIFEST_DIR"),
  "/../test_keys/tls_system_root.pem"
);
const SERVER_CERT: &str =
  include_str!("../../test_keys/tls_server.pem");
const SERVER_KEY: &str =
  include_str!("../../test_keys/tls_server_key.pem");

/// Another cluster's CA, which did not issue the server's certificate.
const OTHER_CLUSTER_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBnzCCAUWgAwIBAgIUIuvSPYqV4+n1sabgMijcZ10yCP8wCgYIKoZIzj0EAwIw
JDEiMCAGA1UEAwwZbW9naC1hdXRoIHRlc3QgY2x1c3RlciBDQTAgFw0yNjExMTQw
MDUwNTdaGA8yMTI2MTAyMTAwNTA1N1owJDEiMCAGA1UEAwwZbW9naC1hdXRoIHRl
c3QgY2x1c3RlciBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHQdpeYkEEZM
BEvColbhKbwJ1FkyxjqpqvtidUIJZ1e7rkFWMBPt8t20i34VDGc/sIGDI2YyKyTx
kNzMf5ea4wmjUzBRMB0GA1UdDgQWBBS4c1NEW7+ai18hMXApm8z4EQD5PjAfBgNV
HSMEGDAWgBS4c1NEW7+ai18hMXApm8z4EQD5PjAPBgNVHRMBAf8EBTADAQH/MAoG
CCqGSM49BAMCA0gAMEUCIQDGD46RxHJF58R/0QYazl83zwyyXuCTeT36xviDwWaK
YQIgO/cghak0+HrYEOzcV9qmMhhKzWhsiTYu9iV+UdRt1IQ=
-----END CERTIFICATE-----
";

/// Serves the TokenReview api over TLS with [SERVER_CERT],
/// authenticating every token, and counts the reviews it receives.
async fn serve_tls_cluster() -> (String, Arc<AtomicUsize>) {
  let certs = CertificateDer::pem_slice_iter(SERVER_CERT.as_bytes())
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
  let key =
    PrivateKeyDer::from_pem_slice(SERVER_KEY.as_bytes()).unwrap();
  let config = rustls::ServerConfig::builder_with_provider(Arc::new(
    rustls::crypto::aws_lc_rs::default_provider(),
  ))
  .with_safe_default_protocol_versions()
  .unwrap()
  .with_no_client_auth()
  .with_single_cert(certs, key)
  .unwrap();
  let reviews = Arc::new(AtomicUsize::new(0));
  let counted = reviews.clone();
  let router = Router::new().route(
    "/apis/authentication.k8s.io/v1/tokenreviews",
    post(move || {
      counted.fetch_add(1, Ordering::SeqCst);
      async {
        (
          axum::http::StatusCode::CREATED,
          Json(serde_json::json!({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "status": {
              "authenticated": true,
              "user": { "username": "system:serviceaccount:ns:app" },
              "audiences": ["app"],
            },
          })),
        )
      }
    }),
  );
  let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  let address = format!("https://{}", listener.local_addr().unwrap());
  let server = axum_server::from_tcp_rustls(
    listener,
    RustlsConfig::from_config(Arc::new(config)),
  )
  .unwrap();
  tokio::spawn(server.serve(router.into_make_service()));
  (address, reviews)
}

fn review_issuer(id: &str, url: &str, ca: &str) -> TrustedIssuer {
  TrustedIssuer {
    id: id.to_string(),
    name: id.to_string(),
    enabled: true,
    issuer: String::from(
      "https://kubernetes.default.svc.cluster.local",
    ),
    keys: TrustedIssuerKeys::TokenReview(TokenReviewConfig {
      url: url.to_string(),
      ca: ca.to_string(),
      token: String::from("reviewer-secret"),
      ..Default::default()
    }),
    audiences: vec![String::from("app")],
    max_token_age_secs: 0,
    rules: Vec::new(),
  }
}

async fn review(issuer: &TrustedIssuer) -> mogh_error::Result<()> {
  let TrustedIssuerKeys::TokenReview(config) = &issuer.keys else {
    unreachable!()
  };
  direct_token_review(issuer, config, "the-token")
    .await
    .map(|_| ())
}

#[test]
fn review_ca_replaces_the_system_roots() {
  // SAFETY: the only test of this binary, and it runs before any
  // other thread of its own reads the environment.
  unsafe {
    std::env::set_var("SSL_CERT_FILE", SYSTEM_ROOT);
    std::env::remove_var("SSL_CERT_DIR");
  }
  let runtime = tokio::runtime::Builder::new_multi_thread()
    .enable_all()
    .build()
    .unwrap();
  runtime.block_on(async {
    let (address, reviews) = serve_tls_cluster().await;

    // Without a `ca`, the system roots: the server's chain is trusted.
    review(&review_issuer("system-roots", &address, ""))
      .await
      .unwrap();
    assert_eq!(reviews.load(Ordering::SeqCst), 1);

    // With the `ca` of another cluster, a system trusted certificate
    // is not enough: the handshake fails, nothing is sent.
    let error =
      review(&review_issuer("other-ca", &address, OTHER_CLUSTER_CA))
        .await
        .unwrap_err();
    assert_eq!(
      error.status,
      axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(reviews.load(Ordering::SeqCst), 1);

    // With the CA which issued it, the review goes through.
    let issuing_ca = std::fs::read_to_string(SYSTEM_ROOT).unwrap();
    review(&review_issuer("issuing-ca", &address, &issuing_ca))
      .await
      .unwrap();
    assert_eq!(reviews.load(Ordering::SeqCst), 2);
  });
}
