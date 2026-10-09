//! Credentials in the OTLP endpoint reach the collector as basic
//! auth. Its own test binary: [mogh_logger::init] installs the
//! process wide subscriber.
#![allow(unused_crate_dependencies)]

mod support;

use support::{Config, collector};

#[test]
fn endpoint_credentials_are_sent_as_basic_auth() {
  let (port, exports) = collector();
  mogh_logger::init(Config {
    // Percent-encoded `@` and `:`, as in any url.
    otlp_endpoint: format!(
      "http://otel%40corp:hunter%3A2@127.0.0.1:{port}"
    ),
    targets: vec![String::from("otel_export_credentials")],
  })
  .unwrap();

  tracing::info_span!("CredentialedSpan").in_scope(|| {
    tracing::info!("inside the span");
  });
  mogh_logger::shutdown().unwrap();

  let exports = exports.lock().unwrap();
  assert_eq!(exports.len(), 1);
  let export = &exports[0];
  assert!(
    export.request_line.starts_with("POST /v1/traces "),
    "{}",
    export.request_line
  );
  // `otel@corp:hunter:2`, base64.
  assert_eq!(
    export.header("authorization"),
    Some("Basic b3RlbEBjb3JwOmh1bnRlcjoy")
  );
  // The userinfo goes nowhere else.
  assert_eq!(
    export.header("host"),
    Some(format!("127.0.0.1:{port}").as_str())
  );
  assert!(
    export
      .body
      .windows(16)
      .any(|window| window == b"CredentialedSpan"),
    "the span is in the export"
  );
}
