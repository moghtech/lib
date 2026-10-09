//! OTLP export end to end, against a local collector stand in.
//! Its own test binary: [mogh_logger::init] installs the process
//! wide subscriber.
#![allow(unused_crate_dependencies)]

mod support;

use support::{Config, collector};

#[test]
fn shutdown_exports_the_queued_spans() {
  let (port, exports) = collector();
  mogh_logger::init(Config {
    // No path: the standard traces path is added.
    otlp_endpoint: format!("http://127.0.0.1:{port}"),
    targets: vec![String::from("otel_export")],
  })
  .unwrap();

  tracing::info_span!("QueuedSpan").in_scope(|| {
    tracing::info!("inside the span");
  });
  // The batch exporter sends every 5s: nothing has gone out yet,
  // and before 'shutdown' existed nothing ever did at exit.
  assert!(exports.lock().unwrap().is_empty());

  mogh_logger::shutdown().unwrap();

  let exports = exports.lock().unwrap();
  assert_eq!(exports.len(), 1);
  let export = &exports[0];
  assert!(
    export.request_line.starts_with("POST /v1/traces "),
    "{}",
    export.request_line
  );
  assert!(
    export
      .body
      .windows(10)
      .any(|window| window == b"QueuedSpan"),
    "the span is in the export"
  );
  // No credentials in the endpoint, none sent.
  assert!(export.header("authorization").is_none());
  drop(exports);

  // Once shut down, it is a no-op.
  mogh_logger::shutdown().unwrap();
}
