//! The per router hiding of server error details. The process wide
//! setting stays at its default (Full) in this test binary.
#![allow(unused_crate_dependencies)]
#![cfg(feature = "axum")]

use std::sync::{Arc, Mutex};

use axum::{
  Router,
  body::Body,
  http::{HeaderValue, Request, header},
  routing::get,
};
use mogh_error::{
  HiddenDetails, Serror, ServerError, ServerErrorDetail, StatusCode,
  hide_server_error_details,
};
use tower::ServiceExt as _;

fn internal_error() -> mogh_error::Error {
  anyhow::anyhow!("connection refused (db.internal:5432)")
    .context("Failed to query users")
    .into()
}

const FULL_CHAIN: &str =
  "Failed to query users: connection refused (db.internal:5432)";

/// The same routes, nested once behind the layer and once without.
fn routes() -> Router {
  Router::new()
    .route(
      "/fail",
      get(|| async {
        mogh_error::Result::<()>::Err(internal_error())
      }),
    )
    .route(
      "/unavailable",
      get(|| async {
        mogh_error::Result::<()>::Err(
          internal_error()
            .status_code(StatusCode::SERVICE_UNAVAILABLE)
            .header(
              header::RETRY_AFTER,
              HeaderValue::from_static("30"),
            ),
        )
      }),
    )
    .route(
      "/client",
      get(|| async {
        mogh_error::Result::<()>::Err(
          internal_error().status_code(StatusCode::BAD_REQUEST),
        )
      }),
    )
    // A server error which is not a mogh_error::Error.
    .route(
      "/plain",
      get(|| async {
        (
          StatusCode::INTERNAL_SERVER_ERROR,
          [(header::CONTENT_LENGTH, "28")],
          "panicked at db.internal:5432",
        )
      }),
    )
    .route(
      "/large",
      get(|| async {
        mogh_error::Result::<()>::Err(
          anyhow::anyhow!("x".repeat(1024 * 1024))
            .context("Failed to read the dump")
            .into(),
        )
      }),
    )
    .route("/ok", get(|| async { "fine" }))
}

/// What the hook was called with: method, path, status, error.
type Hidden =
  Arc<Mutex<Vec<(String, String, StatusCode, Option<String>)>>>;

fn app(detail: ServerErrorDetail) -> (Router, Hidden) {
  let hidden = Hidden::default();
  let record = hidden.clone();
  let layer = hide_server_error_details(detail).on_hidden(
    move |HiddenDetails {
            method,
            path,
            status,
            error,
          }| {
      record.lock().unwrap().push((
        method.to_string(),
        path.to_string(),
        *status,
        error.map(|e| format!("{e:#}")),
      ))
    },
  );
  let app = Router::new()
    .nest("/login", routes().layer(layer))
    .nest("/api", routes());
  (app, hidden)
}

async fn get_path(
  app: &Router,
  path: &str,
) -> axum::response::Response {
  app
    .clone()
    .oneshot(Request::get(path).body(Body::empty()).unwrap())
    .await
    .unwrap()
}

async fn body_text(response: axum::response::Response) -> String {
  let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
    .await
    .unwrap();
  String::from_utf8(bytes.to_vec()).unwrap()
}

async fn read_serror(response: axum::response::Response) -> Serror {
  assert_eq!(
    response.headers()[header::CONTENT_TYPE],
    "application/json"
  );
  serde_json::from_str(&body_text(response).await).unwrap()
}

#[tokio::test]
async fn generic_hides_the_server_errors_of_the_wrapped_routes() {
  let (app, hidden) = app(ServerErrorDetail::Generic);

  let response = get_path(&app, "/login/fail?code=secret").await;
  assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
  // Still there for an outer logging middleware.
  let ServerError(error) =
    response.extensions().get::<ServerError>().unwrap().clone();
  assert_eq!(format!("{error:#}"), FULL_CHAIN);
  let serror = read_serror(response).await;
  assert_eq!(serror.error, "Internal Server Error");
  assert!(serror.trace.is_empty());
  // The whole path, without the query.
  assert_eq!(
    hidden.lock().unwrap().pop().unwrap(),
    (
      String::from("GET"),
      String::from("/login/fail"),
      StatusCode::INTERNAL_SERVER_ERROR,
      Some(String::from(FULL_CHAIN))
    )
  );

  // Other headers stay.
  let response = get_path(&app, "/login/unavailable").await;
  assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
  assert_eq!(response.headers()[header::RETRY_AFTER], "30");
  assert_eq!(
    read_serror(response).await.error,
    "Service Unavailable"
  );
  assert_eq!(hidden.lock().unwrap().len(), 1);

  // Not an Error: replaced unread. The old body's length goes with
  // it (axum sets the new one).
  let response = get_path(&app, "/login/plain").await;
  assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
  let length = response.headers()[header::CONTENT_LENGTH].clone();
  let body = body_text(response).await;
  assert_eq!(length, body.len().to_string());
  let serror: Serror = serde_json::from_str(&body).unwrap();
  assert_eq!(serror.error, "Internal Server Error");
  assert!(serror.trace.is_empty());
  assert_eq!(hidden.lock().unwrap()[1].3, None);

  // Client errors and successes pass unchanged.
  let response = get_path(&app, "/login/client").await;
  assert_eq!(response.status(), StatusCode::BAD_REQUEST);
  let serror = read_serror(response).await;
  assert_eq!(serror.error, "Failed to query users");
  assert_eq!(serror.trace, ["connection refused (db.internal:5432)"]);
  let response = get_path(&app, "/login/ok").await;
  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(body_text(response).await, "fine");
  assert_eq!(hidden.lock().unwrap().len(), 2);

  // The routes outside the layer keep their details.
  let response = get_path(&app, "/api/fail").await;
  assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
  let serror = read_serror(response).await;
  assert_eq!(serror.error, "Failed to query users");
  assert_eq!(serror.trace, ["connection refused (db.internal:5432)"]);
  let response = get_path(&app, "/api/plain").await;
  assert_eq!(
    body_text(response).await,
    "panicked at db.internal:5432"
  );
  assert_eq!(hidden.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn message_keeps_the_top_level_message() {
  let (app, hidden) = app(ServerErrorDetail::Message);
  let serror = read_serror(get_path(&app, "/login/fail").await).await;
  assert_eq!(serror.error, "Failed to query users");
  assert!(serror.trace.is_empty());
  // Without an Error there is no message to keep.
  let serror =
    read_serror(get_path(&app, "/login/plain").await).await;
  assert_eq!(serror.error, "Internal Server Error");
  assert_eq!(hidden.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn full_changes_nothing() {
  let (app, hidden) = app(ServerErrorDetail::Full);
  let serror = read_serror(get_path(&app, "/login/fail").await).await;
  assert_eq!(serror.trace, ["connection refused (db.internal:5432)"]);
  let response = get_path(&app, "/login/plain").await;
  assert_eq!(
    body_text(response).await,
    "panicked at db.internal:5432"
  );
  assert!(hidden.lock().unwrap().is_empty());
}

/// Eg. an authenticated sub-router of a router built elsewhere.
#[tokio::test]
async fn except_leaves_the_matching_paths_alone() {
  let hidden = Hidden::default();
  let record = hidden.clone();
  let layer = hide_server_error_details(ServerErrorDetail::Generic)
    .on_hidden(move |details| {
      record.lock().unwrap().push((
        details.method.to_string(),
        details.path.to_string(),
        details.status,
        None,
      ))
    })
    // The path within the router the layer is on.
    .except(|path| path == "/fail");
  let app = Router::new().nest("/login", routes().layer(layer));

  let response = get_path(&app, "/login/fail").await;
  assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
  let serror = read_serror(response).await;
  assert_eq!(serror.error, "Failed to query users");
  assert_eq!(serror.trace, ["connection refused (db.internal:5432)"]);
  assert!(hidden.lock().unwrap().is_empty());

  let response = get_path(&app, "/login/unavailable").await;
  assert_eq!(
    read_serror(response).await.error,
    "Service Unavailable"
  );
  assert_eq!(hidden.lock().unwrap()[0].1, "/login/unavailable");
}

/// The body is rebuilt from the error, never read back, so there is
/// no size limit: the hook gets the whole error.
#[tokio::test]
async fn large_errors_are_hidden_and_reported_whole() {
  let (app, hidden) = app(ServerErrorDetail::Generic);
  let serror =
    read_serror(get_path(&app, "/login/large").await).await;
  assert_eq!(serror.error, "Internal Server Error");
  let (_, _, _, error) = hidden.lock().unwrap().pop().unwrap();
  let error = error.unwrap();
  assert!(error.starts_with("Failed to read the dump: xxx"));
  assert_eq!(
    error.len(),
    "Failed to read the dump: ".len() + 1024 * 1024
  );
}

/// A writer the log lines are captured into.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    self.0.lock().unwrap().extend_from_slice(buf);
    Ok(buf.len())
  }
  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
  type Writer = Captured;
  fn make_writer(&'a self) -> Captured {
    self.clone()
  }
}

#[tokio::test]
async fn hidden_details_are_logged_as_a_warning_by_default() {
  let captured = Captured::default();
  let subscriber = tracing_subscriber::fmt()
    .with_writer(captured.clone())
    .with_ansi(false)
    .finish();
  let _guard = tracing::subscriber::set_default(subscriber);
  let app = Router::new().nest(
    "/login",
    routes()
      .layer(hide_server_error_details(ServerErrorDetail::Generic)),
  );

  let response = get_path(&app, "/login/fail?code=secret").await;
  assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
  get_path(&app, "/login/plain").await;
  get_path(&app, "/login/client").await;

  let log =
    String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
  let lines = log.lines().collect::<Vec<_>>();
  assert_eq!(lines.len(), 2, "{log}");
  assert!(lines[0].contains("WARN"), "{log}");
  assert!(lines[0].contains("method=GET"), "{log}");
  assert!(lines[0].contains("path=\"/login/fail\""), "{log}");
  assert!(lines[0].contains("status=500"), "{log}");
  assert!(lines[0].contains(FULL_CHAIN), "{log}");
  assert!(!log.contains("secret"), "{log}");
  // No error to log for a response which wasn't an Error.
  assert!(lines[1].contains("path=\"/login/plain\""), "{log}");
  assert!(
    lines[1].contains("details hidden from the caller method="),
    "{log}"
  );
}
