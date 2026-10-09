//! The server error detail setting is process wide, so it is tested
//! in its own test binary, in one test, to keep other tests from
//! seeing it change.
#![allow(unused_crate_dependencies)]
#![cfg(feature = "axum")]

use axum::{
  Router, body::Body, http::Request, response::IntoResponse as _,
  routing::get,
};
use mogh_error::{
  Serror, ServerError, ServerErrorDetail, StatusCode,
  hide_server_error_details, server_error_detail,
  set_server_error_detail,
};
use tower::ServiceExt as _;

fn error() -> mogh_error::Error {
  anyhow::anyhow!("connection refused (db.internal:5432)")
    .context("Failed to query users")
    .into()
}

async fn body(response: axum::response::Response) -> Serror {
  let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
    .await
    .unwrap();
  serde_json::from_slice(&bytes).unwrap()
}

/// Returns the body and whether the full error was attached
/// as a [ServerError] extension.
async fn respond(status: StatusCode) -> (Serror, bool) {
  let response = error().status_code(status).into_response();
  let attached = response.extensions().get::<ServerError>().is_some();
  (body(response).await, attached)
}

/// The body of a 500 from a route behind
/// `hide_server_error_details(detail)`.
async fn respond_through_layer(detail: ServerErrorDetail) -> Serror {
  let app = Router::new()
    .route(
      "/",
      get(|| async { mogh_error::Result::<()>::Err(error()) }),
    )
    .layer(hide_server_error_details(detail).on_hidden(|_| {}));
  let response = app
    .oneshot(Request::get("/").body(Body::empty()).unwrap())
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
  body(response).await
}

#[tokio::test]
async fn set_server_error_detail_applies_to_server_errors() {
  // Default sends everything
  assert_eq!(server_error_detail(), ServerErrorDetail::Full);
  let (serror, attached) =
    respond(StatusCode::INTERNAL_SERVER_ERROR).await;
  assert_eq!(serror.error, "Failed to query users");
  assert_eq!(
    serror.trace,
    vec!["connection refused (db.internal:5432)"]
  );
  // Server errors always carry the full error, for logs.
  assert!(attached);

  set_server_error_detail(ServerErrorDetail::Message);
  assert_eq!(server_error_detail(), ServerErrorDetail::Message);
  let (serror, attached) =
    respond(StatusCode::INTERNAL_SERVER_ERROR).await;
  assert_eq!(serror.error, "Failed to query users");
  assert!(serror.trace.is_empty());
  assert!(attached);
  // A layer can hide more than the process wide setting ...
  let serror =
    respond_through_layer(ServerErrorDetail::Generic).await;
  assert_eq!(serror.error, "Internal Server Error");
  // ... and does nothing with Full.
  let serror = respond_through_layer(ServerErrorDetail::Full).await;
  assert_eq!(serror.error, "Failed to query users");
  assert!(serror.trace.is_empty());

  set_server_error_detail(ServerErrorDetail::Generic);
  assert_eq!(server_error_detail(), ServerErrorDetail::Generic);
  let (serror, attached) = respond(StatusCode::BAD_GATEWAY).await;
  assert_eq!(serror.error, "Bad Gateway");
  assert!(serror.trace.is_empty());
  assert!(attached);
  // A layer never shows more than the process wide setting.
  let serror =
    respond_through_layer(ServerErrorDetail::Message).await;
  assert_eq!(serror.error, "Internal Server Error");
  assert!(serror.trace.is_empty());

  // Client errors keep their details
  let (serror, attached) = respond(StatusCode::NOT_FOUND).await;
  assert_eq!(serror.error, "Failed to query users");
  assert_eq!(serror.trace.len(), 1);
  assert!(!attached);

  set_server_error_detail(ServerErrorDetail::Full);
  let (serror, attached) =
    respond(StatusCode::INTERNAL_SERVER_ERROR).await;
  assert_eq!(serror.trace.len(), 1);
  assert!(attached);
}
