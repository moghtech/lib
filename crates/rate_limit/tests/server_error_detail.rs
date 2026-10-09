//! mogh_error's server error detail setting is process wide, so it
//! is tested in its own test binary, in one test, to keep other
//! tests from seeing it change.
#![allow(unused_crate_dependencies)]

use std::{net::IpAddr, time::Duration};

use axum::{http::StatusCode, response::IntoResponse as _};
use mogh_error::{
  AddStatusCodeError as _, Serror, ServerErrorDetail,
  set_server_error_detail,
};
use mogh_rate_limit::{
  FailedAttempt, RateLimiter, WithFailureRateLimit as _,
};

const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));

/// A failing lookup, as a login fails with the database down.
fn failure(status: StatusCode) -> mogh_error::Error {
  anyhow::anyhow!("connection refused (db.internal:27017)")
    .context("Failed to query users collection")
    .context("Failed to get user")
    .status_code(status)
}

async fn body(error: mogh_error::Error) -> Serror {
  let bytes = axum::body::to_bytes(
    error.into_response().into_body(),
    usize::MAX,
  )
  .await
  .unwrap();
  mogh_error::try_deserialize_serror_bytes(&bytes).unwrap()
}

/// Runs a failing attempt through the best effort, then the strict
/// limiter (sharing one budget), returning both errors.
async fn attempts(
  limiter: &RateLimiter,
  status: StatusCode,
) -> [mogh_error::Error; 2] {
  let lax = async { Err::<(), _>(failure(status)) }
    .with_failure_rate_limit_using_ip(limiter, &IP)
    .await
    .unwrap_err();
  let strict = async { Err::<(), _>(failure(status)) }
    .with_strict_failure_rate_limit_using_ip(limiter, &IP)
    .await
    .unwrap_err();
  [lax, strict]
}

/// A server error is no failed attempt: it comes back as it went
/// in, so its response hides what the detail setting hides (the
/// limiter adds no note repeating the causes), and it uses up no
/// budget. A client error gets the note, causes included.
#[tokio::test]
async fn rate_limited_server_errors_follow_the_detail_setting() {
  // One attempt: a single counted failure would show.
  let limiter = RateLimiter::new(false, 1, Duration::from_secs(60));

  // Full (the default): the causes are in the message too.
  for error in
    attempts(&limiter, StatusCode::INTERNAL_SERVER_ERROR).await
  {
    assert!(error.error.downcast_ref::<FailedAttempt>().is_none());
    let serror = body(error).await;
    assert_eq!(serror.error, "Failed to get user");
    assert!(
      serror
        .trace
        .iter()
        .any(|cause| cause.contains("db.internal")),
      "{serror:?}"
    );
  }

  // Message: the response carries the top-level message alone.
  set_server_error_detail(ServerErrorDetail::Message);
  for error in
    attempts(&limiter, StatusCode::INTERNAL_SERVER_ERROR).await
  {
    assert_eq!(error.error.to_string(), "Failed to get user");
    // Still in the chain, for logs.
    assert!(format!("{:#}", error.error).contains("db.internal"));
    let serror = body(error).await;
    assert_eq!(serror.error, "Failed to get user");
    assert!(serror.trace.is_empty(), "{serror:?}");
  }

  // Generic: only the status reason.
  set_server_error_detail(ServerErrorDetail::Generic);
  for error in attempts(&limiter, StatusCode::BAD_GATEWAY).await {
    let serror = body(error).await;
    assert_eq!(serror.error, "Bad Gateway");
    assert!(serror.trace.is_empty(), "{serror:?}");
  }

  // None of the six used the budget up: the client error, which
  // keeps its causes (they are meant for the caller), is the first
  // failure, then the client is refused.
  let [lax, strict] =
    attempts(&limiter, StatusCode::UNAUTHORIZED).await;
  let serror = body(lax).await;
  assert!(serror.error.contains("db.internal"), "{serror:?}");
  assert!(
    serror.error.ends_with("You have 0 attempts remaining"),
    "{serror:?}"
  );
  assert_eq!(strict.status, StatusCode::TOO_MANY_REQUESTS);

  set_server_error_detail(ServerErrorDetail::Full);
}
