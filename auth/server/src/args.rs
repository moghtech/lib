use std::net::IpAddr;

use axum::extract::FromRequestParts;
use mogh_request_ip::get_ip_from_headers_and_extensions;
use tower_sessions::Session;

pub struct RequestClientArgs {
  /// Prefers extraction from headers 'x-forwarded-for', then 'x-real-ip'.
  /// If missing, uses fallback IP extracted directly from request.
  pub ip: IpAddr,
  /// Per-client session state
  pub session: Option<Session>,
}

impl<S: Send + Sync> FromRequestParts<S> for RequestClientArgs {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    Ok(RequestClientArgs {
      ip: get_ip_from_headers_and_extensions(
        &parts.headers,
        &parts.extensions,
      )?,
      session: parts.extensions.get::<Session>().cloned(),
    })
  }
}
