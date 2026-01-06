use std::net::{IpAddr, SocketAddr};

use anyhow::Context;
use axum::{
  extract::{ConnectInfo, FromRequestParts, Request},
  http::{HeaderMap, StatusCode},
};
use mogh_error::AddStatusCode as _;
use tower_sessions::Session;

use crate::ip::get_ip_from_headers;

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
    state: &S,
  ) -> Result<Self, Self::Rejection> {
    Ok(RequestClientArgs {
      ip: get_ip_from_request_parts(parts, state).await?,
      session: parts.extensions.get::<Session>().cloned(),
    })
  }
}

async fn get_ip_from_request_parts<S: Send + Sync>(
  parts: &mut axum::http::request::Parts,
  state: &S,
) -> mogh_error::Result<IpAddr> {
  if let Some(ip) = get_ip_from_headers(&parts.headers)? {
    return Ok(ip);
  }

  let info = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
    .await
    .context("'x-forwarded-for' and 'x-real-ip' headers are both missing, and no fallback ip could be extracted from the request.")
    .status_code(StatusCode::UNAUTHORIZED)?;

  Ok(info.0.ip())
}
