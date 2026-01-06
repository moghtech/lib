use std::net::{IpAddr, SocketAddr};

use anyhow::Context;
use axum::{
  extract::{ConnectInfo, FromRequestParts},
  http::StatusCode,
};
use mogh_error::AddStatusCode as _;
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
  // Check X-Forwarded-For header (first IP in chain)
  if let Some(forwarded) = parts.headers.get("x-forwarded-for")
    && let Ok(forwarded_str) = forwarded.to_str()
    && let Some(ip) = forwarded_str.split(',').next()
  {
    return ip.trim().parse().status_code(StatusCode::UNAUTHORIZED);
  }

  // Check X-Real-IP header
  if let Some(real_ip) = parts.headers.get("x-real-ip")
    && let Ok(ip) = real_ip.to_str()
  {
    return ip.trim().parse().status_code(StatusCode::UNAUTHORIZED);
  }

  let info = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
    .await
    .context("'x-forwarded-for' and 'x-real-ip' headers are both missing, and no fallback ip could be extracted from the request.")
    .status_code(StatusCode::UNAUTHORIZED)?;

  Ok(info.0.ip())
}
