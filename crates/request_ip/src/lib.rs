//! This library includes an axum extractor for client ip, [RequestIp],
//! as well as functions to help with extracting the client ip from requests.

use std::net::{IpAddr, SocketAddr};

use anyhow::Context as _;
use axum::{
  extract::{ConnectInfo, FromRequestParts},
  http::{Extensions, HeaderMap, StatusCode},
};
use mogh_error::AddStatusCode as _;

/// Extract the client IP in the following order:
///
/// 1. X-FORWARDED-FOR header
/// 2. X-REAL-IP header
/// 3. Connection SocketAddr (will be reverse proxy ip if using one)
pub struct RequestIp(pub IpAddr);

impl From<RequestIp> for IpAddr {
  fn from(value: RequestIp) -> Self {
    value.0
  }
}

impl From<IpAddr> for RequestIp {
  fn from(value: IpAddr) -> Self {
    RequestIp(value)
  }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestIp {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    get_ip_from_headers_and_extensions(
      &parts.headers,
      &parts.extensions,
    )
    .map(RequestIp)
  }
}

pub fn get_ip_from_headers_and_extensions(
  headers: &HeaderMap,
  extensions: &Extensions,
) -> mogh_error::Result<IpAddr> {
  if let Some(ip) = get_ip_from_headers(headers)? {
    return Ok(ip);
  }

  let info = extensions.get::<ConnectInfo<SocketAddr>>()
    .context("'x-forwarded-for' and 'x-real-ip' headers are both missing, and no fallback ip could be extracted from the request.")
    .status_code(StatusCode::UNAUTHORIZED)?;

  Ok(info.0.ip())
}

pub fn get_ip_from_headers(
  headers: &HeaderMap,
) -> mogh_error::Result<Option<IpAddr>> {
  // Check X-Forwarded-For header (first IP in chain)
  if let Some(forwarded) = headers.get("x-forwarded-for")
    && let Ok(forwarded_str) = forwarded.to_str()
    && let Some(ip) = forwarded_str.split(',').next()
  {
    return Ok(Some(
      ip.trim().parse().status_code(StatusCode::UNAUTHORIZED)?,
    ));
  }

  // Check X-Real-IP header
  if let Some(real_ip) = headers.get("x-real-ip")
    && let Ok(ip) = real_ip.to_str()
  {
    return Ok(Some(
      ip.trim().parse().status_code(StatusCode::UNAUTHORIZED)?,
    ));
  }

  Ok(None)
}
