use std::net::{IpAddr, SocketAddr};

use anyhow::Context as _;
use axum::{
  extract::{ConnectInfo, Request},
  http::{HeaderMap, StatusCode},
};
use mogh_error::AddStatusCode as _;

fn get_ip_from_request(req: &Request) -> mogh_error::Result<IpAddr> {
  if let Some(ip) = get_ip_from_headers(req.headers())? {
    return Ok(ip);
  }

  let info = req.extensions().get::<ConnectInfo<SocketAddr>>()
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
