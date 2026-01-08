use anyhow::{Context, anyhow};
use axum::{
  extract::{FromRequestParts, Request},
  http::StatusCode,
  middleware::Next,
  response::Response,
};
use mogh_error::AddStatusCode;

use crate::{AuthExtractor, AuthImpl};

/// Must layer the
#[derive(Debug, Clone)]
pub struct UserId(pub String);

impl<S: Send + Sync> FromRequestParts<S> for UserId {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    parts
      .extensions
      .get()
      .cloned()
      .context("Missing authorization credentials")
      .status_code(StatusCode::UNAUTHORIZED)
  }
}

/// Requires 'Authorization' header including jwt
pub async fn attach_user_id<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
  mut req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  let jwt = req
    .headers()
    .get("authorization")
    .context("Missing authorization header")?
    .to_str()
    .context("Authorization header is not valid UTF-8")?;
  // Strip the "Bearer" prefix, if there
  let jwt = jwt.strip_prefix("Bearer ").unwrap_or(jwt);
  let user_id = auth
    .jwt_provider()
    .decode_sub(jwt)
    .map_err(|_| anyhow!("Invalid authorization token"))
    .status_code(StatusCode::UNAUTHORIZED)?;
  req.extensions_mut().insert(UserId(user_id));
  Ok(next.run(req).await)
}
