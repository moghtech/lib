use std::sync::Arc;

use anyhow::Context;
use axum::{
  extract::{FromRequestParts, OriginalUri, Request},
  http::StatusCode,
  middleware::Next,
  response::Response,
};
use mogh_error::AddStatusCode;

use crate::{
  AuthImpl, middleware::extract_request_authentication,
  user::BoxAuthUser,
};

#[derive(Clone)]
pub struct UserExtractor(pub Arc<BoxAuthUser>);

impl<S: Send + Sync> FromRequestParts<S> for UserExtractor {
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

pub async fn attach_user<I: AuthImpl>(
  OriginalUri(uri): OriginalUri,
  mut req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  let auth = I::new();

  let req_auth = extract_request_authentication(
    &auth,
    req.method(),
    &uri,
    req.headers(),
  )?
  .context("Invalid client credentials")
  .status_code(StatusCode::UNAUTHORIZED)?;

  let user_id = auth
    .get_user_id_from_request_authentication(req_auth)
    .await?;

  let user = auth.get_user(user_id).await?;

  req.extensions_mut().insert(UserExtractor(Arc::new(user)));

  Ok(next.run(req).await)
}
