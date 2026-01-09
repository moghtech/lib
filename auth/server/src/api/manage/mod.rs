use std::{sync::Arc, time::Instant};

use axum::{Router, extract::Path, routing::post};
use derive_variants::{EnumVariants, ExtractVariant as _};
use mogh_auth_client::api::manage::*;
use mogh_error::Json;
use resolver_api::Resolve;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;
use typeshare::typeshare;
use uuid::Uuid;

use crate::{
  AuthExtractor, AuthImpl, BoxAuthImpl, api::Variant,
  user::BoxAuthUser,
};

pub mod local;
pub mod passkey;
pub mod totp;

mod middleware;

use middleware::*;

pub struct ManageArgs {
  auth: BoxAuthImpl,
  user: Arc<BoxAuthUser>,
}

#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumVariants,
)]
#[args(ManageArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[variant_derive(Debug)]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names, clippy::large_enum_variant)]
pub enum ManageRequest {
  // Local
  UpdateUsername(UpdateUsername),
  UpdatePassword(UpdatePassword),
  // Passkey
  BeginPasskeyEnrollment(BeginPasskeyEnrollment),
  ConfirmPasskeyEnrollment(ConfirmPasskeyEnrollment),
  UnenrollPasskey(UnenrollPasskey),
  // TOTP
  BeginTotpEnrollment(BeginTotpEnrollment),
  ConfirmTotpEnrollment(ConfirmTotpEnrollment),
  UnenrollTotp(UnenrollTotp),
}

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/", post(handler::<I>))
    .route("/{variant}", post(variant_handler::<I>))
    .layer(axum::middleware::from_fn(attach_user::<I>))
}

async fn variant_handler<I: AuthImpl>(
  auth: AuthExtractor<I>,
  user: UserExtractor,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: ManageRequest = serde_json::from_value(json!({
    "type": variant,
    "params": params,
  }))?;
  handler::<I>(auth, user, Json(req)).await
}

async fn handler<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
  UserExtractor(user): UserExtractor,
  Json(request): Json<ManageRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let timer = Instant::now();
  let req_id = Uuid::new_v4();
  debug!(
    "/auth/manage request {req_id} | METHOD: {:?}",
    request.extract_variant()
  );
  let args = ManageArgs {
    auth: Box::new(auth),
    user,
  };
  let res = request.resolve(&args).await;
  if let Err(e) = &res {
    debug!("/auth/login request {req_id} | error: {:#}", e.error);
  }
  let elapsed = timer.elapsed();
  debug!("/auth/login request {req_id} | resolve time: {elapsed:?}");
  res.map(|res| res.0)
}
