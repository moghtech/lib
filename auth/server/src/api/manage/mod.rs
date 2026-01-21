use std::{sync::Arc, time::Instant};

use axum::{Router, extract::Path, routing::post};
use mogh_auth_client::api::{NoData, manage::*};
use mogh_error::Json;
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use serde_json::json;
use strum::{Display, EnumDiscriminants};
use tracing::debug;
use typeshare::typeshare;
use uuid::Uuid;

use crate::{
  AuthImpl, BoxAuthImpl, api::Variant, session::Session,
  user::BoxAuthUser,
};

pub mod api_key;
pub mod external;
pub mod local;
pub mod passkey;
pub mod totp;

mod middleware;

use middleware::{UserExtractor, attach_user};

pub struct ManageArgs {
  auth: BoxAuthImpl,
  user: Arc<BoxAuthUser>,
  session: Session,
}

#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[args(ManageArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[strum_discriminants(name(ManageRequestMethod), derive(Display))]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names, clippy::large_enum_variant)]
pub enum ManageRequest {
  // Local
  UpdateUsername(UpdateUsername),
  UpdatePassword(UpdatePassword),
  // External
  BeginExternalLoginLink(BeginExternalLoginLink),
  UnlinkLogin(UnlinkLogin),
  // Passkey
  BeginPasskeyEnrollment(BeginPasskeyEnrollment),
  ConfirmPasskeyEnrollment(ConfirmPasskeyEnrollment),
  UnenrollPasskey(UnenrollPasskey),
  // TOTP
  BeginTotpEnrollment(BeginTotpEnrollment),
  ConfirmTotpEnrollment(ConfirmTotpEnrollment),
  UnenrollTotp(UnenrollTotp),
  // SKIP 2FA
  UpdateExternalSkip2fa(UpdateExternalSkip2fa),
  // API KEY
  CreateApiKey(CreateApiKey),
  DeleteApiKey(DeleteApiKey),
  CreateApiKeyV2(CreateApiKeyV2),
  DeleteApiKeyV2(DeleteApiKeyV2),
}

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/", post(handler::<I>))
    .route("/{variant}", post(variant_handler::<I>))
    .layer(axum::middleware::from_fn(attach_user::<I>))
}

async fn variant_handler<I: AuthImpl>(
  session: Session,
  user: UserExtractor,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: ManageRequest = serde_json::from_value(json!({
    "type": variant,
    "params": params,
  }))?;
  handler::<I>(session, user, Json(req)).await
}

async fn handler<I: AuthImpl>(
  session: Session,
  UserExtractor(user): UserExtractor,
  Json(request): Json<ManageRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let timer = Instant::now();
  let req_id = Uuid::new_v4();
  let method: ManageRequestMethod = (&request).into();
  let username = user.username();
  let user_id = user.id();
  debug!(
    "AUTH MANAGE REQUEST {req_id} | METHOD: {method} | USER: {username} ({user_id})",
  );
  let args = ManageArgs {
    auth: Box::new(I::new()),
    user,
    session,
  };
  let res = request.resolve(&args).await;
  if let Err(e) = &res {
    debug!(
      "AUTH MANAGE REQUEST {req_id} | METHOD: {method} | error: {:#}",
      e.error
    );
  }
  let elapsed = timer.elapsed();
  debug!(
    "AUTH MANAGE REQUEST {req_id} | METHOD: {method} | resolve time: {elapsed:?}"
  );
  res.map(|res| res.0)
}

impl Resolve<ManageArgs> for UpdateExternalSkip2fa {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;
    auth
      .update_user_external_skip_2fa(
        user.id().to_string(),
        self.external_skip_2fa,
      )
      .await?;
    Ok(NoData {})
  }
}
