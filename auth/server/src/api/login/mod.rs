use std::time::Instant;

use axum::{Router, extract::Path, routing::post};
use mogh_auth_client::api::login::*;
use mogh_error::Json;
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use serde_json::json;
use strum::{Display, EnumDiscriminants};
use tracing::debug;
use typeshare::typeshare;
use uuid::Uuid;

use crate::{AuthExtractor, AuthImpl, BoxAuthImpl, api::Variant};

pub mod local;
pub mod passkey;
pub mod totp;

#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[args(BoxAuthImpl)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[strum_discriminants(name(LoginRequestMethod), derive(Display))]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names, clippy::large_enum_variant)]
pub enum LoginRequest {
  GetLoginOptions(GetLoginOptions),
  ExchangeForJwt(ExchangeForJwt),
  SignUpLocalUser(SignUpLocalUser),
  LoginLocalUser(LoginLocalUser),
  CompletePasskeyLogin(CompletePasskeyLogin),
  CompleteTotpLogin(CompleteTotpLogin),
}

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/", post(handler::<I>))
    .route("/{variant}", post(variant_handler::<I>))
}

async fn variant_handler<I: AuthImpl>(
  auth: AuthExtractor<I>,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: LoginRequest = serde_json::from_value(json!({
    "type": variant,
    "params": params,
  }))?;
  handler::<I>(auth, Json(req)).await
}

async fn handler<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
  Json(request): Json<LoginRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let timer = Instant::now();
  let req_id = Uuid::new_v4();
  let method: LoginRequestMethod = (&request).into();
  debug!("/auth/login request {req_id} | METHOD: {method}",);
  let args: BoxAuthImpl = Box::new(auth);
  let res = request.resolve(&args).await;
  if let Err(e) = &res {
    debug!("/auth/login request {req_id} | error: {:#}", e.error);
  }
  let elapsed = timer.elapsed();
  debug!("/auth/login request {req_id} | resolve time: {elapsed:?}");
  res.map(|res| res.0)
}

impl Resolve<BoxAuthImpl> for GetLoginOptions {
  async fn resolve(
    self,
    auth: &BoxAuthImpl,
  ) -> Result<Self::Response, Self::Error> {
    Ok(GetLoginOptionsResponse {
      local: auth.local_auth_enabled(),
      oidc: auth
        .oidc_config()
        .map(|config| config.enabled())
        .unwrap_or_default(),
      github: auth
        .github_config()
        .map(|config| config.enabled())
        .unwrap_or_default(),
      google: auth
        .google_config()
        .map(|config| config.enabled())
        .unwrap_or_default(),
      registration_disabled: auth.registration_disabled(),
    })
  }
}

impl Resolve<BoxAuthImpl> for ExchangeForJwt {
  async fn resolve(
    self,
    auth: &BoxAuthImpl,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let user_id = auth
        .client()
        .session
        .retrieve_authenticated_user_id()
        .await?;
      auth.jwt_provider().encode_sub(&user_id).map_err(Into::into)
    }
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &auth.client().ip,
    )
    .await
  }
}
