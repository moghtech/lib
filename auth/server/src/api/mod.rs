use std::time::Instant;

use anyhow::Context;
use axum::{Router, extract::Path, routing::post};
use derive_variants::{EnumVariants, ExtractVariant as _};
use mogh_auth_client::{JwtResponse, api::*};
use mogh_error::Json;
use mogh_rate_limit::WithFailureRateLimit;
use resolver_api::Resolve;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;
use typeshare::typeshare;
use uuid::Uuid;

use crate::{
  AuthExtractor, AuthImpl, BoxAuthArgs, session::SessionUserId,
};

pub mod local;
pub mod passkey;
pub mod totp;

#[typeshare]
#[derive(
  Debug, Clone, Resolve, Serialize, Deserialize, EnumVariants,
)]
#[args(BoxAuthArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[variant_derive(Debug)]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names, clippy::large_enum_variant)]
pub enum AuthRequest {
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

#[derive(serde::Deserialize)]
struct Variant {
  variant: String,
}

async fn variant_handler<I: AuthImpl>(
  auth: AuthExtractor<I>,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: AuthRequest = serde_json::from_value(json!({
    "type": variant,
    "params": params,
  }))?;
  handler::<I>(auth, Json(req)).await
}

async fn handler<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
  Json(request): Json<AuthRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let timer = Instant::now();
  let req_id = Uuid::new_v4();
  debug!(
    "/auth request {req_id} | METHOD: {:?}",
    request.extract_variant()
  );
  let args: BoxAuthArgs = Box::new(auth);
  let res = request.resolve(&args).await;
  if let Err(e) = &res {
    debug!("/auth request {req_id} | error: {:#}", e.error);
  }
  let elapsed = timer.elapsed();
  debug!("/auth request {req_id} | resolve time: {elapsed:?}");
  res.map(|res| res.0)
}

#[utoipa::path(
  post,
  path = "/auth/GetLoginOptions",
  description = "Get the available login options",
  request_body(content = GetLoginOptions),
  responses(
    (status = 200, description = "The available login options", body = GetLoginOptionsResponse)
  ),
)]
pub fn get_login_options() {}

impl Resolve<BoxAuthArgs> for GetLoginOptions {
  async fn resolve(
    self,
    args: &BoxAuthArgs,
  ) -> Result<Self::Response, Self::Error> {
    Ok(GetLoginOptionsResponse {
      local: args.local_auth_enabled(),
      registration_disabled: args.registration_disabled(),
    })
  }
}

#[utoipa::path(
  post,
  path = "/auth/ExchangeForJwt",
  description = "Follow up call after successful third party login to retrieve an authentication JWT.",
  request_body(content = ExchangeForJwt),
  responses(
    (status = 200, description = "Authentication JWT", body = JwtResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn exchange_for_jwt() {}

impl Resolve<BoxAuthArgs> for ExchangeForJwt {
  async fn resolve(
    self,
    args: &BoxAuthArgs,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let session = args
        .client()
        .session
        .as_ref()
        .context("Method called in context without session")?;

      let SessionUserId(user_id) = session
        .remove(SessionUserId::KEY)
        .await
        .context("Internal session type error")?
        .context("Authentication steps must be completed before JWT can be retrieved")?;

      args.jwt_provider().encode(&user_id).map_err(Into::into)
    }
    .with_failure_rate_limit_using_ip(
      args.general_rate_limiter(),
      &args.client().ip
    )
    .await
  }
}
