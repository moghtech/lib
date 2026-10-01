use anyhow::Context as _;
use axum::{
  Extension, Router, extract::Path, http::StatusCode, routing::post,
};
use example_client::api::execute::*;
use mogh_auth_server::middleware::authenticate_request;
use mogh_error::{AddStatusCode as _, Json};
use mogh_pki::{EncodedKeyPair, PkiKind};
use mogh_resolver::Resolve;
use mogh_validations::{StringValidator, StringValidatorMatches};
use serde::{Deserialize, Serialize};
use serde_json::json;
use strum::{Display, EnumDiscriminants};
use tracing::{debug, info};
use typeshare::typeshare;

use crate::{
  api::{Variant, write::validate_note_title},
  auth::{ExampleAuthImpl, RequestUser},
  crypto,
};

pub struct ExecuteArgs {
  pub user: RequestUser,
}

// No Debug, the requests include secrets.
#[typeshare]
#[derive(
  Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[strum_discriminants(name(ExecuteRequestMethod), derive(Display))]
#[args(ExecuteArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[serde(tag = "type", content = "params")]
enum ExecuteRequest {
  GenerateKeyPair(GenerateKeyPair),
  SealText(SealText),
  OpenText(OpenText),
  ValidateString(ValidateString),
}

pub fn router() -> Router {
  Router::new()
    .route("/", post(handler))
    .route("/{variant}", post(variant_handler))
    .layer(axum::middleware::from_fn(
      authenticate_request::<ExampleAuthImpl, true>,
    ))
}

async fn variant_handler(
  user: Extension<RequestUser>,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: ExecuteRequest = serde_json::from_value(json!({
    "type": variant,
    "params": params,
  }))
  .status_code(StatusCode::BAD_REQUEST)?;
  handler(user, Json(req)).await
}

async fn handler(
  Extension(user): Extension<RequestUser>,
  Json(request): Json<ExecuteRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let method: ExecuteRequestMethod = (&request).into();
  info!(
    "EXECUTE REQUEST | METHOD: {method} | {}",
    user.user.username
  );
  let res = request.resolve(&ExecuteArgs { user }).await;
  if let Err(e) = &res {
    debug!(
      "EXECUTE REQUEST | METHOD: {method} | ERROR: {:#}",
      e.error
    );
  }
  res.map(|res| res.0)
}

impl Resolve<ExecuteArgs> for GenerateKeyPair {
  async fn resolve(
    self,
    _: &ExecuteArgs,
  ) -> Result<Self::Response, Self::Error> {
    let keys = EncodedKeyPair::generate(PkiKind::Signature)?;
    Ok(GenerateKeyPairResponse {
      private_key: keys.private.into_inner(),
      public_key: keys.public.into_inner(),
    })
  }
}

/// What is sealed for one user can't be opened by another.
fn seal_context(user: &RequestUser) -> String {
  format!("seal-text:{}", user.user.id)
}

impl Resolve<ExecuteArgs> for SealText {
  async fn resolve(
    self,
    ExecuteArgs { user }: &ExecuteArgs,
  ) -> Result<Self::Response, Self::Error> {
    StringValidator::default()
      .max_length(10_000)
      .skip_control_check()
      .validate(&self.text)
      .status_code(StatusCode::BAD_REQUEST)?;
    Ok(SealTextResponse {
      sealed: crypto::seal(&self.text, &seal_context(user))?,
    })
  }
}

impl Resolve<ExecuteArgs> for OpenText {
  async fn resolve(
    self,
    ExecuteArgs { user }: &ExecuteArgs,
  ) -> Result<Self::Response, Self::Error> {
    let text = crypto::open(&self.sealed, &seal_context(user))
      .context("The sealed text is not valid for this user")
      .status_code(StatusCode::BAD_REQUEST)?;
    Ok(OpenTextResponse { text })
  }
}

impl Resolve<ExecuteArgs> for ValidateString {
  async fn resolve(
    self,
    _: &ExecuteArgs,
  ) -> Result<Self::Response, Self::Error> {
    let res = match self.kind {
      ValidateStringKind::Username => StringValidator::default()
        .min_length(1)
        .max_length(100)
        .matches(StringValidatorMatches::Username)
        .validate(&self.input),
      ValidateStringKind::VariableName => StringValidator::default()
        .min_length(1)
        .max_length(100)
        .matches(StringValidatorMatches::VariableName)
        .validate(&self.input),
      ValidateStringKind::HttpUrl => StringValidator::default()
        .min_length(1)
        .max_length(2000)
        .matches(StringValidatorMatches::HttpUrl)
        .validate(&self.input),
      ValidateStringKind::NoteTitle => {
        validate_note_title(&self.input)
      }
    };
    Ok(ValidateStringResponse {
      valid: res.is_ok(),
      error: res.err().map(|e| format!("{e:#}")),
    })
  }
}
