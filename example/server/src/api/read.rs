use std::net::IpAddr;

use anyhow::{Context as _, anyhow};
use axum::{
  Extension, Router, extract::Path, http::StatusCode, routing::post,
};
use example_client::api::read::*;
use mogh_auth_server::middleware::authenticate_request;
use mogh_error::{
  AddStatusCode as _, AddStatusCodeError as _, Json, Variant,
  variant_request,
};
use mogh_request_ip::RequestIp;
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumDiscriminants};
use tracing::debug;
use typeshare::typeshare;

use crate::{
  api::admin_only,
  auth::{ExampleAuthImpl, RequestUser},
  config::core_config,
  db,
  state::stats_cache,
};

pub struct ReadArgs {
  pub user: RequestUser,
  pub ip: IpAddr,
}

#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[strum_discriminants(name(ReadRequestMethod), derive(Display))]
#[args(ReadArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names)]
enum ReadRequest {
  GetVersion(GetVersion),
  GetCoreInfo(GetCoreInfo),
  GetRequestInfo(GetRequestInfo),
  GetStats(GetStats),

  // ==== USER ====
  GetUser(GetUser),
  ListUsers(ListUsers),
  ListApiKeys(ListApiKeys),

  // ==== NOTE ====
  ListNotes(ListNotes),
  GetNote(GetNote),
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
  ip: RequestIp,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: ReadRequest = variant_request(&variant, params)?;
  handler(user, ip, Json(req)).await
}

async fn handler(
  Extension(user): Extension<RequestUser>,
  RequestIp(ip): RequestIp,
  Json(request): Json<ReadRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let method: ReadRequestMethod = (&request).into();
  debug!("READ REQUEST | METHOD: {method} | {}", user.user.username);
  let res = request.resolve(&ReadArgs { user, ip }).await;
  if let Err(e) = &res {
    debug!("READ REQUEST | METHOD: {method} | ERROR: {:#}", e.error);
  }
  res.map(|res| res.0)
}

impl Resolve<ReadArgs> for GetVersion {
  async fn resolve(
    self,
    _: &ReadArgs,
  ) -> Result<Self::Response, Self::Error> {
    Ok(GetVersionResponse {
      version: env!("CARGO_PKG_VERSION").to_string(),
    })
  }
}

impl Resolve<ReadArgs> for GetCoreInfo {
  async fn resolve(
    self,
    _: &ReadArgs,
  ) -> Result<Self::Response, Self::Error> {
    let config = core_config();
    Ok(GetCoreInfoResponse {
      app_name: config.title.clone(),
      host: config.host.clone(),
    })
  }
}

impl Resolve<ReadArgs> for GetRequestInfo {
  async fn resolve(
    self,
    ReadArgs { user, ip }: &ReadArgs,
  ) -> Result<Self::Response, Self::Error> {
    Ok(GetRequestInfoResponse {
      ip: ip.to_string(),
      auth_method: user.auth_method,
      user_id: user.user.id.clone(),
    })
  }
}

impl Resolve<ReadArgs> for GetStats {
  async fn resolve(
    self,
    _: &ReadArgs,
  ) -> Result<Self::Response, Self::Error> {
    // Concurrent / rapid requests share one count of the tables.
    let lock = stats_cache().get_lock(()).await;
    let mut entry = lock.lock().await;
    if let Some(res) = entry.fresh_res() {
      return res.map_err(Into::into);
    }
    let now = db::unix_timestamp_ms();
    let res = db::counts().await.map(|(users, notes, api_keys)| {
      GetStatsResponse {
        users,
        notes,
        api_keys,
        computed_at: now,
      }
    });
    entry.set(&res);
    res.map_err(Into::into)
  }
}

impl Resolve<ReadArgs> for GetUser {
  async fn resolve(
    self,
    ReadArgs { user, .. }: &ReadArgs,
  ) -> Result<Self::Response, Self::Error> {
    Ok(user.user.as_ref().clone().into_user())
  }
}

impl Resolve<ReadArgs> for ListUsers {
  async fn resolve(
    self,
    ReadArgs { user, .. }: &ReadArgs,
  ) -> Result<Self::Response, Self::Error> {
    admin_only(user)?;
    let users = db::list_users()
      .await?
      .into_iter()
      .map(db::DbUser::into_user)
      .collect();
    Ok(users)
  }
}

impl Resolve<ReadArgs> for ListApiKeys {
  async fn resolve(
    self,
    ReadArgs { user, .. }: &ReadArgs,
  ) -> Result<Self::Response, Self::Error> {
    db::list_api_keys(&user.user.id).await.map_err(Into::into)
  }
}

impl Resolve<ReadArgs> for ListNotes {
  async fn resolve(
    self,
    ReadArgs { user, .. }: &ReadArgs,
  ) -> Result<Self::Response, Self::Error> {
    db::list_notes(&user.user.id, &self.query)
      .await
      .map_err(Into::into)
  }
}

impl Resolve<ReadArgs> for GetNote {
  async fn resolve(
    self,
    ReadArgs { user, .. }: &ReadArgs,
  ) -> Result<Self::Response, Self::Error> {
    let note = db::find_note(&self.id)
      .await?
      .context("No note found with given id")
      .status_code(StatusCode::NOT_FOUND)?;
    // Same response as a missing note, so ids can't be probed.
    if note.owner_id != user.user.id {
      return Err(
        anyhow!("No note found with given id")
          .status_code(StatusCode::NOT_FOUND),
      );
    }
    Ok(note)
  }
}
