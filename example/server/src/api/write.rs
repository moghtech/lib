use anyhow::{Context as _, anyhow};
use axum::{
  Extension, Router, extract::Path, http::StatusCode, routing::post,
};
use example_client::{
  api::write::*,
  entities::{NoData, Note},
};
use mogh_auth_server::{
  middleware::{
    AuthenticatedAt, authenticate_request, require_recent_login,
  },
  validations::normalize_cidr_whitelist,
};
use mogh_error::{
  AddStatusCode as _, AddStatusCodeError as _, Json, Variant,
  variant_request,
};
use mogh_request_ip::cidr::whitelist_widened;
use mogh_resolver::Resolve;
use mogh_validations::StringValidator;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumDiscriminants};
use tracing::{debug, info};
use typeshare::typeshare;

use crate::{
  api::admin_only,
  auth::{ExampleAuthImpl, RequestUser},
  db::{self, UserUpdate},
};

pub struct WriteArgs {
  pub user: RequestUser,
  /// When the user logged in, for a session token
  /// ([AuthenticatedAt]): the writes which grant access need a recent
  /// login ([require_recent_login]).
  pub authenticated_at: Option<u64>,
}

#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[strum_discriminants(name(WriteRequestMethod), derive(Display))]
#[args(WriteArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[serde(tag = "type", content = "params")]
enum WriteRequest {
  // ==== NOTE ====
  CreateNote(CreateNote),
  UpdateNote(UpdateNote),
  DeleteNote(DeleteNote),

  // ==== USER ====
  UpdateCidrWhitelist(UpdateCidrWhitelist),
  UpdateUserAccess(UpdateUserAccess),
  DeleteUser(DeleteUser),
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
  authenticated_at: AuthenticatedAt,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: WriteRequest = variant_request(&variant, params)?;
  handler(user, authenticated_at, Json(req)).await
}

async fn handler(
  Extension(user): Extension<RequestUser>,
  AuthenticatedAt(authenticated_at): AuthenticatedAt,
  Json(request): Json<WriteRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let method: WriteRequestMethod = (&request).into();
  info!("WRITE REQUEST | METHOD: {method} | {}", user.user.username);
  let res = request
    .resolve(&WriteArgs {
      user,
      authenticated_at,
    })
    .await;
  if let Err(e) = &res {
    debug!("WRITE REQUEST | METHOD: {method} | ERROR: {:#}", e.error);
  }
  res.map(|res| res.0)
}

pub const MAX_NOTE_TITLE_LENGTH: usize = 100;
pub const MAX_NOTE_CONTENT_LENGTH: usize = 10_000;

pub fn validate_note_title(title: &str) -> anyhow::Result<()> {
  StringValidator::default()
    .min_length(1)
    .max_length(MAX_NOTE_TITLE_LENGTH)
    .validate(title)
    .context("Failed to validate note title")
}

fn validate_note_content(content: &str) -> anyhow::Result<()> {
  StringValidator::default()
    .max_length(MAX_NOTE_CONTENT_LENGTH)
    // Notes are multiline.
    .skip_control_check()
    .validate(content)
    .context("Failed to validate note content")
}

/// Missing notes and notes of other users look the same.
async fn get_own_note(
  id: &str,
  user: &RequestUser,
) -> mogh_error::Result<Note> {
  db::find_note(id)
    .await?
    .filter(|note| note.owner_id == user.user.id)
    .context("No note found with given id")
    .status_code(StatusCode::NOT_FOUND)
}

impl Resolve<WriteArgs> for CreateNote {
  async fn resolve(
    self,
    WriteArgs { user, .. }: &WriteArgs,
  ) -> Result<Self::Response, Self::Error> {
    validate_note_title(&self.title)
      .status_code(StatusCode::BAD_REQUEST)?;
    validate_note_content(&self.content)
      .status_code(StatusCode::BAD_REQUEST)?;
    db::create_note(&user.user.id, &self.title, &self.content)
      .await
      .map_err(Into::into)
  }
}

impl Resolve<WriteArgs> for UpdateNote {
  async fn resolve(
    self,
    WriteArgs { user, .. }: &WriteArgs,
  ) -> Result<Self::Response, Self::Error> {
    let mut note = get_own_note(&self.id, user).await?;
    if let Some(title) = self.title {
      validate_note_title(&title)
        .status_code(StatusCode::BAD_REQUEST)?;
      note.title = title;
    }
    if let Some(content) = self.content {
      validate_note_content(&content)
        .status_code(StatusCode::BAD_REQUEST)?;
      note.content = content;
    }
    note.updated_at = db::unix_timestamp_ms();
    db::update_note(&note).await?;
    Ok(note)
  }
}

impl Resolve<WriteArgs> for DeleteNote {
  async fn resolve(
    self,
    WriteArgs { user, .. }: &WriteArgs,
  ) -> Result<Self::Response, Self::Error> {
    let note = get_own_note(&self.id, user).await?;
    db::delete_note(&note.id).await?;
    Ok(NoData {})
  }
}

impl Resolve<WriteArgs> for UpdateCidrWhitelist {
  async fn resolve(
    self,
    WriteArgs {
      user,
      authenticated_at,
    }: &WriteArgs,
  ) -> Result<Self::Response, Self::Error> {
    // The rules of every whitelist the auth server stores: entries
    // trimmed, blank and repeated ones dropped, at most 64 (it is
    // parsed again for every request of the user), each valid.
    let cidr_whitelist = normalize_cidr_whitelist(
      &ExampleAuthImpl,
      self.cidr_whitelist,
    )?;
    // A whitelist letting in an ip the current one doesn't needs a
    // recent login of a session, so a token which leaked can't open
    // the account to the attacker's network for good. Entries are
    // compared as the whitelist is applied: a range within one of the
    // list is no new access. Removing entries (or setting one on an
    // empty list, which lets every ip in) needs none.
    if whitelist_widened(&user.user.cidr_whitelist, &cidr_whitelist) {
      require_recent_login(&ExampleAuthImpl, *authenticated_at)?;
    }
    db::update_user(
      &user.user.id,
      UserUpdate::CidrWhitelist(cidr_whitelist),
    )
    .await?;
    get_user(&user.user.id).await
  }
}

impl Resolve<WriteArgs> for UpdateUserAccess {
  async fn resolve(
    self,
    WriteArgs {
      user,
      authenticated_at,
    }: &WriteArgs,
  ) -> Result<Self::Response, Self::Error> {
    admin_only(user)?;
    // Everything is checked before anything is written: a refused
    // request changes nothing, then all of it is stored at once.
    for group in self.groups.iter().flatten() {
      StringValidator::default()
        .min_length(1)
        .max_length(100)
        .validate(group)
        .context("Failed to validate group")
        .status_code(StatusCode::BAD_REQUEST)?;
    }
    let target = db::find_user(&self.user_id)
      .await?
      .context("No user found with given id")
      .status_code(StatusCode::NOT_FOUND)?;
    // What a workload can do is defined by its rule alone, which
    // sets it again whenever the rule is saved. Its rule (one user
    // per rule) is what to disable.
    if target.workload.is_some()
      && (self.enabled.is_some()
        || self.admin.is_some()
        || self.groups.is_some())
    {
      return Err(
        anyhow!("The access of workload users is set by their rule")
          .status_code(StatusCode::BAD_REQUEST),
      );
    }
    if target.id == user.user.id
      && (self.enabled == Some(false) || self.admin == Some(false))
    {
      return Err(
        anyhow!("Admins can't disable or demote themselves")
          .status_code(StatusCode::BAD_REQUEST),
      );
    }
    // Granting access needs a recent login of a session, like the
    // auth server's account requests: a token which leaked isn't
    // enough to hand out access for good. Api keys pass, they are the
    // automation credentials, and taking access away needs nothing.
    let grants = (self.enabled == Some(true) && !target.enabled)
      || (self.admin == Some(true) && !target.admin)
      || self.groups.as_ref().is_some_and(|groups| {
        groups.iter().any(|group| !target.groups.contains(group))
      });
    if grants {
      require_recent_login(&ExampleAuthImpl, *authenticated_at)?;
    }
    if self.enabled.is_some()
      || self.admin.is_some()
      || self.groups.is_some()
    {
      db::update_user(
        &target.id,
        UserUpdate::Access {
          enabled: self.enabled,
          admin: self.admin,
          groups: self.groups,
        },
      )
      .await?;
    }
    get_user(&target.id).await
  }
}

impl Resolve<WriteArgs> for DeleteUser {
  async fn resolve(
    self,
    WriteArgs { user, .. }: &WriteArgs,
  ) -> Result<Self::Response, Self::Error> {
    admin_only(user)?;
    if self.user_id == user.user.id {
      return Err(
        anyhow!("Admins can't delete themselves")
          .status_code(StatusCode::BAD_REQUEST),
      );
    }
    db::delete_user(&self.user_id).await?;
    Ok(NoData {})
  }
}

async fn get_user(
  id: &str,
) -> mogh_error::Result<example_client::entities::User> {
  db::find_user(id)
    .await?
    .map(db::DbUser::into_user)
    .context("No user found with given id")
    .status_code(StatusCode::NOT_FOUND)
}
