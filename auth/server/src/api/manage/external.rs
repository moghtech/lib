use anyhow::Context as _;
use mogh_auth_client::api::manage::{
  BeginExternalLoginLink, BeginExternalLoginLinkResponse,
  UnlinkLogin, UnlinkLoginResponse,
};
use resolver_api::Resolve;

use crate::{
  api::manage::ManageArgs, session::SessionExternalLinkInfo,
};

//

#[utoipa::path(
  post,
  path = "/manage/BeginExternalLoginLink",
  description = "Begin external login linking flow.",
  request_body(content = BeginExternalLoginLink),
  responses(
    (status = 200, description = "Login linking flow begun", body = BeginExternalLoginLinkResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn begin_external_login_link() {}

impl Resolve<ManageArgs> for BeginExternalLoginLink {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;

    let session = auth.client().session.as_ref().context(
      "Method called in invalid context. This should not happen.",
    )?;

    session
      .insert(
        SessionExternalLinkInfo::KEY,
        SessionExternalLinkInfo {
          user_id: user.id().to_string(),
        },
      )
      .await
      .context(
        "Failed to insert external link info into client session",
      )?;

    Ok(BeginExternalLoginLinkResponse {})
  }
}

//

#[utoipa::path(
  post,
  path = "/manage/UnlinkLogin",
  description = "Unlink a login provider.",
  request_body(content = UnlinkLogin),
  responses(
    (status = 200, description = "Login provider unlinked", body = UnlinkLoginResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn unlink_login() {}

impl Resolve<ManageArgs> for UnlinkLogin {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;

    auth
      .unlink_login(user.id().to_string(), self.provider)
      .await?;

    Ok(UnlinkLoginResponse {})
  }
}
