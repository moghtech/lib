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
