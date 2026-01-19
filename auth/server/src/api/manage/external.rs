use mogh_auth_client::api::manage::{
  BeginExternalLoginLink, BeginExternalLoginLinkResponse,
  UnlinkLogin, UnlinkLoginResponse,
};
use mogh_resolver::Resolve;

use crate::api::manage::ManageArgs;

//

impl Resolve<ManageArgs> for BeginExternalLoginLink {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;

    auth
      .client()
      .session
      .insert_external_link_user_id(user.id())
      .await?;

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
