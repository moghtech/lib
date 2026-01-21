use mogh_auth_client::api::{
  login::LoginProvider,
  manage::{
    BeginExternalLoginLink, BeginExternalLoginLinkResponse,
    UnlinkLogin, UnlinkLoginResponse,
  },
};
use mogh_resolver::Resolve;

use crate::{AuthImpl, api::manage::ManageArgs};

//

impl Resolve<ManageArgs> for BeginExternalLoginLink {
  async fn resolve(
    self,
    ManageArgs {
      auth,
      user,
      session,
    }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;

    session.insert_external_link_user_id(user.id()).await?;

    Ok(BeginExternalLoginLinkResponse {})
  }
}

//

pub async fn unlink_login<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: String,
  provider: LoginProvider,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;
  auth.unlink_login(user_id, provider).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UnlinkLogin {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    unlink_login(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
      self.provider,
    )
    .await?;
    Ok(UnlinkLoginResponse {})
  }
}
