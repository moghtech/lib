use mogh_auth_client::api::{
  NoData,
  manage::{UpdatePassword, UpdateUsername},
};
use mogh_resolver::Resolve;

use crate::api::manage::ManageArgs;

impl Resolve<ManageArgs> for UpdateUsername {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;
    auth.validate_username(&self.username)?;
    auth
      .update_user_username(user.id().to_string(), self.username)
      .await?;
    Ok(NoData {})
  }
}

impl Resolve<ManageArgs> for UpdatePassword {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;
    auth.validate_password(&self.password)?;
    let hashed_password = bcrypt::hash(
      self.password.as_bytes(),
      auth.local_auth_bcrypt_cost(),
    )?;
    auth
      .update_user_password(user.id().to_string(), hashed_password)
      .await?;
    Ok(NoData {})
  }
}
