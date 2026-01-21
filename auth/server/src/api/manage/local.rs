use mogh_auth_client::api::{
  NoData,
  manage::{UpdatePassword, UpdateUsername},
};
use mogh_resolver::Resolve;

use crate::{AuthImpl, api::manage::ManageArgs};

pub async fn update_username<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: String,
  new_username: String,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;
  auth.validate_username(&new_username)?;
  auth.update_user_username(user_id, new_username).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UpdateUsername {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    update_username(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
      self.username,
    )
    .await?;
    Ok(NoData {})
  }
}

pub async fn update_password<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: String,
  password: &str,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;
  auth.validate_password(password)?;
  let hashed_password =
    bcrypt::hash(password.as_bytes(), auth.local_auth_bcrypt_cost())?;
  auth.update_user_password(user_id, hashed_password).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UpdatePassword {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    update_password(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
      &self.password,
    )
    .await?;
    Ok(NoData {})
  }
}
