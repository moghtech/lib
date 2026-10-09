use mogh_auth_client::api::{
  NoData,
  manage::{UpdatePassword, UpdateUsername},
};
use mogh_resolver::Resolve;
use tracing::instrument;

use crate::{
  AuthImpl, CredentialChange,
  api::{
    check_new_username, login::local::check_username_available,
    manage::ManageArgs,
  },
  bcrypt_pool::bcrypt_hash,
};

pub async fn update_username<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: String,
  new_username: String,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;
  check_new_username(auth, &new_username)?;
  check_username_available(auth, &new_username, Some(&user_id))
    .await?;
  auth.update_user_username(user_id, new_username).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UpdateUsername {
  #[instrument(
    "UpdateUsername",
    skip_all,
    fields(
      user_id = user.id(),
      from = user.username(),
      to = self.username
    )
  )]
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
    bcrypt_hash(password.as_bytes(), auth.local_auth_bcrypt_cost())
      .await?;
  auth.update_user_password(user_id, hashed_password).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UpdatePassword {
  #[instrument(
    "UpdatePassword",
    skip_all,
    fields(
      user_id = args.user.id(),
    )
  )]
  async fn resolve(
    self,
    args: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let ManageArgs { auth, user, .. } = args;
    update_password(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
      &self.password,
    )
    .await?;
    args.credentials_changed(CredentialChange::Password).await?;
    Ok(NoData {})
  }
}
