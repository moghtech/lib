use mogh_auth_client::api::{
  NoData,
  manage::{UpdatePassword, UpdateUsername},
};
use resolver_api::Resolve;

use crate::api::manage::ManageArgs;

#[utoipa::path(
  post,
  path = "/manage/UpdateUsername",
  description = "Update the calling user's username",
  request_body(content = UpdateUsername),
  responses(
    (status = 200, description = "Username updated", body = NoData),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn update_username() {}

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

#[utoipa::path(
  post,
  path = "/manage/UpdatePassword",
  description = "Update the calling user's password",
  request_body(content = UpdatePassword),
  responses(
    (status = 200, description = "Password updated", body = NoData),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn update_password() {}

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
