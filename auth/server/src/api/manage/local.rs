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
    ManageArgs { auth, user_id }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    todo!()
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
    ManageArgs { auth, user_id }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    todo!()
  }
}
