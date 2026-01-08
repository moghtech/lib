use mogh_auth_client::api::{
  NoData,
  manage::{
    BeginTotpEnrollment, BeginTotpEnrollmentResponse,
    ConfirmTotpEnrollment, ConfirmTotpEnrollmentResponse,
    UnenrollTotp, UnenrollTotpResponse,
  },
};
use resolver_api::Resolve;

use crate::api::manage::ManageArgs;

//

#[utoipa::path(
  post,
  path = "/manage/BeginTotpEnrollment",
  description = "Begins enrollment flow for Totp 2FA.",
  request_body(content = BeginTotpEnrollment),
  responses(
    (status = 200, description = "Creation challenge", body = BeginTotpEnrollmentResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn begin_totp_enrollment() {}

impl Resolve<ManageArgs> for BeginTotpEnrollment {
  async fn resolve(
    self,
    ManageArgs { auth, user_id }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    todo!()
  }
}

//

#[utoipa::path(
  post,
  path = "/manage/ConfirmTotpEnrollment",
  description = "Confirm enrollment for Totp 2FA.",
  request_body(content = ConfirmTotpEnrollment),
  responses(
    (status = 200, description = "Enrolled in Totp 2FA", body = ConfirmTotpEnrollmentResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn confirm_totp_enrollment() {}

impl Resolve<ManageArgs> for ConfirmTotpEnrollment {
  async fn resolve(
    self,
    ManageArgs { auth, user_id }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    todo!()
  }
}

//

#[utoipa::path(
  post,
  path = "/manage/UnenrollTotp",
  description = "Unenroll in Totp 2FA.",
  request_body(content = UnenrollTotp),
  responses(
    (status = 200, description = "Unenrolled in Totp 2FA", body = UnenrollTotpResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn unenroll_totp() {}

impl Resolve<ManageArgs> for UnenrollTotp {
  async fn resolve(
    self,
    ManageArgs { auth, user_id }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    todo!()
  }
}
