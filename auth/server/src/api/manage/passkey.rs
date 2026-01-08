use mogh_auth_client::api::{
  NoData,
  manage::{
    BeginPasskeyEnrollment, BeginPasskeyEnrollmentResponse,
    ConfirmPasskeyEnrollment, ConfirmPasskeyEnrollmentResponse,
    UnenrollPasskey, UnenrollPasskeyResponse,
  },
};
use resolver_api::Resolve;

use crate::api::manage::ManageArgs;

//

#[utoipa::path(
  post,
  path = "/manage/BeginPasskeyEnrollment",
  description = "Begins enrollment flow for Passkey 2FA.",
  request_body(content = BeginPasskeyEnrollment),
  responses(
    (status = 200, description = "Creation challenge", body = BeginPasskeyEnrollmentResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn begin_passkey_enrollment() {}

impl Resolve<ManageArgs> for BeginPasskeyEnrollment {
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
  path = "/manage/ConfirmPasskeyEnrollment",
  description = "Confirm enrollment for Passkey 2FA.",
  request_body(content = ConfirmPasskeyEnrollment),
  responses(
    (status = 200, description = "Enrolled in Passkey 2FA", body = ConfirmPasskeyEnrollmentResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn confirm_passkey_enrollment() {}

impl Resolve<ManageArgs> for ConfirmPasskeyEnrollment {
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
  path = "/manage/UnenrollPasskey",
  description = "Unenroll in Passkey 2FA.",
  request_body(content = UnenrollPasskey),
  responses(
    (status = 200, description = "Unenrolled in Passkey 2FA", body = UnenrollPasskeyResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn unenroll_passkey() {}

impl Resolve<ManageArgs> for UnenrollPasskey {
  async fn resolve(
    self,
    ManageArgs { auth, user_id }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    todo!()
  }
}
