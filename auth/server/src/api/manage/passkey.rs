use anyhow::Context as _;
use mogh_auth_client::api::manage::{
  BeginPasskeyEnrollment, BeginPasskeyEnrollmentResponse,
  ConfirmPasskeyEnrollment, ConfirmPasskeyEnrollmentResponse,
  UnenrollPasskey, UnenrollPasskeyResponse,
};
use mogh_resolver::Resolve;

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
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let username = user.username();

    auth.check_username_locked(username)?;

    let provider = auth.passkey_provider().context(
      "No passkey provider available, invalid 'host' config",
    )?;

    // Get two parts from this, the first is returned to the client.
    // The second must stay server side and is used in confirmation flow.
    let (challenge, state) =
      provider.start_passkey_registration(username)?;

    auth
      .client()
      .session
      .insert_passkey_enrollment(&state)
      .await?;

    Ok(challenge)
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
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let provider = auth.passkey_provider().context(
      "No passkey provider available, invalid 'host' config",
    )?;

    let state =
      auth.client().session.retrieve_passkey_enrollment().await?;

    let passkey = provider
      .finish_passkey_registration(&self.credential, &state)?;

    auth
      .update_user_stored_passkey(
        user.id().to_string(),
        Some(passkey),
      )
      .await?;

    Ok(ConfirmPasskeyEnrollmentResponse {})
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
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;
    auth
      .update_user_stored_passkey(user.id().to_string(), None)
      .await?;
    Ok(UnenrollPasskeyResponse {})
  }
}
