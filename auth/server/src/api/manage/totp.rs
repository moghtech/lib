use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use data_encoding::BASE32_NOPAD;
use mogh_auth_client::api::manage::{
  BeginTotpEnrollment, BeginTotpEnrollmentResponse,
  ConfirmTotpEnrollment, ConfirmTotpEnrollmentResponse, UnenrollTotp,
  UnenrollTotpResponse,
};
use mogh_error::AddStatusCodeError as _;
use resolver_api::Resolve;

use crate::{
  api::manage::ManageArgs,
  rand::{random_bytes, random_string},
  session::SessionTotpEnrollment,
};

/// 160 bits
const TOTP_ENROLLMENT_SECRET_LENGTH: usize = 40;

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
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;

    let session = auth.client().session.as_ref().context(
      "Method called in invalid context. This should not happen.",
    )?;

    let totp = auth.make_totp(
      random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH),
      Some(user.id().to_string()),
    )?;

    let png = totp
      .get_qr_base64()
      .map_err(anyhow::Error::msg)
      .context("Failed to generate QR code png")?;
    let uri = totp.get_url();

    session
      .insert(
        SessionTotpEnrollment::KEY,
        SessionTotpEnrollment { totp },
      )
      .await?;

    Ok(BeginTotpEnrollmentResponse { uri, png })
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
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let session = auth.client().session.as_ref().context(
      "Method called in invalid context. This should not happen.",
    )?;

    let SessionTotpEnrollment { totp } = session
      .remove(SessionTotpEnrollment::KEY)
      .await
      .context("Totp enrollment was not initiated correctly")?
      .context(
        "Totp enrollment was not initiated correctly or timed out",
      )?;

    let valid = totp
      .check_current(&self.code)
      .context("Failed to check code validity")?;

    if !valid {
      return Err(anyhow!(
        "The provided code was not valid. Please try BeginTotpEnrollment flow again."
      ).status_code(StatusCode::BAD_REQUEST));
    }

    let recovery_codes =
      (0..10).map(|_| random_string(20)).collect::<Vec<_>>();
    let hashed_recovery_codes = recovery_codes
      .iter()
      .map(|code| {
        bcrypt::hash(code, auth.local_auth_bcrypt_cost())
          .context("Failed to hash a recovery code.")
      })
      .collect::<anyhow::Result<Vec<_>>>()
      .context("Failed to generate valid recovery codes")?;

    auth
      .update_user_stored_totp(
        user.id().to_string(),
        BASE32_NOPAD.encode(&totp.secret),
        hashed_recovery_codes,
      )
      .await?;

    Ok(ConfirmTotpEnrollmentResponse { recovery_codes })
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
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;
    auth.remove_user_stored_totp(user.id().to_string()).await?;
    Ok(UnenrollTotpResponse {})
  }
}
