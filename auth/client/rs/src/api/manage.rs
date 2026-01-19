//! # Mogh Auth Management API
//!
//! This module includes *authenticated* API methods
//! to manage user login options, such as updating
//! username / password, or configuring 2FA.

use mogh_resolver::{HasResponse, Resolve};
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{
  api::{NoData, login::LoginProvider},
  passkey::{CreationChallengeResponse, RegisterPublicKeyCredential},
};

//

pub trait MoghAuthManageRequest: HasResponse {}

//

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UpdateUsername",
  description = "Update the calling user's username.",
  request_body(content = UpdateUsername),
  responses(
    (status = 200, description = "Username updated", body = UpdateUsernameResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn update_username() {}

/// Update the calling user's username.
/// Response: [NoData].
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UpdateUsernameResponse)]
#[error(mogh_error::Error)]
pub struct UpdateUsername {
  pub username: String,
}

#[typeshare]
pub type UpdateUsernameResponse = NoData;

//

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UpdatePassword",
  description = "Update the calling user's password.",
  request_body(content = UpdatePassword),
  responses(
    (status = 200, description = "Password updated", body = UpdatePasswordResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn update_password() {}

/// Update the calling user's password.
/// Response: [NoData].
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UpdateUsernameResponse)]
#[error(mogh_error::Error)]
pub struct UpdatePassword {
  pub password: String,
}

#[typeshare]
pub type UpdatePasswordResponse = NoData;

// ===============
// = PASSKEY 2FA =
// ===============

#[cfg(feature = "utoipa")]
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

/// Begins enrollment flow for Passkey 2FA.
/// Response: [BeginPasskeyEnrollmentResponse]
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(BeginPasskeyEnrollmentResponse)]
#[error(mogh_error::Error)]
pub struct BeginPasskeyEnrollment {}

/// Response for [BeginPasskeyEnrollment].
#[typeshare]
pub type BeginPasskeyEnrollmentResponse = CreationChallengeResponse;

//

#[cfg(feature = "utoipa")]
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

/// Confirm enrollment flow for Passkey 2FA.
/// Response: [NoData]
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(ConfirmPasskeyEnrollmentResponse)]
#[error(mogh_error::Error)]
pub struct ConfirmPasskeyEnrollment {
  pub credential: RegisterPublicKeyCredential,
}

/// Response for [ConfirmPasskeyEnrollment].
#[typeshare]
pub type ConfirmPasskeyEnrollmentResponse = NoData;

//

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UnenrollPasskey",
  description = "Unenroll user in Passkey 2FA.",
  request_body(content = UnenrollPasskey),
  responses(
    (status = 200, description = "Unenrolled in Passkey 2FA", body = UnenrollPasskeyResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn unenroll_passkey() {}

/// Unenrolls user in Passkey 2FA.
/// Response: [NoData]
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UnenrollPasskeyResponse)]
#[error(mogh_error::Error)]
pub struct UnenrollPasskey {}

/// Response for [UnenrollPasskey].
#[typeshare]
pub type UnenrollPasskeyResponse = NoData;

// ============
// = TOTP 2FA =
// ============

#[cfg(feature = "utoipa")]
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

/// Starts enrollment flow for TOTP 2FA auth support.
/// Response: [BeginTotpEnrollmentResponse]
///
/// This generates an otpauth URI for the user. User must confirm
/// by providing a valid 6 digit code for the URI to [ConfirmTotpEnrollment].
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(BeginTotpEnrollmentResponse)]
#[error(mogh_error::Error)]
pub struct BeginTotpEnrollment {}

/// Response for [BeginTotpEnrollment].
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct BeginTotpEnrollmentResponse {
  /// TOTP enrollment URI for manual addition to password manager.
  pub uri: String,
  /// Base64 encoded PNG embeddable in HTML to display uri QR code.
  pub png: String,
}

//

#[cfg(feature = "utoipa")]
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

/// Confirm enrollment flow for TOTP 2FA auth support
/// Response: [ConfirmTotpEnrollmentResponse]
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(ConfirmTotpEnrollmentResponse)]
#[error(mogh_error::Error)]
pub struct ConfirmTotpEnrollment {
  pub code: String,
}

/// Response for [ConfirmTotpEnrollment].
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ConfirmTotpEnrollmentResponse {
  pub recovery_codes: Vec<String>,
}

//

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UnenrollTotp",
  description = "Unenroll user in Totp 2FA.",
  request_body(content = UnenrollTotp),
  responses(
    (status = 200, description = "Unenrolled in Totp 2FA", body = UnenrollTotpResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn unenroll_totp() {}

/// Unenrolls user in TOTP 2FA.
/// Response: [UnenrollTotpResponse]
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UnenrollTotpResponse)]
#[error(mogh_error::Error)]
pub struct UnenrollTotp {}

/// Response for [UnenrollTotp].
#[typeshare]
pub type UnenrollTotpResponse = NoData;

//

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/BeginExternalLoginLink",
  description = "Begin linking flow for an external login.",
  request_body(content = BeginExternalLoginLink),
  responses(
    (status = 200, description = "Login linking flow has been started", body = BeginExternalLoginLinkResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn begin_external_login_link() {}

/// Begin linking flow for an external login. Response: [NoData].
///
/// First call this method when authenticated, then
/// redirect user to /auth/{provider}/link.
///
/// 'provider' can be:
/// - oidc
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(BeginExternalLoginLinkResponse)]
#[error(mogh_error::Error)]
pub struct BeginExternalLoginLink {}

#[typeshare]
pub type BeginExternalLoginLinkResponse = NoData;

//

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UnlinkLogin",
  description = "Unlink a login provider.",
  request_body(content = UnlinkLogin),
  responses(
    (status = 200, description = "Login provider unlinked", body = UnlinkLoginResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn unlink_login() {}

/// Unlink a login provider. Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UnlinkLoginResponse)]
#[error(mogh_error::Error)]
pub struct UnlinkLogin {
  /// 'provider' can be:
  /// - Local
  /// - Oidc
  pub provider: LoginProvider,
}

#[typeshare]
pub type UnlinkLoginResponse = NoData;

//

#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UpdateExternalSkip2fa",
  description = "Update whether the calling user skips 2fa when using external login method.",
  request_body(content = UpdateExternalSkip2fa),
  responses(
    (status = 200, description = "External skip 2fa mode updated", body = UpdateExternalSkip2faResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn update_external_skip_2fa() {}

/// Update whether the calling user skips 2fa when using external login method.
/// Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UpdateExternalSkip2faResponse)]
#[error(mogh_error::Error)]
pub struct UpdateExternalSkip2fa {
  /// Whether user skips 2fa when using external login method.
  pub external_skip_2fa: bool,
}

#[typeshare]
pub type UpdateExternalSkip2faResponse = NoData;
