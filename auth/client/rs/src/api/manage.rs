//! # Mogh Auth Management API
//!
//! This module includes *authenticated* API methods
//! to manage user login options, such as updating
//! username / password, or configuring 2FA.

use derive_empty_traits::EmptyTraits;
use resolver_api::{HasResponse, Resolve};
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{
  api::{NoData, login::LoginProvider},
  passkey::{CreationChallengeResponse, RegisterPublicKeyCredential},
};

//

pub trait MoghAuthManageRequest: HasResponse {}

//

/// Update the calling user's username.
/// Response: [NoData].
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
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

/// Update the calling user's password.
/// Response: [NoData].
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
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

/// Begins enrollment flow for Passkey 2FA.
/// Response: [BeginPasskeyEnrollmentResponse]
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(BeginPasskeyEnrollmentResponse)]
#[error(mogh_error::Error)]
pub struct BeginPasskeyEnrollment {}

/// Response for [BeginPasskeyEnrollment].
#[typeshare]
pub type BeginPasskeyEnrollmentResponse = CreationChallengeResponse;

//

/// Confirm enrollment flow for Passkey 2FA.
/// Response: [NoData]
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
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

/// Unenrolls user in Passkey 2FA.
/// Response: [NoData]
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
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

/// Starts enrollment flow for TOTP 2FA auth support.
/// Response: [BeginTotpEnrollmentResponse]
///
/// This generates an otpauth URI for the user. User must confirm
/// by providing a valid 6 digit code for the URI to [ConfirmTotpEnrollment].
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
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

/// Confirm enrollment flow for TOTP 2FA auth support
/// Response: [ConfirmTotpEnrollmentResponse]
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
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

/// Unenrolls user in TOTP 2FA.
/// Response: [UnenrollTotpResponse]
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UnenrollTotpResponse)]
#[error(mogh_error::Error)]
pub struct UnenrollTotp {}

/// Response for [UnenrollTotp].
#[typeshare]
pub type UnenrollTotpResponse = NoData;

//

/// Begin linking flow for an external login. Response: [NoData].
///
/// First call this method when authenticated, then
/// redirect user to /auth/{provider}/link.
///
/// 'provider' can be:
/// - oidc
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(BeginExternalLoginLinkResponse)]
#[error(mogh_error::Error)]
pub struct BeginExternalLoginLink {}

#[typeshare]
pub type BeginExternalLoginLinkResponse = NoData;

//

/// Unlink a login. Response: [NoData].
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Resolve, EmptyTraits,
)]
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

/// Update whether user skips 2fa. Response: [NoData].
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Resolve, EmptyTraits,
)]
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
