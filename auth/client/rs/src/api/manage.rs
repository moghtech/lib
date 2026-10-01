//! # Mogh Auth Management API
//!
//! This module includes *authenticated* API methods
//! to manage user login options, such as updating
//! username / password, or configuring 2FA.

use mogh_resolver::{HasResponse, Resolve};
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{
  U64,
  api::NoData,
  config::{
    ExternalLoginProvider, ExternalLoginProviderConfig,
    TokenExchangeConfig, TrustedIssuer, empty_or_redacted,
  },
  passkey::{CreationChallengeResponse, RegisterPublicKeyCredential},
};

//

pub trait MoghAuthManageRequest: HasResponse {}

/// The error message of a request refused with `403 Forbidden` because
/// it needs a recent login starts with this. Requests which change how a
/// user (or anyone, for the admin requests) can log in are only accepted
/// with a token from a login a short while ago, so a token which leaked
/// isn't enough to take over the account. For a token from a token
/// exchange, the login is when the user authenticated at the provider
/// (the provider token's `auth_time`, else when it was issued).
/// Clients should send the user to log in again, and retry.
pub const REAUTHENTICATION_REQUIRED: &str =
  "Reauthentication required";

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/GetUserId",
  description = "Get the calling user's ID.",
  request_body(content = GetUserId),
  responses(
    (status = 200, description = "The calling user's ID", body = GetUserIdResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn get_user_id() {}

/// Get the calling user's ID.
/// Response: [GetUserIdResponse].
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(GetUserIdResponse)]
#[error(mogh_error::Error)]
pub struct GetUserId {}

#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct GetUserIdResponse {
  pub id: String,
}

//

#[allow(unused)]
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
fn update_username() {}

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

#[allow(unused)]
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
fn update_password() {}

/// Update the calling user's password.
/// Response: [NoData].
#[typeshare]
#[derive(Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UpdatePasswordResponse)]
#[error(mogh_error::Error)]
pub struct UpdatePassword {
  pub password: String,
}

/// The password is redacted.
impl std::fmt::Debug for UpdatePassword {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("UpdatePassword")
      .field("password", &empty_or_redacted(&self.password))
      .finish()
  }
}

#[typeshare]
pub type UpdatePasswordResponse = NoData;

// ===============
// = PASSKEY 2FA =
// ===============

#[allow(unused)]
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
fn begin_passkey_enrollment() {}

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

#[allow(unused)]
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
fn confirm_passkey_enrollment() {}

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

#[allow(unused)]
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
fn unenroll_passkey() {}

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

#[allow(unused)]
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
fn begin_totp_enrollment() {}

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
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct BeginTotpEnrollmentResponse {
  /// TOTP enrollment URI for manual addition to password manager.
  pub uri: String,
  /// Base64 encoded PNG embeddable in HTML to display uri QR code.
  pub png: String,
}

/// Both fields carry the TOTP secret, and are redacted.
impl std::fmt::Debug for BeginTotpEnrollmentResponse {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("BeginTotpEnrollmentResponse")
      .field("uri", &empty_or_redacted(&self.uri))
      .field("png", &empty_or_redacted(&self.png))
      .finish()
  }
}

//

#[allow(unused)]
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
fn confirm_totp_enrollment() {}

/// Confirm enrollment flow for TOTP 2FA auth support
/// Response: [ConfirmTotpEnrollmentResponse]
#[typeshare]
#[derive(Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(ConfirmTotpEnrollmentResponse)]
#[error(mogh_error::Error)]
pub struct ConfirmTotpEnrollment {
  pub code: String,
}

/// The code is redacted.
impl std::fmt::Debug for ConfirmTotpEnrollment {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ConfirmTotpEnrollment")
      .field("code", &empty_or_redacted(&self.code))
      .finish()
  }
}

/// Response for [ConfirmTotpEnrollment].
#[typeshare]
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ConfirmTotpEnrollmentResponse {
  pub recovery_codes: Vec<String>,
}

/// Only the number of recovery codes is shown.
impl std::fmt::Debug for ConfirmTotpEnrollmentResponse {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ConfirmTotpEnrollmentResponse")
      .field(
        "recovery_codes",
        &format_args!("[{} redacted]", self.recovery_codes.len()),
      )
      .finish()
  }
}

//

#[allow(unused)]
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
fn unenroll_totp() {}

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

#[allow(unused)]
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
fn begin_external_login_link() {}

/// Begin linking flow for an external login. Response: [NoData].
///
/// First call this method when authenticated, then redirect the
/// user to `/external/{slug}/link` relative to the auth api path
/// (eg. `/auth/external/{slug}/link`), using the provider `slug`
/// from [GetLoginOptions][crate::api::login::GetLoginOptions]
/// (see [LoginOptionsProvider][crate::api::login::LoginOptionsProvider]).
/// The slug is not the provider id.
///
/// The response sets a new session cookie (the session id changes),
/// and the redirect to `/link` must carry it: only the session which
/// began the link can use it, for 10 minutes. Browsers do this when
/// the request is sent with credentials.
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

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UnlinkLocalLogin",
  description = "Remove the password of the calling user, disabling local login.",
  request_body(content = UnlinkLocalLogin),
  responses(
    (status = 200, description = "Local login unlinked", body = UnlinkLocalLoginResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn unlink_local_login() {}

/// Remove the password of the calling user,
/// disabling local login. Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UnlinkLocalLoginResponse)]
#[error(mogh_error::Error)]
pub struct UnlinkLocalLogin {}

#[typeshare]
pub type UnlinkLocalLoginResponse = NoData;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UnlinkExternalLogin",
  description = "Unlink an external login provider from the calling user.",
  request_body(content = UnlinkExternalLogin),
  responses(
    (status = 200, description = "External login unlinked", body = UnlinkExternalLoginResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn unlink_external_login() {}

/// Unlink an external login provider from the calling user.
/// Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UnlinkExternalLoginResponse)]
#[error(mogh_error::Error)]
pub struct UnlinkExternalLogin {
  /// The id of the provider to unlink.
  pub provider_id: String,
}

#[typeshare]
pub type UnlinkExternalLoginResponse = NoData;

//

/// An external login provider as listed for admins.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ExternalLoginProviderListItem {
  /// The provider. The client secret is redacted.
  pub provider: ExternalLoginProvider,
  /// Whether the provider comes from static app configuration
  /// (file / env), in which case it cannot be updated or deleted.
  pub read_only: bool,
  /// The redirect / callback URI which
  /// must be registered at the provider.
  pub redirect_uri: String,
}

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/ListExternalLoginProviders",
  description = "List all configured external login providers. Admin only.",
  request_body(content = ListExternalLoginProviders),
  responses(
    (status = 200, description = "The external login providers", body = [ExternalLoginProviderListItem]),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 403, description = "Forbidden", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn list_external_login_providers() {}

/// List all configured external login providers,
/// including disabled ones. Admin only.
/// Response: [ListExternalLoginProvidersResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(ListExternalLoginProvidersResponse)]
#[error(mogh_error::Error)]
pub struct ListExternalLoginProviders {}

#[typeshare]
pub type ListExternalLoginProvidersResponse =
  Vec<ExternalLoginProviderListItem>;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/CreateExternalLoginProvider",
  description = "Create an external login provider. Admin only.",
  request_body(content = CreateExternalLoginProvider),
  responses(
    (status = 200, description = "The created provider", body = CreateExternalLoginProviderResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 403, description = "Forbidden", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn create_external_login_provider() {}

/// Create an external login provider. Admin only.
/// The provider id is generated by the server, the slug
/// (the part of its urls naming it) defaults to the name.
/// Response: [ExternalLoginProviderListItem].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(CreateExternalLoginProviderResponse)]
#[error(mogh_error::Error)]
pub struct CreateExternalLoginProvider {
  /// The display name, eg. shown on the login button.
  pub name: String,
  /// The slug naming the provider in its login / callback urls
  /// (`/external/{slug}/callback`): lowercase letters, digits and
  /// single hyphens, unique among all providers. Empty: made from
  /// the name.
  #[serde(default)]
  pub slug: String,
  /// Disable new user registration using this provider.
  #[serde(default)]
  pub registration_disabled: bool,
  /// Allow tokens issued by this provider to be
  /// exchanged for an app token (RFC 8693).
  #[serde(default)]
  pub token_exchange: TokenExchangeConfig,
  /// The kind specific provider configuration.
  pub config: ExternalLoginProviderConfig,
}

#[typeshare]
pub type CreateExternalLoginProviderResponse =
  ExternalLoginProviderListItem;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UpdateExternalLoginProvider",
  description = "Update an external login provider. Admin only.",
  request_body(content = UpdateExternalLoginProvider),
  responses(
    (status = 200, description = "The updated provider", body = UpdateExternalLoginProviderResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 403, description = "Forbidden", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn update_external_login_provider() {}

/// Update an external login provider, replacing its
/// name and configuration. Admin only.
/// Response: [ExternalLoginProviderListItem].
///
/// - The kind of the provider cannot be changed.
/// - If the client secret is empty or the redacted value from
///   [ListExternalLoginProviders], the existing secret is kept.
///   Pass `clear_client_secret` to remove it instead.
/// - An empty slug keeps the existing one. Changing it changes the
///   redirect URI registered at the provider.
/// - ⚠️ Users stay linked to the provider by its id and their user id
///   (subject) at the provider. Pointing an OIDC provider at another
///   identity provider (issuer) lets that one's users log in to the
///   accounts linked with the same subject. Create a new provider
///   instead, unless the same identity provider only moved.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UpdateExternalLoginProviderResponse)]
#[error(mogh_error::Error)]
pub struct UpdateExternalLoginProvider {
  /// The id of the provider to update.
  pub id: String,
  /// The display name, eg. shown on the login button.
  pub name: String,
  /// The slug naming the provider in its login / callback urls.
  /// Empty keeps the existing one.
  #[serde(default)]
  pub slug: String,
  /// Disable new user registration using this provider.
  #[serde(default)]
  pub registration_disabled: bool,
  /// Allow tokens issued by this provider to be
  /// exchanged for an app token (RFC 8693).
  #[serde(default)]
  pub token_exchange: TokenExchangeConfig,
  /// The kind specific provider configuration.
  pub config: ExternalLoginProviderConfig,
  /// Remove the stored client secret, eg. to switch an OIDC
  /// provider to a public client using PKCE. An empty client
  /// secret on its own keeps the stored secret.
  ///
  /// Cannot be combined with a new client secret.
  #[serde(default)]
  pub clear_client_secret: bool,
}

#[typeshare]
pub type UpdateExternalLoginProviderResponse =
  ExternalLoginProviderListItem;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/DeleteExternalLoginProvider",
  description = "Delete an external login provider. Admin only.",
  request_body(content = DeleteExternalLoginProvider),
  responses(
    (status = 200, description = "Provider deleted", body = DeleteExternalLoginProviderResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 403, description = "Forbidden", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn delete_external_login_provider() {}

/// Delete an external login provider. Admin only.
/// Users can no longer log in with the provider,
/// and their links to it are removed by the app.
/// Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(DeleteExternalLoginProviderResponse)]
#[error(mogh_error::Error)]
pub struct DeleteExternalLoginProvider {
  /// The id of the provider to delete.
  pub id: String,
}

#[typeshare]
pub type DeleteExternalLoginProviderResponse = NoData;

//

/// A trusted issuer as listed for admins.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TrustedIssuerListItem {
  pub issuer: TrustedIssuer,
  /// Whether the issuer comes from static app configuration
  /// (file / env), in which case it cannot be updated or deleted.
  pub read_only: bool,
}

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/ListTrustedIssuers",
  description = "List the token issuers trusted for workload identity. Admin only.",
  request_body(content = ListTrustedIssuers),
  responses(
    (status = 200, description = "The trusted issuers", body = [TrustedIssuerListItem]),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 403, description = "Forbidden", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn list_trusted_issuers() {}

/// List the token issuers trusted for workload identity,
/// including disabled ones. Admin only.
/// Response: [ListTrustedIssuersResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(ListTrustedIssuersResponse)]
#[error(mogh_error::Error)]
pub struct ListTrustedIssuers {}

#[typeshare]
pub type ListTrustedIssuersResponse = Vec<TrustedIssuerListItem>;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/CreateTrustedIssuer",
  description = "Create a trusted issuer. Admin only.",
  request_body(content = CreateTrustedIssuer),
  responses(
    (status = 200, description = "The created issuer", body = CreateTrustedIssuerResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 403, description = "Forbidden", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn create_trusted_issuer() {}

/// Create a trusted issuer. Admin only.
/// The ids of the issuer and its rules are generated by the server.
/// Response: [TrustedIssuerListItem].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(CreateTrustedIssuerResponse)]
#[error(mogh_error::Error)]
pub struct CreateTrustedIssuer {
  /// The issuer to create. `id` and the rule ids are ignored.
  pub issuer: TrustedIssuer,
}

#[typeshare]
pub type CreateTrustedIssuerResponse = TrustedIssuerListItem;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/UpdateTrustedIssuer",
  description = "Update a trusted issuer. Admin only.",
  request_body(content = UpdateTrustedIssuer),
  responses(
    (status = 200, description = "The updated issuer", body = UpdateTrustedIssuerResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 403, description = "Forbidden", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn update_trusted_issuer() {}

/// Replace the trusted issuer with the same `id`. Admin only.
/// Response: [TrustedIssuerListItem].
///
/// Rules keep their user as long as they keep their id.
/// Rules with an empty or unknown id are new rules,
/// and get an id generated by the server.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(UpdateTrustedIssuerResponse)]
#[error(mogh_error::Error)]
pub struct UpdateTrustedIssuer {
  pub issuer: TrustedIssuer,
}

#[typeshare]
pub type UpdateTrustedIssuerResponse = TrustedIssuerListItem;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/DeleteTrustedIssuer",
  description = "Delete a trusted issuer. Admin only.",
  request_body(content = DeleteTrustedIssuer),
  responses(
    (status = 200, description = "Issuer deleted", body = DeleteTrustedIssuerResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 403, description = "Forbidden", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn delete_trusted_issuer() {}

/// Delete a trusted issuer. Admin only.
/// Its workloads can no longer get app tokens,
/// and the users of its rules are removed by the app.
/// Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(DeleteTrustedIssuerResponse)]
#[error(mogh_error::Error)]
pub struct DeleteTrustedIssuer {
  /// The id of the issuer to delete.
  pub id: String,
}

#[typeshare]
pub type DeleteTrustedIssuerResponse = NoData;

//

#[allow(unused)]
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
fn update_external_skip_2fa() {}

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

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/CreateApiKey",
  description = "Create an api key for the calling user.",
  request_body(content = CreateApiKey),
  responses(
    (status = 200, description = "The api key and secret. The secret is not available again after this response is returned.", body = CreateApiKeyResponse),
    (status = 400, description = "Invalid api key name", body = mogh_error::Serror),
    (status = 500, description = "Failed", body = mogh_error::Serror),
  ),
)]
fn create_api_key() {}

/// Create an API key for the calling user.
/// Response: [CreateApiKeyResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(CreateApiKeyResponse)]
#[error(mogh_error::Error)]
pub struct CreateApiKey {
  /// The name for the api key.
  pub name: String,

  /// A unix timestamp in millseconds specifying api key expire time.
  /// Default is 0, which means no expiry.
  #[serde(default)]
  pub expires: U64,

  /// Whitelist of CIDR ranges (eg `10.0.0.0/8`) or ip addresses
  /// from which requests using this api key are accepted.
  /// Empty (the default) means all ips are allowed.
  #[serde(default)]
  pub cidr_whitelist: Vec<String>,
}

/// Response for [CreateApiKey].
#[typeshare]
#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateApiKeyResponse {
  /// X-API-KEY
  pub key: String,

  /// X-API-SECRET
  ///
  /// Note.
  /// There is no way to get the secret again after it is distributed in this response
  pub secret: String,
}

/// The secret is redacted.
impl std::fmt::Debug for CreateApiKeyResponse {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("CreateApiKeyResponse")
      .field("key", &self.key)
      .field("secret", &empty_or_redacted(&self.secret))
      .finish()
  }
}

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/DeleteApiKey",
  description = "Delete an api key for the calling user.",
  request_body(content = DeleteApiKey),
  responses(
    (status = 200, description = "Api key deleted.", body = DeleteApiKeyResponse),
    (status = 404, description = "Api key not found.", body = mogh_error::Serror),
    (status = 500, description = "Failed", body = mogh_error::Serror),
  ),
)]
fn delete_api_key() {}

/// Delete an API key for the calling user.
/// Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(DeleteApiKeyResponse)]
#[error(mogh_error::Error)]
pub struct DeleteApiKey {
  /// The key which the user intends to delete.
  pub key: String,
}

/// Response for [DeleteApiKey].
#[typeshare]
pub type DeleteApiKeyResponse = NoData;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/CreateSigningKey",
  description = "Create a signing key for the calling user: a key pair whose public key the server stores, and whose private key signs the requests.",
  request_body(content = CreateSigningKey),
  responses(
    (status = 200, description = "The private key, if one was generated.", body = CreateSigningKeyResponse),
    (status = 400, description = "Invalid signing key name, cidr whitelist or public key", body = mogh_error::Serror),
    (status = 409, description = "The public key is already in use.", body = mogh_error::Serror),
    (status = 500, description = "Failed", body = mogh_error::Serror),
  ),
)]
fn create_signing_key() {}

/// Create a signing key for the calling user: a key pair whose
/// public key the server stores, and whose private key signs the
/// requests (see [crate::signature]).
/// Response: [CreateSigningKeyResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(CreateSigningKeyResponse)]
#[error(mogh_error::Error)]
pub struct CreateSigningKey {
  /// The name for the signing key.
  pub name: String,

  /// A unix timestamp in millseconds specifying signing key expire
  /// time. Default is 0, which means no expiry.
  #[serde(default)]
  pub expires: U64,

  /// Whitelist of CIDR ranges (eg `10.0.0.0/8`) or ip addresses
  /// from which requests signed with this key are accepted.
  /// Empty (the default) means all ips are allowed.
  #[serde(default)]
  pub cidr_whitelist: Vec<String>,

  /// Optionally provide a pre-existing public key: an Ed25519
  /// key (spki, base64 or pem). Otherwise, a private key will be
  /// generated and returned in the response
  #[serde(default)]
  pub public_key: String,
}

/// Response for [CreateSigningKey].
#[typeshare]
#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateSigningKeyResponse {
  /// Used to sign requests for authentication
  /// without transmitting the key itself: an Ed25519
  /// key (pkcs8, base64).
  ///
  /// The server will store the associated public key.
  ///
  /// If user provides a pre-existing public key,
  /// this field will be null.
  pub private_key: Option<String>,
}

/// The private key is redacted.
impl std::fmt::Debug for CreateSigningKeyResponse {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("CreateSigningKeyResponse")
      .field(
        "private_key",
        &self.private_key.as_deref().map(empty_or_redacted),
      )
      .finish()
  }
}

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/manage/DeleteSigningKey",
  description = "Delete a signing key for the calling user.",
  request_body(content = DeleteSigningKey),
  responses(
    (status = 200, description = "Signing key deleted.", body = DeleteSigningKeyResponse),
    (status = 404, description = "Signing key not found.", body = mogh_error::Serror),
    (status = 500, description = "Failed", body = mogh_error::Serror),
  ),
)]
fn delete_signing_key() {}

/// Delete a signing key for the calling user.
/// Response: [NoData].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthManageRequest)]
#[response(DeleteSigningKeyResponse)]
#[error(mogh_error::Error)]
pub struct DeleteSigningKey {
  /// The public key of the signing key to delete.
  pub public_key: String,
}

/// Response for [DeleteSigningKey].
#[typeshare]
pub type DeleteSigningKeyResponse = NoData;

#[cfg(test)]
mod tests {
  use mogh_resolver::HasResponse;
  use serde_json::json;

  use super::*;

  #[test]
  fn test_req_types_stable() {
    // These strings are sent as the `type` tag on the wire.
    assert_eq!(GetUserId::req_type(), "GetUserId");
    assert_eq!(UpdateUsername::req_type(), "UpdateUsername");
    assert_eq!(UpdatePassword::req_type(), "UpdatePassword");
    assert_eq!(
      BeginPasskeyEnrollment::req_type(),
      "BeginPasskeyEnrollment"
    );
    assert_eq!(
      ConfirmPasskeyEnrollment::req_type(),
      "ConfirmPasskeyEnrollment"
    );
    assert_eq!(UnenrollPasskey::req_type(), "UnenrollPasskey");
    assert_eq!(
      BeginTotpEnrollment::req_type(),
      "BeginTotpEnrollment"
    );
    assert_eq!(
      ConfirmTotpEnrollment::req_type(),
      "ConfirmTotpEnrollment"
    );
    assert_eq!(UnenrollTotp::req_type(), "UnenrollTotp");
    assert_eq!(
      BeginExternalLoginLink::req_type(),
      "BeginExternalLoginLink"
    );
    assert_eq!(UnlinkLocalLogin::req_type(), "UnlinkLocalLogin");
    assert_eq!(
      UnlinkExternalLogin::req_type(),
      "UnlinkExternalLogin"
    );
    assert_eq!(
      ListExternalLoginProviders::req_type(),
      "ListExternalLoginProviders"
    );
    assert_eq!(
      CreateExternalLoginProvider::req_type(),
      "CreateExternalLoginProvider"
    );
    assert_eq!(
      UpdateExternalLoginProvider::req_type(),
      "UpdateExternalLoginProvider"
    );
    assert_eq!(
      DeleteExternalLoginProvider::req_type(),
      "DeleteExternalLoginProvider"
    );
    assert_eq!(ListTrustedIssuers::req_type(), "ListTrustedIssuers");
    assert_eq!(
      CreateTrustedIssuer::req_type(),
      "CreateTrustedIssuer"
    );
    assert_eq!(
      UpdateTrustedIssuer::req_type(),
      "UpdateTrustedIssuer"
    );
    assert_eq!(
      DeleteTrustedIssuer::req_type(),
      "DeleteTrustedIssuer"
    );
    assert_eq!(
      UpdateExternalSkip2fa::req_type(),
      "UpdateExternalSkip2fa"
    );
    assert_eq!(CreateApiKey::req_type(), "CreateApiKey");
    assert_eq!(DeleteApiKey::req_type(), "DeleteApiKey");
    assert_eq!(CreateSigningKey::req_type(), "CreateSigningKey");
    assert_eq!(DeleteSigningKey::req_type(), "DeleteSigningKey");
  }

  #[test]
  fn test_update_password_response_type() {
    // Regression: UpdatePassword was declared with
    // `#[response(UpdateUsernameResponse)]`. Both aliases
    // resolve to NoData, but the declared response should
    // be UpdatePasswordResponse.
    fn assert_response<T: HasResponse<Response = NoData>>() {}
    assert_response::<UpdatePassword>();
    assert_eq!(UpdatePassword::res_type(), "UpdatePasswordResponse");
  }

  #[test]
  fn test_no_data_wire_format() {
    let value = serde_json::to_value(NoData {}).unwrap();
    assert_eq!(value, json!({}));
    let _: NoData = serde_json::from_value(json!({})).unwrap();
  }

  #[test]
  fn test_get_user_id_response_wire_format() {
    let value = serde_json::to_value(GetUserIdResponse {
      id: "user-id".into(),
    })
    .unwrap();
    assert_eq!(value, json!({ "id": "user-id" }));
  }

  #[test]
  fn test_create_api_key_expires_defaults_to_zero() {
    // Backwards compatibility: `expires` may be omitted.
    let req: CreateApiKey =
      serde_json::from_value(json!({ "name": "key-name" })).unwrap();
    assert_eq!(req.name, "key-name");
    assert_eq!(req.expires, 0);
    assert!(req.cidr_whitelist.is_empty());
    let value = serde_json::to_value(CreateApiKey {
      name: "key-name".into(),
      expires: 100,
      cidr_whitelist: vec!["10.0.0.0/8".into()],
    })
    .unwrap();
    assert_eq!(
      value,
      json!({
        "name": "key-name",
        "expires": 100,
        "cidr_whitelist": ["10.0.0.0/8"]
      })
    );
  }

  #[test]
  fn test_create_signing_key_defaults() {
    // `expires` and `public_key` may both be omitted.
    let req: CreateSigningKey =
      serde_json::from_value(json!({ "name": "key-name" })).unwrap();
    assert_eq!(req.name, "key-name");
    assert_eq!(req.expires, 0);
    assert!(req.cidr_whitelist.is_empty());
    assert!(req.public_key.is_empty());
    let req: CreateSigningKey = serde_json::from_value(json!({
      "name": "key-name",
      "cidr_whitelist": ["10.0.0.0/8", "::1"]
    }))
    .unwrap();
    assert_eq!(req.cidr_whitelist, ["10.0.0.0/8", "::1"]);
  }

  #[test]
  fn test_create_api_key_response_wire_format() {
    let value = serde_json::to_value(CreateApiKeyResponse {
      key: "K".into(),
      secret: "S".into(),
    })
    .unwrap();
    assert_eq!(value, json!({ "key": "K", "secret": "S" }));
  }

  #[test]
  fn test_create_signing_key_response_wire_format() {
    let value = serde_json::to_value(CreateSigningKeyResponse {
      private_key: None,
    })
    .unwrap();
    assert_eq!(value, json!({ "private_key": null }));
    let res: CreateSigningKeyResponse =
      serde_json::from_value(json!({ "private_key": "pk-contents" }))
        .unwrap();
    assert_eq!(res.private_key.as_deref(), Some("pk-contents"));
  }

  #[test]
  fn test_confirm_totp_enrollment_response_wire_format() {
    let value = serde_json::to_value(ConfirmTotpEnrollmentResponse {
      recovery_codes: vec!["a".into(), "b".into()],
    })
    .unwrap();
    assert_eq!(value, json!({ "recovery_codes": ["a", "b"] }));
  }

  #[test]
  fn test_unlink_external_login_wire_format() {
    let value = serde_json::to_value(UnlinkExternalLogin {
      provider_id: "oidc".into(),
    })
    .unwrap();
    assert_eq!(value, json!({ "provider_id": "oidc" }));
  }

  #[test]
  fn test_update_external_login_provider_clear_secret_defaults_false()
  {
    let request: UpdateExternalLoginProvider =
      serde_json::from_value(json!({
        "id": "abc",
        "name": "Github",
        "config": { "kind": "Github", "params": {} },
      }))
      .unwrap();
    assert!(!request.clear_client_secret);
  }

  #[test]
  fn test_create_external_login_provider_wire_format() {
    let request: CreateExternalLoginProvider =
      serde_json::from_value(json!({
        "name": "Github",
        "config": {
          "kind": "Github",
          "params": { "enabled": true, "id": "client-id" },
        },
      }))
      .unwrap();
    assert!(!request.registration_disabled);
    let ExternalLoginProviderConfig::Github(config) = request.config
    else {
      panic!("expected github config")
    };
    assert!(config.enabled);
    assert_eq!(config.client_id, "client-id");
  }

  #[test]
  fn test_update_external_skip_2fa_wire_format() {
    let value = serde_json::to_value(UpdateExternalSkip2fa {
      external_skip_2fa: true,
    })
    .unwrap();
    assert_eq!(value, json!({ "external_skip_2fa": true }));
  }

  #[test]
  fn test_debug_redacts_secrets() {
    let debug = format!(
      "{:?}",
      UpdatePassword {
        password: "hunter2".into()
      }
    );
    assert!(!debug.contains("hunter2"), "{debug}");
    let debug = format!(
      "{:?}",
      ConfirmTotpEnrollment {
        code: "123456".into()
      }
    );
    assert!(!debug.contains("123456"), "{debug}");

    let enrollment = BeginTotpEnrollmentResponse {
      uri: "otpauth://totp/app:alice?secret=JBSWY3DPEHPK3PXP".into(),
      png: "iVBORw0KGgoAAAANSUhEUg".into(),
    };
    let debug = format!("{enrollment:?}");
    assert!(!debug.contains("JBSWY3DPEHPK3PXP"), "{debug}");
    assert!(!debug.contains("iVBORw0KGgo"), "{debug}");

    let recovery = ConfirmTotpEnrollmentResponse {
      recovery_codes: vec!["code-one".into(), "code-two".into()],
    };
    let debug = format!("{recovery:?}");
    assert!(!debug.contains("code-one"), "{debug}");
    assert!(debug.contains("[2 redacted]"), "{debug}");
    assert_eq!(
      serde_json::to_value(&recovery).unwrap(),
      json!({ "recovery_codes": ["code-one", "code-two"] })
    );

    let api_key = CreateApiKeyResponse {
      key: "K_abc_K".into(),
      secret: "S_s3cr3t_S".into(),
    };
    let debug = format!("{api_key:?}");
    assert!(!debug.contains("s3cr3t"), "{debug}");
    assert!(debug.contains("K_abc_K"), "{debug}");

    let debug = format!(
      "{:?}",
      CreateSigningKeyResponse {
        private_key: Some("MC4CAQAwBQYDK2VuBCIEI".into()),
      }
    );
    assert!(!debug.contains("MC4CAQAw"), "{debug}");
    assert!(debug.contains("Some"), "{debug}");
    let debug =
      format!("{:?}", CreateSigningKeyResponse { private_key: None });
    assert!(debug.contains("None"), "{debug}");
  }

  #[test]
  fn test_begin_totp_enrollment_response_wire_format() {
    let value = serde_json::to_value(BeginTotpEnrollmentResponse {
      uri: "otpauth://totp/x".into(),
      png: "base64png".into(),
    })
    .unwrap();
    assert_eq!(
      value,
      json!({ "uri": "otpauth://totp/x", "png": "base64png" })
    );
  }
}
