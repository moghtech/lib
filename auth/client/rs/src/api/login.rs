//! # Mogh Auth Login API
//!
//! This module includes *unauthenticated* API methods
//! used in order to gain a temporary access token (JWT)
//! to use with other authenticated API methods.

use mogh_resolver::{HasResponse, Resolve};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use typeshare::typeshare;

use crate::passkey::{PublicKeyCredential, RequestChallengeResponse};

/// JSON containing a jwt authentication token.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct JwtResponse {
  /// A token the user can use to authenticate their requests.
  pub jwt: String,
}

/// JSON containing either an authentication token or the required 2fa auth check.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "type", content = "data")]
pub enum JwtOrTwoFactor {
  Jwt(JwtResponse),
  Passkey(RequestChallengeResponse),
  Totp {},
}

/// JSON containing either an authentication token or the required 2fa auth check.
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "type", content = "data")]
pub enum UserIdOrTwoFactor {
  UserId(String),
  Passkey(RequestChallengeResponse),
  Totp {},
}

/// The available login providers
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Display, EnumString,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum LoginProvider {
  Local,
  Oidc,
  Github,
  Google,
}

/// The available external login providers
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Display, EnumString,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum ExternalLoginProvider {
  Oidc,
  Github,
  Google,
}

//

pub trait MoghAuthLoginRequest: HasResponse {}

//

#[allow(unused)]
#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/GetLoginOptions",
  description = "Get the available options to login, eg. local and external providers.",
  request_body(content = GetLoginOptions),
  responses(
    (status = 200, description = "The available login options", body = GetLoginOptionsResponse)
  ),
)]
fn get_login_options() {}

/// Get the available options to login, eg. local and external providers.
/// Response: [GetLoginOptionsResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(GetLoginOptionsResponse)]
#[error(mogh_error::Error)]
pub struct GetLoginOptions {}

/// The response for [GetLoginOptions].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct GetLoginOptionsResponse {
  /// Whether Local login is enabled.
  pub local: bool,
  /// Whether OIDC login is enabled.
  pub oidc: bool,
  /// Whether Github login is enabled.
  pub github: bool,
  /// Whether Google login is enabled.
  pub google: bool,
  /// Whether user registration (Sign Up) has been disabled
  pub registration_disabled: bool,
}

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/ExchangeForJwt",
  description = "Retrieve a JWT after completing third party login flows.",
  request_body(content = ExchangeForJwt),
  responses(
    (status = 200, description = "Authentication JWT", body = ExchangeForJwtResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn exchange_for_jwt() {}

/// Retrieve a JWT after completing third party login flows.
/// Response: [ExchangeForJwtResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(ExchangeForJwtResponse)]
#[error(mogh_error::Error)]
pub struct ExchangeForJwt {}

/// Response for [ExchangeForJwt].
#[typeshare]
pub type ExchangeForJwtResponse = JwtResponse;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/SignUpLocalUser",
  description = "Sign up a new local user account.",
  request_body(content = LoginLocalUser),
  responses(
    (status = 200, description = "Authentication JWT", body = SignUpLocalUserResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn sign_up_local_user() {}

/// Sign up a new local user account.
/// Response: [SignUpLocalUserResponse].
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(SignUpLocalUserResponse)]
#[error(mogh_error::Error)]
pub struct SignUpLocalUser {
  /// The username for the new user.
  pub username: String,
  /// The password for the new user.
  /// This cannot be retreived later.
  pub password: String,
}

/// Response for [SignUpLocalUser].
#[typeshare]
pub type SignUpLocalUserResponse = JwtResponse;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/LoginLocalUser",
  description = "Login as a local user.",
  request_body(content = LoginLocalUser),
  responses(
    (status = 200, description = "JWT auth token or 2 factor login continuation", body = LoginLocalUserResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn login_local_user() {}

/// Login as a local user.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(LoginLocalUserResponse)]
#[error(mogh_error::Error)]
pub struct LoginLocalUser {
  /// The user's username
  pub username: String,
  /// The user's password
  pub password: String,
}

/// The response for [LoginLocalUser]
#[typeshare]
pub type LoginLocalUserResponse = JwtOrTwoFactor;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/CompletePasskeyLogin",
  description = "Complete login using passkey as second factor.",
  request_body(content = CompletePasskeyLogin),
  responses(
    (status = 200, description = "Authentication JWT", body = CompletePasskeyLoginResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn complete_passkey_login() {}

/// Complete login using passkey as second factor.
/// Response: [CompletePasskeyLoginResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(CompletePasskeyLoginResponse)]
#[error(mogh_error::Error)]
pub struct CompletePasskeyLogin {
  pub credential: PublicKeyCredential,
}

/// Response for [CompletePasskeyLogin].
#[typeshare]
pub type CompletePasskeyLoginResponse = JwtResponse;

//

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/login/CompleteTotpLogin",
  description = "Complete login using TOTP code as second factor.",
  request_body(content = CompleteTotpLogin),
  responses(
    (status = 200, description = "Authentication JWT", body = CompleteTotpLoginResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn complete_totp_login() {}

/// Complete login using TOTP code as second factor.
/// Response: [CompleteTotpLoginResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(CompleteTotpLoginResponse)]
#[error(mogh_error::Error)]
pub struct CompleteTotpLogin {
  /// The time dependent totp code for user.
  pub code: String,
}

/// Response for [CompleteTotpLogin].
#[typeshare]
pub type CompleteTotpLoginResponse = JwtResponse;
