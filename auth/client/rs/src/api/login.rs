//! # Mogh Auth Login API
//!
//! This module includes *unauthenticated* API methods
//! used in order to gain a temporary access token (JWT)
//! to use with other authenticated API methods.

use derive_empty_traits::EmptyTraits;
use resolver_api::{HasResponse, Resolve};
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

/// See the available options
/// users have to login, eg. local and external providers.
/// Response: [GetLoginOptionsResponse].
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Resolve, EmptyTraits,
)]
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
  /// Whether local auth is enabled.
  pub local: bool,
  /// Whether OIDC auth is enabled.
  pub oidc: bool,
  /// Whether user registration (Sign Up) has been disabled
  pub registration_disabled: bool,
}

//

/// Sign up a new local user account.
/// Response: [SignUpLocalUserResponse].
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EmptyTraits,
)]
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

/// Login as a local user. Will fail if the users credentials don't match
/// any local user.
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Resolve, EmptyTraits,
)]
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

/// Retrieve a JWT after completing third party login flows.
/// Response: [ExchangeForJwtResponse].
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Resolve, EmptyTraits,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[empty_traits(MoghAuthLoginRequest)]
#[response(ExchangeForJwtResponse)]
#[error(mogh_error::Error)]
pub struct ExchangeForJwt {}

/// Response for [ExchangeForJwt].
#[typeshare]
pub type ExchangeForJwtResponse = JwtResponse;

//

/// Confirm a single use 2fa pending token + time-dependent user totp code for a jwt.
/// Response: [CompletePasskeyLoginResponse].
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Resolve, EmptyTraits,
)]
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

/// Confirm a single use 2fa pending token + time-dependent user totp code for a jwt.
/// Response: [CompleteTotpLoginResponse].
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Resolve, EmptyTraits,
)]
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
