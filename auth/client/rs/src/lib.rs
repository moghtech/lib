use serde::{Deserialize, Serialize};
use typeshare::typeshare;

pub mod api;
pub mod passkey;

use passkey::RequestChallengeResponse;

/// JSON containing a jwt authentication token.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone)]
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
