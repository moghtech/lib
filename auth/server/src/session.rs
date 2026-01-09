use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
  PasskeyAuthentication, PasskeyRegistration,
};

//

#[derive(Serialize, Deserialize)]
pub struct SessionUserId(pub String);

impl SessionUserId {
  pub const KEY: &str = "user-id";
}

//

/// This is stored in server-side, per-client session.
#[derive(Serialize, Deserialize)]
pub struct SessionPasskeyLogin {
  pub user_id: String,
  /// ⚠️ This value must stay server side only
  pub state: PasskeyAuthentication,
}

impl SessionPasskeyLogin {
  pub const KEY: &str = "passkey-login";
}

//

#[derive(Serialize, Deserialize)]
pub struct SessionPasskeyEnrollment {
  /// ⚠️ This value must stay server side only
  pub state: PasskeyRegistration,
}
impl SessionPasskeyEnrollment {
  pub const KEY: &str = "passkey-enrollment";
}

//

/// This is stored in server-side, per-client session.
#[derive(Serialize, Deserialize)]
pub struct SessionTotpLogin {
  pub user_id: String,
}

impl SessionTotpLogin {
  pub const KEY: &str = "totp-login";
}

//

#[derive(Serialize, Deserialize)]
pub struct SessionTotpEnrollment {
  pub totp: totp_rs::TOTP,
}

impl SessionTotpEnrollment {
  pub const KEY: &str = "totp-enrollment";
}

//

#[derive(Serialize, Deserialize)]
pub struct SessionOidcVerificationInfo {
  pub csrf_token: String,
  pub pkce_verifier: openidconnect::PkceCodeVerifier,
  pub nonce: openidconnect::Nonce,
  pub redirect: Option<String>,
}

impl SessionOidcVerificationInfo {
  pub const KEY: &str = "oidc-verification-info";
}

//

#[derive(Serialize, Deserialize)]
pub struct SessionOidcLinkInfo {
  pub user_id: String,
  pub csrf_token: String,
  pub pkce_verifier: openidconnect::PkceCodeVerifier,
  pub nonce: openidconnect::Nonce,
}

impl SessionOidcLinkInfo {
  pub const KEY: &str = "oidc-link-info";
}

//

#[derive(Serialize, Deserialize)]
pub struct SessionThirdPartyLinkInfo {
  pub user_id: String,
}

impl SessionThirdPartyLinkInfo {
  pub const KEY: &str = "third-party-link-info";
}
