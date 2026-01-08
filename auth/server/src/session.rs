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
