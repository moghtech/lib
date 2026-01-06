/// Implemented for app specific User struct.
pub trait AuthUserImpl: Send + Sync + 'static {
  fn id(&self) -> &str;

  fn hashed_password(&self) -> Option<&str> {
    None
  }

  fn passkey(&self) -> Option<webauthn_rs::prelude::Passkey> {
    None
  }

  fn totp_secret(&self) -> Option<&str> {
    None
  }
}
