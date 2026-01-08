use mogh_auth_client::passkey::Passkey;

/// Implemented for app specific User struct.
pub trait AuthUserImpl: Send + Sync + 'static {
  fn id(&self) -> &str;

  fn hashed_password(&self) -> Option<&str> {
    None
  }

  fn passkey(&self) -> Option<Passkey> {
    None
  }

  fn totp_secret(&self) -> Option<&str> {
    None
  }
}

pub type BoxAuthUser = Box<dyn AuthUserImpl>;
