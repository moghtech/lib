use crate::{JsonValue, U64};

/// Emit authentication event logs,
/// like password updates and external links.
pub struct AuthEvent {
  /// The associated user id
  pub user: String,
  /// The auth event operation (IE what happened).
  pub operation: AuthOperation,
  /// Optional. Any data associated with the event.
  pub data: Option<JsonValue>,
  /// The unix timestamp in milliseconds
  pub timestamp: U64,
}

/// The operation type.
pub enum AuthOperation {
  /// User created.
  Creation,
  /// User logged in.
  Login,
  /// User deleted
  Deletion,
  /// User enabled
  Enabled,
  /// User disabled
  Disabled,
  /// User completed primary login
  /// but failed second factor.
  TwoFactorFailure,
  /// User updated username
  UpdateUsername,
  /// User updated password
  UpdatePassword,
  /// User cleared password, disallowing local login.
  ClearPassword,
  /// User linked an OIDC login
  LinkOidc,
  /// User unlinked an OIDC login
  UnlinkOidc,
  /// User linked a Github login
  LinkGithub,
  /// User unlinked a Github login
  UnlinkGithub,
  /// User linked a google login
  LinkGoogle,
  /// User unlinked a google login
  UnlinkGoogle,
  /// User enrolled in passkey 2fa
  EnrollPasskey2fa,
  /// User unenrolled in passkey 2fa
  UnenrollPasskey2fa,
  /// User enrolled in totp 2fa
  EnrollTotp2fa,
  /// User unenrolled in totp 2fa
  UnenrollTotp2fa,
}
