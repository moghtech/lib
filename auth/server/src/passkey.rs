//! The passkey a user enrolled for passkey 2fa, as the app stores it.

use serde::{Deserialize, Serialize};

/// A user's passkey: the credential which verifies their passkey
/// logins (its id, public key and signature counter).
///
/// The app stores it as [AuthImpl::update_user_stored_passkey][crate::AuthImpl::update_user_stored_passkey]
/// gives it, and returns it from
/// [AuthUserImpl::passkey][crate::user::AuthUserImpl::passkey]. Its
/// JSON is the form `webauthn-rs` serializes the passkey in, the same
/// as when this type was `mogh_auth_client::passkey::Passkey` (before
/// 8.0), so stored passkeys keep working.
///
/// It is not in `mogh_auth_client` with the passkey challenges and
/// credentials sent over the wire: reading it takes `webauthn-rs`, and
/// with it OpenSSL, which clients have no use for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey(pub webauthn_rs::prelude::Passkey);

#[cfg(test)]
mod tests {
  use super::*;
  use crate::provider::passkey::test_passkey;

  /// Apps store the passkey as its JSON: the `webauthn-rs` passkey
  /// itself, as when the type was in `mogh_auth_client`. A stored
  /// one reads, and is written back the same.
  #[test]
  fn test_stored_form_is_the_webauthn_passkey() {
    let passkey = test_passkey(&[1; 16]);
    let stored = serde_json::to_value(&passkey).unwrap();
    assert_eq!(stored, serde_json::to_value(&passkey.0).unwrap());
    assert!(stored["cred"]["cred_id"].is_string(), "{stored}");
    let read: Passkey =
      serde_json::from_value(stored.clone()).unwrap();
    assert_eq!(read.0.cred_id(), passkey.0.cred_id());
    assert_eq!(serde_json::to_value(&read).unwrap(), stored);
  }
}
