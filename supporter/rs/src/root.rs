//! The root public keys of Mogh: the keys which sign the supporter
//! keys of an app. A root key is given as its Ed25519 public key in
//! base64 SPKI DER, the body of the PEM `openssl pkey -pubout`
//! writes: 60 characters starting `MCowBQYDK2VwAyEA`.
//!
//! Each app has its own, and hardcodes the ones it trusts: on its
//! server (`SupporterImpl::supporter_root_keys`), which serves a key
//! only when it verifies under them, and, the same ones, in its UI,
//! which verifies it again. Rotation adds an entry, and an old entry
//! is removed a few releases later: several may be trusted at once.
//!
//! The id of a root key, the `k` of the payloads it signed, is never
//! declared: it is derived from the key ([`root_key_id`]). An app's
//! unit test checks its list with [`check_root_keys`].
//!
//! [`root_key_id`]: crate::root_key_id
//! [`check_root_keys`]: crate::check_root_keys

use data_encoding::BASE64;
use ed25519_dalek::VerifyingKey;
use sha2::Digest as _;

use crate::{fixture, payload::hex};

/// Why a root public key is not one. Never echoes the key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootKeyError {
  #[error("The root key is not base64")]
  Base64,
  #[error("The root key is not the SPKI DER of an Ed25519 key")]
  Spki,
  #[error("The root key is not a canonical Ed25519 public key")]
  Invalid,
}

/// Why a list of root keys is not what a release hardcodes. See
/// [check_root_keys].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootKeysError {
  #[error(
    "The root key at position {position} is not valid | {error}"
  )]
  Key {
    /// Counted from 1.
    position: usize,
    error: RootKeyError,
  },
  #[error("The root key {0} is listed twice")]
  Duplicate(String),
  #[error(
    "The root key {0} is the test root of the fixture, which is public: a release never trusts it"
  )]
  Fixture(String),
}

/// The SPKI DER of an Ed25519 public key is this, then the 32 raw
/// key bytes (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21,
  0x00,
];

/// The raw 32 bytes of a root public key (base64 SPKI DER).
/// Surrounding whitespace is ignored. Refused: bytes which are no
/// point of the curve, non canonical encodings (another string for
/// the same key), and the low order points, which have signatures
/// verifying for any message.
pub fn root_key_bytes(spki: &str) -> Result<[u8; 32], RootKeyError> {
  let der = BASE64
    .decode(spki.trim().as_bytes())
    .map_err(|_| RootKeyError::Base64)?;
  let raw = der
    .strip_prefix(&ED25519_SPKI_PREFIX)
    .ok_or(RootKeyError::Spki)?;
  let raw: [u8; 32] =
    raw.try_into().map_err(|_| RootKeyError::Spki)?;
  let key = VerifyingKey::from_bytes(&raw)
    .map_err(|_| RootKeyError::Invalid)?;
  if key.to_edwards().compress().to_bytes() != raw || key.is_weak() {
    return Err(RootKeyError::Invalid);
  }
  Ok(raw)
}

/// The id of raw root key bytes.
fn raw_key_id(raw: &[u8; 32]) -> String {
  hex(&sha2::Sha256::digest(raw)[..8])
}

/// The id of a root public key (base64 SPKI DER): lowercase hex of
/// the first 8 bytes of the SHA-256 of its raw 32 bytes. The `k` of
/// the payloads the key signed, and what the platform publishes next
/// to the key.
pub fn root_key_id(spki: &str) -> Result<String, RootKeyError> {
  Ok(raw_key_id(&root_key_bytes(spki)?))
}

/// The key among `roots` which has the id `kid`, to verify with. An
/// entry which is no key has no id, and is passed over.
pub(crate) fn find_root_key(
  roots: &[&str],
  kid: &str,
) -> Option<VerifyingKey> {
  roots
    .iter()
    .filter_map(|root| root_key_bytes(root).ok())
    .find(|raw| raw_key_id(raw) == kid)
    // Checked by `root_key_bytes`.
    .and_then(|raw| VerifyingKey::from_bytes(&raw).ok())
}

/// Checks the root keys an app hardcodes, for a unit test of the
/// app: every entry is an Ed25519 public key, listed once, and none
/// is the test root of [crate::fixture], whose key anyone can sign
/// with. Returns their ids, in order, to compare with what the
/// platform published. An empty list is fine: no key verifies then.
pub fn check_root_keys(
  roots: &[&str],
) -> Result<Vec<String>, RootKeysError> {
  let mut ids = Vec::with_capacity(roots.len());
  for (i, root) in roots.iter().enumerate() {
    let id =
      root_key_id(root).map_err(|error| RootKeysError::Key {
        position: i + 1,
        error,
      })?;
    if ids.contains(&id) {
      return Err(RootKeysError::Duplicate(id));
    }
    if id == fixture::ROOT_KEY_ID {
      return Err(RootKeysError::Fixture(id));
    }
    ids.push(id);
  }
  Ok(ids)
}
