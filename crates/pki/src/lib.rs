#![doc = include_str!("../README.md")]

mod key;
mod kinds;

pub use key::*;
pub use kinds::*;

#[cfg(feature = "cli")]
pub mod cli;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiKind {
  /// The client signs a message both sides know (such as the
  /// request) with its private key, and whoever has its public key
  /// can verify the signature ([signature::sign],
  /// [signature::verify]). The verifier needs no key of its own, and
  /// can't make a signature for a client.
  ///
  /// A signature verifies wherever the public key is known, and
  /// again whenever it is replayed: sign who the message is for, and
  /// a timestamp or nonce the verifier enforces a window on.
  ///
  /// Uses Ed25519 keys and signatures.
  /// <https://www.rfc-editor.org/rfc/rfc8032>
  Signature,
  /// Multistep handshake where each side
  /// gains zero trust knowledge of the other's
  /// public key for verification.
  ///
  /// Uses Noise XX handshake over X25519 keys.
  /// <https://noiseprotocol.org/noise.html#handshake-patterns>
  Mutual,
}

impl PkiKind {
  /// The noise parameters of [PkiKind::Mutual].
  pub(crate) const MUTUAL: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

  /// The algorithm of this kind's keys. A key of one kind is not a
  /// key of the other: it is refused with [WrongKeyAlgorithm].
  pub fn key_algorithm(&self) -> KeyAlgorithm {
    match self {
      PkiKind::Signature => KeyAlgorithm::Ed25519,
      PkiKind::Mutual => KeyAlgorithm::X25519,
    }
  }
}

/// The algorithm of a key, as its pkcs8 / spki encoding names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
  /// The keys of [PkiKind::Signature] (`1.3.101.112`).
  Ed25519,
  /// The keys of [PkiKind::Mutual] (`1.3.101.110`).
  X25519,
}

impl std::fmt::Display for KeyAlgorithm {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(match self {
      KeyAlgorithm::Ed25519 => "Ed25519",
      KeyAlgorithm::X25519 => "X25519",
    })
  }
}

/// The error for a well formed key of the other algorithm than the
/// [PkiKind] it is used as: an X25519 key given for
/// [PkiKind::Signature] (eg. a signing key from before 3.0), or an
/// Ed25519 key given for [PkiKind::Mutual].
///
/// Find it in a returned error with
/// `error.downcast_ref::<WrongKeyAlgorithm>()`, eg. to tell a key
/// which has to be generated again from one which is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrongKeyAlgorithm {
  pub expected: KeyAlgorithm,
  pub found: KeyAlgorithm,
}

impl std::fmt::Display for WrongKeyAlgorithm {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "Expected an {} key, this is an {} key",
      self.expected, self.found
    )
  }
}

impl std::error::Error for WrongKeyAlgorithm {}
