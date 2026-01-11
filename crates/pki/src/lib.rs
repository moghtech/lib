//! # Mogh PKI
//!
//! Utilities for Public Key Infrastructure

pub mod key;
pub mod mutual;

pub enum PkiType {
  /// Multistep handshake where each side
  /// gains zero trust knowledge of the other's
  /// public key for verificiation.
  ///
  /// Uses Noise XX handshake.
  /// https://noiseprotocol.org/noise.html#handshake-patterns
  Mutual,
}

impl PkiType {
  const MUTUAL: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

  pub fn noise_params(&self) -> &'static str {
    match self {
      PkiType::Mutual => Self::MUTUAL,
    }
  }
}
