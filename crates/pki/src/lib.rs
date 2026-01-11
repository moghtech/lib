//! # Mogh PKI
//!
//! Utilities for Public Key Infrastructure

pub mod key;
pub mod mutual;
pub mod one_way;

pub enum PkiType {
  /// The client has server public key pinned, and transmits
  /// its public key in one zero trust call by encrypting
  /// some mutually known information (such as request body)
  /// into a signature.
  ///
  /// Uses Noise IK handshake.
  /// https://noiseprotocol.org/noise.html#handshake-patterns
  OneWay,
  /// Multistep handshake where each side
  /// gains zero trust knowledge of the other's
  /// public key for verificiation.
  ///
  /// Uses Noise XX handshake.
  /// https://noiseprotocol.org/noise.html#handshake-patterns
  Mutual,
}

impl PkiType {
  const ONE_WAY: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
  const MUTUAL: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
  pub fn noise_params(&self) -> &'static str {
    match self {
      PkiType::OneWay => Self::ONE_WAY,
      PkiType::Mutual => Self::MUTUAL,
    }
  }
}
