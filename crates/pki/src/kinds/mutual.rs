use anyhow::Context;
use zeroize::Zeroizing;

use crate::{PkiKind, key::check_raw_public_key};

/// Wrapper around [snow::HandshakeState] to streamline this implementation
///
/// A Noise XX handshake ([PkiKind::Mutual]) over X25519 keys.
pub struct MutualNoiseHandshake(snow::HandshakeState);

impl MutualNoiseHandshake {
  /// Takes the private key in any form
  /// [crate::Pkcs8PrivateKey::maybe_raw_bytes] accepts.
  pub fn new_initiator(
    maybe_pkcs8_private_key: &str,
    prologue: &[u8],
  ) -> anyhow::Result<MutualNoiseHandshake> {
    let private_key =
      Zeroizing::new(crate::key::Pkcs8PrivateKey::maybe_raw_bytes(
        PkiKind::Mutual,
        maybe_pkcs8_private_key,
      )?);
    Ok(MutualNoiseHandshake(
      snow::Builder::new(PkiKind::MUTUAL.parse()?)
        .local_private_key(&*private_key)
        .context("Invalid private key")?
        .prologue(prologue)
        .context("Invalid prologue")?
        .build_initiator()
        .context("Failed to build initiator")?,
    ))
  }

  /// Takes the private key in any form
  /// [crate::Pkcs8PrivateKey::maybe_raw_bytes] accepts (the base64
  /// pkcs8 der, usually).
  pub fn new_responder(
    maybe_pkcs8_private_key: &str,
    prologue: &[u8],
  ) -> anyhow::Result<MutualNoiseHandshake> {
    let private_key =
      Zeroizing::new(crate::key::Pkcs8PrivateKey::maybe_raw_bytes(
        PkiKind::Mutual,
        maybe_pkcs8_private_key,
      )?);
    Ok(MutualNoiseHandshake(
      snow::Builder::new(PkiKind::MUTUAL.parse()?)
        .local_private_key(&*private_key)
        .context("Invalid private key")?
        .prologue(prologue)
        .context("Invalid prologue")?
        .build_responder()
        .context("Failed to build responder")?,
    ))
  }

  /// Reads message from other side of handshake
  pub fn read_message(
    &mut self,
    message: &[u8],
  ) -> Result<(), snow::Error> {
    self.0.read_message(message, &mut []).map(|_| ())
  }

  /// Produces next message to be read on other side of handshake
  pub fn next_message(&mut self) -> Result<Vec<u8>, snow::Error> {
    let mut buf = [0u8; 1024];
    let written = self.0.write_message(&[], &mut buf)?;
    Ok(buf[..written].to_vec())
  }

  /// Gets the remote public key bytes.
  /// Note that this should only be called after m2 is read on client side,
  /// or m3 is read on server side.
  /// Low order and non canonical keys are refused (see
  /// [crate::SpkiPublicKey::from_raw_bytes]).
  pub fn remote_public_key(&self) -> anyhow::Result<&[u8]> {
    let remote = self
      .0
      .get_remote_static()
      .context("Failed to get remote public key")?;
    check_raw_public_key(PkiKind::Mutual, remote)?;
    Ok(remote)
  }
}
