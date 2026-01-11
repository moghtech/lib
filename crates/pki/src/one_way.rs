use anyhow::Context;

use crate::{
  PkiType,
  key::{Pkcs8PrivateKey, SpkiPublicKey},
};

/// Wrapper around [snow::HandshakeState] to streamline this implementation
pub struct OneWayNoiseHandshake(snow::HandshakeState);

impl OneWayNoiseHandshake {
  pub fn new_initiator(
    private_key: &Pkcs8PrivateKey,
    remote_public_key: &SpkiPublicKey,
    prologue: &[u8],
  ) -> anyhow::Result<OneWayNoiseHandshake> {
    Ok(OneWayNoiseHandshake(
      snow::Builder::new(PkiType::MUTUAL.parse()?)
        .local_private_key(private_key.as_bytes())
        .context("Invalid private key")?
        .remote_public_key(remote_public_key.as_bytes())
        .context("Invalid remote public key")?
        .prologue(prologue)
        .context("Invalid prologue")?
        .build_initiator()
        .context("Failed to build initiator")?,
    ))
  }

  pub fn new_responder(
    private_key: &Pkcs8PrivateKey,
    prologue: &[u8],
  ) -> anyhow::Result<OneWayNoiseHandshake> {
    Ok(OneWayNoiseHandshake(
      snow::Builder::new(PkiType::MUTUAL.parse()?)
        .local_private_key(&private_key.as_bytes())
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
  /// Note that this should only be called after m1 is read on server side.
  pub fn remote_public_key(&self) -> anyhow::Result<&[u8]> {
    self
      .0
      .get_remote_static()
      .context("Failed to get remote public key")
  }
}
