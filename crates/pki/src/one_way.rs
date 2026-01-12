use anyhow::Context;
use data_encoding::BASE64;

use crate::{PkiType, key::SpkiPublicKey};

/// Wrapper around [snow::HandshakeState] to streamline this implementation
pub struct OneWayNoiseHandshake(snow::HandshakeState);

impl OneWayNoiseHandshake {
  pub fn new_initiator(
    private_key: &[u8],
    remote_public_key: &[u8],
    prologue: &[u8],
  ) -> anyhow::Result<OneWayNoiseHandshake> {
    Ok(OneWayNoiseHandshake(
      snow::Builder::new(PkiType::ONE_WAY.parse()?)
        .local_private_key(private_key)
        .context("Invalid private key")?
        .remote_public_key(remote_public_key)
        .context("Invalid remote public key")?
        .prologue(prologue)
        .context("Invalid prologue")?
        .build_initiator()
        .context("Failed to build initiator")?,
    ))
  }

  pub fn new_responder(
    private_key: &[u8],
    prologue: &[u8],
  ) -> anyhow::Result<OneWayNoiseHandshake> {
    Ok(OneWayNoiseHandshake(
      snow::Builder::new(PkiType::ONE_WAY.parse()?)
        .local_private_key(private_key)
        .context("Invalid private key")?
        .prologue(prologue)
        .context("Invalid prologue")?
        .build_responder()
        .context("Failed to build responder")?,
    ))
  }

  /// Produces next message to be read on other side of handshake,
  /// base64 encoded for transport.
  pub fn generate_signature(
    &mut self,
  ) -> Result<String, snow::Error> {
    let mut buf = [0u8; 1024];
    let written = self.0.write_message(&[], &mut buf)?;
    Ok(BASE64.encode(&buf[..written]))
  }

  /// Reads base64 encoded signature from other side of handshake,
  /// and produces the client public key.
  pub fn validate_signature(
    &mut self,
    signature: &str,
  ) -> anyhow::Result<SpkiPublicKey> {
    let decoded = BASE64
      .decode(signature.as_bytes())
      .context("Failed to base64 decode message")?;
    self.0.read_message(&decoded, &mut []).map(|_| ())?;
    let raw = self
      .0
      .get_remote_static()
      .context("Failed to get remote public key")?;
    SpkiPublicKey::from_raw_bytes(raw)
  }
}
