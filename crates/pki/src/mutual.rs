use anyhow::Context;

const NOISE_MUTUAL_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Wrapper around [snow::HandshakeState] to streamline this implementation
pub struct MutualNoiseHandshake(snow::HandshakeState);

impl MutualNoiseHandshake {
  pub fn new_initiator(
    maybe_pkcs8_private_key: &str,
    prologue: &[u8],
  ) -> anyhow::Result<MutualNoiseHandshake> {
    let private_key = crate::key::Pkcs8PrivateKey::maybe_raw_bytes(
      maybe_pkcs8_private_key,
    )?;
    Ok(MutualNoiseHandshake(
      snow::Builder::new(NOISE_MUTUAL_PARAMS.parse()?)
        .local_private_key(&private_key)
        .context("Invalid private key")?
        .prologue(prologue)
        .context("Invalid prologue")?
        .build_initiator()
        .context("Failed to build initiator")?,
    ))
  }

  /// Should pass base64 encoded private key.
  pub fn new_responder(
    maybe_pkcs8_private_key: &str,
    prologue: &[u8],
  ) -> anyhow::Result<MutualNoiseHandshake> {
    let private_key = crate::key::Pkcs8PrivateKey::maybe_raw_bytes(
      maybe_pkcs8_private_key,
    )?;
    Ok(MutualNoiseHandshake(
      snow::Builder::new(NOISE_MUTUAL_PARAMS.parse()?)
        .local_private_key(&private_key)
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
  pub fn remote_public_key(&self) -> anyhow::Result<&[u8]> {
    self
      .0
      .get_remote_static()
      .context("Failed to get remote public key")
  }
}
