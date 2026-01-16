use anyhow::{Context, anyhow};
use chacha20poly1305::{
  KeyInit, XChaCha20Poly1305, XNonce,
  aead::{Aead, Payload},
};
use data_encoding::BASE64URL;
use rand::{Rng, rngs::ThreadRng};

use crate::{AssociatedData, EncryptedData, EnvelopeEncryptedData};

// The lifetime of provider is basically tied to the nonce provider, so they are coupled here.

#[derive(Default)]
pub struct EncryptionProvider(pub ThreadRng);

impl EncryptionProvider {
  /// Encrypts the given bytes using the given 32 byte key,
  /// a random nonce, and the given associated data.
  pub fn encrypt<A: AssociatedData>(
    &mut self,
    data: &[u8],
    key: [u8; 32],
    associated_data: &A,
  ) -> anyhow::Result<EncryptedData> {
    let nonce: [u8; 24] = self.0.random();
    let key = XChaCha20Poly1305::new((&key).into());
    let data = key
      .encrypt(
        XNonce::from_slice(&nonce),
        Payload {
          msg: data,
          aad: associated_data.as_bytes(),
        },
      )
      .map_err(|e| anyhow!("Encryption failed | {e:?}"))?;
    Ok(EncryptedData {
      data: BASE64URL.encode(&data),
      nonce: BASE64URL.encode(&nonce),
    })
  }

  /// Encrypts the given bytes using a random 32 byte key,
  /// a random nonce, and the given associated data.
  /// Then encrypts the key using the master key, a random nonce,
  /// and the same associated data.
  pub fn envelope_encrypt<A: AssociatedData>(
    &mut self,
    data: &[u8],
    master_key: [u8; 32],
    associated_data: &A,
  ) -> anyhow::Result<EnvelopeEncryptedData> {
    let key: [u8; 32] = self.0.random();
    let data = self.encrypt(data, key, associated_data)?;
    let key = self.encrypt(&key, master_key, associated_data)?;
    Ok(EnvelopeEncryptedData { key, data })
  }
}

/// Decrypts the given [EncryptedData] back into bytes using the given 32 byte key
/// and the given associated data.
pub fn decrypt<A: AssociatedData>(
  EncryptedData { data, nonce }: &EncryptedData,
  key: [u8; 32],
  associated_data: &A,
) -> anyhow::Result<Vec<u8>> {
  let data = BASE64URL
    .decode(data.as_bytes())
    .context("Data is not valid base64url")?;
  let nonce = BASE64URL
    .decode(nonce.as_bytes())
    .context("Nonce is not valid base64url")?;
  if nonce.len() != 24 {
    return Err(anyhow!("Invalid nonce"));
  }
  let key = XChaCha20Poly1305::new((&key).into());
  key
    .decrypt(
      XNonce::from_slice(&nonce),
      Payload {
        msg: &data,
        aad: associated_data.as_bytes(),
      },
    )
    .map_err(|e| anyhow!("Decryption failed | {e:?}"))
}

/// Decrypts the given [EnvelopeEncryptedData] back into bytes using the given 32 byte master key
/// and the given associated data.
pub fn envelope_decrypt<A: AssociatedData>(
  EnvelopeEncryptedData { key, data }: &EnvelopeEncryptedData,
  master_key: [u8; 32],
  associated_data: &A,
) -> anyhow::Result<Vec<u8>> {
  let key: [u8; 32] = decrypt(key, master_key, associated_data)?
    .try_into()
    .map_err(|_| {
      anyhow!(
        "The envelope encryption key is not 32 bytes after decryption"
      )
    })?;
  decrypt(data, key, associated_data)
}
