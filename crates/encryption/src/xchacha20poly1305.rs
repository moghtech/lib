use anyhow::{Context, anyhow};
use chacha20poly1305::{
  KeyInit, XChaCha20Poly1305, XNonce,
  aead::{Aead, Payload},
};
use data_encoding::BASE64URL;

use crate::{
  AssociatedData, EncryptedData, NonceProvider, RandNonceProvider,
};

// The lifetime of provider is basically tied to the nonce provider, so they are coupled here.

pub type RandEncryptionProvider =
  EncryptionProvider<RandNonceProvider<24>>;

pub struct EncryptionProvider<N: NonceProvider<24>>(pub N);

impl<N: NonceProvider<24>> EncryptionProvider<N> {
  /// Encrypts the given bytes using the given 32 byte key,
  /// a random nonce, and the given associated data.
  pub fn encrypt<A: AssociatedData>(
    &mut self,
    data: &[u8],
    key: [u8; 32],
    associated_data: &A,
  ) -> anyhow::Result<EncryptedData> {
    let nonce: [u8; 24] = self.0.generate();
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
