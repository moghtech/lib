use rand::{Rng as _, rngs::ThreadRng};

pub mod xchacha20poly1305;

pub struct EncryptedData {
  /// ## data
  /// - encrypted using given cipher plus the below nonce
  /// - base64url encoded
  pub data: String,
  /// ## nonce
  /// - the random nonce used to encrypt the data
  /// - base64url encoded
  pub nonce: String,
}

//

pub trait NonceProvider<const LENGTH: usize> {
  fn generate(&mut self) -> [u8; LENGTH];
}

#[derive(Default)]
pub struct RandNonceProvider<const LENGTH: usize>(pub ThreadRng);

impl<const LENGTH: usize> NonceProvider<LENGTH>
  for RandNonceProvider<LENGTH>
{
  fn generate(&mut self) -> [u8; LENGTH] {
    self.0.random()
  }
}

//

pub trait AssociatedData {
  fn as_bytes(&self) -> &[u8];
}

impl AssociatedData for () {
  fn as_bytes(&self) -> &[u8] {
    &[]
  }
}

impl AssociatedData for &[u8] {
  fn as_bytes(&self) -> &[u8] {
    self
  }
}

impl AssociatedData for Vec<u8> {
  fn as_bytes(&self) -> &[u8] {
    Vec::as_slice(self)
  }
}

impl AssociatedData for &str {
  fn as_bytes(&self) -> &[u8] {
    str::as_bytes(self)
  }
}

impl AssociatedData for String {
  fn as_bytes(&self) -> &[u8] {
    String::as_bytes(self)
  }
}
