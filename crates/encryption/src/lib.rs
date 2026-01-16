pub mod xchacha20poly1305;

pub use data_encoding::BASE64URL;

pub struct EncryptedData {
  /// ## data
  /// - encrypted using given key plus the below nonce
  /// - base64url encoded
  pub data: String,
  /// ## nonce
  /// - the random nonce used to encrypt the data
  /// - base64url encoded
  pub nonce: String,
}

pub struct EnvelopeEncryptedData {
  /// Encrypted using master key
  pub key: EncryptedData,
  /// Encrypted using above key, decrypted.
  pub data: EncryptedData,
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
