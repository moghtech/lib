//! Encrypts secrets before they are stored in the database.

use std::{io::ErrorKind, sync::OnceLock};

use anyhow::Context as _;
use mogh_encryption::{Cipher, EnvelopeEncryptedData, Key, aead};

use crate::config::core_config;

/// The key comes from the config, else it is generated once
/// and kept next to the database with `0600` permissions.
pub fn encryption_key() -> &'static Key {
  static ENCRYPTION_KEY: OnceLock<Key> = OnceLock::new();
  ENCRYPTION_KEY.get_or_init(|| match load_encryption_key() {
    Ok(key) => key,
    Err(e) => panic!("{e:?}"),
  })
}

fn load_encryption_key() -> anyhow::Result<Key> {
  let config = core_config();
  if !config.encryption_key.is_empty() {
    return Key::decode(&config.encryption_key)
      .context("Invalid 'encryption_key' config");
  }
  let path = config.database_path.with_extension("encryption.key");
  if path.exists() {
    // Read into a wiped buffer, errors naming the path.
    return Key::read_file(&path);
  }
  let key = Key::try_generate()?;
  // Never over an existing file: a key replaced by another would
  // leave everything sealed under it unreadable.
  match mogh_secret_file::write_new(
    &path,
    key.to_base64url().as_bytes(),
  ) {
    Ok(()) => {
      tracing::info!("Generated database encryption key at {path:?}");
      Ok(key)
    }
    // Created by another process since the check: its key is the
    // one in use.
    Err(e) if e.kind() == ErrorKind::AlreadyExists => {
      Key::read_file(&path)
    }
    Err(e) => {
      Err(e).with_context(|| format!("Failed to write {path:?}"))
    }
  }
}

/// Envelope encrypts `data`, bound to `associated_data`
/// (eg. the id of the row), so the ciphertext can't be
/// moved to another row.
pub fn seal(
  data: &str,
  associated_data: &str,
) -> anyhow::Result<String> {
  let sealed = aead::envelope_encrypt(
    data.as_bytes(),
    encryption_key(),
    &associated_data,
    Cipher::default(),
  )?;
  Ok(sealed.to_string())
}

/// The text [seal] sealed with the same `associated_data`.
/// Decrypted into a buffer wiped on drop (also when the text turns
/// out not to be UTF-8), then moved out of it, not copied: the
/// caller keeps the plaintext from here (eg. in an api response).
pub fn open(
  sealed: &str,
  associated_data: &str,
) -> anyhow::Result<String> {
  let sealed: EnvelopeEncryptedData = sealed.parse()?;
  let mut text = aead::envelope_decrypt_string(
    &sealed,
    encryption_key(),
    &associated_data,
  )?;
  Ok(std::mem::take(&mut *text))
}
