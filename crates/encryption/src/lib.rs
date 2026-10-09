//! Symmetric encryption utilities: AEAD data and envelope
//! encryption ([aead]) under a 32 byte [Key] that is wiped from
//! memory when dropped, with decrypted outputs wiped the same
//! way ([Zeroizing]). Two ciphers ([Cipher]) share one stored
//! format, told apart by a format marker on the ciphertext.

use std::{
  fmt,
  io::{ErrorKind, Read as _},
  path::Path,
  sync::LazyLock,
};

use anyhow::{Context as _, anyhow};
use data_encoding::Encoding;
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod aead;

pub use data_encoding::BASE64URL;
pub use zeroize::Zeroizing;

/// A 32 byte symmetric key.
///
/// The material is zeroized when the key is dropped, `Debug`
/// prints none of it, and the comparison is constant time. Keys
/// are not `Clone`: pass them by reference (or share an `Arc`),
/// so the process holds one buffer to wipe per key. A plain
/// `[u8; 32]` copied out of one is never wiped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; 32]);

impl Key {
  pub const LEN: usize = 32;

  /// Copy the material out of `bytes` and wipe `bytes` in place,
  /// so the key holds the only copy. (Taking the array by value
  /// would leave the caller's variable holding a second copy: a
  /// move of a `Copy` array is a copy.)
  pub fn from_bytes(bytes: &mut [u8; Key::LEN]) -> Key {
    let key = Key(*bytes);
    bytes.zeroize();
    key
  }

  /// A key from a byte slice of exactly [Key::LEN] bytes. The
  /// slice is the caller's to wipe (hand it over in a
  /// [Zeroizing] buffer).
  pub fn from_slice(bytes: &[u8]) -> Option<Key> {
    let mut key = Key([0; Key::LEN]);
    if bytes.len() != Key::LEN {
      return None;
    }
    key.0.copy_from_slice(bytes);
    Some(key)
  }

  /// Fresh random key material, read directly from the OS
  /// random source ([rand::rngs::SysRng]) so the material cannot
  /// repeat across a `fork`, unlike a userspace generator.
  ///
  /// Panics if the OS random source is unavailable,
  /// see [Key::try_generate].
  pub fn generate() -> Key {
    Key::try_generate().expect("OS random source unavailable")
  }

  /// [Key::generate], returning an error if the
  /// OS random source is unavailable.
  pub fn try_generate() -> anyhow::Result<Key> {
    use rand::TryRng as _;
    let mut bytes = [0u8; Key::LEN];
    rand::rngs::SysRng
      .try_fill_bytes(&mut bytes)
      .context("Failed to read from the OS random source")?;
    Ok(Key::from_bytes(&mut bytes))
  }

  /// Decodes a key from its text form, the way people hand keys
  /// over (a config value, a key file, a request field): base64url
  /// or standard base64 (eg. `openssl rand -base64 32`), padded or
  /// not, surrounding whitespace ignored. It must decode to exactly
  /// [Key::LEN] bytes. [Key::to_base64url] gives the canonical form.
  ///
  /// The decoded bytes are wiped, also when decoding fails part way,
  /// and errors never include the input, only what is wrong with it.
  pub fn decode(text: &str) -> anyhow::Result<Key> {
    // Padding is optional: dropped here, the decoder takes none.
    let text = text.trim().trim_end_matches('=');
    let len = KEY_TEXT
      .decode_len(text.len())
      .map_err(|e| anyhow!("{EXPECTED_KEY_TEXT}: {e}"))?;
    // Checked before decoding: only text the length of a key is
    // decoded, so a long input costs no allocation of its size.
    if len != Key::LEN {
      return Err(anyhow!("{EXPECTED_KEY_TEXT}, got {len} bytes"));
    }
    // Into a buffer of its own, wiped on drop. `Encoding::decode`
    // would free the bytes decoded before a bad symbol (part of the
    // key) without wiping them.
    let mut decoded = Zeroizing::new(vec![0u8; len]);
    let len = KEY_TEXT
      .decode_mut(text.as_bytes(), &mut decoded)
      .map_err(|e| anyhow!("{EXPECTED_KEY_TEXT}: {}", e.error))?;
    Key::from_slice(&decoded[..len])
      .ok_or_else(|| anyhow!("{EXPECTED_KEY_TEXT}, got {len} bytes"))
  }

  /// [Key::decode] for bytes, which have to be UTF-8 text.
  pub fn from_base64url(encoded: &[u8]) -> anyhow::Result<Key> {
    let text = std::str::from_utf8(encoded)
      .map_err(|_| anyhow!("{EXPECTED_KEY_TEXT}: not UTF-8 text"))?;
    Key::decode(text)
  }

  /// Reads the key in a key file, decoding its contents as
  /// [Key::decode] does (so a trailing newline is fine). The
  /// contents are read into a buffer wiped on drop. Errors name the
  /// path, never the contents, and keep the [std::io::Error] of a
  /// failed read, eg. to tell a missing file
  /// (`err.downcast_ref::<std::io::Error>()`).
  pub fn read_file(path: impl AsRef<Path>) -> anyhow::Result<Key> {
    let path = path.as_ref();
    let contents = read_key_file(path)
      .with_context(|| format!("Failed to read key file {path:?}"))?;
    let key = if contents.len() > MAX_KEY_FILE_LEN {
      Err(anyhow!(
        "{EXPECTED_KEY_TEXT}, the file is larger than \
         {MAX_KEY_FILE_LEN} bytes"
      ))
    } else {
      Key::from_base64url(&contents)
    };
    key.with_context(|| format!("Invalid key in key file {path:?}"))
  }

  /// The base64url encoding of the material, wiped on drop.
  pub fn to_base64url(&self) -> Zeroizing<String> {
    Zeroizing::new(BASE64URL.encode(&self.0))
  }

  pub fn as_bytes(&self) -> &[u8; Key::LEN] {
    &self.0
  }
}

impl PartialEq for Key {
  fn eq(&self, other: &Key) -> bool {
    self.0.ct_eq(&other.0).into()
  }
}

impl Eq for Key {}

impl fmt::Debug for Key {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("Key([REDACTED])")
  }
}

/// What [Key::decode] takes, for its errors.
const EXPECTED_KEY_TEXT: &str =
  "Expected a 32 byte key, base64url or base64 encoded";

/// The decoder of [Key::decode]: base64url, also reading the two
/// symbols standard base64 spells differently (`+` and `/`), so
/// either alphabet decodes without a normalized copy of the key.
/// Takes no padding, which is dropped before decoding.
static KEY_TEXT: LazyLock<Encoding> = LazyLock::new(|| {
  let mut spec = data_encoding::BASE64URL_NOPAD.specification();
  spec.translate.from.push_str("+/");
  spec.translate.to.push_str("-_");
  spec
    .encoding()
    .expect("base64url with the standard symbols translated is valid")
});

/// The most of a key file [Key::read_file] reads. A key's text form
/// is 44 characters: a file much longer holds no key, and is refused
/// without reading it in full.
const MAX_KEY_FILE_LEN: usize = 4096;

/// The contents of the file at `path`, up to one byte over
/// [MAX_KEY_FILE_LEN] (to tell a file which is too long), in a
/// buffer wiped on drop. The buffer is sized up front and never
/// grown, as growing it would leave a copy of the contents behind
/// in the freed one.
fn read_key_file(path: &Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
  let mut file = std::fs::File::open(path)?;
  let mut contents = Zeroizing::new(vec![0u8; MAX_KEY_FILE_LEN + 1]);
  let mut len = 0;
  while len < contents.len() {
    match file.read(&mut contents[len..]) {
      Ok(0) => break,
      Ok(read) => len += read,
      Err(e) if e.kind() == ErrorKind::Interrupted => {}
      Err(e) => return Err(e),
    }
  }
  // The rest of the buffer is still wiped on drop.
  contents.truncate(len);
  Ok(contents)
}

/// The AEAD cipher a ciphertext was produced with. Both take a 32
/// byte [Key] and a random nonce per encryption; they differ in
/// nonce size and hardware acceleration.
///
/// XChaCha20-Poly1305's 192 bit nonce makes random nonces safe at
/// any volume. AES-256-GCM's 96 bit nonce is not: keep one key
/// under roughly 2^32 encryptions (NIST SP 800-38D's bound for
/// random IVs) — under envelope encryption every data key seals
/// one message, so the bound applies to the master key's wraps.
/// AES-GCM is the faster of the two where AES-NI is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Cipher {
  #[default]
  XChaCha20Poly1305,
  Aes256Gcm,
}

impl Cipher {
  pub(crate) const ALL: [Cipher; 2] =
    [Cipher::XChaCha20Poly1305, Cipher::Aes256Gcm];

  /// The name in the format marker.
  pub(crate) fn marker(self) -> &'static str {
    match self {
      Cipher::XChaCha20Poly1305 => "xchacha20poly1305",
      Cipher::Aes256Gcm => "aes256gcm",
    }
  }

  pub(crate) fn from_marker(marker: &str) -> Option<Cipher> {
    Cipher::ALL
      .into_iter()
      .find(|cipher| cipher.marker() == marker)
  }

  /// The nonce size the cipher needs, in bytes.
  pub(crate) fn nonce_len(self) -> usize {
    match self {
      Cipher::XChaCha20Poly1305 => 24,
      Cipher::Aes256Gcm => 12,
    }
  }

  /// Prefix a base64url payload with the cipher's format marker:
  /// `$<marker>$<payload>`. `$` is outside the base64url alphabet,
  /// so the marker never collides with an unmarked payload.
  pub(crate) fn mark(self, payload: &str) -> String {
    format!("${}${payload}", self.marker())
  }

  /// Split a stored ciphertext into its cipher and base64url
  /// payload. Ciphertexts written before the marker existed carry
  /// none and are XChaCha20-Poly1305, the only cipher then.
  pub(crate) fn parse(data: &str) -> anyhow::Result<(Cipher, &str)> {
    let Some(rest) = data.strip_prefix('$') else {
      return Ok((Cipher::XChaCha20Poly1305, data));
    };
    let (marker, payload) = rest
      .split_once('$')
      .context("Invalid ciphertext format marker")?;
    let cipher = Cipher::from_marker(marker).with_context(|| {
      // The marker is untrusted input: cap what is echoed.
      let shown = marker.chars().take(32).collect::<String>();
      let more = if marker.chars().count() > 32 {
        "…"
      } else {
        ""
      };
      format!("Unknown cipher '{shown}{more}'")
    })?;
    Ok((cipher, payload))
  }
}

impl fmt::Display for Cipher {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.marker())
  }
}

/// The separator of the text form of [EncryptedData] and
/// [EnvelopeEncryptedData]. Outside of the base64url alphabet
/// and the cipher marker, so it can't appear in a part.
const TEXT_SEPARATOR: char = ':';

/// Ciphertext with the nonce it was encrypted with.
///
/// To store it, either use the text form (`Display` / `FromStr`:
/// `<nonce>:<data>`), or the `serde` feature for a structured one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
  feature = "serde",
  derive(serde::Serialize, serde::Deserialize)
)]
pub struct EncryptedData {
  /// ## data
  /// - encrypted using given key plus the below nonce
  /// - base64url encoded, prefixed with the cipher's format
  ///   marker (`$aes256gcm$...`); no marker means
  ///   XChaCha20-Poly1305, the format before markers existed
  pub data: String,
  /// ## nonce
  /// - the random nonce used to encrypt the data
  /// - base64url encoded
  pub nonce: String,
}

/// Data encrypted with its own key, which is encrypted with the master key.
///
/// To store it, either use the text form (`Display` / `FromStr`:
/// `<key nonce>:<key data>:<nonce>:<data>`), or the `serde` feature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
  feature = "serde",
  derive(serde::Serialize, serde::Deserialize)
)]
pub struct EnvelopeEncryptedData {
  /// Encrypted using master key
  pub key: EncryptedData,
  /// Encrypted using above key, decrypted.
  pub data: EncryptedData,
}

/// A part of the text form: not empty, and only characters which
/// the encryption produces (base64url, and the `$cipher$` marker).
fn check_text_part(part: &str) -> anyhow::Result<()> {
  let valid = !part.is_empty()
    && part.bytes().all(|byte| {
      byte.is_ascii_alphanumeric()
        || matches!(byte, b'-' | b'_' | b'=' | b'$')
    });
  if valid {
    Ok(())
  } else {
    Err(anyhow::anyhow!("Encrypted data has the wrong format"))
  }
}

/// `<nonce>:<data>`
impl fmt::Display for EncryptedData {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}{TEXT_SEPARATOR}{}", self.nonce, self.data)
  }
}

impl std::str::FromStr for EncryptedData {
  type Err = anyhow::Error;

  fn from_str(s: &str) -> anyhow::Result<Self> {
    let mut parts = s.split(TEXT_SEPARATOR);
    let (Some(nonce), Some(data), None) =
      (parts.next(), parts.next(), parts.next())
    else {
      return Err(anyhow::anyhow!(
        "Encrypted data has the wrong format"
      ));
    };
    check_text_part(nonce)?;
    check_text_part(data)?;
    Ok(EncryptedData {
      data: data.to_string(),
      nonce: nonce.to_string(),
    })
  }
}

/// `<key nonce>:<key data>:<nonce>:<data>`
impl fmt::Display for EnvelopeEncryptedData {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}{TEXT_SEPARATOR}{}", self.key, self.data)
  }
}

impl std::str::FromStr for EnvelopeEncryptedData {
  type Err = anyhow::Error;

  fn from_str(s: &str) -> anyhow::Result<Self> {
    let parts = s.split(TEXT_SEPARATOR).collect::<Vec<_>>();
    let [key_nonce, key_data, nonce, data] = parts.as_slice() else {
      return Err(anyhow::anyhow!(
        "Envelope encrypted data has the wrong format"
      ));
    };
    for part in [key_nonce, key_data, nonce, data] {
      check_text_part(part)?;
    }
    Ok(EnvelopeEncryptedData {
      key: EncryptedData {
        data: key_data.to_string(),
        nonce: key_nonce.to_string(),
      },
      data: EncryptedData {
        data: data.to_string(),
        nonce: nonce.to_string(),
      },
    })
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

// Dev dependency only used by the `serde` feature test.
#[cfg(all(test, not(feature = "serde")))]
use serde_json as _;

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn text_form_round_trips_and_decrypts() {
    let key = Key::generate();
    for cipher in Cipher::ALL {
      let encrypted =
        aead::encrypt(b"secret", &key, &"aad", cipher).unwrap();
      let text = encrypted.to_string();
      assert_eq!(text.split(':').count(), 2);
      let parsed: EncryptedData = text.parse().unwrap();
      assert_eq!(parsed, encrypted);
      assert_eq!(
        aead::decrypt(&parsed, &key, &"aad").unwrap().as_slice(),
        b"secret"
      );

      let envelope =
        aead::envelope_encrypt(b"secret", &key, &"aad", cipher)
          .unwrap();
      let text = envelope.to_string();
      assert_eq!(text.split(':').count(), 4);
      let parsed: EnvelopeEncryptedData = text.parse().unwrap();
      assert_eq!(parsed, envelope);
      assert_eq!(
        aead::envelope_decrypt(&parsed, &key, &"aad")
          .unwrap()
          .as_slice(),
        b"secret"
      );
    }
  }

  #[test]
  fn text_form_rejects_malformed_input() {
    for invalid in [
      "",
      ":",
      "nonce",
      "nonce:",
      ":data",
      "a:b:c",
      "a:b:c:d:e",
      "no spaces:data",
      "nonce:da\nta",
      "€:data",
    ] {
      assert!(
        invalid.parse::<EncryptedData>().is_err(),
        "{invalid:?}"
      );
    }
    for invalid in
      ["", ":::", "a:b:c", "a:b:c:d:e", "a:b::d", "a:b:c:d e"]
    {
      assert!(
        invalid.parse::<EnvelopeEncryptedData>().is_err(),
        "{invalid:?}"
      );
    }
    // Well formed, which says nothing about it decrypting.
    assert!("a:b".parse::<EncryptedData>().is_ok());
    assert!(
      "a:b:c:$aes256gcm$d"
        .parse::<EnvelopeEncryptedData>()
        .is_ok()
    );
  }

  #[cfg(feature = "serde")]
  #[test]
  fn serde_round_trip() {
    let key = Key::generate();
    let envelope = aead::envelope_encrypt(
      b"secret",
      &key,
      &"aad",
      Cipher::default(),
    )
    .unwrap();
    let json = serde_json::to_string(&envelope).unwrap();
    let parsed: EnvelopeEncryptedData =
      serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, envelope);
  }

  #[test]
  fn key_round_trips_through_base64url_and_compares() {
    let key = Key::from_bytes(&mut [7u8; 32]);
    let encoded = key.to_base64url();
    assert_eq!(Key::from_base64url(encoded.as_bytes()).unwrap(), key);
    assert_ne!(Key::from_bytes(&mut [8u8; 32]), key);
    assert!(Key::from_slice(&[1u8; 31]).is_none());
    assert!(Key::from_base64url(b"!!").is_err());
    assert_eq!(format!("{key:?}"), "Key([REDACTED])");
  }

  #[test]
  fn key_from_base64url_rejects_wrong_lengths() {
    // Valid base64url, wrong decoded length.
    let short = BASE64URL.encode(&[1u8; 31]);
    let err = Key::from_base64url(short.as_bytes()).unwrap_err();
    assert!(err.to_string().contains("got 31 bytes"), "{err}");
    let long = BASE64URL.encode(&[1u8; 33]);
    assert!(Key::from_base64url(long.as_bytes()).is_err());
    assert!(Key::from_base64url(b"").is_err());
    // Not UTF-8, so not base64 either.
    assert!(Key::from_base64url(&[0xff; 44]).is_err());
    // Delegates to Key::decode: unpadded input is accepted too.
    let key = Key::from_bytes(&mut [7u8; 32]);
    let unpadded = key.to_base64url();
    let unpadded = unpadded.trim_end_matches('=');
    assert_eq!(
      Key::from_base64url(unpadded.as_bytes()).unwrap(),
      key
    );
  }

  /// A key whose text form has the two symbols base64url and
  /// standard base64 spell differently (`-` / `+`, `_` / `/`).
  fn key_with_url_symbols() -> (Key, Zeroizing<String>) {
    let key = Key::from_bytes(&mut [0xfb; 32]);
    let text = key.to_base64url();
    assert!(text.contains('-') && text.contains('_'), "{}", *text);
    assert!(text.ends_with('='), "{}", *text);
    (key, text)
  }

  #[test]
  fn key_decode_accepts_the_common_text_forms() {
    let (key, padded) = key_with_url_symbols();
    let unpadded = padded.trim_end_matches('=').to_string();
    // eg. `openssl rand -base64 32`.
    let standard = padded.replace('-', "+").replace('_', "/");
    for text in [
      padded.to_string(),
      unpadded.clone(),
      standard.clone(),
      standard.trim_end_matches('=').to_string(),
      format!("  {}\n", *padded),
      format!("\t{unpadded} \r\n"),
    ] {
      assert_eq!(Key::decode(&text).unwrap(), key, "{text:?}");
    }
  }

  #[test]
  fn key_decode_errors_never_include_the_input() {
    let short = BASE64URL.encode(&[0x5a; 31]);
    let long = BASE64URL.encode(&[0x5a; 33]);
    let (_, valid) = key_with_url_symbols();
    // A bad symbol near the end, once part of the key is decoded.
    let mut bad_symbol = valid.to_string();
    bad_symbol.replace_range(40..41, ".");
    let truncated = valid[..41].to_string();
    for (text, detail) in [
      (short.as_str(), "got 31 bytes"),
      (short.trim_end_matches('='), "got 31 bytes"),
      (long.as_str(), "got 33 bytes"),
      (bad_symbol.as_str(), "invalid symbol"),
      (truncated.as_str(), "invalid length"),
      ("not base64 !!", "invalid"),
      ("", "got 0 bytes"),
      ("  \n", "got 0 bytes"),
    ] {
      let err = format!("{:#}", Key::decode(text).unwrap_err());
      assert!(
        err.starts_with("Expected a 32 byte key")
          && err.contains(detail),
        "{text:?}: {err}"
      );
      let text = text.trim();
      if !text.is_empty() {
        assert!(!err.contains(text), "{err}");
      }
      // No part of the encoded material either.
      assert!(
        !err.contains("Wlpa") && !err.contains("-_v7"),
        "{err}"
      );
    }
  }

  /// Inputs which can't be a key are refused by their length,
  /// before anything is decoded.
  #[test]
  fn key_decode_refuses_long_input_by_its_length() {
    let long = "A".repeat(1 << 20);
    let err = Key::decode(&long).unwrap_err().to_string();
    assert!(err.contains("got 786432 bytes"), "{err}");
  }

  fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
      "mogh_encryption_test_{}_{name}",
      std::process::id()
    ))
  }

  #[test]
  fn key_read_file_decodes_the_contents() {
    let (key, text) = key_with_url_symbols();
    let path = temp_path("key_file");
    std::fs::write(&path, format!("{}\n", *text)).unwrap();
    let read = Key::read_file(&path);
    std::fs::remove_file(&path).unwrap();
    assert_eq!(read.unwrap(), key);
  }

  #[test]
  fn key_read_file_errors_name_the_path_not_the_contents() {
    // Missing: the io error is kept, so callers can tell.
    let missing = temp_path("missing_key_file");
    let err = Key::read_file(&missing).unwrap_err();
    assert!(format!("{err:#}").contains(&format!("{missing:?}")));
    assert_eq!(
      err.downcast_ref::<std::io::Error>().map(|e| e.kind()),
      Some(std::io::ErrorKind::NotFound)
    );

    let path = temp_path("bad_key_file");
    let short = BASE64URL.encode(&[0x5a; 31]);
    let not_utf8 = [0xfbu8; 32];
    let too_long = "A".repeat(10_000);
    for (contents, detail) in [
      (short.as_bytes(), "got 31 bytes"),
      // Raw key bytes, rather than their text form.
      (&not_utf8[..], "not UTF-8"),
      (too_long.as_bytes(), "larger than"),
    ] {
      std::fs::write(&path, contents).unwrap();
      let err = format!("{:#}", Key::read_file(&path).unwrap_err());
      assert!(err.contains(&format!("{path:?}")), "{err}");
      assert!(err.contains(detail), "{err}");
      assert!(
        !err.contains("Wlpa") && !err.contains("AAAA"),
        "{err}"
      );
    }
    std::fs::remove_file(&path).unwrap();
  }

  #[test]
  fn unknown_marker_error_is_capped() {
    let long = format!("${}$payload", "a".repeat(5_000));
    let err = Cipher::parse(&long).unwrap_err().to_string();
    assert!(err.len() < 100, "{}", err.len());
    assert!(err.contains("Unknown cipher"));
  }

  #[test]
  fn from_bytes_wipes_the_source() {
    let mut bytes = [9u8; 32];
    let key = Key::from_bytes(&mut bytes);
    assert_eq!(key.as_bytes(), &[9u8; 32]);
    assert_eq!(bytes, [0u8; 32]);
  }

  #[test]
  fn generated_keys_differ() {
    assert_ne!(Key::generate(), Key::generate());
  }

  #[test]
  fn format_markers_round_trip_and_default_to_legacy() {
    for cipher in Cipher::ALL {
      let marked = cipher.mark("cGF5bG9hZA");
      assert_eq!(
        Cipher::parse(&marked).unwrap(),
        (cipher, "cGF5bG9hZA")
      );
      assert_eq!(Cipher::from_marker(cipher.marker()), Some(cipher));
    }
    // Unmarked: the format before markers, XChaCha20-Poly1305.
    assert_eq!(
      Cipher::parse("cGF5bG9hZA").unwrap(),
      (Cipher::XChaCha20Poly1305, "cGF5bG9hZA")
    );
    assert!(Cipher::parse("$nope$cGF5bG9hZA").is_err());
    assert!(Cipher::parse("$aes256gcm").is_err());
  }
}
