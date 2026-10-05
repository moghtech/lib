use std::fmt;

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tracing::{info, warn};
use typeshare::typeshare;
use zeroize::Zeroizing;

use crate::{
  FORMAT_VERSION, MAX_PAYLOAD_BYTES, Payload, PayloadError,
  root::find_root_key,
};

/// The length of the nonce the browser draws, in bytes.
pub const NONCE_BYTES: usize = 32;

/// What `GetSupporterKey` answers: everything the browser needs to
/// verify the key offline, and nothing secret. All fields are
/// base64url without padding.
///
/// The typescript package has it as `SignedSupporterKey` too.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SignedSupporterKey {
  /// `P`, the payload bytes exactly as decoded from the configured
  /// key.
  pub payload: String,
  /// `SP`, the root key's signature over `P || I2`.
  pub payload_sig: String,
  /// `I2`, the instance public key, 32 bytes.
  pub instance_public_key: String,
  /// `SN`, the instance key's signature over the nonce message
  /// ([nonce_message]).
  pub nonce_sig: String,
}

/// A configured supporter key, parsed once at startup and kept for
/// the process lifetime. It holds the instance private key (`I1`),
/// the only secret in a key: it never leaves this struct (the
/// `Debug` is redacted), and is wiped from memory on drop.
///
/// The server decides nothing on it. The browser verifies the key
/// (the typescript package), the server only parses it and answers
/// `GetSupporterKey` ([Self::respond]). [Self::verify] is for the
/// startup log.
pub struct SupporterKey {
  app: String,
  payload: Vec<u8>,
  payload_sig: [u8; 64],
  instance_key: SigningKey,
  instance_public_key: [u8; 32],
}

impl fmt::Debug for SupporterKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("SupporterKey")
      .field("app", &self.app)
      .field("payload_bytes", &self.payload.len())
      .field(
        "instance_public_key",
        &BASE64URL_NOPAD.encode(&self.instance_public_key),
      )
      .finish_non_exhaustive()
  }
}

/// Why a configured key is not one. Never echoes the key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
  #[error("The key is empty")]
  Empty,
  #[error("The key has {0} parts separated by `.`, expected 3")]
  Parts(usize),
  #[error("The {0} of the key is empty")]
  EmptyPart(&'static str),
  #[error(
    "The {part} of the key is not base64url without padding | {error}"
  )]
  Base64 {
    part: &'static str,
    error: data_encoding::DecodeError,
  },
  #[error(
    "The payload of the key is {0} bytes, the most is {MAX_PAYLOAD_BYTES}"
  )]
  PayloadTooLong(usize),
  #[error(
    "The {part} of the key is {got} bytes, expected {expected}"
  )]
  Length {
    part: &'static str,
    expected: usize,
    got: usize,
  },
}

/// Why a nonce is not one. A `GetSupporterKey` with such a nonce is
/// a 400 error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
  #[error("The nonce is not base64url without padding | {0}")]
  Base64(data_encoding::DecodeError),
  #[error("The nonce is {0} bytes, expected {NONCE_BYTES}")]
  Length(usize),
}

/// Why a parsed key does not verify, so it is not served and shows
/// no badge, see [SupporterKey::verify].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
  #[error("{0}")]
  Payload(#[from] PayloadError),
  #[error("No root key with the id {0} is embedded")]
  UnknownRoot(String),
  #[error("The root signature does not verify")]
  Signature,
  #[error(
    "The key has the format version {0}, this version of mogh_supporter reads {FORMAT_VERSION}"
  )]
  Version(u64),
  #[error("The key is for `{key_app}`, this app is `{app}`")]
  OtherApp { key_app: String, app: String },
}

/// Decodes the nonce of a `GetSupporterKey`: base64url without
/// padding of exactly [NONCE_BYTES] bytes. Anything else is a 400
/// error. The server only ever signs a fixed domain string, these
/// bytes it did not choose, and a hash ([nonce_message]), which is
/// what keeps the request from being a signing oracle.
pub fn decode_nonce(
  nonce: &str,
) -> Result<[u8; NONCE_BYTES], NonceError> {
  let bytes = BASE64URL_NOPAD
    .decode(nonce.as_bytes())
    .map_err(NonceError::Base64)?;
  bytes
    .as_slice()
    .try_into()
    .map_err(|_| NonceError::Length(bytes.len()))
}

/// The message the instance key signs for a nonce:
/// `UTF-8("{app}-supporter-v1") || nonce || SHA-256(payload)`.
pub fn nonce_message(
  app: &str,
  nonce: &[u8; NONCE_BYTES],
  payload: &[u8],
) -> Vec<u8> {
  let mut message =
    Vec::with_capacity(app.len() + 13 + NONCE_BYTES + 32);
  message.extend_from_slice(app.as_bytes());
  message.extend_from_slice(b"-supporter-v1");
  message.extend_from_slice(nonce);
  message.extend_from_slice(&sha2::Sha256::digest(payload));
  message
}

/// The key without any whitespace: the form it is parsed and stored
/// in. A pasted key is long, and wrapped in config files and emails.
pub fn compact_key(key: &str) -> Zeroizing<String> {
  Zeroizing::new(
    key
      .chars()
      .filter(|c| !c.is_whitespace())
      .collect::<String>(),
  )
}

fn decode_part(
  part: &'static str,
  text: &str,
) -> Result<Vec<u8>, ParseError> {
  if text.is_empty() {
    return Err(ParseError::EmptyPart(part));
  }
  BASE64URL_NOPAD
    .decode(text.as_bytes())
    .map_err(|error| ParseError::Base64 { part, error })
}

fn sized<const N: usize>(
  part: &'static str,
  bytes: &[u8],
) -> Result<[u8; N], ParseError> {
  bytes.try_into().map_err(|_| ParseError::Length {
    part,
    expected: N,
    got: bytes.len(),
  })
}

impl SupporterKey {
  /// Parses a configured key for `app` (`komodo`, `cicada`): all
  /// whitespace removed (the key is long, and wrapped in config
  /// files and emails), three non empty parts separated by `.`,
  /// each base64url without padding, the root signature 64 bytes,
  /// the instance private key 32 bytes, the payload at most
  /// [MAX_PAYLOAD_BYTES]. The payload is kept as decoded, it is
  /// what the root key signed.
  ///
  /// This does not verify the key, see [Self::verify].
  pub fn parse(
    app: impl Into<String>,
    key: &str,
  ) -> Result<SupporterKey, ParseError> {
    let key = compact_key(key);
    if key.is_empty() {
      return Err(ParseError::Empty);
    }
    let parts = key.split('.').collect::<Vec<_>>();
    let [payload, payload_sig, instance_key] = parts[..] else {
      return Err(ParseError::Parts(parts.len()));
    };

    let payload = decode_part("payload", payload)?;
    if payload.len() > MAX_PAYLOAD_BYTES {
      return Err(ParseError::PayloadTooLong(payload.len()));
    }
    let payload_sig = sized(
      "root signature",
      &decode_part("root signature", payload_sig)?,
    )?;
    // Wiped on drop, like the signing key built from it.
    let seed = Zeroizing::new(decode_part(
      "instance private key",
      instance_key,
    )?);
    let seed = Zeroizing::new(sized("instance private key", &seed)?);
    let instance_key = SigningKey::from_bytes(&seed);
    let instance_public_key = instance_key.verifying_key().to_bytes();

    Ok(SupporterKey {
      app: app.into(),
      payload,
      payload_sig,
      instance_key,
      instance_public_key,
    })
  }

  /// Loads the configured key at startup: `None` for an empty
  /// setting (no badge), and for a key which does not parse, which
  /// is logged at warn level with the reason, never the key. A key
  /// which parses is logged at info level with what the badge will
  /// show, or at warn level with why it will not ([Self::verify]
  /// under `roots`, the root keys the app hardcodes): a key which
  /// does not verify stays in use, and is not served.
  pub fn load(
    app: &str,
    key: &str,
    roots: &[&str],
  ) -> Option<SupporterKey> {
    if key.trim().is_empty() {
      return None;
    }
    let key = match SupporterKey::parse(app, key) {
      Ok(key) => key,
      Err(e) => {
        warn!(
          "Ignoring the configured supporter key, which could not be parsed | {e}"
        );
        return None;
      }
    };
    match key.verify(roots) {
      Ok(payload) => info!(
        "Supporter key configured for {} ({}), covers releases up to {}",
        payload.name, payload.tier, payload.covers
      ),
      Err(e) => warn!(
        "Supporter key configured, but it is not served and the badge will not show | {e}"
      ),
    }
    Some(key)
  }

  /// The app the key was parsed for.
  pub fn app(&self) -> &str {
    &self.app
  }

  /// `P`, the bytes the root key signed.
  pub fn payload(&self) -> &[u8] {
    &self.payload
  }

  /// `SP`, the root key's signature over `P || I2`.
  pub fn payload_sig(&self) -> &[u8; 64] {
    &self.payload_sig
  }

  /// `I2`, derived from the instance private key.
  pub fn instance_public_key(&self) -> &[u8; 32] {
    &self.instance_public_key
  }

  /// The payload, decoded. Nothing is verified, see [Self::verify].
  pub fn decode_payload(&self) -> Result<Payload, PayloadError> {
    Payload::decode(&self.payload)
  }

  /// What the browser will check, except the release date and the
  /// revocation list: the payload decodes, it names a root in
  /// `roots` whose signature over `P || I2` verifies, its format
  /// version is [FORMAT_VERSION] and it is for this app. The server
  /// answers `GetSupporterKey` only for a key which verifies, and
  /// the browser verifies again what it is served.
  pub fn verify(
    &self,
    roots: &[&str],
  ) -> Result<Payload, VerifyError> {
    let payload = self.decode_payload()?;
    // The root whose id, derived from its key, the payload names.
    let kid = payload.root_key_id_hex();
    let verifying_key = find_root_key(roots, &kid)
      .ok_or(VerifyError::UnknownRoot(kid))?;
    let mut signed = Vec::with_capacity(
      self.payload.len() + self.instance_public_key.len(),
    );
    signed.extend_from_slice(&self.payload);
    signed.extend_from_slice(&self.instance_public_key);
    verifying_key
      .verify_strict(
        &signed,
        &ed25519_dalek::Signature::from_bytes(&self.payload_sig),
      )
      .map_err(|_| VerifyError::Signature)?;
    if payload.version != FORMAT_VERSION {
      return Err(VerifyError::Version(payload.version));
    }
    if payload.app != self.app {
      return Err(VerifyError::OtherApp {
        key_app: payload.app,
        app: self.app.clone(),
      });
    }
    Ok(payload)
  }

  /// Answers `GetSupporterKey` for a nonce ([decode_nonce]): the
  /// key as the browser verifies it, with the instance key's
  /// signature over the [nonce_message]. Signing is deterministic,
  /// the same nonce always gets the same answer.
  pub fn respond(
    &self,
    nonce: &[u8; NONCE_BYTES],
  ) -> SignedSupporterKey {
    let message = nonce_message(&self.app, nonce, &self.payload);
    let nonce_sig = self.instance_key.sign(&message);
    SignedSupporterKey {
      payload: BASE64URL_NOPAD.encode(&self.payload),
      payload_sig: BASE64URL_NOPAD.encode(&self.payload_sig),
      instance_public_key: BASE64URL_NOPAD
        .encode(&self.instance_public_key),
      nonce_sig: BASE64URL_NOPAD.encode(&nonce_sig.to_bytes()),
    }
  }
}
