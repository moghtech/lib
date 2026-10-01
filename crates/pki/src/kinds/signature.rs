//! Ed25519 signatures ([PkiKind::Signature]): the holder of a
//! private key signs a message, and whoever has the public key can
//! verify the signature. What it gives, and what it does not:
//! - The verifier needs no key of its own, and nothing the verifier
//!   holds lets it make a signature: a client is recognized by its
//!   public key alone.
//! - The message is authenticated, not encrypted: the verifier must
//!   already know it (the request being signed).
//! - A signature verifies for whoever has the public key, wherever
//!   that is: sign who the message is for (the host of the server).
//! - A signature verifies again whenever it is replayed. Bind a
//!   freshness value into the message (a timestamp, a nonce) and
//!   have the verifier enforce a window, as mogh_auth signed
//!   requests do.
//! - Signing is deterministic: the same key and message always give
//!   the same signature. Two messages only differ in their signature
//!   when they differ themselves (a nonce).

use anyhow::{Context, anyhow};
use data_encoding::BASE64;
use ed25519_dalek::Signer as _;
use zeroize::Zeroizing;

use crate::{PkiKind, key::Pkcs8PrivateKey, key::SpkiPublicKey};

/// The order of the Ed25519 base point, little endian:
/// 2^252 + 27742317777372353535851937790883648493.
const ORDER: [u8; 32] = [
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
  0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Signs `message` with an Ed25519 private key
/// ([PkiKind::Signature]). Returns the 64 byte signature base64
/// encoded for transport (88 characters).
pub fn sign(
  private_key: &Pkcs8PrivateKey,
  message: &[u8],
) -> anyhow::Result<String> {
  let seed =
    Zeroizing::new(private_key.as_raw_bytes(PkiKind::Signature)?);
  // Wiped on drop.
  let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
  Ok(BASE64.encode(&signing_key.sign(message).to_bytes()))
}

/// Verifies that `signature` (base64, as [sign] returns it) was made
/// over `message` by the holder of the private key of `public_key`,
/// an Ed25519 key ([PkiKind::Signature]).
///
/// The key is checked again here (see
/// [SpkiPublicKey::from_raw_bytes]), also one wrapped unchecked with
/// `From<String>`. A signature has one accepted form: the strict
/// verification of RFC 8032 (a canonical `S`, no low order `R`), and
/// canonical base64. So nobody can turn a valid signature into
/// another valid one for the same message, and a signature seen
/// before identifies a replay.
///
/// It does not prevent replay, see the [module][self] docs.
pub fn verify(
  public_key: &SpkiPublicKey,
  message: &[u8],
  signature: &str,
) -> anyhow::Result<()> {
  let public_key = SpkiPublicKey::maybe_pem_to_raw_bytes(
    PkiKind::Signature,
    public_key.as_str(),
  )
  .context("Invalid public key")?;
  let public_key =
    ed25519_dalek::VerifyingKey::from_bytes(&public_key)
      .map_err(|_| anyhow!("Invalid public key"))?;

  let signature = BASE64
    .decode(signature.as_bytes())
    .context("Failed to base64 decode signature")?;
  let signature: [u8; 64] =
    signature.as_slice().try_into().map_err(|_| {
      anyhow!("Signature should be 64 bytes, got {}", signature.len())
    })?;
  // ed25519-dalek only checks this without its
  // 'legacy_compatibility' feature, which any crate of the build
  // can turn on.
  if !is_canonical_scalar(&signature[32..]) {
    return Err(anyhow!("Signature is not canonical"));
  }

  public_key
    .verify_strict(
      message,
      &ed25519_dalek::Signature::from_bytes(&signature),
    )
    .map_err(|_| anyhow!("Signature does not verify"))
}

/// Whether `signature` has the form [sign] returns one in: 64 bytes
/// in canonical base64 (88 characters). It says nothing of whether
/// it verifies, and needs neither the key nor the message: what
/// could never verify can be refused before more work is done for
/// it.
pub fn well_formed(signature: &str) -> bool {
  signature.len() == 88
    && BASE64
      .decode(signature.as_bytes())
      .is_ok_and(|signature| signature.len() == 64)
}

/// Whether the 32 little endian bytes are below the [ORDER] of the
/// base point, as the `S` of a signature must be: `S + ORDER`
/// verifies just the same otherwise.
fn is_canonical_scalar(scalar: &[u8]) -> bool {
  // Compared from the most significant byte down. Nothing here is
  // secret, a signature is public.
  for (byte, order) in scalar.iter().zip(ORDER.iter()).rev() {
    if byte != order {
      return byte < order;
    }
  }
  false
}
