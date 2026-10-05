//! Test data, for the tests of this crate and of apps: a supporter
//! key as a buyer would paste it ([`KEY`]), minted by the platform
//! for "Acme Corp" and the app `komodo` and signed by a test root
//! key rather than one of Mogh's, the answer a correct `komodo`
//! server gives for it and a fixed nonce ([`response`]), and the
//! test root itself ([`ROOT`]).
//!
//! [`ROOT`] is no root key of an app, so [`KEY`] shows a badge only
//! where a test passes [`ROOT`] as a trusted root. Never hardcode it
//! as one in a release (`check_root_keys` refuses it): this key is
//! public, and a build which trusted its root would show a badge for
//! anyone who configured it.
//!
//! [`KEY`]: crate::fixture::KEY
//! [`response`]: crate::fixture::response
//! [`ROOT`]: crate::fixture::ROOT

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::Digest as _;

use crate::{SignedSupporterKey, Tier};

/// The test root key which signed [KEY]: its public key, as an app
/// hardcodes a root key.
pub const ROOT: &str =
  "MCowBQYDK2VwAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";

/// The id of [ROOT], as `root_key_id` derives it: the `k` of [KEY].
pub const ROOT_KEY_ID: &str = "fe812c12f3ab4ce6";

/// The app [KEY] is for.
pub const APP: &str = "komodo";

/// The key, as a buyer would paste it.
pub const KEY: &str = "qGF2AWFrSP6BLBLzq0zmYWlQAZCjwntqfMKx8EpdnjyPIWFhZmtvbW9kb2FuaUFjbWUgQ29ycGF0bG9yZ2FuaXphdGlvbmFzajIwMjUtMDEtMTVhY2oyMDI3LTA5LTMw.B569urTvMsFeTldR8Cmt9cnCY7SB81t_cG4-53VueFqF51BOmrAmoYk1o0toBHlUe0Z0WBpN2sGDEri4TVCwCA.NUVlvQ9tLCimq2RpjTvrr9t44m-zUjHDDVk5nymZQQw";

/// The payload of [KEY] (its first part), base64url without padding.
pub const PAYLOAD: &str = "qGF2AWFrSP6BLBLzq0zmYWlQAZCjwntqfMKx8EpdnjyPIWFhZmtvbW9kb2FuaUFjbWUgQ29ycGF0bG9yZ2FuaXphdGlvbmFzajIwMjUtMDEtMTVhY2oyMDI3LTA5LTMw";

/// The payload of [KEY], hex.
pub const PAYLOAD_HEX: &str = "a8617601616b48fe812c12f3ab4ce66169500190a3c27b6a7cc2b1f04a5d9e3c8f216161666b6f6d6f646f616e6941636d6520436f727061746c6f7267616e697a6174696f6e61736a323032352d30312d313561636a323032372d30392d3330";

/// The root signature of [KEY] (its second part).
pub const PAYLOAD_SIG: &str = "B569urTvMsFeTldR8Cmt9cnCY7SB81t_cG4-53VueFqF51BOmrAmoYk1o0toBHlUe0Z0WBpN2sGDEri4TVCwCA";

/// The instance public key derived from the third part of [KEY].
pub const INSTANCE_PUBLIC_KEY: &str =
  "tU_ASxS6_yGAysVMYx0NGCR6Swuntgu-uby1IaODjK8";

/// A nonce: 32 bytes all `0x01`.
pub const NONCE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

/// The signature a `komodo` server answers [NONCE] with.
pub const NONCE_SIG: &str = "_hTfDp5rVtAtRhe2i8vM7Hx3kLYN8ks4TnW4b5MjIsB1zLJwiKjEc1ENRo7q_nKN9utZXP12WNqGxVuVTLzQCg";

/// The `i` of the payload, as the revocation list would name it.
pub const ID: &str = "0190a3c2-7b6a-7cc2-b1f0-4a5d9e3c8f21";
/// The `n` of the payload.
pub const NAME: &str = "Acme Corp";
/// The `t` of the payload.
pub const TIER: Tier = Tier::Organization;
/// The `s` of the payload.
pub const SINCE: &str = "2025-01-15";
/// The `c` of the payload.
pub const COVERS: &str = "2027-09-30";

/// What a correct `komodo` server answers `GetSupporterKey` with for
/// [NONCE].
pub fn response() -> SignedSupporterKey {
  SignedSupporterKey {
    payload: PAYLOAD.to_string(),
    payload_sig: PAYLOAD_SIG.to_string(),
    instance_public_key: INSTANCE_PUBLIC_KEY.to_string(),
    nonce_sig: NONCE_SIG.to_string(),
  }
}

/// The seed of the private key of [ROOT]: 32 bytes of `0x07`. It is
/// why no release trusts the test root: anyone can sign with it.
const ROOT_SEED: [u8; 32] = [7; 32];

/// A CBOR text string of less than 256 bytes.
fn cbor_text(out: &mut Vec<u8>, text: &str) {
  let len = u8::try_from(text.len())
    .expect("fixture::mint takes texts of less than 256 bytes");
  if len < 24 {
    out.push(0x60 + len);
  } else {
    out.extend_from_slice(&[0x78, len]);
  }
  out.extend_from_slice(text.as_bytes());
}

/// A CBOR byte string of less than 24 bytes.
fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
  debug_assert!(bytes.len() < 24);
  out.push(0x40 + bytes.len() as u8);
  out.extend_from_slice(bytes);
}

/// Mints a supporter key under the test root [ROOT], as a buyer would
/// paste it: for a test which needs another app, name or tier than
/// [KEY] has. It is supporter since [SINCE] and covers the releases
/// up to [COVERS], like [KEY]. The same input mints the same key.
///
/// It verifies only where [ROOT] is trusted, which a test does and a
/// release never (`check_root_keys` refuses it).
pub fn mint(app: &str, name: &str, tier: Tier) -> String {
  // The key id and the instance key, made from what the key is for.
  let digest = sha2::Sha256::digest(
    format!("mogh_supporter fixture\n{app}\n{name}\n{tier}")
      .as_bytes(),
  );
  let id = &digest[..16];
  let instance_seed: [u8; 32] = sha2::Sha256::digest(digest).into();
  let instance_public_key =
    SigningKey::from_bytes(&instance_seed).verifying_key();

  let mut payload = vec![0xa8];
  cbor_text(&mut payload, "v");
  payload.push(0x01);
  cbor_text(&mut payload, "k");
  cbor_bytes(
    &mut payload,
    &data_encoding::HEXLOWER
      .decode(ROOT_KEY_ID.as_bytes())
      .expect("the id of the test root is hex"),
  );
  cbor_text(&mut payload, "i");
  cbor_bytes(&mut payload, id);
  for (key, value) in [
    ("a", app),
    ("n", name),
    ("t", tier.as_str()),
    ("s", SINCE),
    ("c", COVERS),
  ] {
    cbor_text(&mut payload, key);
    cbor_text(&mut payload, value);
  }

  // The root signs `P || I2`.
  let mut signed = payload.clone();
  signed.extend_from_slice(instance_public_key.as_bytes());
  let signature = SigningKey::from_bytes(&ROOT_SEED).sign(&signed);
  format!(
    "{}.{}.{}",
    BASE64URL_NOPAD.encode(&payload),
    BASE64URL_NOPAD.encode(&signature.to_bytes()),
    BASE64URL_NOPAD.encode(&instance_seed)
  )
}
