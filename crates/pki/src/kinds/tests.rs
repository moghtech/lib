use data_encoding::{BASE64, HEXLOWER};

use crate::{
  EncodedKeyPair, KeyAlgorithm, Pkcs8PrivateKey, PkiKind,
  SpkiPublicKey, WrongKeyAlgorithm, mutual::MutualNoiseHandshake,
  signature,
};

/// The public key string of raw bytes, as given: also ones the
/// checked constructors refuse.
fn unchecked_public_key(
  pki_kind: PkiKind,
  raw: &[u8; 32],
) -> SpkiPublicKey {
  // The spki der of either algorithm is a 12 byte header followed
  // by the key.
  let valid = EncodedKeyPair::generate(pki_kind).unwrap().public;
  let mut der = BASE64.decode(valid.as_bytes()).unwrap();
  assert_eq!(der.len(), 44);
  der[12..].copy_from_slice(raw);
  SpkiPublicKey::from(BASE64.encode(&der))
}

/// `signature` with its byte at `index` changed.
fn tamper(signature: &str, index: usize) -> String {
  let mut bytes = BASE64.decode(signature.as_bytes()).unwrap();
  bytes[index] ^= 0x01;
  BASE64.encode(&bytes)
}

#[test]
fn signature_verifies_with_the_public_key_alone() {
  let client = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let message = b"request";

  let signature = signature::sign(&client.private, message).unwrap();
  // 64 bytes, base64.
  assert_eq!(signature.len(), 88);
  assert_eq!(BASE64.decode(signature.as_bytes()).unwrap().len(), 64);
  // The verifier has the public key, and no key of its own.
  signature::verify(&client.public, message, &signature).unwrap();

  // Deterministic: the same key and message, the same signature.
  assert_eq!(
    signature::sign(&client.private, message).unwrap(),
    signature
  );
  // Another message (a nonce in it), another signature.
  assert_ne!(
    signature::sign(&client.private, b"request 2").unwrap(),
    signature
  );
}

#[test]
fn signature_rejects_tampered_signature() {
  let client = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let message = b"message";
  let signature = signature::sign(&client.private, message).unwrap();

  // Any byte of R or S.
  for index in [0, 31, 32, 63] {
    assert!(
      signature::verify(
        &client.public,
        message,
        &tamper(&signature, index)
      )
      .is_err(),
      "{index}"
    );
  }
  // Not 64 bytes, not base64, nothing.
  let bytes = BASE64.decode(signature.as_bytes()).unwrap();
  let mut longer = bytes.clone();
  longer.push(0);
  for wrong in [
    BASE64.encode(&bytes[..63]),
    BASE64.encode(&longer),
    BASE64.encode(&bytes[..32]),
    String::from("not base64!"),
    String::new(),
    format!(" {signature}"),
    format!("{signature}\n"),
  ] {
    assert!(
      signature::verify(&client.public, message, &wrong).is_err(),
      "{wrong:?}"
    );
  }
  // The signature itself is fine.
  signature::verify(&client.public, message, &signature).unwrap();
}

#[test]
fn signature_rejects_another_message_or_key() {
  let client = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let other = EncodedKeyPair::generate(PkiKind::Signature).unwrap();

  let signature =
    signature::sign(&client.private, b"request body").unwrap();
  assert!(
    signature::verify(&client.public, b"tampered body", &signature)
      .is_err()
  );
  assert!(
    signature::verify(&client.public, b"", &signature).is_err()
  );
  assert!(
    signature::verify(&other.public, b"request body", &signature)
      .is_err()
  );
  signature::verify(&client.public, b"request body", &signature)
    .unwrap();
}

/// The test vectors of RFC 8032 (section 7.1): secret key, public
/// key, message, signature.
#[test]
fn signature_matches_rfc8032() {
  let vectors = [
    (
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "af82",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
  ];
  let hex = |hex: &str| HEXLOWER.decode(hex.as_bytes()).unwrap();
  for (secret_key, public_key, message, expected) in vectors {
    let private = Pkcs8PrivateKey::from_raw_bytes(
      PkiKind::Signature,
      &hex(secret_key),
    )
    .unwrap();
    let public =
      private.compute_public_key(PkiKind::Signature).unwrap();
    assert_eq!(
      SpkiPublicKey::maybe_pem_to_raw_bytes(
        PkiKind::Signature,
        public.as_str()
      )
      .unwrap()
      .as_slice(),
      hex(public_key)
    );
    let message = hex(message);
    let signature = signature::sign(&private, &message).unwrap();
    assert_eq!(
      BASE64.decode(signature.as_bytes()).unwrap(),
      hex(expected)
    );
    signature::verify(&public, &message, &signature).unwrap();
  }
}

/// A signature has one accepted form. `S + L` (L the order of the
/// base point) satisfies the verification equation just like `S`:
/// accepting it would let anyone turn a signature into a second one
/// for the same message, which a "signature seen before" replay
/// check would not recognize.
#[test]
fn signature_rejects_a_non_canonical_s() {
  let client = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let message = b"message";
  let signature = signature::sign(&client.private, message).unwrap();
  let bytes = BASE64.decode(signature.as_bytes()).unwrap();

  // S + L, little endian. S < L < 2^253, so it fits.
  let order = HEXLOWER
    .decode(
      b"edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
    )
    .unwrap();
  let mut malleated = bytes.clone();
  let mut carry = 0u16;
  for (byte, order) in malleated[32..].iter_mut().zip(&order) {
    let sum = u16::from(*byte) + u16::from(*order) + carry;
    *byte = sum as u8;
    carry = sum >> 8;
  }
  assert_eq!(carry, 0);
  let err = signature::verify(
    &client.public,
    message,
    &BASE64.encode(&malleated),
  )
  .unwrap_err();
  assert!(format!("{err:#}").contains("not canonical"), "{err:#}");

  // L itself (a non canonical 0) and above are refused as such,
  // L - 1 is a canonical S (of another signature: it doesn't
  // verify).
  let mut s_is_order = bytes.clone();
  s_is_order[32..].copy_from_slice(&order);
  let mut s_is_max = bytes.clone();
  s_is_max[32..].fill(0xff);
  for non_canonical in [s_is_order.clone(), s_is_max] {
    let err = signature::verify(
      &client.public,
      message,
      &BASE64.encode(&non_canonical),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("not canonical"), "{err:#}");
  }
  let mut below_order = s_is_order;
  below_order[32] -= 1;
  let mut s_is_zero = bytes.clone();
  s_is_zero[32..].fill(0);
  for canonical in [below_order, s_is_zero] {
    let err = signature::verify(
      &client.public,
      message,
      &BASE64.encode(&canonical),
    )
    .unwrap_err();
    assert!(
      format!("{err:#}").contains("does not verify"),
      "{err:#}"
    );
  }
}

/// Nor does the base64 have a second form: the last character of a
/// 64 byte signature carries 4 unused bits, which must be zero, and
/// the padding is required.
#[test]
fn signature_has_one_base64_form() {
  let client = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let message = b"message";
  let signature = signature::sign(&client.private, message).unwrap();
  let (data, padding) = signature.split_at(86);
  assert_eq!(padding, "==");

  let last = data.chars().last().unwrap();
  // The same 2 bits of the signature, with an unused bit set.
  let alias = match last {
    'A' => 'B',
    'Q' => 'R',
    'g' => 'h',
    'w' => 'x',
    other => panic!("not a canonical last character: {other}"),
  };
  let aliased = format!("{}{alias}==", &data[..85]);
  assert_ne!(aliased, signature);
  for wrong in [aliased, data.to_string(), format!("{data}=")] {
    assert!(
      signature::verify(&client.public, message, &wrong).is_err(),
      "{wrong}"
    );
  }
}

/// What is told of a signature without the key and the message: it
/// has the form of one, which says nothing of whether it verifies.
#[test]
fn signature_well_formed() {
  let client = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let signature = signature::sign(&client.private, b"m").unwrap();
  assert!(signature::well_formed(&signature));
  // Any 64 bytes are, whatever they sign.
  assert!(signature::well_formed(&BASE64.encode(&[0u8; 64])));
  assert!(signature::well_formed(&tamper(&signature, 0)));

  let (data, _) = signature.split_at(86);
  let last = data.chars().last().unwrap();
  // An unused bit of the last character set: 88 characters which
  // decode nowhere.
  let alias = match last {
    'A' => 'B',
    'Q' => 'R',
    'g' => 'h',
    'w' => 'x',
    other => panic!("not a canonical last character: {other}"),
  };
  for wrong in [
    String::new(),
    String::from("AAAA"),
    // Without the padding, or half of it.
    data.to_string(),
    format!("{data}="),
    format!("{}{alias}==", &data[..85]),
    // 63 and 65 bytes.
    BASE64.encode(&[0u8; 63]),
    BASE64.encode(&[0u8; 65]),
    // 88 characters of something else.
    "!".repeat(88),
    format!(" {}", &signature[..87]),
    format!("{}\n", &signature[..87]),
    // The url safe alphabet.
    format!("-_{}", &signature[2..]),
    // 66 bytes, which are 88 characters too.
    BASE64.encode(&[0u8; 66]),
  ] {
    assert!(!signature::well_formed(&wrong), "{wrong:?}");
    assert!(
      signature::verify(&client.public, b"m", &wrong).is_err(),
      "{wrong:?}"
    );
  }
}

/// With a public key of low order, a signature can be made without
/// any private key. Those keys are refused, also when the string
/// was wrapped unchecked.
#[test]
fn signature_refuses_a_low_order_public_key() {
  use ed25519_dalek::Verifier as _;

  // The identity: R = identity and S = 0 satisfy the verification
  // equation for every message.
  let mut identity = [0u8; 32];
  identity[0] = 1;
  let mut forged = [0u8; 64];
  forged[0] = 1;
  let message = b"any message at all";
  // Plain verification accepts it...
  ed25519_dalek::VerifyingKey::from_bytes(&identity)
    .unwrap()
    .verify(message, &ed25519_dalek::Signature::from_bytes(&forged))
    .unwrap();
  // ...which is why the key is no key here.
  assert!(
    SpkiPublicKey::from_raw_bytes(PkiKind::Signature, &identity)
      .is_err()
  );
  let public_key =
    unchecked_public_key(PkiKind::Signature, &identity);
  let err =
    signature::verify(&public_key, message, &BASE64.encode(&forged))
      .unwrap_err();
  assert!(format!("{err:#}").contains("low order"), "{err:#}");

  // All 8 points of low order are refused.
  for point in curve25519_dalek::constants::EIGHT_TORSION {
    let raw = point.compress().to_bytes();
    let public_key = unchecked_public_key(PkiKind::Signature, &raw);
    let err = signature::verify(
      &public_key,
      message,
      &BASE64.encode(&forged),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("low order"), "{err:#}");
  }

  // The helper itself is sound: an honest key wrapped the same way
  // verifies.
  let client = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let raw = SpkiPublicKey::maybe_pem_to_raw_bytes(
    PkiKind::Signature,
    client.public.as_str(),
  )
  .unwrap();
  let public_key = unchecked_public_key(PkiKind::Signature, &raw);
  assert_eq!(public_key, client.public);
  let signature = signature::sign(&client.private, message).unwrap();
  signature::verify(&public_key, message, &signature).unwrap();
}

/// The keys of the two kinds are of different algorithms, and not
/// interchangeable: an X25519 key (as signing keys were before 3.0)
/// neither signs nor verifies, and an Ed25519 key completes no
/// handshake.
#[test]
fn keys_of_the_other_kind_are_refused() {
  let x25519 = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let ed25519 = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let not_ed25519 = WrongKeyAlgorithm {
    expected: KeyAlgorithm::Ed25519,
    found: KeyAlgorithm::X25519,
  };
  let not_x25519 = WrongKeyAlgorithm {
    expected: KeyAlgorithm::X25519,
    found: KeyAlgorithm::Ed25519,
  };

  let err = signature::sign(&x25519.private, b"m").unwrap_err();
  assert_eq!(err.downcast_ref(), Some(&not_ed25519), "{err:#}");

  let signature = signature::sign(&ed25519.private, b"m").unwrap();
  let err =
    signature::verify(&x25519.public, b"m", &signature).unwrap_err();
  assert_eq!(err.downcast_ref(), Some(&not_ed25519), "{err:#}");

  for handshake in [
    MutualNoiseHandshake::new_initiator(
      ed25519.private.as_str(),
      b"p",
    ),
    MutualNoiseHandshake::new_responder(
      ed25519.private.as_str(),
      b"p",
    ),
  ] {
    let err = handshake.err().unwrap();
    assert_eq!(err.downcast_ref(), Some(&not_x25519), "{err:#}");
  }
}

#[test]
fn mutual_handshake_exchanges_public_keys() {
  let client = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let server = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();

  let prologue = b"prologue";

  let mut initiator = MutualNoiseHandshake::new_initiator(
    client.private.as_str(),
    prologue,
  )
  .unwrap();
  let mut responder = MutualNoiseHandshake::new_responder(
    server.private.as_str(),
    prologue,
  )
  .unwrap();

  let m1 = initiator.next_message().unwrap();
  responder.read_message(&m1).unwrap();

  let m2 = responder.next_message().unwrap();
  initiator.read_message(&m2).unwrap();

  // Initiator has the responder public key after m2
  let server_public = crate::SpkiPublicKey::from_raw_bytes(
    PkiKind::Mutual,
    initiator.remote_public_key().unwrap(),
  )
  .unwrap();
  assert_eq!(server.public, server_public);

  let m3 = initiator.next_message().unwrap();
  responder.read_message(&m3).unwrap();

  // Responder has the initiator public key after m3
  let client_public = crate::SpkiPublicKey::from_raw_bytes(
    PkiKind::Mutual,
    responder.remote_public_key().unwrap(),
  )
  .unwrap();
  assert_eq!(client.public, client_public);
}

#[test]
fn mutual_handshake_rejects_tampered_message() {
  let client = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let server = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();

  let mut initiator = MutualNoiseHandshake::new_initiator(
    client.private.as_str(),
    b"prologue",
  )
  .unwrap();
  let mut responder = MutualNoiseHandshake::new_responder(
    server.private.as_str(),
    b"prologue",
  )
  .unwrap();

  let m1 = initiator.next_message().unwrap();
  responder.read_message(&m1).unwrap();

  let mut m2 = responder.next_message().unwrap();
  let last = m2.len() - 1;
  m2[last] ^= 0xff;
  assert!(initiator.read_message(&m2).is_err());
}

/// A DH which, once set to [FORGED], claims the all zero (low order)
/// public key and outputs the all zero shared secret, as the
/// honest side computes with that key. This is how a handshake is
/// completed "as" a low order key with no private key at all.
/// Keys generated or set otherwise behave normally.
struct ForgingDh {
  inner: Box<dyn snow::types::Dh>,
  forged: bool,
}

const FORGED: [u8; 32] = [0xaa; 32];

impl snow::types::Dh for ForgingDh {
  fn name(&self) -> &'static str {
    self.inner.name()
  }
  fn pub_len(&self) -> usize {
    self.inner.pub_len()
  }
  fn priv_len(&self) -> usize {
    self.inner.priv_len()
  }
  fn set(&mut self, privkey: &[u8]) {
    self.forged = privkey == FORGED;
    self.inner.set(privkey);
  }
  fn generate(
    &mut self,
    rng: &mut dyn snow::types::Random,
  ) -> Result<(), snow::Error> {
    self.forged = false;
    self.inner.generate(rng)
  }
  fn pubkey(&self) -> &[u8] {
    if self.forged {
      &[0; 32]
    } else {
      self.inner.pubkey()
    }
  }
  fn privkey(&self) -> &[u8] {
    self.inner.privkey()
  }
  fn dh(
    &self,
    pubkey: &[u8],
    out: &mut [u8],
  ) -> Result<(), snow::Error> {
    if self.forged {
      out[..32].fill(0);
      Ok(())
    } else {
      self.inner.dh(pubkey, out)
    }
  }
}

struct ForgingResolver;

impl snow::resolvers::CryptoResolver for ForgingResolver {
  fn resolve_rng(&self) -> Option<Box<dyn snow::types::Random>> {
    snow::resolvers::DefaultResolver.resolve_rng()
  }
  fn resolve_dh(
    &self,
    choice: &snow::params::DHChoice,
  ) -> Option<Box<dyn snow::types::Dh>> {
    let inner =
      snow::resolvers::DefaultResolver.resolve_dh(choice)?;
    Some(Box::new(ForgingDh {
      inner,
      forged: false,
    }))
  }
  fn resolve_hash(
    &self,
    choice: &snow::params::HashChoice,
  ) -> Option<Box<dyn snow::types::Hash>> {
    snow::resolvers::DefaultResolver.resolve_hash(choice)
  }
  fn resolve_cipher(
    &self,
    choice: &snow::params::CipherChoice,
  ) -> Option<Box<dyn snow::types::Cipher>> {
    snow::resolvers::DefaultResolver.resolve_cipher(choice)
  }
}

fn forging_builder() -> snow::Builder<'static> {
  snow::Builder::with_resolver(
    PkiKind::MUTUAL.parse().unwrap(),
    Box::new(ForgingResolver),
  )
}

#[test]
fn mutual_refuses_a_low_order_initiator_key() {
  let server = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();

  let mut forged = forging_builder()
    .local_private_key(&FORGED)
    .unwrap()
    .prologue(b"prologue")
    .unwrap()
    .build_initiator()
    .unwrap();
  let mut responder = MutualNoiseHandshake::new_responder(
    server.private.as_str(),
    b"prologue",
  )
  .unwrap();

  let mut buf = [0u8; 1024];
  let written = forged.write_message(&[], &mut buf).unwrap();
  responder.read_message(&buf[..written]).unwrap();
  let m2 = responder.next_message().unwrap();
  forged.read_message(&m2, &mut buf).unwrap();
  let written = forged.write_message(&[], &mut buf).unwrap();
  // The forged handshake completes as far as Noise goes...
  responder.read_message(&buf[..written]).unwrap();
  // ...but the claimed key is refused.
  let err = responder.remote_public_key().err().unwrap();
  assert!(format!("{err:#}").contains("low order"), "{err:#}");

  // The forging resolver itself is sound: an honest key through it
  // completes the handshake as itself.
  let client = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let client_private =
    client.private.as_raw_bytes(PkiKind::Mutual).unwrap();
  let mut honest = forging_builder()
    .local_private_key(&client_private)
    .unwrap()
    .prologue(b"prologue")
    .unwrap()
    .build_initiator()
    .unwrap();
  let mut responder = MutualNoiseHandshake::new_responder(
    server.private.as_str(),
    b"prologue",
  )
  .unwrap();
  let written = honest.write_message(&[], &mut buf).unwrap();
  responder.read_message(&buf[..written]).unwrap();
  let m2 = responder.next_message().unwrap();
  honest.read_message(&m2, &mut buf).unwrap();
  let written = honest.write_message(&[], &mut buf).unwrap();
  responder.read_message(&buf[..written]).unwrap();
  assert_eq!(
    crate::SpkiPublicKey::from_raw_bytes(
      PkiKind::Mutual,
      responder.remote_public_key().unwrap()
    )
    .unwrap(),
    client.public
  );
}
