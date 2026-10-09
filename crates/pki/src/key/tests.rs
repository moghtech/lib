use data_encoding::BASE64;
use der::Encode as _;

use super::{EncodedKeyPair, Pkcs8PrivateKey, SpkiPublicKey};
use crate::{PkiKind, WrongKeyAlgorithm};

const KINDS: [PkiKind; 2] = [PkiKind::Signature, PkiKind::Mutual];

/// The oid the keys of `pki_kind` are encoded with.
fn oid(pki_kind: PkiKind) -> &'static str {
  match pki_kind {
    PkiKind::Signature => "1.3.101.112",
    PkiKind::Mutual => "1.3.101.110",
  }
}

/// The kind whose keys are of the other algorithm.
fn other(pki_kind: PkiKind) -> PkiKind {
  match pki_kind {
    PkiKind::Signature => PkiKind::Mutual,
    PkiKind::Mutual => PkiKind::Signature,
  }
}

/// `err` refuses a key of the other algorithm than `used_as` uses.
#[track_caller]
fn assert_wrong_algorithm(err: &anyhow::Error, used_as: PkiKind) {
  assert_eq!(
    err.downcast_ref::<WrongKeyAlgorithm>(),
    Some(&WrongKeyAlgorithm {
      expected: used_as.key_algorithm(),
      found: other(used_as).key_algorithm(),
    }),
    "{err:#}"
  );
}

fn encode_pkcs8_b64(oid: &str, raw_private_key: &[u8]) -> String {
  let octet =
    der::asn1::OctetStringRef::new(raw_private_key).unwrap();
  let mut buf = [0u8; 128];
  let octet_der = octet.encode_to_slice(&mut buf).unwrap();
  let pki = pkcs8::PrivateKeyInfo {
    algorithm: spki::AlgorithmIdentifier {
      oid: spki::ObjectIdentifier::new_unwrap(oid),
      parameters: None,
    },
    private_key: octet_der,
    public_key: None,
  };
  let mut buf = [0u8; 128];
  BASE64.encode(pki.encode_to_slice(&mut buf).unwrap())
}

fn encode_spki_der(
  oid: &str,
  raw_public_key: &[u8],
  unused_bits: u8,
) -> Vec<u8> {
  let spki = spki::SubjectPublicKeyInfo {
    algorithm: spki::AlgorithmIdentifier::<der::AnyRef<'_>> {
      oid: spki::ObjectIdentifier::new_unwrap(oid),
      parameters: None,
    },
    subject_public_key: der::asn1::BitStringRef::new(
      unused_bits,
      raw_public_key,
    )
    .unwrap(),
  };
  let mut buf = [0u8; 128];
  spki.encode_to_slice(&mut buf).unwrap().to_vec()
}

#[test]
fn generate_private_key_raw_bytes_round_trip() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let raw = keys.private.as_raw_bytes(kind).unwrap();
    let restored =
      Pkcs8PrivateKey::from_raw_bytes(kind, &raw).unwrap();
    assert_eq!(keys.private.as_str(), restored.as_str());
  }
}

#[test]
fn generate_private_key_pem_round_trip() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let pem = keys.private.as_pem();
    let restored =
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, &pem).unwrap();
    assert_eq!(keys.private.as_str(), restored.as_str());
    assert_eq!(
      Pkcs8PrivateKey::maybe_raw_bytes(kind, &pem).unwrap(),
      keys.private.as_raw_bytes(kind).unwrap()
    );
  }
}

#[test]
fn generate_private_key_base64_round_trip() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    // Stored format is 64 character base64 der
    assert_eq!(keys.private.as_str().len(), 64);
    let restored = Pkcs8PrivateKey::from_maybe_raw_bytes(
      kind,
      keys.private.as_str(),
    )
    .unwrap();
    assert_eq!(keys.private.as_str(), restored.as_str());
  }
}

#[test]
fn private_key_constant_time_eq_matches_expected() {
  let keys = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let same = Pkcs8PrivateKey::from(keys.private.as_str().to_string());
  // Pkcs8PrivateKey has no Debug impl (it is secret
  // material), so use plain boolean assertions.
  assert!(keys.private == same);
  assert!(keys.private == keys.private.clone());

  let other = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  assert!(keys.private != other.private);

  // Differing lengths must compare unequal
  let truncated =
    Pkcs8PrivateKey::from(keys.private.as_str()[..32].to_string());
  assert!(keys.private != truncated);
}

#[test]
fn generate_public_key_pem_round_trip() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let pem = keys.public.as_pem();
    let restored = SpkiPublicKey::from_maybe_pem(kind, &pem).unwrap();
    assert_eq!(keys.public, restored);
  }
}

/// The stored public key names its algorithm: its first 16
/// characters tell the keys of the two kinds apart.
#[test]
fn public_key_strings_name_their_algorithm() {
  for (kind, prefix) in [
    (PkiKind::Signature, "MCowBQYDK2VwAyEA"),
    (PkiKind::Mutual, "MCowBQYDK2VuAyEA"),
  ] {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    assert_eq!(keys.public.as_str().len(), 60);
    assert!(
      keys.public.as_str().starts_with(prefix),
      "{}",
      keys.public
    );
  }
}

#[test]
fn generate_public_key_der_and_raw_bytes_round_trip() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let der =
      SpkiPublicKey::maybe_pem_to_der(keys.public.as_str()).unwrap();
    assert_eq!(
      SpkiPublicKey::from_der(kind, &der).unwrap(),
      keys.public
    );
    let raw = SpkiPublicKey::der_to_raw_bytes(kind, &der).unwrap();
    assert_eq!(
      SpkiPublicKey::from_raw_bytes(kind, &raw).unwrap(),
      keys.public
    );
    assert_eq!(
      SpkiPublicKey::maybe_pem_to_raw_bytes(
        kind,
        keys.public.as_str()
      )
      .unwrap(),
      raw
    );
  }
}

#[test]
fn public_key_derivation_is_consistent() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let computed = keys.private.compute_public_key(kind).unwrap();
    assert_eq!(keys.public, computed);
    assert_eq!(
      SpkiPublicKey::from_private_key(kind, keys.private.as_str())
        .unwrap(),
      keys.public
    );
    // Not as a key of the other kind: the algorithm is another.
    let err =
      keys.private.compute_public_key(other(kind)).unwrap_err();
    assert_wrong_algorithm(&err, other(kind));
  }
}

#[test]
fn from_private_key_derives_matching_public_key() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let restored =
      EncodedKeyPair::from_private_key(kind, keys.private.as_str())
        .unwrap();
    assert_eq!(keys.private.as_str(), restored.private.as_str());
    assert_eq!(keys.public, restored.public);
  }
}

#[test]
fn short_raw_private_key_is_zero_padded() {
  let mut expected = [0u8; 32];
  expected[..5].copy_from_slice(b"hello");
  for kind in KINDS {
    let key =
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, "hello").unwrap();
    assert_eq!(key.as_raw_bytes(kind).unwrap(), expected);
    assert_eq!(
      Pkcs8PrivateKey::maybe_raw_bytes(kind, "hello").unwrap(),
      expected
    );
    // Derivation must agree between the raw and pkcs8 forms
    let from_raw =
      SpkiPublicKey::from_private_key(kind, "hello").unwrap();
    let from_pkcs8 = key.compute_public_key(kind).unwrap();
    assert_eq!(from_raw, from_pkcs8);
  }
}

/// Raw key bytes name no algorithm: they are the key of whichever
/// kind they are used as, and so another key for each.
#[test]
fn raw_private_key_is_the_key_of_the_kind_it_is_used_as() {
  // 32 characters, as an onboarding key is.
  let raw = "O_abcdefghijklmnopqrstuvwxyz01_O";
  assert_eq!(raw.len(), 32);
  let signature =
    EncodedKeyPair::from_private_key(PkiKind::Signature, raw)
      .unwrap();
  let mutual =
    EncodedKeyPair::from_private_key(PkiKind::Mutual, raw).unwrap();
  assert_ne!(signature.public.as_str(), mutual.public.as_str());
  assert!(signature.private != mutual.private);

  // For signatures it is the Ed25519 seed.
  let seed: [u8; 32] = raw.as_bytes().try_into().unwrap();
  let expected = ed25519_dalek::SigningKey::from_bytes(&seed)
    .verifying_key()
    .to_bytes();
  assert_eq!(
    SpkiPublicKey::maybe_pem_to_raw_bytes(
      PkiKind::Signature,
      signature.public.as_str()
    )
    .unwrap(),
    expected
  );

  // Once encoded, the key names its algorithm.
  let err = EncodedKeyPair::from_private_key(
    PkiKind::Mutual,
    signature.private.as_str(),
  )
  .err()
  .unwrap();
  assert_wrong_algorithm(&err, PkiKind::Mutual);

  // One character more is no raw key.
  let longer = format!("{raw}x");
  for kind in KINDS {
    assert!(
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, &longer).is_err()
    );
  }
}

/// The example key of RFC 8410 (section 10.3), in the form
/// `openssl genpkey -algorithm ed25519` writes one.
#[test]
fn signature_keys_are_rfc8410_ed25519_keys() {
  let private = "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";
  let public =
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
  let private_pem = format!(
    "-----BEGIN PRIVATE KEY-----\n{private}\n-----END PRIVATE KEY-----\n"
  );
  let public_pem = format!(
    "-----BEGIN PUBLIC KEY-----\n{public}\n-----END PUBLIC KEY-----\n"
  );

  let keys = EncodedKeyPair::from_private_key(
    PkiKind::Signature,
    &private_pem,
  )
  .unwrap();
  assert_eq!(keys.private.as_str(), private);
  assert_eq!(keys.public.as_str(), public);
  assert_eq!(keys.private.as_pem(), private_pem);
  assert_eq!(keys.public.as_pem(), public_pem);
  assert_eq!(
    SpkiPublicKey::from_maybe_pem(PkiKind::Signature, &public_pem)
      .unwrap(),
    keys.public
  );
}

#[test]
fn private_key_rejects_oversized_input() {
  let too_long = "a".repeat(65);
  for kind in KINDS {
    assert!(
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, &too_long).is_err()
    );
    assert!(
      Pkcs8PrivateKey::maybe_raw_bytes(kind, &too_long).is_err()
    );
    assert!(
      Pkcs8PrivateKey::from_raw_bytes(kind, &[0u8; 33]).is_err()
    );
  }
}

#[test]
fn private_key_rejects_invalid_base64() {
  let invalid = "!".repeat(64);
  for kind in KINDS {
    assert!(
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, &invalid).is_err()
    );
    assert!(
      Pkcs8PrivateKey::maybe_raw_bytes(kind, &invalid).is_err()
    );
  }
}

#[test]
fn private_key_rejects_garbage_pem() {
  let pem =
    "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
  for kind in KINDS {
    assert!(
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, pem).is_err()
    );
    assert!(Pkcs8PrivateKey::maybe_raw_bytes(kind, pem).is_err());
  }
}

#[test]
fn private_key_rejects_truncated_der() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let mut der = BASE64.decode(keys.private.as_bytes()).unwrap();
    der.truncate(der.len() - 4);
    let truncated = BASE64.encode(&der);
    assert!(
      Pkcs8PrivateKey::raw_bytes(kind, truncated.as_bytes()).is_err()
    );
  }
}

/// A key names its algorithm, and is only a key of the kind using
/// it: an X25519 key is no signature key, an Ed25519 key no mutual
/// handshake key. Refused with an error callers can tell from a
/// malformed key.
#[test]
fn keys_of_the_other_algorithm_are_refused() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(other(kind)).unwrap();

    let private = keys.private.as_str();
    let private_pem = keys.private.as_pem();
    for input in [private, private_pem.as_str()] {
      assert_wrong_algorithm(
        &Pkcs8PrivateKey::from_maybe_raw_bytes(kind, input)
          .unwrap_err(),
        kind,
      );
      assert_wrong_algorithm(
        &Pkcs8PrivateKey::maybe_raw_bytes(kind, input).unwrap_err(),
        kind,
      );
      assert_wrong_algorithm(
        &EncodedKeyPair::from_private_key(kind, input).err().unwrap(),
        kind,
      );
      assert_wrong_algorithm(
        &SpkiPublicKey::from_private_key(kind, input).unwrap_err(),
        kind,
      );
    }
    assert_wrong_algorithm(
      &Pkcs8PrivateKey::raw_bytes(kind, private.as_bytes())
        .unwrap_err(),
      kind,
    );
    assert_wrong_algorithm(
      &keys.private.as_raw_bytes(kind).unwrap_err(),
      kind,
    );

    let public = keys.public.as_str();
    let public_pem = keys.public.as_pem();
    for input in [public, public_pem.as_str()] {
      assert_wrong_algorithm(
        &SpkiPublicKey::from_maybe_pem(kind, input).unwrap_err(),
        kind,
      );
      assert_wrong_algorithm(
        &SpkiPublicKey::maybe_pem_to_raw_bytes(kind, input)
          .unwrap_err(),
        kind,
      );
      assert_wrong_algorithm(
        &SpkiPublicKey::from_spec(kind, input).unwrap_err(),
        kind,
      );
    }
    let der = SpkiPublicKey::maybe_pem_to_der(public).unwrap();
    assert_wrong_algorithm(
      &SpkiPublicKey::from_der(kind, &der).unwrap_err(),
      kind,
    );
    assert_wrong_algorithm(
      &SpkiPublicKey::der_to_raw_bytes(kind, &der).unwrap_err(),
      kind,
    );

    // The message names both algorithms.
    for message in [
      SpkiPublicKey::from_maybe_pem(kind, public)
        .unwrap_err()
        .to_string(),
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, private)
        .unwrap_err()
        .to_string(),
    ] {
      assert!(
        message.contains(&kind.key_algorithm().to_string()),
        "{message}"
      );
      assert!(
        message.contains(&other(kind).key_algorithm().to_string()),
        "{message}"
      );
    }
  }
}

#[test]
fn keys_of_an_unsupported_algorithm_are_refused() {
  // X448 and Ed448: neither of the two, so no WrongKeyAlgorithm.
  for unsupported in ["1.3.101.111", "1.3.101.113"] {
    let private = encode_pkcs8_b64(unsupported, &[7u8; 32]);
    let public = encode_spki_der(unsupported, &[7u8; 32], 0);
    for kind in KINDS {
      for err in [
        Pkcs8PrivateKey::raw_bytes(kind, private.as_bytes())
          .unwrap_err(),
        Pkcs8PrivateKey::from_maybe_raw_bytes(kind, &private)
          .unwrap_err(),
        SpkiPublicKey::from_der(kind, &public).unwrap_err(),
        SpkiPublicKey::der_to_raw_bytes(kind, &public).unwrap_err(),
      ] {
        assert!(
          err.downcast_ref::<WrongKeyAlgorithm>().is_none(),
          "{err:#}"
        );
        assert!(
          format!("{err:#}").contains("not supported"),
          "{err:#}"
        );
      }
    }
  }
}

#[test]
fn private_key_rejects_oversized_inner_octet_without_panic() {
  // Well formed pkcs8 with a 48 byte inner key must
  // error (not panic) on conversion to raw bytes.
  for kind in KINDS {
    let b64 = encode_pkcs8_b64(oid(kind), &[7u8; 48]);
    assert!(
      Pkcs8PrivateKey::raw_bytes(kind, b64.as_bytes()).is_err()
    );
    assert!(
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, &b64).is_err()
    );
  }
}

#[test]
fn public_key_rejects_invalid_input() {
  for kind in KINDS {
    assert!(
      SpkiPublicKey::from_maybe_pem(kind, "not-base-64!").is_err()
    );
    assert!(
      SpkiPublicKey::from_maybe_pem(
        kind,
        "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
      )
      .is_err()
    );
    assert!(SpkiPublicKey::from_raw_bytes(kind, &[0u8; 16]).is_err());
    assert!(SpkiPublicKey::from_raw_bytes(kind, &[0u8; 33]).is_err());
  }
}

#[test]
fn public_key_rejects_truncated_der() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let mut der =
      SpkiPublicKey::maybe_pem_to_der(keys.public.as_str()).unwrap();
    der.truncate(der.len() - 4);
    assert!(SpkiPublicKey::from_der(kind, &der).is_err());
    assert!(SpkiPublicKey::der_to_raw_bytes(kind, &der).is_err());
  }
}

#[test]
fn public_key_rejects_wrong_length_bit_string() {
  for kind in KINDS {
    let der = encode_spki_der(oid(kind), &[7u8; 16], 0);
    assert!(SpkiPublicKey::from_der(kind, &der).is_err());
    assert!(SpkiPublicKey::der_to_raw_bytes(kind, &der).is_err());
  }
}

#[test]
fn public_key_rejects_unaligned_bit_string() {
  for kind in KINDS {
    // A real key, so only the unused bits are wrong with it.
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let raw = SpkiPublicKey::maybe_pem_to_raw_bytes(
      kind,
      keys.public.as_str(),
    )
    .unwrap();
    let der = encode_spki_der(oid(kind), &raw, 0);
    assert!(SpkiPublicKey::from_der(kind, &der).is_ok());
    let der = encode_spki_der(oid(kind), &raw, 3);
    let err = SpkiPublicKey::from_der(kind, &der).unwrap_err();
    assert!(format!("{err:#}").contains("byte-aligned"), "{err:#}");
    assert!(SpkiPublicKey::der_to_raw_bytes(kind, &der).is_err());
  }
}

#[test]
fn pem_wrapping_matches_rfc7468() {
  // A 96 character base64 body must wrap at 64 characters,
  // or pem_rfc7468 will reject it on re-parse.
  let long = SpkiPublicKey::from("A".repeat(96));
  let pem = long.as_pem();
  for line in pem.lines() {
    assert!(line.len() <= 64);
  }
  assert!(pem_rfc7468::decode_vec(pem.as_bytes()).is_ok());
}

#[test]
fn generate_write_and_load_round_trip() {
  for kind in KINDS {
    let dir = std::env::temp_dir().join(format!(
      "mogh_pki_test_{kind:?}_{}_{}",
      std::process::id(),
      std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
    ));
    let path = dir.join("test.key");

    let keys =
      EncodedKeyPair::generate_write_sync(kind, &path).unwrap();

    let private = Pkcs8PrivateKey::from_file(kind, &path).unwrap();
    assert_eq!(keys.private.as_str(), private.as_str());

    let public =
      SpkiPublicKey::from_file(kind, path.with_extension("pub"))
        .unwrap();
    assert_eq!(keys.public, public);

    // Loading with existing file must return the same pair
    let loaded =
      EncodedKeyPair::load_maybe_generate(kind, &path).unwrap();
    assert_eq!(keys.private.as_str(), loaded.private.as_str());
    assert_eq!(keys.public, loaded.public);

    let spec =
      format!("file:{}", path.with_extension("pub").display());
    assert_eq!(
      SpkiPublicKey::from_spec(kind, &spec).unwrap(),
      keys.public
    );

    // The key file of one kind is not loaded as the other, and not
    // replaced by a new key either.
    let before = std::fs::read(&path).unwrap();
    let err = EncodedKeyPair::load_maybe_generate(other(kind), &path)
      .err()
      .unwrap();
    assert_wrong_algorithm(&err, other(kind));
    assert_eq!(std::fs::read(&path).unwrap(), before);

    std::fs::remove_dir_all(&dir).ok();
  }
}

/// A fresh scratch directory per test (no tempfile dependency).
fn scratch_dir(name: &str) -> std::path::PathBuf {
  let dir = std::env::temp_dir().join(format!(
    "mogh_pki_{name}_{}_{}",
    std::process::id(),
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos()
  ));
  std::fs::create_dir_all(&dir).unwrap();
  dir
}

/// A path given without `file:` (or with it misspelled) would be
/// taken for the key itself, as up to 32 bytes are: one anybody can
/// derive from where key files usually are.
#[test]
fn a_private_key_spec_which_looks_like_a_path_is_refused() {
  use super::RotatableKeyPair;

  for pki_kind in [PkiKind::Signature, PkiKind::Mutual] {
    for spec in [
      "/config/keys/periphery.key",
      "/etc/cicada/keys/cperiphery.key",
      "./keys/device.key",
      "../device.key",
      "~/.config/komodo/core.key",
      " /config/keys/periphery.key",
      // The prefix in another case, not as it is taken.
      "File:/etc/cicada/key",
      "FILE:/k",
      // Whatever its length.
      "/a/path/which/is/longer/than/a/raw/key/could/be/device.key",
      // Made of what base64 is made of, at a length base64 has: a
      // path all the same, not what a random key reads like.
      "/config/keys/corekey",
      "/run/secrets/key",
      "/run/secrets/passkey",
      "/etc/app/key",
      "/var/lib/app/private",
      "/path/to/key",
      // Without anything a path starts with, by how it ends.
      "keys/device.key",
      "device.key",
      "config/core.PEM",
      "signing.pk8",
      // On Windows.
      "C:\\keys\\core",
      "c:/keys/core",
      ".\\core",
    ] {
      let err =
        match RotatableKeyPair::from_private_key_spec(pki_kind, spec)
        {
          Ok(_) => panic!("{spec:?} was taken as a key"),
          Err(e) => format!("{e:#}"),
        };
      assert!(
        err.contains("looks like a file path"),
        "{spec}: {err}"
      );
    }
    // A raw key (exactly 32 bytes) is still one, also with a slash
    // in it, or at its start where the rest reads as random base64
    // (as one in 64 of the keys `openssl rand -base64 24` prints
    // do).
    let random = format!("/{}", "aB3+".repeat(8).split_at(31).0);
    let raw = |start: &str| format!("{start:-<32}");
    for spec in [
      raw("a-raw-key"),
      raw("pass/word"),
      raw("file"),
      raw("files:1"),
      random,
      "/Zk8+Q2xw9AaQm5vR3hLp0Z7Tw1Yc2Ux".to_string(),
    ] {
      assert_eq!(spec.len(), 32);
      let pair =
        RotatableKeyPair::from_private_key_spec(pki_kind, &spec)
          .unwrap_or_else(|e| panic!("{spec:?}: {e:#}"));
      assert!(pair.path().is_none());
    }
    // The name of a file which is there (the tests run in the
    // directory of the crate) is never looked up as one: as a raw
    // key, it is too short.
    for spec in ["Cargo.toml", "key", ".key"] {
      let err =
        RotatableKeyPair::from_private_key_spec(pki_kind, spec)
          .err()
          .unwrap_or_else(|| panic!("{spec:?} was taken"));
      assert!(
        format!("{err:#}").contains("exactly 32 raw bytes"),
        "{spec}: {err:#}"
      );
    }
    // And so is a key in either pkcs8 form.
    let keys = EncodedKeyPair::generate(pki_kind).unwrap();
    for spec in [
      keys.private.as_str().to_string(),
      keys.private.as_pem().to_string(),
    ] {
      let pair =
        RotatableKeyPair::from_private_key_spec(pki_kind, &spec)
          .unwrap();
      assert_eq!(pair.load().public, keys.public);
    }
  }
}

/// A key given inline (the key of a node's own identity in its
/// config) is pkcs8 (pem, or base64 der) or exactly 32 raw bytes. A
/// shorter raw value is the key itself, zero padded, with no key
/// derivation: `changeme` or the node's name is a key anybody can
/// find from its public key, so it is refused, with an error naming
/// the accepted forms and never the value. The entry points of keys
/// given on purpose as raw values (onboarding and recovery keys,
/// [Pkcs8PrivateKey::from_maybe_raw_bytes]) still take them.
#[test]
fn a_short_raw_inline_key_is_refused() {
  use super::RotatableKeyPair;

  for kind in KINDS {
    for short in [
      "changeme",
      "komodo-periphery-1",
      "a",
      // 31 bytes.
      "0123456789012345678901234567890",
    ] {
      for err in [
        RotatableKeyPair::from_private_key_spec(kind, short)
          .err()
          .map(|e| format!("{e:#}")),
        EncodedKeyPair::from_inline_key(kind, short)
          .err()
          .map(|e| format!("{e:#}")),
        Pkcs8PrivateKey::from_inline_key(kind, short)
          .err()
          .map(|e| format!("{e:#}")),
      ] {
        let err =
          err.unwrap_or_else(|| panic!("{short:?} was taken"));
        assert!(err.contains("shorter than 32 bytes"), "{err}");
        assert!(
          err.contains("pkcs8 encoded (pem, or base64 der)")
            && err.contains("exactly 32 raw bytes"),
          "{err}"
        );
        // (Not checked for a one letter value: messages have letters.)
        assert!(short.len() < 2 || !err.contains(short), "{err}");
      }
      // Onboarding and recovery keys are still read as given.
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, short).unwrap();
      EncodedKeyPair::from_private_key(kind, short).unwrap();
    }

    // Exactly 32 raw bytes, as given (a trailing line break is a
    // byte of the key).
    let raw = "0123456789012345678901234567890\n";
    assert_eq!(raw.len(), 32);
    let pair =
      RotatableKeyPair::from_private_key_spec(kind, raw).unwrap();
    assert_eq!(
      pair.load().public,
      EncodedKeyPair::from_private_key(kind, raw).unwrap().public
    );
    assert_eq!(
      EncodedKeyPair::from_inline_key(kind, raw).unwrap().public,
      pair.load().public
    );

    // Pkcs8, in either form, whatever its length.
    let keys = EncodedKeyPair::generate(kind).unwrap();
    for key in
      [keys.private.as_str().to_string(), keys.private.as_pem()]
    {
      assert_eq!(
        Pkcs8PrivateKey::from_inline_key(kind, &key).unwrap(),
        keys.private
      );
      assert_eq!(
        RotatableKeyPair::from_private_key_spec(kind, &key)
          .unwrap()
          .load()
          .public,
        keys.public
      );
    }

    // Longer, and no pkcs8: the accepted forms, never the value.
    let long = "this-is-not-a-key-but-a-passphrase-of-some-length";
    for err in [
      RotatableKeyPair::from_private_key_spec(kind, long)
        .err()
        .map(|e| format!("{e:#}")),
      Pkcs8PrivateKey::from_inline_key(kind, long)
        .err()
        .map(|e| format!("{e:#}")),
    ] {
      let err = err.expect("a passphrase was taken");
      assert!(
        err.contains("pkcs8 encoded (pem, or base64 der)")
          && err.contains("exactly 32 raw bytes"),
        "{err}"
      );
      assert!(!err.contains(long), "{err}");
      assert!(!err.contains("32 characters or less"), "{err}");
    }

    // A path, whatever its length, also for a chosen key.
    let path = "/etc/komodo/keys/periphery-01.key";
    let err = Pkcs8PrivateKey::from_inline_key(kind, path)
      .err()
      .map(|e| format!("{e:#}"))
      .expect("a path was taken");
    assert!(err.contains("looks like a file path"), "{err}");
    assert!(!err.contains(path), "{err}");
    // A key of the other algorithm says so.
    let other_keys = EncodedKeyPair::generate(other(kind)).unwrap();
    let err = Pkcs8PrivateKey::from_inline_key(
      kind,
      other_keys.private.as_str(),
    )
    .unwrap_err();
    assert_wrong_algorithm(&err, kind);
  }
}

/// A `file:` spec as an environment variable or a config line gives
/// it: whitespace around the spec, or after `file:`, is no part of
/// the path. Taken with it, the path named another file, where a
/// new key was generated in place of the configured one.
#[test]
fn a_file_spec_is_read_without_surrounding_whitespace() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("trimmed_spec");
  for kind in KINDS {
    let key_path = dir.join(format!("{kind:?}.key"));
    let keys =
      EncodedKeyPair::generate_write_sync(kind, &key_path).unwrap();
    let path = key_path.display();
    for spec in [
      format!("file:{path} "),
      format!("file:{path}\r"),
      format!("file: {path}"),
      format!(" file:{path}\r\n"),
      format!("\tfile:\t{path}\n"),
    ] {
      let pair = RotatableKeyPair::from_private_key_spec(kind, &spec)
        .unwrap_or_else(|e| panic!("{spec:?}: {e:#}"));
      assert_eq!(pair.load().public, keys.public, "{spec:?}");
      // Resolved: the same file (temp dirs may sit behind a link).
      assert_eq!(
        pair.path(),
        Some(std::fs::canonicalize(&*key_path).unwrap().as_path())
      );
      assert_eq!(
        super::key_spec_path(&spec)
          .unwrap()
          .map(|path| path.display().to_string()),
        Some(path.to_string())
      );
    }
    let public = dir.join(format!("{kind:?}.pub"));
    let public = public.display();
    for spec in
      [format!("file:{public} "), format!(" file: {public}\n")]
    {
      assert_eq!(
        SpkiPublicKey::from_spec(kind, &spec)
          .unwrap_or_else(|e| panic!("{spec:?}: {e:#}")),
        keys.public
      );
    }
  }
  // No key was generated anywhere else.
  let mut names = std::fs::read_dir(&dir)
    .unwrap()
    .map(|entry| entry.unwrap().file_name())
    .collect::<Vec<_>>();
  names.sort();
  assert_eq!(
    names,
    ["Mutual.key", "Mutual.pub", "Signature.key", "Signature.pub"]
  );
  // An inline key is not a spec of a file.
  assert!(super::key_spec_path(" MC4CAQ ").unwrap().is_none());
  std::fs::remove_dir_all(dir).unwrap();
}

/// `file:` naming no file is an error saying so, never a key file
/// at an empty or blank path.
#[test]
fn a_file_spec_without_a_path_is_refused() {
  use super::RotatableKeyPair;

  for spec in ["file:", "file: ", " file:\r\n", "file:\t"] {
    for kind in KINDS {
      let err =
        match RotatableKeyPair::from_private_key_spec(kind, spec) {
          Ok(_) => panic!("{spec:?} was taken"),
          Err(e) => format!("{e:#}"),
        };
      assert!(err.contains("names no key file"), "{spec:?}: {err}");
      let err = SpkiPublicKey::from_spec(kind, spec)
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_else(|| panic!("{spec:?} was taken"));
      assert!(err.contains("names no key file"), "{spec:?}: {err}");
    }
    assert!(super::key_spec_path(spec).is_err());
  }
}

/// The public key is written beside the private key, at
/// `path.with_extension("pub")`: for a private key path ending in
/// `.pub`, the private key file itself, which then held only the
/// public key. Refused wherever a private key is written, or loaded
/// to be used (in any case, as case insensitive filesystems take
/// it), and nothing is written.
#[tokio::test]
async fn a_private_key_path_ending_in_pub_is_refused() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("pub_extension");
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    for name in ["device.pub", "device.PUB", "device.Pub"] {
      let path = dir.join(name);
      let spec = format!("file:{}", path.display());
      for err in [
        RotatableKeyPair::from_private_key_spec(kind, &spec)
          .err()
          .map(|e| format!("{e:#}")),
        EncodedKeyPair::load_maybe_generate(kind, &path)
          .err()
          .map(|e| format!("{e:#}")),
        EncodedKeyPair::generate_write_sync(kind, &path)
          .err()
          .map(|e| format!("{e:#}")),
        EncodedKeyPair::generate_write_async(kind, &path)
          .await
          .err()
          .map(|e| format!("{e:#}")),
        keys
          .private
          .write_pem_sync(&path)
          .err()
          .map(|e| format!("{e:#}")),
        keys
          .private
          .write_pem_async(&path)
          .await
          .err()
          .map(|e| format!("{e:#}")),
      ] {
        let err = err.unwrap_or_else(|| panic!("{name}: taken"));
        assert!(err.contains("ends in `.pub`"), "{name}: {err}");
      }
      assert!(!path.exists(), "{name}");
      // A key file there already is refused all the same (a
      // rotation would write its public key over it), and left as
      // it is.
      std::fs::write(&path, keys.private.as_pem()).unwrap();
      for err in [
        RotatableKeyPair::from_private_key_spec(kind, &spec)
          .err()
          .map(|e| format!("{e:#}")),
        EncodedKeyPair::load_maybe_generate(kind, &path)
          .err()
          .map(|e| format!("{e:#}")),
      ] {
        let err = err.unwrap_or_else(|| panic!("{name}: taken"));
        assert!(err.contains("ends in `.pub`"), "{name}: {err}");
      }
      assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        keys.private.as_pem()
      );
      // Reading it is fine, eg. to compute its public key.
      assert_eq!(
        EncodedKeyPair::from_file(kind, &path).unwrap().public,
        keys.public
      );
      std::fs::remove_file(&path).unwrap();
    }
    // `.pub` elsewhere in the name is no public key file name.
    let path = dir.join(format!("{kind:?}.pub.key"));
    let pair = RotatableKeyPair::from_private_key_spec(
      kind,
      &format!("file:{}", path.display()),
    )
    .unwrap();
    assert_eq!(
      SpkiPublicKey::from_file(kind, path.with_extension("pub"))
        .unwrap(),
      pair.load().public
    );
  }
  std::fs::remove_dir_all(dir).unwrap();
}

/// A pair rotates within its algorithm, so a rotation file beside
/// the key file (`<key>.next`, `<key>.old`) holding a key of the
/// other algorithm was left by a rotation of an earlier key (one
/// moved away for a new key of this kind), and no rotation of this
/// key can resume or finish with it there. Refused at load as a key
/// of the other algorithm, naming the file, which is left as it is.
/// Checked before a key is generated, so a refused start writes no
/// key.
#[test]
fn a_rotation_file_of_the_other_algorithm_is_refused() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotation_file_algorithm");
  for kind in KINDS {
    let path = dir.join(format!("{kind:?}.key"));
    let spec = format!("file:{}", path.display());
    for suffix in [".next", ".old"] {
      let file = super::sibling(&path, suffix);
      let left = EncodedKeyPair::generate(other(kind)).unwrap();
      left.private.write_pem_sync(&file).unwrap();
      // Without a key file yet, then with one.
      for live in [false, true] {
        if live {
          EncodedKeyPair::generate_write_sync(kind, &path).unwrap();
        }
        let err =
          RotatableKeyPair::from_private_key_spec(kind, &spec)
            .err()
            .unwrap_or_else(|| panic!("{suffix}, {live}: taken"));
        assert_wrong_algorithm(&err, kind);
        let message = format!("{err:#}");
        assert!(message.contains("left by a rotation"), "{message}");
        assert!(
          message.contains(&format!("{kind:?}.key{suffix}")),
          "{message}"
        );
        assert!(
          Pkcs8PrivateKey::from_file(other(kind), &file).unwrap()
            == left.private
        );
        assert_eq!(path.exists(), live, "{suffix}");
      }
      std::fs::remove_file(&file).unwrap();
      // Moved away, the key loads.
      RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
      std::fs::remove_file(&path).unwrap();
    }
    // A rotation file of the same algorithm is one of this key's,
    // left to the rotation (a candidate to resume), and so is one
    // which holds no key.
    let pair =
      RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
    let candidate =
      pair.begin_rotation().unwrap().candidate().clone();
    std::fs::write(super::sibling(&path, ".old"), "garbage").unwrap();
    let reloaded =
      RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
    assert!(reloaded.rotation_pending());
    std::fs::remove_file(super::sibling(&path, ".old")).unwrap();
    assert_eq!(
      reloaded.begin_rotation().unwrap().candidate().public,
      candidate.public
    );
  }
  std::fs::remove_dir_all(dir).unwrap();
}

/// Whether the key was generated at load, as nothing can know it
/// yet (eg. a server it has to be registered with).
#[tokio::test]
async fn a_pair_tells_whether_its_key_was_generated() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("generated");
  for kind in KINDS {
    let spec =
      format!("file:{}", dir.join(format!("{kind:?}.key")).display());
    let pair =
      RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
    assert!(pair.generated());
    // What the load did, whatever happens to the key after.
    pair.rotate().await.unwrap();
    assert!(pair.generated());
    // The next load finds the key file.
    let reloaded =
      RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
    assert!(!reloaded.generated());
    assert_eq!(reloaded.load().public, pair.load().public);
    // A key given inline is never generated.
    let inline = RotatableKeyPair::from_private_key_spec(
      kind,
      reloaded.load().private.as_str(),
    )
    .unwrap();
    assert!(!inline.generated());
  }
  std::fs::remove_dir_all(dir).unwrap();
}

/// A key file another process created between the look for one and
/// the write of a new one (two processes starting at once on the
/// same missing key file): its key is loaded, never replaced, so no
/// process runs on a key which is no longer on disk.
#[test]
fn a_key_file_created_meanwhile_is_loaded_not_replaced() {
  let dir = scratch_dir("created_meanwhile");
  for kind in KINDS {
    let path = dir.join(format!("{kind:?}.key"));
    // Found missing ...
    assert!(
      EncodedKeyPair::load_existing(kind, &path)
        .unwrap()
        .is_none()
    );
    // ... then created by the other process, which writes its
    // public key file next.
    let winner = EncodedKeyPair::generate(kind).unwrap();
    winner.private.write_pem_sync(&path).unwrap();
    let (keys, generated) =
      EncodedKeyPair::generate_missing(kind, &path).unwrap();
    assert!(!generated);
    assert_eq!(keys.public, winner.public);
    assert!(keys.private == winner.private);
    assert!(
      Pkcs8PrivateKey::from_file(kind, &path).unwrap()
        == winner.private
    );
    assert!(!path.with_extension("pub").exists());
  }
  // Nothing else was written: no public key file, no temp file.
  let mut names = std::fs::read_dir(&dir)
    .unwrap()
    .map(|entry| entry.unwrap().file_name())
    .collect::<Vec<_>>();
  names.sort();
  assert_eq!(names, ["Mutual.key", "Signature.key"]);
  std::fs::remove_dir_all(dir).unwrap();
}

/// Processes starting at once on the same missing key file (threads
/// here, racing on the file system the same way) end up on one key,
/// the one on disk, and only the start which wrote it tells it
/// generated it.
#[test]
fn starts_racing_on_a_missing_key_file_share_one_key() {
  use std::sync::{Arc, Barrier};

  use super::RotatableKeyPair;

  const STARTS: usize = 8;
  /// Runs `start` on `STARTS` threads at once.
  fn race<T: Send + 'static>(
    start: impl Fn() -> T + Send + Sync + 'static,
  ) -> Vec<T> {
    let start = Arc::new(start);
    let barrier = Arc::new(Barrier::new(STARTS));
    let threads = (0..STARTS)
      .map(|_| {
        let (start, barrier) = (start.clone(), barrier.clone());
        std::thread::spawn(move || {
          barrier.wait();
          start()
        })
      })
      .collect::<Vec<_>>();
    threads
      .into_iter()
      .map(|thread| thread.join().unwrap())
      .collect()
  }

  let dir = scratch_dir("racing_starts");
  for kind in KINDS {
    let path = dir.join(format!("{kind:?}.key"));
    let spec = format!("file:{}", path.display());
    let started = race(move || {
      let pair =
        RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
      (pair.load().public.clone(), pair.generated())
    });
    let on_disk = EncodedKeyPair::from_file(kind, &path).unwrap();
    for (public, _) in &started {
      assert_eq!(*public, on_disk.public);
    }
    let generated =
      started.iter().filter(|(_, generated)| *generated).count();
    assert_eq!(generated, 1);
    assert_eq!(
      SpkiPublicKey::from_file(kind, path.with_extension("pub"))
        .unwrap(),
      on_disk.public
    );

    let path = dir.join(format!("{kind:?}-loaded.key"));
    let loaded = race({
      let path = path.clone();
      move || {
        EncodedKeyPair::load_maybe_generate(kind, &path)
          .unwrap()
          .public
      }
    });
    let on_disk = EncodedKeyPair::from_file(kind, &path).unwrap();
    for public in &loaded {
      assert_eq!(*public, on_disk.public);
    }
  }
  std::fs::remove_dir_all(dir).unwrap();
}

/// A symlink at the key path to a file which does not exist is
/// refused, the link and where it points left alone: a new key file
/// is created, never written over anything at the path (as a race
/// with another start could have it), nor through a link.
#[cfg(unix)]
#[test]
fn a_symlink_to_a_missing_key_file_is_refused() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("dangling_link");
  for kind in KINDS {
    let target = dir.join(format!("{kind:?}-target.key"));
    let path = dir.join(format!("{kind:?}.key"));
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let spec = format!("file:{}", path.display());
    for err in [
      RotatableKeyPair::from_private_key_spec(kind, &spec)
        .err()
        .map(|e| format!("{e:#}")),
      EncodedKeyPair::load_maybe_generate(kind, &path)
        .err()
        .map(|e| format!("{e:#}")),
    ] {
      let err = err.unwrap_or_else(|| panic!("{kind:?}: generated"));
      assert!(
        err.contains("is a symlink to a file which does not exist"),
        "{err}"
      );
    }
    assert!(path.is_symlink());
    assert!(!target.exists());
    assert!(!path.with_extension("pub").exists());
    // With the key file it points to in place, the key loads
    // through the link, as before.
    let keys =
      EncodedKeyPair::generate_write_sync(kind, &target).unwrap();
    let pair =
      RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
    assert_eq!(pair.load().public, keys.public);
    assert!(!pair.generated());
  }
  std::fs::remove_dir_all(dir).unwrap();
}

/// A key file reached through a symlink (eg. a key path in the
/// config directory pointing into a persistent volume) is rotated
/// where the link points: the link stays, the file it points to holds
/// the new key, and the rotation files and the public key file are
/// written beside that file. A rotation used to replace the link with
/// a file of its own, leaving the previous key where the link pointed:
/// recreated (re-provisioning), the link brought the retired key back.
#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_key_file_is_rotated_where_the_link_points() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("symlinked_key");
  let volume = dir.join("volume");
  let config = dir.join("config");
  std::fs::create_dir_all(&volume).unwrap();
  std::fs::create_dir_all(&config).unwrap();
  let kind = PkiKind::Signature;
  let target = volume.join("device.key");
  let original =
    EncodedKeyPair::generate_write_sync(kind, &target).unwrap();
  let link = config.join("device.key");
  // A relative link, as `ln -s` makes them.
  let points_to = std::path::Path::new("../volume/device.key");
  std::os::unix::fs::symlink(points_to, &link).unwrap();
  let link_intact = || {
    assert!(link.is_symlink(), "the link was replaced");
    assert_eq!(std::fs::read_link(&link).unwrap(), points_to);
  };
  let spec = format!("file:{}", link.display());
  let pair =
    RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
  assert_eq!(pair.load().public, original.public);
  assert!(!pair.generated());
  // The file the link points to, absolute.
  let resolved = std::fs::canonicalize(&target).unwrap();
  assert_eq!(pair.path(), Some(resolved.as_path()));

  // In one step.
  let rotated = pair.rotate().await.unwrap();
  assert_ne!(rotated, original.public);
  link_intact();
  assert_eq!(
    EncodedKeyPair::from_file(kind, &target).unwrap().public,
    rotated
  );
  assert_eq!(
    SpkiPublicKey::from_file(kind, volume.join("device.pub"))
      .unwrap(),
    rotated
  );
  // A restart through the link loads it.
  let reloaded =
    RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
  assert_eq!(reloaded.load().public, rotated);

  // In two phases.
  let rotation = pair.begin_rotation().unwrap();
  let candidate = rotation.candidate().clone();
  assert!(volume.join("device.key.next").exists());
  rotation.commit().unwrap();
  link_intact();
  assert_eq!(
    EncodedKeyPair::from_file(kind, &link).unwrap().public,
    candidate.public
  );
  assert_eq!(pair.retired().unwrap().unwrap().public, rotated);
  assert!(volume.join("device.key.old").exists());
  pair.finish_rotation().unwrap();
  assert!(!volume.join("device.key.old").exists());
  assert!(!pair.rotation_pending());

  // Nothing was written beside the link.
  let names = std::fs::read_dir(&config)
    .unwrap()
    .map(|entry| entry.unwrap().file_name())
    .collect::<Vec<_>>();
  assert_eq!(names, ["device.key"]);
  std::fs::remove_dir_all(dir).unwrap();
}

/// A symlink to a key file named `*.pub` is refused as such a path
/// is: the public key file written beside it would be the key file.
#[cfg(unix)]
#[test]
fn a_symlink_to_a_key_file_named_pub_is_refused() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("link_to_pub");
  let kind = PkiKind::Signature;
  let keys = EncodedKeyPair::generate(kind).unwrap();
  let target = dir.join("device.pub");
  std::fs::write(&target, keys.private.as_pem()).unwrap();
  let link = dir.join("device.key");
  std::os::unix::fs::symlink(&target, &link).unwrap();
  let err = RotatableKeyPair::from_private_key_spec(
    kind,
    &format!("file:{}", link.display()),
  )
  .err()
  .expect("a key file named .pub was taken");
  assert!(format!("{err:#}").contains("ends in `.pub`"), "{err:#}");
  assert_eq!(
    Pkcs8PrivateKey::from_file(kind, &target).unwrap(),
    keys.private
  );
  std::fs::remove_dir_all(dir).unwrap();
}

/// The rotation files an earlier version left beside a symlinked key
/// file (it rotated the link's path) are refused, naming where they
/// belong now: ignored, a candidate the caller registered, or a
/// retired key waiting to be revoked, would stay registered.
#[cfg(unix)]
#[test]
fn rotation_files_beside_a_symlinked_key_file_are_refused() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("link_rotation_files");
  let volume = dir.join("volume");
  std::fs::create_dir_all(&volume).unwrap();
  let kind = PkiKind::Signature;
  let target = volume.join("device.key");
  EncodedKeyPair::generate_write_sync(kind, &target).unwrap();
  let link = dir.join("device.key");
  std::os::unix::fs::symlink(&target, &link).unwrap();
  let spec = format!("file:{}", link.display());
  for suffix in [".next", ".old"] {
    let left = dir.join(format!("device.key{suffix}"));
    let candidate = EncodedKeyPair::generate(kind).unwrap();
    candidate.private.write_pem_sync(&left).unwrap();
    let err = RotatableKeyPair::from_private_key_spec(kind, &spec)
      .err()
      .unwrap_or_else(|| panic!("{suffix} beside the link ignored"));
    let err = format!("{err:#}");
    let belongs = std::fs::canonicalize(&volume)
      .unwrap()
      .join(format!("device.key{suffix}"));
    assert!(err.contains(&format!("{left:?}")), "{err}");
    assert!(err.contains(&format!("{belongs:?}")), "{err}");
    // Moved where it belongs, the pair loads (and sees it).
    std::fs::rename(&left, &belongs).unwrap();
    let pair =
      RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
    assert!(pair.rotation_pending());
    std::fs::remove_file(&belongs).unwrap();
  }
  std::fs::remove_dir_all(dir).unwrap();
}

/// [SpkiPublicKey::from_spec] covers what apps read a list of
/// public key specs for (eg. the Periphery keys Komodo Core
/// accepts): a key file in pem or base64 der, or the key inline in
/// either form. An error names the file it is about.
#[test]
fn public_key_specs_read_files_and_inline_keys() {
  let dir = scratch_dir("public_key_spec");
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let pem = dir.join(format!("{kind:?}.pem.pub"));
    std::fs::write(&pem, keys.public.as_pem()).unwrap();
    let der = dir.join(format!("{kind:?}.der.pub"));
    std::fs::write(&der, format!("{}\n", keys.public)).unwrap();
    for spec in [
      format!("file:{}", pem.display()),
      format!("file:{}", der.display()),
      keys.public.to_string(),
      format!(" {}\n", keys.public),
      keys.public.as_pem(),
    ] {
      assert_eq!(
        SpkiPublicKey::from_spec(kind, &spec)
          .unwrap_or_else(|e| panic!("{spec:?}: {e:#}")),
        keys.public
      );
    }
    let garbage = dir.join("garbage.pub");
    std::fs::write(&garbage, "not a key").unwrap();
    let missing = dir.join("missing.pub");
    for (file, name) in
      [(&garbage, "garbage.pub"), (&missing, "missing.pub")]
    {
      let spec = format!("file:{}", file.display());
      let err = SpkiPublicKey::from_spec(kind, &spec).unwrap_err();
      let err = format!("{err:#}");
      assert!(err.contains(name), "{err}");
    }
    assert_wrong_algorithm(
      &SpkiPublicKey::from_spec(
        other(kind),
        &keys.public.to_string(),
      )
      .unwrap_err(),
      other(kind),
    );
  }
  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rotation_commit_swaps_the_live_key_and_keeps_the_old_one() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_commit");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();
  assert!(pair.retired().unwrap().is_none());

  assert!(!pair.rotation_pending());
  let rotation = pair.begin_rotation().unwrap();
  assert!(pair.rotation_pending());
  let candidate = rotation.candidate().clone();
  assert_ne!(candidate.public, original.public);
  // Nothing live changed before commit.
  assert_eq!(pair.load().public, original.public);
  assert!(dir.join("test.key.next").exists());
  assert!(
    Pkcs8PrivateKey::from_file(PkiKind::Signature, &path).unwrap()
      == original.private
  );

  rotation.commit().unwrap();
  // The candidate is live, on disk and in memory; the previous
  // key waits for revocation.
  assert_eq!(pair.load().public, candidate.public);
  assert!(
    Pkcs8PrivateKey::from_file(PkiKind::Signature, &path).unwrap()
      == candidate.private
  );
  assert_eq!(
    SpkiPublicKey::from_file(
      PkiKind::Signature,
      dir.join("test.pub")
    )
    .unwrap(),
    candidate.public
  );
  assert!(!dir.join("test.key.next").exists());
  let retired = pair.retired().unwrap().unwrap();
  assert_eq!(retired.public, original.public);
  // Until finished, no new rotation may start.
  assert!(pair.begin_rotation().is_err());

  pair.finish_rotation().unwrap();
  assert!(pair.retired().unwrap().is_none());
  assert!(!pair.rotation_pending());
  // Idempotent.
  pair.finish_rotation().unwrap();

  // A restart loads the committed key.
  let reloaded = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  assert_eq!(reloaded.load().public, candidate.public);

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rotation_resumes_and_aborts_a_candidate() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_resume");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();

  // A candidate left behind (crash before commit) is resumed, not
  // replaced: the caller may already have registered it.
  let first = pair.begin_rotation().unwrap();
  let candidate = first.candidate().clone();
  drop(first);
  let resumed = pair.begin_rotation().unwrap();
  assert_eq!(resumed.candidate().public, candidate.public);
  assert_eq!(resumed.previous().public, original.public);

  // Abort leaves the live key alone and drops the candidate.
  resumed.abort().unwrap();
  assert!(!dir.join("test.key.next").exists());
  assert_eq!(pair.load().public, original.public);
  assert!(
    Pkcs8PrivateKey::from_file(PkiKind::Signature, &path).unwrap()
      == original.private
  );

  // An unreadable leftover is replaced.
  std::fs::write(dir.join("test.key.next"), "garbage").unwrap();
  let fresh = pair.begin_rotation().unwrap();
  assert_ne!(fresh.candidate().public, candidate.public);
  fresh.abort().unwrap();

  // Not file backed: no rotation.
  let inline = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    original.private.as_str(),
  )
  .unwrap();
  assert!(!inline.rotatable());
  assert!(inline.begin_rotation().is_err());
  assert!(inline.retired().unwrap().is_none());
  inline.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

// ---- Empty and well known private keys ----

#[test]
fn empty_private_key_is_refused_everywhere() {
  use super::RotatableKeyPair;
  use crate::mutual::MutualNoiseHandshake;

  for empty in ["", " ", "\n", "\t\r\n"] {
    for kind in KINDS {
      assert!(
        Pkcs8PrivateKey::from_maybe_raw_bytes(kind, empty).is_err()
      );
      assert!(Pkcs8PrivateKey::maybe_raw_bytes(kind, empty).is_err());
      assert!(EncodedKeyPair::from_private_key(kind, empty).is_err());
      assert!(
        RotatableKeyPair::from_private_key_spec(kind, empty).is_err()
      );
      assert!(SpkiPublicKey::from_private_key(kind, empty).is_err());
      assert!(
        Pkcs8PrivateKey::from(empty.to_string())
          .compute_public_key(kind)
          .is_err()
      );
    }
    assert!(
      MutualNoiseHandshake::new_initiator(empty, b"p").is_err()
    );
    assert!(
      MutualNoiseHandshake::new_responder(empty, b"p").is_err()
    );
    assert!(
      crate::signature::sign(
        &Pkcs8PrivateKey::from(empty.to_string()),
        b"m"
      )
      .is_err()
    );
  }
  for kind in KINDS {
    assert!(Pkcs8PrivateKey::from_raw_bytes(kind, &[]).is_err());
  }
}

#[test]
fn all_zero_private_key_is_refused() {
  let kind = PkiKind::Mutual;
  // The all zero scalar, and inputs X25519 clamps to it.
  assert!(Pkcs8PrivateKey::from_raw_bytes(kind, &[0; 32]).is_err());
  assert!(Pkcs8PrivateKey::from_raw_bytes(kind, &[7]).is_err());
  let mut clamped_away = [0u8; 32];
  clamped_away[0] = 0x07;
  clamped_away[31] = 0xc0;
  assert!(
    Pkcs8PrivateKey::from_raw_bytes(kind, &clamped_away).is_err()
  );
  for raw in ["\u{1}", "\u{7}", "\0\0\0"] {
    assert!(
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, raw).is_err()
    );
    assert!(Pkcs8PrivateKey::maybe_raw_bytes(kind, raw).is_err());
  }
  // Also when pkcs8 wraps it.
  let zero = encode_pkcs8_b64(oid(kind), &[0; 32]);
  assert!(Pkcs8PrivateKey::raw_bytes(kind, zero.as_bytes()).is_err());
  assert!(
    Pkcs8PrivateKey::from_maybe_raw_bytes(kind, &zero).is_err()
  );
  let pem = super::encode_pem("PRIVATE KEY", &zero);
  assert!(Pkcs8PrivateKey::maybe_raw_bytes(kind, &pem).is_err());
  // A key one bit away is fine.
  let mut one_bit = [0u8; 32];
  one_bit[0] = 0x08;
  assert!(Pkcs8PrivateKey::from_raw_bytes(kind, &one_bit).is_ok());
}

#[test]
fn all_zero_signature_key_is_refused() {
  let kind = PkiKind::Signature;
  // The all zero seed.
  assert!(Pkcs8PrivateKey::from_raw_bytes(kind, &[0; 32]).is_err());
  assert!(Pkcs8PrivateKey::from_raw_bytes(kind, &[0]).is_err());
  for raw in ["\0", "\0\0\0"] {
    assert!(
      Pkcs8PrivateKey::from_maybe_raw_bytes(kind, raw).is_err()
    );
    assert!(Pkcs8PrivateKey::maybe_raw_bytes(kind, raw).is_err());
  }
  // Also when pkcs8 wraps it.
  let zero = encode_pkcs8_b64(oid(kind), &[0; 32]);
  assert!(Pkcs8PrivateKey::raw_bytes(kind, zero.as_bytes()).is_err());
  assert!(
    Pkcs8PrivateKey::from_maybe_raw_bytes(kind, &zero).is_err()
  );
  let pem = super::encode_pem("PRIVATE KEY", &zero);
  assert!(Pkcs8PrivateKey::maybe_raw_bytes(kind, &pem).is_err());
  // A seed is hashed, not clamped: the inputs X25519 clamps to its
  // zero key are seeds of their own here.
  let mut clamped_away = [0u8; 32];
  clamped_away[0] = 0x07;
  clamped_away[31] = 0xc0;
  let seeds: [&[u8]; 3] = [&[7], &[1], &clamped_away];
  let mut public_keys = Vec::new();
  for seed in seeds {
    let key = Pkcs8PrivateKey::from_raw_bytes(kind, seed).unwrap();
    public_keys.push(key.compute_public_key(kind).unwrap());
  }
  assert_ne!(public_keys[0], public_keys[1]);
  assert_ne!(public_keys[0], public_keys[2]);
  assert_ne!(public_keys[1], public_keys[2]);
}

#[test]
fn empty_private_key_file_is_refused_not_replaced() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("empty_key_file");
  for kind in KINDS {
    for (name, contents) in [("empty.key", ""), ("newline.key", "\n")]
    {
      let path = dir.join(name);
      std::fs::write(&path, contents).unwrap();
      let spec = format!("file:{}", path.display());
      let err = RotatableKeyPair::from_private_key_spec(kind, &spec)
        .err()
        .expect("an empty key file must be refused");
      let err = format!("{err:#}");
      assert!(err.contains("empty"), "{err}");
      assert!(err.contains(name), "{err}");
      assert!(Pkcs8PrivateKey::from_file(kind, &path).is_err());
      assert!(EncodedKeyPair::from_file(kind, &path).is_err());
      // Left as it is for the operator, not replaced by a new key.
      assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
    }
  }
  std::fs::remove_dir_all(dir).unwrap();
}

// ---- Encodings ----

#[test]
fn private_key_encodings_tolerate_surrounding_whitespace() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let raw = keys.private.as_raw_bytes(kind).unwrap();
    let pem = keys.private.as_pem();
    for input in [
      format!("{}\n", keys.private.as_str()),
      format!("  {}\r\n", keys.private.as_str()),
      format!("\n{pem}"),
      format!("{pem}\n\n"),
    ] {
      let parsed =
        Pkcs8PrivateKey::from_maybe_raw_bytes(kind, &input).unwrap();
      assert_eq!(parsed.as_str(), keys.private.as_str());
      assert_eq!(
        Pkcs8PrivateKey::maybe_raw_bytes(kind, &input).unwrap(),
        raw
      );
    }

    // A key file written by hand (`echo`) ends in a newline.
    let dir = scratch_dir("key_newline");
    let path = dir.join("hand.key");
    std::fs::write(&path, format!("{}\n", keys.private.as_str()))
      .unwrap();
    let loaded = EncodedKeyPair::from_file(kind, &path).unwrap();
    assert_eq!(loaded.private.as_str(), keys.private.as_str());
    assert_eq!(loaded.public, keys.public);
    let pub_path = dir.join("hand.pub");
    std::fs::write(&pub_path, format!("{}\n", keys.public.as_str()))
      .unwrap();
    let spec = format!("file:{}", pub_path.display());
    assert_eq!(
      SpkiPublicKey::from_spec(kind, &spec).unwrap(),
      keys.public
    );
    assert_eq!(
      SpkiPublicKey::from_maybe_pem(
        kind,
        &format!(" {}\n", keys.public)
      )
      .unwrap(),
      keys.public
    );
    std::fs::remove_dir_all(dir).unwrap();
  }
}

#[test]
fn raw_private_keys_are_used_exactly_as_given() {
  // Raw input is not trimmed, so a raw key keeps deriving the same
  // public key it always did.
  let mut expected = [0u8; 32];
  expected[..6].copy_from_slice(b"hello\n");
  for kind in KINDS {
    assert_eq!(
      Pkcs8PrivateKey::maybe_raw_bytes(kind, "hello\n").unwrap(),
      expected
    );
    assert_ne!(
      Pkcs8PrivateKey::maybe_raw_bytes(kind, "hello\n").unwrap(),
      Pkcs8PrivateKey::maybe_raw_bytes(kind, "hello").unwrap()
    );
  }
}

#[test]
fn pkcs8_v2_private_key_is_normalized_to_v1() {
  for kind in KINDS {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    let raw = keys.private.as_raw_bytes(kind).unwrap();
    let public_raw = SpkiPublicKey::maybe_pem_to_raw_bytes(
      kind,
      keys.public.as_str(),
    )
    .unwrap();
    // OneAsymmetricKey (pkcs8 v2), carrying the public key.
    let octet = der::asn1::OctetStringRef::new(&raw).unwrap();
    let mut buf = [0u8; 128];
    let octet_der = octet.encode_to_slice(&mut buf).unwrap();
    let v2 = pkcs8::PrivateKeyInfo {
      algorithm: super::algorithm(kind),
      private_key: octet_der,
      public_key: Some(&public_raw),
    };
    assert_eq!(v2.version(), pkcs8::Version::V2);
    let mut buf = [0u8; 128];
    let v2 = BASE64.encode(v2.encode_to_slice(&mut buf).unwrap());
    assert_ne!(v2.len(), 64);
    let v2_pem = super::encode_pem("PRIVATE KEY", &v2);

    for input in [&v2, &v2_pem] {
      let parsed =
        Pkcs8PrivateKey::from_maybe_raw_bytes(kind, input).unwrap();
      // Stored in the canonical v1 form, which every consumer reads.
      assert_eq!(parsed.as_str(), keys.private.as_str());
      assert_eq!(
        Pkcs8PrivateKey::maybe_raw_bytes(kind, input).unwrap(),
        raw
      );
      let pair =
        EncodedKeyPair::from_private_key(kind, input).unwrap();
      assert_eq!(pair.public, keys.public);
      assert_eq!(pair.private.as_str(), keys.private.as_str());
    }
  }
}

#[test]
fn private_key_debug_is_redacted() {
  let keys = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  let debug = format!("{:?}", keys.private);
  assert!(!debug.contains(keys.private.as_str()), "{debug}");
  assert!(debug.contains("redacted"), "{debug}");
  // into_inner hands the key out (the Drop impl must not wipe it).
  let expected = keys.private.as_str().to_string();
  assert_eq!(keys.private.clone().into_inner(), expected);
}

// ---- Public key validation ----

/// Canonical low order X25519 points (see public::LOW_ORDER_POINTS).
fn low_order_points() -> Vec<[u8; 32]> {
  let hex = |s: &str| -> [u8; 32] {
    data_encoding::HEXLOWER
      .decode(s.as_bytes())
      .unwrap()
      .try_into()
      .unwrap()
  };
  vec![
    [0; 32],
    hex(
      "0100000000000000000000000000000000000000000000000000000000000000",
    ),
    hex(
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    ),
    hex(
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    ),
    hex(
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ),
  ]
}

#[test]
fn low_order_points_give_an_all_zero_shared_secret() {
  use snow::resolvers::{CryptoResolver as _, DefaultResolver};
  // The blocklist is right: with any private key, the DH output is
  // all zero, so no private key is needed to complete a handshake.
  let params: snow::params::NoiseParams =
    PkiKind::MUTUAL.parse().unwrap();
  let keys = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
  let mut dh = DefaultResolver.resolve_dh(&params.dh).unwrap();
  dh.set(&keys.private.as_raw_bytes(PkiKind::Mutual).unwrap());
  for point in low_order_points() {
    let mut out = [0xffu8; 32];
    dh.dh(&point, &mut out).unwrap();
    assert_eq!(out, [0; 32], "{point:?}");
  }
}

#[test]
fn low_order_and_non_canonical_public_keys_are_refused() {
  let kind = PkiKind::Mutual;
  for point in low_order_points() {
    assert!(SpkiPublicKey::from_raw_bytes(kind, &point).is_err());
    let der = encode_spki_der(oid(kind), &point, 0);
    assert!(SpkiPublicKey::from_der(kind, &der).is_err());
    assert!(SpkiPublicKey::der_to_raw_bytes(kind, &der).is_err());
    let b64 = BASE64.encode(&der);
    assert!(SpkiPublicKey::from_maybe_pem(kind, &b64).is_err());
    assert!(
      SpkiPublicKey::maybe_pem_to_raw_bytes(kind, &b64).is_err()
    );
  }
  // The all zero key, as a client would register it.
  assert!(
    SpkiPublicKey::from_maybe_pem(
      kind,
      "MCowBQYDK2VuAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    .is_err()
  );

  let keys = EncodedKeyPair::generate(kind).unwrap();
  let raw =
    SpkiPublicKey::maybe_pem_to_raw_bytes(kind, keys.public.as_str())
      .unwrap();
  // The same key with the ignored top bit set: another string for
  // the same key.
  let mut high_bit = raw;
  high_bit[31] |= 0x80;
  assert!(SpkiPublicKey::from_raw_bytes(kind, &high_bit).is_err());
  let der = encode_spki_der(oid(kind), &high_bit, 0);
  assert!(SpkiPublicKey::from_der(kind, &der).is_err());
  // u >= p: p itself (= 0), p + 1 (= 1) and 2^255 - 1.
  for first in [0xed, 0xee, 0xff] {
    let mut at_least_p = [0xffu8; 32];
    at_least_p[0] = first;
    at_least_p[31] = 0x7f;
    assert!(
      SpkiPublicKey::from_raw_bytes(kind, &at_least_p).is_err()
    );
  }
  // The largest canonical u (p - 2) is fine.
  let mut largest = [0xffu8; 32];
  largest[0] = 0xeb;
  largest[31] = 0x7f;
  assert!(SpkiPublicKey::from_raw_bytes(kind, &largest).is_ok());
  // Generated keys always pass.
  for _ in 0..32 {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    assert!(
      SpkiPublicKey::from_maybe_pem(kind, keys.public.as_str())
        .is_ok()
    );
  }
}

#[test]
fn low_order_signature_public_keys_are_refused() {
  let kind = PkiKind::Signature;
  // The 8 points of low order: a signature can be made for them
  // without a private key (see the signature tests).
  let low_order = curve25519_dalek::constants::EIGHT_TORSION
    .map(|point| point.compress().to_bytes());
  for (i, point) in low_order.iter().enumerate() {
    // All different, so these are the 8.
    assert!(!low_order[..i].contains(point));
    let err = SpkiPublicKey::from_raw_bytes(kind, point).unwrap_err();
    assert!(format!("{err:#}").contains("low order"), "{err:#}");
    let der = encode_spki_der(oid(kind), point, 0);
    assert!(SpkiPublicKey::from_der(kind, &der).is_err());
    assert!(SpkiPublicKey::der_to_raw_bytes(kind, &der).is_err());
    let b64 = BASE64.encode(&der);
    assert!(SpkiPublicKey::from_maybe_pem(kind, &b64).is_err());
    assert!(
      SpkiPublicKey::maybe_pem_to_raw_bytes(kind, &b64).is_err()
    );
  }
  // The identity, as a client would register it.
  assert!(
    SpkiPublicKey::from_maybe_pem(
      kind,
      "MCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    .is_err()
  );
  // Generated keys always pass.
  for _ in 0..32 {
    let keys = EncodedKeyPair::generate(kind).unwrap();
    assert!(
      SpkiPublicKey::from_maybe_pem(kind, keys.public.as_str())
        .is_ok()
    );
  }
}

/// A key has one string: the encodings ed25519 decoding also takes
/// for a point (it reduces y mod p = 2^255 - 19, and takes the sign
/// bit of x = 0) are refused.
#[test]
fn non_canonical_signature_public_keys_are_refused() {
  let kind = PkiKind::Signature;
  // The points with y < 19 also decode from y + p.
  let mut aliased = 0;
  let mut off_curve = 0;
  for y in 0u8..19 {
    let mut canonical = [0u8; 32];
    canonical[0] = y;
    let mut alias = [0xffu8; 32];
    alias[0] = 0xed + y;
    alias[31] = 0x7f;
    let Ok(point) =
      ed25519_dalek::VerifyingKey::from_bytes(&canonical)
    else {
      // Not every y is on the curve.
      off_curve += 1;
      let err =
        SpkiPublicKey::from_raw_bytes(kind, &canonical).unwrap_err();
      assert!(format!("{err:#}").contains("not a point"), "{err:#}");
      assert!(SpkiPublicKey::from_raw_bytes(kind, &alias).is_err());
      continue;
    };
    // The alias decodes to the same point...
    let decoded =
      ed25519_dalek::VerifyingKey::from_bytes(&alias).unwrap();
    assert_eq!(decoded.to_edwards(), point.to_edwards(), "{y}");
    // ...and is refused, while the canonical encoding is a key
    // (unless it is of low order).
    let err =
      SpkiPublicKey::from_raw_bytes(kind, &alias).unwrap_err();
    assert!(format!("{err:#}").contains("canonical"), "{err:#}");
    let der = encode_spki_der(oid(kind), &alias, 0);
    assert!(SpkiPublicKey::from_der(kind, &der).is_err());
    assert_eq!(
      SpkiPublicKey::from_raw_bytes(kind, &canonical).is_ok(),
      !point.is_weak(),
      "{y}"
    );
    if !point.is_weak() {
      aliased += 1;
    }
  }
  // Both cases were met, with keys which are fine otherwise.
  assert!(aliased > 0);
  assert!(off_curve > 0);

  // x = 0 (y = 1 and y = -1) with the sign bit set.
  let mut identity = [0u8; 32];
  identity[0] = 1;
  identity[31] = 0x80;
  let mut minus_one = [0xffu8; 32];
  minus_one[0] = 0xec;
  for alias in [identity, minus_one] {
    assert!(ed25519_dalek::VerifyingKey::from_bytes(&alias).is_ok());
    let err =
      SpkiPublicKey::from_raw_bytes(kind, &alias).unwrap_err();
    assert!(format!("{err:#}").contains("canonical"), "{err:#}");
  }
}

// ---- Rotation ----

#[test]
fn a_failed_commit_leaves_no_retired_key() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_failed_commit");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();
  let original_file = std::fs::read(&path).unwrap();

  let rotation = pair.begin_rotation().unwrap();
  let candidate = rotation.candidate().clone();
  // Writing the live path fails: make it a non empty directory.
  std::fs::remove_file(&path).unwrap();
  std::fs::create_dir(&path).unwrap();
  std::fs::write(path.join("occupied"), "").unwrap();
  assert!(rotation.commit().is_err());

  // Nothing switched, and nothing offers the live key for
  // revocation. The live file can't be read, so `.old` keeps the
  // key in use rather than dropping its only copy on disk.
  assert_eq!(pair.load().public, original.public);
  assert!(dir.join("test.key.old").exists());
  assert!(pair.retired().unwrap().is_none());

  // Once the live file is back, the candidate resumes.
  std::fs::remove_dir_all(&path).unwrap();
  std::fs::write(&path, &original_file).unwrap();
  let resumed = pair.begin_rotation().unwrap();
  assert_eq!(resumed.candidate().public, candidate.public);
  resumed.commit().unwrap();
  assert_eq!(pair.load().public, candidate.public);
  let retired = pair.retired().unwrap().unwrap();
  assert_eq!(retired.public, original.public);
  pair.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn an_old_key_equal_to_the_live_one_is_not_retired() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_interrupted_commit");
  let path = dir.join("test.key");
  let old = dir.join("test.key.old");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let live = pair.load().clone();

  // A crash between keeping the previous key and the switch.
  let rotation = pair.begin_rotation().unwrap();
  let candidate = rotation.candidate().clone();
  drop(rotation);
  live.private.write_pem_sync(&old).unwrap();
  assert!(pair.rotation_pending());
  // Never handed out for revocation: it is the key in use. Only
  // read, so it stays until begin_rotation.
  assert!(pair.retired().unwrap().is_none());
  assert!(old.exists());
  assert!(pair.rotation_pending());

  // begin_rotation settles it, and resumes the candidate.
  let resumed = pair.begin_rotation().unwrap();
  assert!(!old.exists());
  assert_eq!(resumed.candidate().public, candidate.public);
  resumed.abort().unwrap();

  // A real retired key (another key) still blocks a new rotation.
  EncodedKeyPair::generate(PkiKind::Signature)
    .unwrap()
    .private
    .write_pem_sync(&old)
    .unwrap();
  assert!(pair.retired().unwrap().is_some());
  assert!(pair.begin_rotation().is_err());
  pair.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn one_rotation_at_a_time() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_exclusive");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();

  let rotation = pair.begin_rotation().unwrap();
  let err = pair.begin_rotation().err().unwrap();
  assert!(err.to_string().contains("in progress"), "{err:#}");
  assert!(pair.rotate().await.is_err());
  assert!(pair.finish_rotation().is_err());
  // Nothing changed meanwhile.
  assert_eq!(pair.load().public, original.public);

  // Dropping ends it.
  drop(rotation);
  let rotation = pair.begin_rotation().unwrap();
  rotation.abort().unwrap();
  let rotated = pair.rotate().await.unwrap();
  assert_eq!(pair.load().public, rotated);
  let rotation = pair.begin_rotation().unwrap();
  rotation.commit().unwrap();
  pair.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn commit_refuses_a_replaced_candidate() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_replaced_candidate");
  let path = dir.join("test.key");
  let next = dir.join("test.key.next");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();

  let rotation = pair.begin_rotation().unwrap();
  // Another writer replaced the candidate file meanwhile.
  let other = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  other.private.write_pem_sync(&next).unwrap();
  let err = rotation.commit().err().unwrap();
  assert!(err.to_string().contains("changed"), "{err:#}");

  // Nothing changed: memory and disk agree on the previous key.
  assert_eq!(pair.load().public, original.public);
  assert!(
    Pkcs8PrivateKey::from_file(PkiKind::Signature, &path).unwrap()
      == original.private
  );
  assert!(!dir.join("test.key.old").exists());
  assert!(pair.retired().unwrap().is_none());

  std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn rotate_switches_memory_with_the_key_file() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_pub_fails");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();

  // The `.pub` sidecar can't be written (a directory in its place).
  let pub_path = dir.join("test.pub");
  std::fs::remove_file(&pub_path).unwrap();
  std::fs::create_dir(&pub_path).unwrap();
  std::fs::write(pub_path.join("occupied"), "").unwrap();

  // The private key file switched, so memory must switch with it.
  let public = pair.rotate().await.unwrap();
  assert_ne!(public, original.public);
  assert_eq!(pair.load().public, public);
  let on_disk =
    EncodedKeyPair::from_file(PkiKind::Signature, &path).unwrap();
  assert_eq!(on_disk.public, public);

  // Not file backed: nothing to rotate.
  let inline = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    original.private.as_str(),
  )
  .unwrap();
  assert_eq!(inline.rotate().await.unwrap(), original.public);

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rotate_follows_the_key_file_when_the_write_errors() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_write_errors");
  let path = dir.join("test.key");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();

  // Fails before touching the file: nothing switched.
  let err = pair
    .rotate_with(|_, _| Err(anyhow::anyhow!("create failed")))
    .err()
    .unwrap();
  assert!(err.to_string().contains("create failed"), "{err:#}");
  assert_eq!(pair.load().public, original.public);
  assert!(
    Pkcs8PrivateKey::from_file(PkiKind::Signature, &path).unwrap()
      == original.private
  );

  // Fails midway through an in place write: the file holds no key
  // memory could switch to, so the error stands.
  let err = pair
    .rotate_with(|_, path| {
      std::fs::write(path, "-----BEGIN PRIVATE KEY-----\nMC4C")
        .unwrap();
      Err(anyhow::anyhow!("write failed"))
    })
    .err()
    .unwrap();
  assert!(err.to_string().contains("write failed"), "{err:#}");
  assert_eq!(pair.load().public, original.public);
  original.private.write_pem_sync(&path).unwrap();

  // Fails after the new key is in place (syncing the directory):
  // the file switched, so memory switches with it.
  let public = pair
    .rotate_with(|private, path| {
      private.write_pem_sync(path)?;
      Err(anyhow::anyhow!("directory sync failed"))
    })
    .unwrap();
  assert_ne!(public, original.public);
  assert_eq!(pair.load().public, public);
  let on_disk =
    EncodedKeyPair::from_file(PkiKind::Signature, &path).unwrap();
  assert_eq!(on_disk.public, public);
  assert_eq!(
    SpkiPublicKey::from_file(
      PkiKind::Signature,
      dir.join("test.pub")
    )
    .unwrap(),
    public
  );

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reading_the_retired_key_never_blocks_a_rotation() {
  use super::{RotatableKeyPair, RotationGuard};

  let dir = scratch_dir("retired_unguarded");
  let path = dir.join("test.key");
  let old = dir.join("test.key.old");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  // While one thread keeps reading `.old`, a rotation starting on
  // another is never refused as already in progress: the number of
  // refusals.
  let race = |expected: Option<&SpkiPublicKey>| {
    std::thread::scope(|scope| {
      let reader = scope.spawn(|| {
        for _ in 0..500 {
          let loaded = pair.retired().unwrap();
          assert_eq!(loaded.map(|k| k.public).as_ref(), expected);
        }
      });
      let mut refused = 0;
      while !reader.is_finished() {
        if RotationGuard::acquire(&pair.rotating).is_err() {
          refused += 1;
        }
      }
      refused
    })
  };

  // A retired key.
  let retired = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
  retired.private.write_pem_sync(&old).unwrap();
  assert_eq!(race(Some(&retired.public)), 0);
  pair.finish_rotation().unwrap();

  // An `.old` holding the live key (a commit that did not switch):
  // not retired, and never removed by a read, which would need the
  // guard.
  let live = pair.load().clone();
  live.private.write_pem_sync(&old).unwrap();
  assert_eq!(race(None), 0);
  assert!(old.exists());
  // Nor while a rotation is in flight (a commit writes it before
  // its switch).
  let rotation = pair.begin_rotation().unwrap();
  // begin_rotation removed it, under the guard.
  assert!(!old.exists());
  live.private.write_pem_sync(&old).unwrap();
  assert!(pair.retired().unwrap().is_none());
  assert!(old.exists());
  rotation.abort().unwrap();
  assert!(pair.retired().unwrap().is_none());
  assert!(old.exists());
  let rotation = pair.begin_rotation().unwrap();
  assert!(!old.exists());
  rotation.abort().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn only_an_empty_key_file_suggests_deleting_it() {
  let dir = scratch_dir("load_hint");

  for kind in KINDS {
    let empty = dir.join("empty.key");
    std::fs::write(&empty, " \n").unwrap();
    let err = EncodedKeyPair::load_maybe_generate(kind, &empty)
      .err()
      .unwrap();
    assert!(
      format!("{err:#}")
        .contains("delete it to have a new key generated"),
      "{err:#}"
    );

    // A real key in a form this can't load (a key of the other
    // algorithm), garbage, and an unreadable file (a directory) are
    // refused without the hint: deleting would throw away a
    // registered identity.
    let other_algorithm = dir.join(format!("{kind:?}_other.key"));
    std::fs::write(
      &other_algorithm,
      encode_pkcs8_b64(oid(other(kind)), &[7u8; 32]) + "\n",
    )
    .unwrap();
    let garbage = dir.join(format!("{kind:?}_garbage.key"));
    std::fs::write(
      &garbage,
      "this is not a private key, not at all\n",
    )
    .unwrap();
    let unreadable = dir.join(format!("{kind:?}_unreadable.key"));
    std::fs::create_dir(&unreadable).unwrap();
    for path in [&other_algorithm, &garbage, &unreadable] {
      let before = std::fs::symlink_metadata(path).unwrap();
      let err = EncodedKeyPair::load_maybe_generate(kind, path)
        .err()
        .unwrap();
      // Only the key of the other algorithm says so.
      if path == &other_algorithm {
        assert_wrong_algorithm(&err, kind);
      } else {
        assert!(err.downcast_ref::<WrongKeyAlgorithm>().is_none());
      }
      let err = format!("{err:#}");
      assert!(
        err.contains("Failed to load the private key"),
        "{err}"
      );
      assert!(!err.contains("new key generated"), "{err}");
      // Left as it is.
      let after = std::fs::symlink_metadata(path).unwrap();
      assert_eq!(before.len(), after.len());
      assert_eq!(before.is_dir(), after.is_dir());
    }
  }

  std::fs::remove_dir_all(dir).unwrap();
}

/// A pair keeps the kind it was loaded as: every key it rotates to
/// is of that kind's algorithm, never the other's.
#[tokio::test]
async fn a_pair_rotates_within_its_algorithm() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_algorithm");
  for kind in KINDS {
    let path = dir.join(format!("{kind:?}.key"));
    let spec = format!("file:{}", path.display());
    let pair =
      RotatableKeyPair::from_private_key_spec(kind, &spec).unwrap();
    assert_eq!(pair.kind(), kind);
    let original = pair.load().clone();
    let is_of_kind = |keys: &EncodedKeyPair| {
      keys.private.as_raw_bytes(kind).unwrap();
      assert_eq!(
        keys.private.compute_public_key(kind).unwrap(),
        keys.public
      );
      assert_wrong_algorithm(
        &keys.private.as_raw_bytes(other(kind)).unwrap_err(),
        other(kind),
      );
      assert_wrong_algorithm(
        &SpkiPublicKey::from_maybe_pem(
          other(kind),
          keys.public.as_str(),
        )
        .unwrap_err(),
        other(kind),
      );
    };
    is_of_kind(&original);

    // In one step.
    let rotated = pair.rotate().await.unwrap();
    assert_ne!(rotated, original.public);
    is_of_kind(&pair.load());
    is_of_kind(&EncodedKeyPair::from_file(kind, &path).unwrap());

    // In two phases.
    let rotation = pair.begin_rotation().unwrap();
    let candidate = rotation.candidate().clone();
    is_of_kind(&candidate);
    rotation.commit().unwrap();
    assert_eq!(pair.load().public, candidate.public);
    let retired = pair.retired().unwrap().unwrap();
    assert_eq!(retired.public, rotated);
    is_of_kind(&retired);
    pair.finish_rotation().unwrap();
    assert!(!pair.rotation_pending());

    // The key file is not loaded as the other kind.
    let err =
      RotatableKeyPair::from_private_key_spec(other(kind), &spec)
        .err()
        .unwrap();
    assert_wrong_algorithm(&err, other(kind));
  }
  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_commit_whose_write_errors_follows_the_live_file() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_commit_write_errors");
  let path = dir.join("test.key");
  let old = dir.join("test.key.old");
  let next = dir.join("test.key.next");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();

  // The write fails outright: nothing switched, `.old` (a copy of
  // the live key) is removed, the candidate resumes.
  let rotation = pair.begin_rotation().unwrap();
  let candidate = rotation.candidate().clone();
  let err = rotation
    .commit_with(|_, _| Err(anyhow::anyhow!("write failed")))
    .err()
    .unwrap();
  assert!(format!("{err:#}").contains("write failed"), "{err:#}");
  assert_eq!(pair.load().public, original.public);
  assert!(!old.exists());
  assert!(next.exists());

  // The write reports an error but happened (syncing the directory
  // after the replace, a retried NFS rename): memory switches with
  // the file, and the previous key is kept at `.old` for
  // revocation.
  let rotation = pair.begin_rotation().unwrap();
  assert_eq!(rotation.candidate().public, candidate.public);
  rotation
    .commit_with(|private, live| {
      // The candidate, over the live key file.
      assert!(*private == candidate.private);
      assert_eq!(live, path);
      private.write_pem_sync(live)?;
      Err(anyhow::anyhow!("reported after the write"))
    })
    .unwrap();
  assert_eq!(pair.load().public, candidate.public);
  let on_disk =
    EncodedKeyPair::from_file(PkiKind::Signature, &path).unwrap();
  assert_eq!(on_disk.public, candidate.public);
  assert!(!next.exists());
  let retired = pair.retired().unwrap().unwrap();
  assert_eq!(retired.public, original.public);
  pair.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_commit_interrupted_mid_write_is_retried() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_commit_mid_write");
  let path = dir.join("test.key");
  let old = dir.join("test.key.old");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();

  // An in place write (a bind mounted key file) fails midway: the
  // live file holds no key, so `.old` keeps the key in use.
  let rotation = pair.begin_rotation().unwrap();
  let candidate = rotation.candidate().clone();
  let err = rotation
    .commit_with(|_, live| {
      std::fs::write(live, "-----BEGIN PRIVATE KEY-----\nMC4C")
        .unwrap();
      Err(anyhow::anyhow!("write failed midway"))
    })
    .err()
    .unwrap();
  assert!(format!("{err:#}").contains("midway"), "{err:#}");
  assert_eq!(pair.load().public, original.public);
  assert!(
    Pkcs8PrivateKey::from_file(PkiKind::Signature, &old).unwrap()
      == original.private
  );
  // Not a retired key: it is the key in use.
  assert!(pair.retired().unwrap().is_none());
  assert!(pair.rotation_pending());

  // The retry resumes the candidate, and its commit writes the live
  // file again (`.old` holding the key in use doesn't block it).
  let rotation = pair.begin_rotation().unwrap();
  assert_eq!(rotation.candidate().public, candidate.public);
  rotation.commit().unwrap();
  assert_eq!(pair.load().public, candidate.public);
  let on_disk =
    EncodedKeyPair::from_file(PkiKind::Signature, &path).unwrap();
  assert_eq!(on_disk.public, candidate.public);
  let retired = pair.retired().unwrap().unwrap();
  assert_eq!(retired.public, original.public);
  pair.finish_rotation().unwrap();
  assert!(!pair.rotation_pending());

  std::fs::remove_dir_all(dir).unwrap();
}

/// The resume flow (revoke [RotatableKeyPair::retired], then
/// [RotatableKeyPair::finish_rotation]) after a commit whose write
/// failed midway never deletes the only copy of the key in use.
#[test]
fn finishing_after_a_failed_commit_keeps_the_key_in_use() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_finish_failed_commit");
  let path = dir.join("test.key");
  let old = dir.join("test.key.old");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();
  let fail_midway = |_: &Pkcs8PrivateKey, live: &std::path::Path| {
    std::fs::write(live, "-----BEGIN PRIVATE KEY-----\nMC4C")
      .unwrap();
    Err(anyhow::anyhow!("write failed midway"))
  };
  let old_holds_original = || {
    Pkcs8PrivateKey::from_file(PkiKind::Signature, &old)
      .is_ok_and(|old| old == original.private)
  };

  // An in place write fails midway: the live file holds no key, and
  // `.old` is the only copy of the key in use on disk.
  let rotation = pair.begin_rotation().unwrap();
  let candidate = rotation.candidate().clone();
  assert!(rotation.commit_with(fail_midway).is_err());
  assert!(pair.retired().unwrap().is_none());
  // Nothing retired to revoke, so the caller finishes: `.old` stays.
  pair.finish_rotation().unwrap();
  assert!(old_holds_original());
  assert!(pair.rotation_pending());
  // Nor while the live file holds another key.
  EncodedKeyPair::generate(PkiKind::Signature)
    .unwrap()
    .private
    .write_pem_sync(&path)
    .unwrap();
  pair.finish_rotation().unwrap();
  assert!(old_holds_original());
  // Once the live file holds the key in use again, `.old` is a
  // spare copy, and finishing removes it.
  original.private.write_pem_sync(&path).unwrap();
  pair.finish_rotation().unwrap();
  assert!(!old.exists());
  // The candidate still waits.
  assert!(pair.rotation_pending());

  // Again, resumed the way a caller does after finishing: the
  // candidate resumes, and its commit writes the live file again.
  let rotation = pair.begin_rotation().unwrap();
  assert_eq!(rotation.candidate().public, candidate.public);
  assert!(rotation.commit_with(fail_midway).is_err());
  pair.finish_rotation().unwrap();
  assert!(old_holds_original());
  let rotation = pair.begin_rotation().unwrap();
  assert_eq!(rotation.candidate().public, candidate.public);
  rotation.commit().unwrap();
  assert_eq!(pair.load().public, candidate.public);
  // Now `.old` is a retired key, which finishing removes.
  let retired = pair.retired().unwrap().unwrap();
  assert_eq!(retired.public, original.public);
  pair.finish_rotation().unwrap();
  assert!(!old.exists());
  assert!(!pair.rotation_pending());
  let reloaded = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  assert_eq!(reloaded.load().public, candidate.public);

  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_candidate_holding_the_live_key_is_not_resumed() {
  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_switched_candidate");
  let path = dir.join("test.key");
  let next = dir.join("test.key.next");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  let original = pair.load().clone();

  // A commit interrupted after its switch, before removing `.next`.
  let rotation = pair.begin_rotation().unwrap();
  let candidate = rotation.candidate().clone();
  rotation.commit().unwrap();
  pair.finish_rotation().unwrap();
  candidate.private.write_pem_sync(&next).unwrap();
  // A restart loads the switched key.
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();
  assert_eq!(pair.load().public, candidate.public);

  // That rotation is done: nothing to resume.
  assert!(!pair.rotation_pending());
  // The next one starts over, never offering the live key as its
  // candidate (committing it would retire the key in use).
  let rotation = pair.begin_rotation().unwrap();
  let fresh = rotation.candidate().clone();
  assert_ne!(fresh.public, candidate.public);
  assert_ne!(fresh.public, original.public);
  assert!(
    Pkcs8PrivateKey::from_file(PkiKind::Signature, &next).unwrap()
      == fresh.private
  );
  assert!(pair.rotation_pending());
  rotation.commit().unwrap();
  assert_eq!(pair.load().public, fresh.public);
  let retired = pair.retired().unwrap().unwrap();
  assert_eq!(retired.public, candidate.public);
  pair.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

/// A key file which can't simply be replaced (a single file bind
/// mount, a hard link) is written in place by the commit, keeping
/// its owner, group and mode, as [RotatableKeyPair::rotate] does.
#[cfg(unix)]
#[test]
fn a_commit_writes_the_live_file_like_rotate() {
  use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

  use super::RotatableKeyPair;

  let dir = scratch_dir("rotate_commit_identity");
  let path = dir.join("test.key");
  let link = dir.join("linked.key");
  let spec = format!("file:{}", path.display());
  let pair = RotatableKeyPair::from_private_key_spec(
    PkiKind::Signature,
    &spec,
  )
  .unwrap();

  // A key file shared with a group this process is in.
  std::fs::set_permissions(
    &path,
    std::fs::Permissions::from_mode(0o640),
  )
  .unwrap();
  let group =
    supplementary_group(std::fs::metadata(&path).unwrap().gid());
  if let Some(gid) = group {
    std::os::unix::fs::chown(&path, None, Some(gid)).unwrap();
  }

  let rotation = pair.begin_rotation().unwrap();
  let candidate = rotation.candidate().clone();
  rotation.commit().unwrap();
  assert_eq!(pair.load().public, candidate.public);
  let meta = std::fs::metadata(&path).unwrap();
  assert_eq!(meta.mode() & 0o7777, 0o640);
  if let Some(gid) = group {
    assert_eq!(meta.gid(), gid);
  }
  pair.finish_rotation().unwrap();

  // A hard linked key file in a directory only its owner can write
  // to is written in place, as a bind mounted one is: the same
  // file, which the other link sees switch too.
  std::fs::set_permissions(
    &dir,
    std::fs::Permissions::from_mode(0o700),
  )
  .unwrap();
  std::fs::hard_link(&path, &link).unwrap();
  let inode = std::fs::metadata(&path).unwrap().ino();
  let rotation = pair.begin_rotation().unwrap();
  let candidate = rotation.candidate().clone();
  rotation.commit().unwrap();
  assert_eq!(pair.load().public, candidate.public);
  assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
  assert!(
    Pkcs8PrivateKey::from_file(PkiKind::Signature, &link).unwrap()
      == candidate.private
  );
  assert!(!dir.join("test.key.next").exists());
  pair.finish_rotation().unwrap();

  std::fs::remove_dir_all(dir).unwrap();
}

/// A group this process is in, other than `gid` (linux only).
#[cfg(unix)]
fn supplementary_group(gid: u32) -> Option<u32> {
  let status = std::fs::read_to_string("/proc/self/status").ok()?;
  let groups = status
    .lines()
    .find_map(|line| line.strip_prefix("Groups:"))?;
  groups
    .split_whitespace()
    .filter_map(|group| group.parse().ok())
    .find(|group| *group != gid)
}
