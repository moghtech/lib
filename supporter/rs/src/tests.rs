use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

use crate::{
  CborError, CborValue, NonceError, ParseError, Payload,
  PayloadError, RootKeyError, SupporterKey, Tier, VerifyError,
  decode_cbor, decode_nonce, fixture, nonce_message, root_key_bytes,
  root_key_id,
};

fn key() -> SupporterKey {
  SupporterKey::parse(fixture::APP, fixture::KEY).unwrap()
}

fn parts() -> [&'static str; 3] {
  let mut parts = fixture::KEY.split('.');
  let parts = [
    parts.next().unwrap(),
    parts.next().unwrap(),
    parts.next().unwrap(),
  ];
  assert_eq!(fixture::KEY.split('.').count(), 3);
  parts
}

fn nonce() -> [u8; 32] {
  decode_nonce(fixture::NONCE).unwrap()
}

#[test]
fn fixture_parses_and_derives_the_instance_key() {
  let key = key();
  assert_eq!(key.app(), "komodo");
  assert_eq!(HEXLOWER.encode(key.payload()), fixture::PAYLOAD_HEX);
  assert_eq!(
    BASE64URL_NOPAD.encode(key.payload_sig()),
    fixture::PAYLOAD_SIG
  );
  assert_eq!(
    BASE64URL_NOPAD.encode(key.instance_public_key()),
    fixture::INSTANCE_PUBLIC_KEY
  );
}

#[test]
fn whitespace_anywhere_is_removed() {
  let text = fixture::KEY;
  let variants = [
    format!("  {text}\n"),
    text.replace('.', " .\n\t"),
    // Inside every part, every 20 characters.
    text
      .chars()
      .enumerate()
      .flat_map(|(i, c)| {
        if i % 20 == 0 {
          vec![' ', c, '\n']
        } else {
          vec![c]
        }
      })
      .collect::<String>(),
    // Unicode whitespace too (no-break space, line separator).
    text.replacen('.', "\u{a0}.\u{2028}", 1),
  ];
  for variant in variants {
    let parsed = SupporterKey::parse(fixture::APP, &variant)
      .unwrap_or_else(|e| panic!("{variant:?}: {e}"));
    assert_eq!(parsed.payload(), key().payload());
    assert_eq!(
      parsed.instance_public_key(),
      key().instance_public_key()
    );
  }
}

#[test]
fn malformed_keys_are_rejected() {
  let [p, sp, i1] = parts();
  let err =
    |key: &str| SupporterKey::parse(fixture::APP, key).unwrap_err();

  assert_eq!(err(""), ParseError::Empty);
  assert_eq!(err(" \n"), ParseError::Empty);
  assert_eq!(err(&format!("{p}.{sp}")), ParseError::Parts(2));
  assert_eq!(
    err(&format!("{p}.{sp}.{i1}.{i1}")),
    ParseError::Parts(4)
  );
  assert_eq!(
    err(&format!("{p}..{i1}")),
    ParseError::EmptyPart("root signature")
  );
  assert_eq!(
    err(&format!(".{sp}.{i1}")),
    ParseError::EmptyPart("payload")
  );
  assert_eq!(
    err(&format!("{p}.{sp}.")),
    ParseError::EmptyPart("instance private key")
  );

  // Padding, and the characters of standard base64.
  for (key, part) in [
    (format!("{p}=.{sp}.{i1}"), "payload"),
    (format!("{p}.{sp}==.{i1}"), "root signature"),
    (format!("{p}.{sp}.{i1}="), "instance private key"),
    (format!("{}+{}.{sp}.{i1}", &p[..10], &p[11..]), "payload"),
    (
      format!("{p}.{}/{}.{i1}", &sp[..10], &sp[11..]),
      "root signature",
    ),
    (
      format!("{p}.{sp}.{}*{}", &i1[..10], &i1[11..]),
      "instance private key",
    ),
  ] {
    match err(&key) {
      ParseError::Base64 { part: got, .. } => {
        assert_eq!(got, part, "{key}")
      }
      other => panic!("{key}: {other:?}"),
    }
  }

  // Wrong lengths: 60 and 69 bytes of signature, 31 and 33 of seed.
  assert_eq!(
    err(&format!("{p}.{}.{i1}", &sp[..sp.len() - 6])),
    ParseError::Length {
      part: "root signature",
      expected: 64,
      got: 60
    }
  );
  assert_eq!(
    err(&format!("{p}.{sp}AAAAAA.{i1}")),
    ParseError::Length {
      part: "root signature",
      expected: 64,
      got: 69
    }
  );
  assert_eq!(
    err(&format!("{p}.{sp}.{}", BASE64URL_NOPAD.encode(&[1; 31]))),
    ParseError::Length {
      part: "instance private key",
      expected: 32,
      got: 31
    }
  );
  assert_eq!(
    err(&format!("{p}.{sp}.{}", BASE64URL_NOPAD.encode(&[1; 33]))),
    ParseError::Length {
      part: "instance private key",
      expected: 32,
      got: 33
    }
  );

  // A payload over 4 KiB.
  let long = BASE64URL_NOPAD.encode(&[0xa0; 4097]);
  assert_eq!(
    err(&format!("{long}.{sp}.{i1}")),
    ParseError::PayloadTooLong(4097)
  );
  // Exactly 4 KiB parses (the payload isn't decoded by `parse`).
  let max = BASE64URL_NOPAD.encode(&[0xa0; 4096]);
  SupporterKey::parse(fixture::APP, &format!("{max}.{sp}.{i1}"))
    .unwrap();

  // Errors never carry the key.
  for key in [format!("{p}=.{sp}.{i1}"), format!("{p}.{sp}")] {
    let text = format!("{:?} {}", err(&key), err(&key));
    assert!(!text.contains(&i1[..8]), "{text}");
    assert!(!text.contains(&p[..8]), "{text}");
  }
}

#[test]
fn responds_with_the_fixture_signature() {
  let response = key().respond(&nonce());
  assert_eq!(response, fixture::response());
  assert_eq!(response.nonce_sig, fixture::NONCE_SIG);
  // Deterministic.
  assert_eq!(key().respond(&nonce()), response);
  // Another nonce, another signature.
  assert_ne!(key().respond(&[2; 32]).nonce_sig, response.nonce_sig);
  // The same key for another app signs another message.
  let cicada = SupporterKey::parse("cicada", fixture::KEY).unwrap();
  assert_ne!(cicada.respond(&nonce()).nonce_sig, response.nonce_sig);
  assert_eq!(cicada.respond(&nonce()).payload, response.payload);
}

#[test]
fn response_json_shape_is_pinned() {
  // The typescript package reads these names.
  let json = serde_json::to_value(fixture::response()).unwrap();
  assert_eq!(
    json,
    serde_json::json!({
      "payload": fixture::PAYLOAD,
      "payload_sig": fixture::PAYLOAD_SIG,
      "instance_public_key": fixture::INSTANCE_PUBLIC_KEY,
      "nonce_sig": fixture::NONCE_SIG,
    })
  );
}

#[test]
fn nonce_message_layout() {
  let message = nonce_message("komodo", &nonce(), key().payload());
  assert_eq!(message.len(), 19 + 32 + 32);
  assert_eq!(&message[..19], b"komodo-supporter-v1");
  assert_eq!(&message[19..51], &[1; 32]);
  assert_eq!(
    HEXLOWER.encode(&message[51..]),
    HEXLOWER.encode(&<sha2::Sha256 as sha2::Digest>::digest(
      key().payload()
    ))
  );
}

#[test]
fn nonce_must_be_32_bytes_base64url() {
  assert_eq!(nonce(), [1; 32]);
  assert_eq!(
    decode_nonce(&BASE64URL_NOPAD.encode(&[1; 31])),
    Err(NonceError::Length(31))
  );
  assert_eq!(
    decode_nonce(&BASE64URL_NOPAD.encode(&[1; 33])),
    Err(NonceError::Length(33))
  );
  assert_eq!(decode_nonce(""), Err(NonceError::Length(0)));
  for nonce in [
    format!("{}=", fixture::NONCE),
    fixture::NONCE.replacen('A', "+", 1),
    format!(" {}", fixture::NONCE),
    // Non canonical trailing bits.
    format!("{}B", &fixture::NONCE[..fixture::NONCE.len() - 1]),
  ] {
    assert!(
      matches!(decode_nonce(&nonce), Err(NonceError::Base64(_))),
      "{nonce:?}"
    );
  }
}

#[test]
fn payload_decodes() {
  let payload = key().decode_payload().unwrap();
  assert_eq!(
    payload,
    Payload {
      version: 1,
      root_key_id: HEXLOWER
        .decode(b"fe812c12f3ab4ce6")
        .unwrap()
        .try_into()
        .unwrap(),
      id: HEXLOWER
        .decode(b"0190a3c27b6a7cc2b1f04a5d9e3c8f21")
        .unwrap()
        .try_into()
        .unwrap(),
      app: "komodo".into(),
      name: fixture::NAME.into(),
      tier: fixture::TIER,
      since: fixture::SINCE.into(),
      covers: fixture::COVERS.into(),
    }
  );
  assert_eq!(payload.id_string(), fixture::ID);
  assert_eq!(payload.root_key_id_hex(), fixture::ROOT_KEY_ID);
  assert_eq!(Tier::Organization.to_string(), "organization");
  assert_eq!("sponsor".parse::<Tier>(), Ok(Tier::Sponsor));
  assert_eq!("Sponsor".parse::<Tier>(), Err(PayloadError::Tier));
}

/// The fixture payload with `field` replaced by `value` (diagnostic
/// notation is not available, so the map is rebuilt by hand).
fn payload_with(field: &str, value: &[u8]) -> Vec<u8> {
  let fields: [(&str, &[u8]); 8] = [
    ("v", &[0x01]),
    ("k", &[0x48, 0xfe, 0x81, 0x2c, 0x12, 0xf3, 0xab, 0x4c, 0xe6]),
    (
      "i",
      &[
        0x50, 0x01, 0x90, 0xa3, 0xc2, 0x7b, 0x6a, 0x7c, 0xc2, 0xb1,
        0xf0, 0x4a, 0x5d, 0x9e, 0x3c, 0x8f, 0x21,
      ],
    ),
    ("a", b"\x66komodo"),
    ("n", b"\x69Acme Corp"),
    ("t", b"\x6corganization"),
    ("s", b"\x6a2025-01-15"),
    ("c", b"\x6a2027-09-30"),
  ];
  let mut out = vec![0xa8];
  for (name, encoded) in fields {
    out.push(0x61);
    out.push(name.as_bytes()[0]);
    out.extend_from_slice(if name == field {
      value
    } else {
      encoded
    });
  }
  out
}

#[test]
fn payload_fields_are_checked() {
  // The rebuilt payload is the fixture.
  assert_eq!(
    HEXLOWER.encode(&payload_with("", &[])),
    fixture::PAYLOAD_HEX
  );
  let err = |field, value: &[u8]| {
    Payload::decode(&payload_with(field, value)).unwrap_err()
  };
  assert_eq!(
    err("v", &[0x61, 0x31]),
    PayloadError::Type("v", "an unsigned integer")
  );
  assert_eq!(
    err("v", &[0x20]),
    PayloadError::Type("v", "an unsigned integer")
  );
  assert_eq!(
    err("k", &[0x47, 1, 2, 3, 4, 5, 6, 7]),
    PayloadError::Length {
      field: "k",
      expected: 8,
      got: 7
    }
  );
  assert_eq!(
    err("k", &[0x68, b'f', b'e', b'8', b'1', b'2', b'c', b'1', b'2']),
    PayloadError::Type("k", "a byte string")
  );
  assert_eq!(
    err("i", &[0x40]),
    PayloadError::Length {
      field: "i",
      expected: 16,
      got: 0
    }
  );
  assert_eq!(err("a", &[0x01]), PayloadError::Type("a", "text"));
  assert_eq!(err("t", b"\x66patron"), PayloadError::Tier);
  assert_eq!(err("c", b"\x6a2027/09/30"), PayloadError::Date("c"));
  assert_eq!(err("c", b"\x692027-9-30"), PayloadError::Date("c"));
  assert_eq!(err("s", b"\x6a2025-01-1x"), PayloadError::Date("s"));
  assert_eq!(err("n", &[0xf6]), PayloadError::Type("n", "text"));
  // A missing field: 7 pairs.
  let mut short = payload_with("", &[]);
  short[0] = 0xa7;
  short.truncate(short.len() - 13);
  assert_eq!(
    Payload::decode(&short),
    Err(PayloadError::Missing("c"))
  );
  // Unknown fields are ignored, whatever their type.
  let mut extended = payload_with("", &[]);
  extended[0] = 0xaa;
  extended
    .extend_from_slice(&[0x61, b'x', 0x82, 0x01, 0xa1, 0x01, 0xf5]);
  extended.extend_from_slice(&[0x01, 0x40]);
  assert_eq!(Payload::decode(&extended), key().decode_payload());
  // Not a map.
  assert_eq!(Payload::decode(&[0x80]), Err(PayloadError::NotAMap));
  assert_eq!(
    Payload::decode(&[0xa0]),
    Err(PayloadError::Missing("v"))
  );
  assert_eq!(
    Payload::decode(&vec![0; 4097]),
    Err(PayloadError::TooLong(4097))
  );
  assert!(matches!(Payload::decode(&[]), Err(PayloadError::Cbor(_))));
}

#[test]
fn verifies_under_the_fixture_root() {
  let key = key();
  let payload = key.verify(&[fixture::ROOT]).unwrap();
  assert_eq!(payload.name, fixture::NAME);
  // Several roots, this one among them.
  // Another key (the example key of RFC 8410), and an entry which
  // is no key at all: passed over.
  let other =
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
  assert_eq!(
    key
      .verify(&[other, "not a key", fixture::ROOT])
      .unwrap()
      .name,
    fixture::NAME
  );

  // The root is found by the id derived from its key: without it,
  // no other key stands in.
  assert_eq!(
    key.verify(&[]),
    Err(VerifyError::UnknownRoot(fixture::ROOT_KEY_ID.into()))
  );
  assert_eq!(
    key.verify(&[other]),
    Err(VerifyError::UnknownRoot(fixture::ROOT_KEY_ID.into()))
  );
  // An entry copied wrong is another key, or none.
  assert_eq!(
    key.verify(&[
      "MCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ]),
    Err(VerifyError::UnknownRoot(fixture::ROOT_KEY_ID.into()))
  );

  let cicada = SupporterKey::parse("cicada", fixture::KEY).unwrap();
  assert_eq!(
    cicada.verify(&[fixture::ROOT]),
    Err(VerifyError::OtherApp {
      key_app: "komodo".into(),
      app: "cicada".into()
    })
  );
}

#[test]
fn tampering_fails_the_root_signature() {
  let [p, sp, i1] = parts();
  // A byte of the payload: the `A` of `Acme Corp`.
  let mut payload = BASE64URL_NOPAD.decode(p.as_bytes()).unwrap();
  let at = payload.windows(4).position(|w| w == b"Acme").unwrap();
  payload[at] = b'B';
  let tampered =
    format!("{}.{sp}.{i1}", BASE64URL_NOPAD.encode(&payload));
  let tampered =
    SupporterKey::parse(fixture::APP, &tampered).unwrap();
  assert_eq!(tampered.decode_payload().unwrap().name, "Bcme Corp");
  assert_eq!(
    tampered.verify(&[fixture::ROOT]),
    Err(VerifyError::Signature)
  );

  // Another instance key with the same payload and root signature.
  let other =
    format!("{p}.{sp}.{}", BASE64URL_NOPAD.encode(&[7; 32]));
  let other = SupporterKey::parse(fixture::APP, &other).unwrap();
  assert_ne!(
    other.instance_public_key(),
    key().instance_public_key()
  );
  assert_eq!(
    other.verify(&[fixture::ROOT]),
    Err(VerifyError::Signature)
  );

  // A bit of the signature.
  let mut sig = BASE64URL_NOPAD.decode(sp.as_bytes()).unwrap();
  sig[0] ^= 1;
  let bad_sig = format!("{p}.{}.{i1}", BASE64URL_NOPAD.encode(&sig));
  let bad_sig = SupporterKey::parse(fixture::APP, &bad_sig).unwrap();
  assert_eq!(
    bad_sig.verify(&[fixture::ROOT]),
    Err(VerifyError::Signature)
  );
}

#[test]
fn test_keys_are_minted_under_the_test_root() {
  // For another app, name and tier than the fixture key has.
  let key = fixture::mint("cicada", "Ada Lovelace", Tier::Individual);
  let parsed = SupporterKey::parse("cicada", &key).unwrap();
  let payload = parsed.verify(&[fixture::ROOT]).unwrap();
  assert_eq!(payload.app, "cicada");
  assert_eq!(payload.name, "Ada Lovelace");
  assert_eq!(payload.tier, Tier::Individual);
  assert_eq!(payload.since, fixture::SINCE);
  assert_eq!(payload.covers, fixture::COVERS);
  assert_eq!(payload.root_key_id_hex(), fixture::ROOT_KEY_ID);
  // Under the test root alone, and for its app alone.
  assert_eq!(
    parsed.verify(&[]),
    Err(VerifyError::UnknownRoot(fixture::ROOT_KEY_ID.into()))
  );
  assert!(matches!(
    SupporterKey::parse("komodo", &key)
      .unwrap()
      .verify(&[fixture::ROOT]),
    Err(VerifyError::OtherApp { .. })
  ));
  // The same input mints the same key, another input another one.
  assert_eq!(
    key,
    fixture::mint("cicada", "Ada Lovelace", Tier::Individual)
  );
  let other =
    fixture::mint("cicada", "Ada Lovelace", Tier::Organization);
  assert_ne!(key, other);
  let other = SupporterKey::parse("cicada", &other)
    .unwrap()
    .verify(&[fixture::ROOT])
    .unwrap();
  assert_ne!(other.id, payload.id);
  // Long names too: a text of 24 bytes and more.
  let long = "International Business Machines of Northern Europe";
  let key = fixture::mint("komodo", long, Tier::Sponsor);
  let payload = SupporterKey::parse("komodo", &key)
    .unwrap()
    .verify(&[fixture::ROOT])
    .unwrap();
  assert_eq!(payload.name, long);
  // It answers a nonce like any key.
  let nonce = decode_nonce(fixture::NONCE).unwrap();
  let answer =
    SupporterKey::parse("komodo", &key).unwrap().respond(&nonce);
  assert_eq!(answer.nonce_sig.len(), 86);
}

#[test]
fn an_apps_root_keys_are_checked() {
  use crate::{RootKeysError, check_root_keys};

  // No root keys yet: no key verifies, which is fine.
  assert_eq!(check_root_keys(&[]), Ok(Vec::new()));
  // Another key than the fixture's test root (whose seed is 32
  // bytes of 0x07): 32 bytes of 0x09 as the seed.
  let other = {
    use ed25519_dalek::SigningKey;
    let raw =
      SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let mut der = vec![
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03,
      0x21, 0x00,
    ];
    der.extend_from_slice(&raw);
    data_encoding::BASE64.encode(&der)
  };
  let other_id = root_key_id(&other).unwrap();
  // Their ids, in order: to compare with what the platform published.
  let rfc =
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
  assert_eq!(
    check_root_keys(&[&other, rfc]),
    Ok(vec![other_id.clone(), root_key_id(rfc).unwrap()])
  );
  // The test root of the fixture is public.
  assert_eq!(
    check_root_keys(&[&other, fixture::ROOT]),
    Err(RootKeysError::Fixture(fixture::ROOT_KEY_ID.into()))
  );
  // Not a key at all: named by its position.
  assert_eq!(
    check_root_keys(&[&other, "MCowBQYDK2VwAyEA"]),
    Err(RootKeysError::Key {
      position: 2,
      error: RootKeyError::Spki,
    })
  );
  // Listed twice, also when written another way.
  assert_eq!(
    check_root_keys(&[&other, &format!(" {other}\n")]),
    Err(RootKeysError::Duplicate(other_id))
  );
}

#[test]
fn root_key_ids_are_derived_from_the_raw_key() {
  assert_eq!(
    root_key_id(fixture::ROOT).unwrap(),
    fixture::ROOT_KEY_ID
  );
  assert_eq!(
    root_key_id(&format!(" {}\n", fixture::ROOT)).unwrap(),
    fixture::ROOT_KEY_ID
  );
  assert_eq!(root_key_bytes(fixture::ROOT).unwrap().len(), 32);
  assert_eq!(root_key_id("not base64!"), Err(RootKeyError::Base64));
  // An X25519 key.
  assert_eq!(
    root_key_id(
      "MCowBQYDK2VuAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="
    ),
    Err(RootKeyError::Spki)
  );
  // The identity point: low order.
  assert_eq!(
    root_key_id(
      "MCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ),
    Err(RootKeyError::Invalid)
  );
}

#[test]
fn debug_is_redacted() {
  let [_, _, i1] = parts();
  let seed = BASE64URL_NOPAD.decode(i1.as_bytes()).unwrap();
  let debug = format!("{:?}", key());
  assert!(debug.contains(fixture::INSTANCE_PUBLIC_KEY), "{debug}");
  assert!(!debug.contains(i1), "{debug}");
  assert!(!debug.contains(&HEXLOWER.encode(&seed)), "{debug}");
  assert!(!debug.contains(&format!("{seed:?}")), "{debug}");
}

#[test]
fn load_ignores_what_does_not_parse() {
  assert!(SupporterKey::load(fixture::APP, "", &[]).is_none());
  assert!(SupporterKey::load(fixture::APP, " \n", &[]).is_none());
  assert!(SupporterKey::load(fixture::APP, "garbage", &[]).is_none());
  // Served even when it would show no badge (no root here).
  let key =
    SupporterKey::load(fixture::APP, fixture::KEY, &[]).unwrap();
  assert_eq!(key.respond(&nonce()), fixture::response());
  let key =
    SupporterKey::load(fixture::APP, fixture::KEY, &[fixture::ROOT])
      .unwrap();
  assert_eq!(key.respond(&nonce()), fixture::response());
}

#[test]
fn cbor_decodes_the_subset() {
  let payload =
    HEXLOWER.decode(fixture::PAYLOAD_HEX.as_bytes()).unwrap();
  let CborValue::Map(pairs) = decode_cbor(&payload).unwrap() else {
    panic!()
  };
  assert_eq!(pairs.len(), 8);
  assert_eq!(
    pairs[0],
    (CborValue::Text("v".into()), CborValue::Unsigned(1))
  );
  assert_eq!(
    pairs[4],
    (
      CborValue::Text("n".into()),
      CborValue::Text("Acme Corp".into())
    )
  );

  let ok = |bytes: &[u8]| decode_cbor(bytes).unwrap();
  assert_eq!(ok(&[0x17]), CborValue::Unsigned(23));
  assert_eq!(ok(&[0x18, 0x18]), CborValue::Unsigned(24));
  assert_eq!(ok(&[0x19, 0x01, 0x00]), CborValue::Unsigned(256));
  assert_eq!(ok(&[0x1a, 0, 1, 0, 0]), CborValue::Unsigned(65536));
  assert_eq!(
    ok(&[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
    CborValue::Unsigned(1 << 32)
  );
  assert_eq!(ok(&[0x20]), CborValue::Negative(0));
  assert_eq!(ok(&[0x38, 0x63]), CborValue::Negative(99));
  assert_eq!(ok(&[0x42, 1, 2]), CborValue::Bytes(vec![1, 2]));
  assert_eq!(ok(&[0x60]), CborValue::Text(String::new()));
  assert_eq!(
    ok(&[0x63, 0xe2, 0x82, 0xac]),
    CborValue::Text("€".into())
  );
  assert_eq!(
    ok(&[0x82, 0x01, 0xf6]),
    CborValue::Array(vec![CborValue::Unsigned(1), CborValue::Null])
  );
  assert_eq!(
    ok(&[0xa2, 0x01, 0xf4, 0x61, 0x61, 0xf5]),
    CborValue::Map(vec![
      (CborValue::Unsigned(1), CborValue::Bool(false)),
      (CborValue::Text("a".into()), CborValue::Bool(true)),
    ])
  );
  assert_eq!(ok(&[0xa0]), CborValue::Map(vec![]));
  // Text keys only in `get`.
  assert_eq!(
    ok(&[0xa1, 0x61, 0x61, 0x02]).get("a"),
    Some(&CborValue::Unsigned(2))
  );
  assert_eq!(ok(&[0xa1, 0x01, 0x02]).get("1"), None);
  assert_eq!(ok(&[0x01]).get("a"), None);
}

#[test]
fn cbor_rejects_the_rest() {
  let err = |bytes: &[u8]| decode_cbor(bytes).unwrap_err();
  assert_eq!(err(&[]), CborError::UnexpectedEnd(0));
  assert_eq!(err(&[0x18]), CborError::UnexpectedEnd(1));
  assert_eq!(err(&[0x42, 1]), CborError::UnexpectedEnd(1));
  // Two items can't fit in one byte: refused before the first is read.
  assert_eq!(err(&[0x82, 1]), CborError::UnexpectedEnd(1));
  assert_eq!(err(&[0xa1, 1]), CborError::UnexpectedEnd(2));
  assert_eq!(
    err(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    CborError::UnexpectedEnd(9)
  );
  assert_eq!(err(&[0x9f, 0x01, 0xff]), CborError::Indefinite(0));
  assert_eq!(
    err(&[0x5f, 0x41, 0x01, 0xff]),
    CborError::Indefinite(0)
  );
  assert_eq!(err(&[0xbf, 0xff]), CborError::Indefinite(0));
  assert_eq!(err(&[0x81, 0xff]), CborError::Indefinite(1));
  assert_eq!(err(&[0xc0, 0x61, 0x61]), CborError::Tag(0));
  assert_eq!(err(&[0xd8, 0x18, 0x01]), CborError::Tag(0));
  assert_eq!(err(&[0xf9, 0x3c, 0x00]), CborError::Float(0));
  assert_eq!(err(&[0xfa, 0, 0, 0, 0]), CborError::Float(0));
  assert_eq!(
    err(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]),
    CborError::Float(0)
  );
  // `undefined`, a one byte simple value, reserved additional info.
  assert_eq!(
    err(&[0xf7]),
    CborError::Unsupported {
      major: 7,
      info: 23,
      at: 0
    }
  );
  assert_eq!(
    err(&[0xf8, 0x20]),
    CborError::Unsupported {
      major: 7,
      info: 24,
      at: 0
    }
  );
  assert_eq!(
    err(&[0x1c]),
    CborError::Unsupported {
      major: 0,
      info: 28,
      at: 0
    }
  );
  assert_eq!(err(&[0x61, 0xff]), CborError::Utf8(0));
  assert_eq!(
    err(&[0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02]),
    CborError::DuplicateKey(4)
  );
  assert_eq!(
    err(&[0xa2, 0x01, 0x01, 0x01, 0x02]),
    CborError::DuplicateKey(3)
  );
  assert_eq!(err(&[0x01, 0x02]), CborError::TrailingBytes(1));
  assert_eq!(err(&[0xa0, 0x00, 0x00]), CborError::TrailingBytes(2));
  // 16 nested arrays decode, 17 don't.
  let mut nested = vec![0x81; 15];
  nested.push(0x80);
  decode_cbor(&nested).unwrap();
  nested.insert(0, 0x81);
  assert_eq!(err(&nested), CborError::TooDeep(16));
  let mut maps = vec![0xa1, 0x01];
  for _ in 0..15 {
    maps.extend_from_slice(&[0xa1, 0x01]);
  }
  maps.push(0xa0);
  assert_eq!(err(&maps), CborError::TooDeep(32));
  // Errors never echo the input.
  assert!(!format!("{}", err(&[0x61, 0xff])).contains("ff"));
}

#[test]
fn compact_key_strips_whitespace() {
  assert_eq!(
    *crate::compact_key(" a b\nc\t\u{a0}d "),
    "abcd".to_string()
  );
  assert_eq!(*crate::compact_key(""), String::new());
}

#[test]
fn api_json_shapes_are_pinned() {
  use crate::api::*;
  // The typescript package reads these.
  let info = SupporterKeyInfo {
    source: SupporterKeySource::Stored,
    config_key: true,
    supporter: Some(key().decode_payload().unwrap().into()),
    problem: None,
  };
  assert_eq!(
    serde_json::to_value(&info).unwrap(),
    serde_json::json!({
      "source": "Stored",
      "config_key": true,
      "supporter": {
        "version": 1,
        "root_key_id": fixture::ROOT_KEY_ID,
        "id": fixture::ID,
        "app": "komodo",
        "name": fixture::NAME,
        "tier": "organization",
        "since": fixture::SINCE,
        "covers": fixture::COVERS,
      },
      "problem": null,
    })
  );
  assert_eq!(
    serde_json::to_string(&SupporterKeySource::None).unwrap(),
    "\"None\""
  );
  assert_eq!(
    serde_json::to_string(&SetSupporterKey { key: "k".into() })
      .unwrap(),
    r#"{"key":"k"}"#
  );
  assert_eq!(
    serde_json::from_str::<Tier>("\"sponsor\"").unwrap(),
    Tier::Sponsor
  );
  assert!(serde_json::from_str::<Tier>("\"Sponsor\"").is_err());
}

#[test]
fn branding_icons_are_checked() {
  use crate::{
    BrandingError, MAX_ICON_BYTES, MAX_ICON_URL_LENGTH, check_icon,
  };
  use data_encoding::BASE64;

  for icon in [
    "https://example.com/logo.png",
    "http://10.0.0.5:9120/logo.svg?v=2#x",
    "https://example.com",
    "/icons/acme.png",
    "/logo",
    "data:image/png;base64,AQID",
    "data:image/svg+xml;base64,PHN2Zy8+",
    "data:image/jpeg;base64,AQ==",
    "data:image/webp;base64,AQI=",
    "data:image/gif;base64,AQID",
  ] {
    assert_eq!(check_icon(icon), Ok(()), "{icon}");
  }
  for icon in [
    "",
    "logo.png",
    "./logo.png",
    "//evil.example/logo.png",
    "/\\evil.example/logo.png",
    "javascript:alert(1)",
    "ftp://example.com/logo.png",
    "HTTPS://example.com/logo.png",
    "https://",
    "https:///logo.png",
    "https://example.com/a logo.png",
    "https://example.com/logo.png\n",
    "/icons/\u{7}.png",
    "data:image/png,AQID",
    "data:text/html;base64,AQID",
    "data:;base64,AQID",
  ] {
    let got = check_icon(icon);
    assert!(
      matches!(
        got,
        Err(BrandingError::IconForm | BrandingError::IconMediaType)
      ),
      "{icon:?}: {got:?}"
    );
  }
  assert_eq!(
    check_icon("data:text/html;base64,AQID"),
    Err(BrandingError::IconMediaType)
  );
  assert_eq!(
    check_icon("data:image/png;base64,AQI"),
    Err(BrandingError::IconEncoding)
  );
  assert_eq!(
    check_icon("data:image/png;base64,A-_D"),
    Err(BrandingError::IconEncoding)
  );
  assert_eq!(
    check_icon("data:image/png;base64,"),
    Err(BrandingError::IconEmpty)
  );
  // The image itself is bounded, not its base64.
  let most = BASE64.encode(&vec![7u8; MAX_ICON_BYTES]);
  assert_eq!(
    check_icon(&format!("data:image/png;base64,{most}")),
    Ok(())
  );
  let over = BASE64.encode(&vec![7u8; MAX_ICON_BYTES + 1]);
  assert_eq!(
    check_icon(&format!("data:image/png;base64,{over}")),
    Err(BrandingError::IconBytes(MAX_ICON_BYTES + 1))
  );
  let far_over = "A".repeat(4 * MAX_ICON_BYTES);
  assert!(matches!(
    check_icon(&format!("data:image/png;base64,{far_over}")),
    Err(BrandingError::IconBytes(_))
  ));
  let long = format!(
    "https://example.com/{}",
    "a".repeat(MAX_ICON_URL_LENGTH)
  );
  assert_eq!(
    check_icon(&long),
    Err(BrandingError::IconUrlLength(long.len()))
  );
  // Errors never echo the icon.
  let text =
    check_icon("javascript:alert(1)").unwrap_err().to_string();
  assert!(!text.contains("alert"), "{text}");
}

#[test]
fn branding_is_validated_and_normalized() {
  use crate::{
    BrandingError, MAX_ICON_HEIGHT, MAX_ICON_WIDTH, MIN_ICON_SIZE,
    SupporterBranding,
  };

  assert!(SupporterBranding::default().is_default());
  assert_eq!(
    SupporterBranding::default().validated(),
    Ok(SupporterBranding::default())
  );
  // The icon trimmed, an empty one as none.
  let branding = SupporterBranding {
    icon: Some(" /icons/acme.png\n".into()),
    icon_width: Some(120),
    icon_height: Some(32),
    link: Some(" https://acme.example/about\n".into()),
    replace_home: true,
    hide_name: true,
    uppercase_name: true,
  };
  let valid = branding.clone().validated().unwrap();
  assert_eq!(valid.icon.as_deref(), Some("/icons/acme.png"));
  // So is the link.
  assert_eq!(
    valid.link.as_deref(),
    Some("https://acme.example/about")
  );
  let blank_link = SupporterBranding {
    link: Some("  ".into()),
    ..Default::default()
  };
  assert!(blank_link.validated().unwrap().is_default());
  assert!(
    !SupporterBranding {
      link: Some("https://acme.example".into()),
      ..Default::default()
    }
    .is_default()
  );
  assert_eq!(
    SupporterBranding {
      link: Some("javascript:alert(1)".into()),
      ..Default::default()
    }
    .validated(),
    Err(BrandingError::LinkForm)
  );
  assert_eq!(
    (valid.icon_width, valid.icon_height),
    (Some(120), Some(32))
  );
  assert!(valid.replace_home && !valid.is_default());
  // The name is hidden with an icon, which stands for it.
  assert!(valid.hide_name);
  // In capitals, with or without an icon.
  assert!(valid.uppercase_name);
  let capitals = SupporterBranding {
    uppercase_name: true,
    ..Default::default()
  };
  assert_eq!(capitals.clone().validated(), Ok(capitals.clone()));
  assert!(!capitals.is_default());
  // Never without one: nothing would name the supporter.
  for icon in [None, Some(String::new()), Some("  ".into())] {
    let without = SupporterBranding {
      icon,
      hide_name: true,
      ..Default::default()
    }
    .validated()
    .unwrap();
    assert!(!without.hide_name);
    assert!(without.is_default());
  }
  assert!(
    !SupporterBranding {
      hide_name: true,
      ..Default::default()
    }
    .is_default()
  );
  assert_eq!(valid.icon_kind(), "url");
  let blank = SupporterBranding {
    icon: Some("  ".into()),
    ..Default::default()
  };
  assert!(blank.validated().unwrap().is_default());
  let uploaded = SupporterBranding {
    icon: Some("data:image/png;base64,AQID".into()),
    ..Default::default()
  };
  assert_eq!(uploaded.icon_kind(), "uploaded");
  assert_eq!(SupporterBranding::default().icon_kind(), "none");

  assert_eq!(
    SupporterBranding {
      icon: Some("logo.png".into()),
      ..Default::default()
    }
    .validated(),
    Err(BrandingError::IconForm)
  );
  // The size, in both directions.
  for (width, height, ok) in [
    (Some(MIN_ICON_SIZE), Some(MIN_ICON_SIZE), true),
    (Some(MAX_ICON_WIDTH), Some(MAX_ICON_HEIGHT), true),
    (None, Some(40), true),
    (Some(MIN_ICON_SIZE - 1), None, false),
    (Some(0), None, false),
    (Some(MAX_ICON_WIDTH + 1), None, false),
    (None, Some(MIN_ICON_SIZE - 1), false),
    (None, Some(MAX_ICON_HEIGHT + 1), false),
  ] {
    let result = SupporterBranding {
      icon_width: width,
      icon_height: height,
      ..Default::default()
    }
    .validated();
    assert_eq!(
      result.is_ok(),
      ok,
      "{width:?} x {height:?}: {result:?}"
    );
  }
  assert_eq!(
    SupporterBranding {
      icon_height: Some(MAX_ICON_HEIGHT + 1),
      ..Default::default()
    }
    .validated(),
    Err(BrandingError::IconSize {
      dimension: "height",
      got: MAX_ICON_HEIGHT + 1,
      max: MAX_ICON_HEIGHT
    })
  );
}

#[test]
fn branding_links_are_web_addresses() {
  use crate::{BrandingError, MAX_LINK_LENGTH, check_link};

  for link in [
    "https://acme.example",
    "https://acme.example/about?from=komodo#team",
    "http://intranet.acme.example:8080/",
    "https://xn--mnchen-3ya.example",
  ] {
    assert_eq!(check_link(link), Ok(()), "{link}");
  }
  // Nothing but a web address is opened by a click on the badge.
  for link in [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD4=",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
    "ftp://acme.example",
    "//acme.example",
    "/settings",
    "acme.example",
    "www.acme.example",
    "https://",
    "https:///path",
    "https://?query",
    "HTTPS://acme.example",
    "https://acme.example/a b",
    "https://acme.example/\n",
    " https://acme.example",
    "https://acme.example\u{0}",
    "",
  ] {
    assert_eq!(
      check_link(link),
      Err(BrandingError::LinkForm),
      "{link:?}"
    );
  }
  // Its length.
  let longest = format!(
    "https://acme.example/{}",
    "a".repeat(MAX_LINK_LENGTH - 21)
  );
  assert_eq!(longest.len(), MAX_LINK_LENGTH);
  assert_eq!(check_link(&longest), Ok(()));
  assert_eq!(
    check_link(&format!("{longest}a")),
    Err(BrandingError::LinkLength(MAX_LINK_LENGTH + 1))
  );
  // Errors never echo the link.
  let text =
    check_link("javascript:alert(1)").unwrap_err().to_string();
  assert!(!text.contains("alert"), "{text}");
}

#[test]
fn branding_json_shape_is_pinned() {
  use crate::{SupporterBranding, api::SetSupporterBranding};
  // The typescript package reads these. Unset fields are left out.
  assert_eq!(
    serde_json::to_string(&SupporterBranding::default()).unwrap(),
    r#"{"replace_home":false,"hide_name":false,"uppercase_name":false}"#
  );
  let branding = SupporterBranding {
    icon: Some("/icons/acme.png".into()),
    icon_width: Some(120),
    icon_height: Some(32),
    link: Some("https://acme.example".into()),
    replace_home: true,
    hide_name: true,
    uppercase_name: true,
  };
  assert_eq!(
    serde_json::to_value(&branding).unwrap(),
    serde_json::json!({
      "icon": "/icons/acme.png",
      "icon_width": 120,
      "icon_height": 32,
      "link": "https://acme.example",
      "replace_home": true,
      "hide_name": true,
      "uppercase_name": true,
    })
  );
  // Everything is optional when read, also `null`.
  for json in [
    "{}",
    r#"{"icon":null,"icon_width":null,"icon_height":null,"link":null}"#,
  ] {
    assert_eq!(
      serde_json::from_str::<SupporterBranding>(json).unwrap(),
      SupporterBranding::default(),
      "{json}"
    );
  }
  let request: SetSupporterBranding =
    serde_json::from_str(r#"{"branding":{"replace_home":true}}"#)
      .unwrap();
  assert!(request.branding.replace_home);
  // A branding kept before the name could be hidden reads as it was.
  assert!(!request.branding.hide_name);
  assert!(!request.branding.uppercase_name);
}
