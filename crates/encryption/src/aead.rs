//! Authenticated encryption under a [Key], with the cipher chosen
//! per call ([Cipher]) and recorded on the ciphertext through its
//! format marker, so decryption needs no out of band knowledge.

use aes_gcm::Aes256Gcm;
use anyhow::{Context, anyhow};
use chacha20poly1305::{
  KeyInit, XChaCha20Poly1305,
  aead::{Aead, AeadCore, Nonce, Payload},
};
use data_encoding::BASE64URL;
use rand::{TryRng as _, rngs::SysRng};
use zeroize::Zeroizing;

use crate::{
  AssociatedData, Cipher, EncryptedData, EnvelopeEncryptedData, Key,
};

/// Encrypts the given bytes using the given key, a random nonce,
/// and the given associated data, with `cipher`.
///
/// The nonce is read directly from the OS random source ([SysRng]),
/// so it cannot repeat across a `fork` the way a userspace
/// generator's stream can.
pub fn encrypt<A: AssociatedData>(
  data: &[u8],
  key: &Key,
  associated_data: &A,
  cipher: Cipher,
) -> anyhow::Result<EncryptedData> {
  let mut nonce = vec![0u8; cipher.nonce_len()];
  SysRng
    .try_fill_bytes(&mut nonce)
    .context("Failed to read nonce from the OS random source")?;
  let payload = Payload {
    msg: data,
    aad: associated_data.as_bytes(),
  };
  let sealed = match cipher {
    Cipher::XChaCha20Poly1305 => {
      XChaCha20Poly1305::new(key.as_bytes().into())
        .encrypt(&nonce_array::<XChaCha20Poly1305>(&nonce)?, payload)
    }
    Cipher::Aes256Gcm => Aes256Gcm::new(key.as_bytes().into())
      .encrypt(&nonce_array::<Aes256Gcm>(&nonce)?, payload),
  }
  .map_err(|e| anyhow!("Encryption failed | {e:?}"))?;
  Ok(EncryptedData {
    data: cipher.mark(&BASE64URL.encode(&sealed)),
    nonce: BASE64URL.encode(&nonce),
  })
}

/// Encrypts the given bytes using a random key, a random nonce,
/// and the given associated data. Then encrypts the key using
/// the master key, a random nonce, and the same associated
/// data. Both layers use `cipher`.
pub fn envelope_encrypt<A: AssociatedData>(
  data: &[u8],
  master_key: &Key,
  associated_data: &A,
  cipher: Cipher,
) -> anyhow::Result<EnvelopeEncryptedData> {
  let key = Key::try_generate()?;
  let data = encrypt(data, &key, associated_data, cipher)?;
  let key =
    encrypt(key.as_bytes(), master_key, associated_data, cipher)?;
  Ok(EnvelopeEncryptedData { key, data })
}

/// Decrypts the given [EncryptedData] back into bytes using the
/// given key and the given associated data, with the cipher its
/// format marker names. The plaintext is wiped when dropped.
pub fn decrypt<A: AssociatedData>(
  EncryptedData { data, nonce }: &EncryptedData,
  key: &Key,
  associated_data: &A,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
  let (cipher, payload) = Cipher::parse(data)?;
  let data = BASE64URL
    .decode(payload.as_bytes())
    .context("Data is not valid base64url")?;
  let nonce = BASE64URL
    .decode(nonce.as_bytes())
    .context("Nonce is not valid base64url")?;
  if nonce.len() != cipher.nonce_len() {
    return Err(anyhow!("Invalid nonce"));
  }
  let payload = Payload {
    msg: &data,
    aad: associated_data.as_bytes(),
  };
  match cipher {
    Cipher::XChaCha20Poly1305 => {
      XChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt(&nonce_array::<XChaCha20Poly1305>(&nonce)?, payload)
    }
    Cipher::Aes256Gcm => Aes256Gcm::new(key.as_bytes().into())
      .decrypt(&nonce_array::<Aes256Gcm>(&nonce)?, payload),
  }
  .map(Zeroizing::new)
  .map_err(|e| anyhow!("Decryption failed | {e:?}"))
}

/// [decrypt] for text: the plaintext as a string, wiped when
/// dropped like the bytes. Plaintext which is not UTF-8 is an error.
pub fn decrypt_string<A: AssociatedData>(
  encrypted: &EncryptedData,
  key: &Key,
  associated_data: &A,
) -> anyhow::Result<Zeroizing<String>> {
  into_string(decrypt(encrypted, key, associated_data)?)
}

/// The nonce bytes as the cipher's fixed size nonce,
/// erroring (never panicking) on a length mismatch.
fn nonce_array<A: AeadCore>(
  nonce: &[u8],
) -> anyhow::Result<Nonce<A>> {
  Nonce::<A>::try_from(nonce).map_err(|_| anyhow!("Invalid nonce"))
}

/// Decrypts the given [EnvelopeEncryptedData] back into bytes
/// using the given master key and the given associated data; each
/// layer uses the cipher its own marker names. The plaintext (and
/// the unwrapped data key) are wiped when dropped.
pub fn envelope_decrypt<A: AssociatedData>(
  EnvelopeEncryptedData { key, data }: &EnvelopeEncryptedData,
  master_key: &Key,
  associated_data: &A,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
  let key = unwrap_data_key(key, master_key, associated_data)?;
  decrypt(data, &key, associated_data)
}

/// [envelope_decrypt] for text: the plaintext as a string, wiped
/// when dropped like the bytes. Plaintext which is not UTF-8 is an
/// error.
pub fn envelope_decrypt_string<A: AssociatedData>(
  envelope: &EnvelopeEncryptedData,
  master_key: &Key,
  associated_data: &A,
) -> anyhow::Result<Zeroizing<String>> {
  into_string(envelope_decrypt(
    envelope,
    master_key,
    associated_data,
  )?)
}

/// Moves the envelope onto another master key (a master key
/// rotation): its data key is decrypted with `old_master_key` and
/// encrypted again under `new_master_key` with `cipher`, bound to the
/// same associated data.
///
/// The data layer is kept byte for byte (and keeps its cipher), so
/// this costs the same whatever the size of the data. It is still
/// decrypted (the plaintext is dropped, wiped), so an envelope whose
/// data doesn't decrypt is an error, rather than moved onto the new
/// key as if it were readable, to fail on its next read.
pub fn envelope_rewrap<A: AssociatedData>(
  envelope: &EnvelopeEncryptedData,
  old_master_key: &Key,
  new_master_key: &Key,
  associated_data: &A,
  cipher: Cipher,
) -> anyhow::Result<EnvelopeEncryptedData> {
  let data_key =
    unwrap_data_key(&envelope.key, old_master_key, associated_data)?;
  decrypt(&envelope.data, &data_key, associated_data)
    .context("The envelope's data does not decrypt with its key")?;
  let key = encrypt(
    data_key.as_bytes(),
    new_master_key,
    associated_data,
    cipher,
  )?;
  Ok(EnvelopeEncryptedData {
    key,
    data: envelope.data.clone(),
  })
}

/// The data key of an envelope, decrypted with the master key.
fn unwrap_data_key<A: AssociatedData>(
  key: &EncryptedData,
  master_key: &Key,
  associated_data: &A,
) -> anyhow::Result<Key> {
  let key = decrypt(key, master_key, associated_data)?;
  Key::from_slice(&key).ok_or_else(|| {
    anyhow!(
      "The envelope encryption key is not 32 bytes after decryption"
    )
  })
}

/// The plaintext as text. Checked in place, then copied into a
/// buffer wiped on drop: `String::from_utf8` would hand the bytes to
/// its error value, which is never wiped.
fn into_string(
  plaintext: Zeroizing<Vec<u8>>,
) -> anyhow::Result<Zeroizing<String>> {
  let text = std::str::from_utf8(&plaintext)
    .map_err(|_| anyhow!("Decrypted data is not valid UTF-8"))?;
  Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn key() -> Key {
    Key::from_bytes(&mut [7u8; 32])
  }
  fn other_key() -> Key {
    Key::from_bytes(&mut [8u8; 32])
  }

  #[test]
  fn encrypt_decrypt_round_trip_every_cipher() {
    for cipher in Cipher::ALL {
      let encrypted =
        encrypt(b"secret payload", &key(), &(), cipher).unwrap();
      assert!(
        encrypted
          .data
          .starts_with(&format!("${}$", cipher.marker()))
      );
      let decrypted = decrypt(&encrypted, &key(), &()).unwrap();
      assert_eq!(decrypted.as_slice(), b"secret payload");
      // Wrong key fails.
      assert!(decrypt(&encrypted, &other_key(), &()).is_err());
      // Nonce sized for the cipher.
      assert_eq!(
        BASE64URL.decode(encrypted.nonce.as_bytes()).unwrap().len(),
        cipher.nonce_len()
      );
    }
  }

  #[test]
  fn unmarked_ciphertext_reads_as_xchacha() {
    let encrypted =
      encrypt(b"legacy", &key(), &(), Cipher::XChaCha20Poly1305)
        .unwrap();
    let (_, payload) = Cipher::parse(&encrypted.data).unwrap();
    let legacy = EncryptedData {
      data: payload.to_string(),
      nonce: encrypted.nonce.clone(),
    };
    assert_eq!(
      decrypt(&legacy, &key(), &()).unwrap().as_slice(),
      b"legacy"
    );
  }

  #[test]
  fn marker_and_nonce_must_agree() {
    let encrypted =
      encrypt(b"data", &key(), &(), Cipher::Aes256Gcm).unwrap();
    // Relabelled as XChaCha: the 12 byte nonce is rejected before
    // any decryption is attempted.
    let (_, payload) = Cipher::parse(&encrypted.data).unwrap();
    let relabelled = EncryptedData {
      data: Cipher::XChaCha20Poly1305.mark(payload),
      nonce: encrypted.nonce.clone(),
    };
    let err = decrypt(&relabelled, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Invalid nonce"));
  }

  #[test]
  fn round_trip_with_associated_data() {
    let aad = "user-123";
    for cipher in Cipher::ALL {
      let encrypted = encrypt(b"data", &key(), &aad, cipher).unwrap();
      assert_eq!(
        decrypt(&encrypted, &key(), &aad).unwrap().as_slice(),
        b"data"
      );
      // Different associated data must fail authentication.
      assert!(decrypt(&encrypted, &key(), &"user-456").is_err());
      // Missing associated data must fail too.
      assert!(decrypt(&encrypted, &key(), &()).is_err());
    }
  }

  #[test]
  fn tampered_ciphertext_fails() {
    for cipher in Cipher::ALL {
      let encrypted = encrypt(b"data", &key(), &(), cipher).unwrap();
      let (_, payload) = Cipher::parse(&encrypted.data).unwrap();
      let mut raw = BASE64URL.decode(payload.as_bytes()).unwrap();
      raw[0] ^= 0xff;
      let tampered = EncryptedData {
        data: cipher.mark(&BASE64URL.encode(&raw)),
        nonce: encrypted.nonce.clone(),
      };
      assert!(decrypt(&tampered, &key(), &()).is_err());
    }
  }

  #[test]
  fn nonces_are_unique_per_encryption() {
    let a = encrypt(b"data", &key(), &(), Cipher::default()).unwrap();
    let b = encrypt(b"data", &key(), &(), Cipher::default()).unwrap();
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.data, b.data);
  }

  #[test]
  fn empty_plaintext_round_trip() {
    for cipher in Cipher::ALL {
      let encrypted = encrypt(b"", &key(), &(), cipher).unwrap();
      assert_eq!(
        decrypt(&encrypted, &key(), &()).unwrap().as_slice(),
        b""
      );
      assert!(decrypt(&encrypted, &other_key(), &()).is_err());
    }
  }

  #[test]
  fn truncated_ciphertext_is_error_not_panic() {
    for cipher in Cipher::ALL {
      let encrypted = encrypt(b"data", &key(), &(), cipher).unwrap();
      let (_, payload) = Cipher::parse(&encrypted.data).unwrap();
      let raw = BASE64URL.decode(payload.as_bytes()).unwrap();
      // Shorter than the 16 byte tag, and empty.
      for len in [raw.len() - 1, 15, 1, 0] {
        let truncated = EncryptedData {
          data: cipher.mark(&BASE64URL.encode(&raw[..len])),
          nonce: encrypted.nonce.clone(),
        };
        let err = decrypt(&truncated, &key(), &()).unwrap_err();
        assert!(err.to_string().contains("Decryption failed"));
      }
    }
  }

  #[test]
  fn tampered_nonce_or_tag_fails() {
    for cipher in Cipher::ALL {
      let encrypted = encrypt(b"data", &key(), &(), cipher).unwrap();
      // Flip a bit in the nonce (still the right length).
      let mut nonce =
        BASE64URL.decode(encrypted.nonce.as_bytes()).unwrap();
      nonce[0] ^= 0x01;
      let bad_nonce = EncryptedData {
        data: encrypted.data.clone(),
        nonce: BASE64URL.encode(&nonce),
      };
      assert!(decrypt(&bad_nonce, &key(), &()).is_err());
      // Flip a bit in the tag (last byte of the payload).
      let (_, payload) = Cipher::parse(&encrypted.data).unwrap();
      let mut raw = BASE64URL.decode(payload.as_bytes()).unwrap();
      *raw.last_mut().unwrap() ^= 0x01;
      let bad_tag = EncryptedData {
        data: cipher.mark(&BASE64URL.encode(&raw)),
        nonce: encrypted.nonce.clone(),
      };
      assert!(decrypt(&bad_tag, &key(), &()).is_err());
    }
  }

  #[test]
  fn xchacha_relabelled_as_aes_is_rejected() {
    let encrypted =
      encrypt(b"data", &key(), &(), Cipher::XChaCha20Poly1305)
        .unwrap();
    let (_, payload) = Cipher::parse(&encrypted.data).unwrap();
    let relabelled = EncryptedData {
      data: Cipher::Aes256Gcm.mark(payload),
      nonce: encrypted.nonce.clone(),
    };
    let err = decrypt(&relabelled, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Invalid nonce"));
  }

  #[test]
  fn envelope_rejects_tampered_or_swapped_keys() {
    let aad = "tenant";
    let a = envelope_encrypt(b"a", &key(), &aad, Cipher::default())
      .unwrap();
    let b = envelope_encrypt(b"b", &key(), &aad, Cipher::default())
      .unwrap();
    let c = envelope_encrypt(b"c", &key(), &aad, Cipher::default())
      .unwrap();
    // Data key from another envelope under the same master key.
    let swapped = EnvelopeEncryptedData {
      key: b.key,
      data: a.data,
    };
    assert!(envelope_decrypt(&swapped, &key(), &aad).is_err());
    // Wrapped key which decrypts to the wrong length.
    let wrong_len = EnvelopeEncryptedData {
      key: encrypt(&[1u8; 16], &key(), &aad, Cipher::default())
        .unwrap(),
      data: c.data,
    };
    let err = envelope_decrypt(&wrong_len, &key(), &aad).unwrap_err();
    assert!(err.to_string().contains("not 32 bytes"));
    // Tampered wrapped key.
    let (cipher, payload) = Cipher::parse(&a.key.data).unwrap();
    let mut raw = BASE64URL.decode(payload.as_bytes()).unwrap();
    raw[0] ^= 0xff;
    let tampered = EnvelopeEncryptedData {
      key: EncryptedData {
        data: cipher.mark(&BASE64URL.encode(&raw)),
        nonce: a.key.nonce.clone(),
      },
      data: b.data,
    };
    assert!(envelope_decrypt(&tampered, &key(), &aad).is_err());
  }

  #[test]
  fn envelope_rewrap_moves_the_key_layer_keeping_the_data_layer() {
    let aad = "row-1";
    for (from, to) in [
      (Cipher::XChaCha20Poly1305, Cipher::XChaCha20Poly1305),
      (Cipher::XChaCha20Poly1305, Cipher::Aes256Gcm),
      (Cipher::Aes256Gcm, Cipher::XChaCha20Poly1305),
    ] {
      let envelope =
        envelope_encrypt(b"contents", &key(), &aad, from).unwrap();
      let rewrapped =
        envelope_rewrap(&envelope, &key(), &other_key(), &aad, to)
          .unwrap();
      // The data layer byte for byte, the key layer under the new
      // master key and cipher.
      assert_eq!(rewrapped.data, envelope.data);
      assert_ne!(rewrapped.key, envelope.key);
      assert_eq!(Cipher::parse(&rewrapped.key.data).unwrap().0, to);
      assert_eq!(
        envelope_decrypt(&rewrapped, &other_key(), &aad)
          .unwrap()
          .as_slice(),
        b"contents"
      );
      assert!(envelope_decrypt(&rewrapped, &key(), &aad).is_err());
    }
  }

  #[test]
  fn envelope_rewrap_authenticates_both_layers() {
    let aad = "row-1";
    let cipher = Cipher::default();
    let a = envelope_encrypt(b"a", &key(), &aad, cipher).unwrap();
    let b = envelope_encrypt(b"b", &key(), &aad, cipher).unwrap();
    // The key layer of one envelope with the data layer of another:
    // the key layer alone unwraps, but the data no longer opens, so
    // it must not be moved (and reported) as readable.
    let spliced = EnvelopeEncryptedData {
      key: a.key.clone(),
      data: b.data.clone(),
    };
    let err =
      envelope_rewrap(&spliced, &key(), &other_key(), &aad, cipher)
        .unwrap_err();
    assert!(format!("{err:#}").contains("data"), "{err:#}");
    // Wrong old master key, or associated data.
    assert!(
      envelope_rewrap(&a, &other_key(), &key(), &aad, cipher)
        .is_err()
    );
    assert!(
      envelope_rewrap(&a, &key(), &other_key(), &"row-2", cipher)
        .is_err()
    );
    // A key layer which unwraps to something other than a key.
    let wrong_len = EnvelopeEncryptedData {
      key: encrypt(&[1u8; 16], &key(), &aad, cipher).unwrap(),
      data: a.data,
    };
    let err =
      envelope_rewrap(&wrong_len, &key(), &other_key(), &aad, cipher)
        .unwrap_err();
    assert!(err.to_string().contains("not 32 bytes"), "{err}");
  }

  #[test]
  fn decrypt_string_round_trips_and_refuses_non_utf8() {
    let aad = "row-1";
    for cipher in Cipher::ALL {
      let encrypted =
        encrypt("hunter2 ✓".as_bytes(), &key(), &aad, cipher)
          .unwrap();
      let text: Zeroizing<String> =
        decrypt_string(&encrypted, &key(), &aad).unwrap();
      assert_eq!(text.as_str(), "hunter2 ✓");
      let envelope = envelope_encrypt(
        "hunter2 ✓".as_bytes(),
        &key(),
        &aad,
        cipher,
      )
      .unwrap();
      let text: Zeroizing<String> =
        envelope_decrypt_string(&envelope, &key(), &aad).unwrap();
      assert_eq!(text.as_str(), "hunter2 ✓");

      // Not UTF-8: an error, which doesn't carry the plaintext.
      let bytes = [b'p', b'w', 0xff, b'!'];
      let encrypted = encrypt(&bytes, &key(), &aad, cipher).unwrap();
      let err = decrypt_string(&encrypted, &key(), &aad).unwrap_err();
      assert_eq!(
        err.to_string(),
        "Decrypted data is not valid UTF-8"
      );
      let envelope =
        envelope_encrypt(&bytes, &key(), &aad, cipher).unwrap();
      let err =
        envelope_decrypt_string(&envelope, &key(), &aad).unwrap_err();
      assert_eq!(
        err.to_string(),
        "Decrypted data is not valid UTF-8"
      );
      // Failing authentication is still the decryption error.
      assert!(
        decrypt_string(&encrypted, &other_key(), &aad).is_err()
      );
    }
  }

  /// Fixed ciphertexts produced by this crate, so a change to the
  /// stored format (marker, encoding, nonce handling) is caught
  /// rather than hidden by a round trip through the same code.
  #[test]
  fn known_answer_vectors() {
    const XCHACHA: (&str, &str) = (
      "$xchacha20poly1305$bgNSPhWMQyezLxOJKR7hBvtjrjgJ2yEvn-p4Zg==",
      "QqrpYRkC0Eee51HST8rEu440AD-2CKgq",
    );
    const AES: (&str, &str) = (
      "$aes256gcm$iSi9HUEIH_JxguRGTpXqsdHbkSu7IGo_6IgQOA==",
      "tKPaN50KUJKEZLAs",
    );
    // Legacy: the XChaCha payload without its marker.
    const LEGACY: (&str, &str) = (
      "bgNSPhWMQyezLxOJKR7hBvtjrjgJ2yEvn-p4Zg==",
      "QqrpYRkC0Eee51HST8rEu440AD-2CKgq",
    );
    for (data, nonce) in [XCHACHA, AES, LEGACY] {
      let encrypted = EncryptedData {
        data: data.to_string(),
        nonce: nonce.to_string(),
      };
      assert_eq!(
        decrypt(&encrypted, &key(), &"aad").unwrap().as_slice(),
        b"known answer",
        "{data}"
      );
      assert!(decrypt(&encrypted, &key(), &"other").is_err());
    }
  }

  #[test]
  fn invalid_input_is_error_not_panic() {
    let bad_data = EncryptedData {
      data: "!!not-base64!!".to_string(),
      nonce: BASE64URL.encode(&[0u8; 24]),
    };
    let err = decrypt(&bad_data, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Data is not valid base64url"));

    let bad_nonce = EncryptedData {
      data: BASE64URL.encode(b"whatever"),
      nonce: "!!not-base64!!".to_string(),
    };
    let err = decrypt(&bad_nonce, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Nonce is not valid base64url"));

    let short_nonce = EncryptedData {
      data: BASE64URL.encode(b"whatever"),
      nonce: BASE64URL.encode(&[0u8; 12]),
    };
    let err = decrypt(&short_nonce, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Invalid nonce"));

    let unknown = EncryptedData {
      data: "$rot13$whatever".to_string(),
      nonce: BASE64URL.encode(&[0u8; 12]),
    };
    let err = decrypt(&unknown, &key(), &()).unwrap_err();
    assert!(err.to_string().contains("Unknown cipher"));
  }

  #[test]
  fn envelope_round_trip_and_mixed_layers() {
    let aad = "tenant-1".to_string();
    for cipher in Cipher::ALL {
      let envelope =
        envelope_encrypt(b"envelope contents", &key(), &aad, cipher)
          .unwrap();
      assert_eq!(
        envelope_decrypt(&envelope, &key(), &aad)
          .unwrap()
          .as_slice(),
        b"envelope contents"
      );
      assert!(
        envelope_decrypt(&envelope, &other_key(), &aad).is_err()
      );
      assert!(
        envelope_decrypt(&envelope, &key(), &"tenant-2").is_err()
      );
      // Data cannot be decrypted directly with the master key.
      assert!(decrypt(&envelope.data, &key(), &aad).is_err());
    }
    // The key layer rewrapped under the other cipher (a master
    // key rotation): each layer decrypts by its own marker.
    let envelope = envelope_encrypt(
      b"contents",
      &key(),
      &aad,
      Cipher::XChaCha20Poly1305,
    )
    .unwrap();
    let inner = decrypt(&envelope.key, &key(), &aad).unwrap();
    let rewrapped = EnvelopeEncryptedData {
      key: encrypt(&inner, &other_key(), &aad, Cipher::Aes256Gcm)
        .unwrap(),
      data: envelope.data,
    };
    assert_eq!(
      envelope_decrypt(&rewrapped, &other_key(), &aad)
        .unwrap()
        .as_slice(),
      b"contents"
    );
  }
}
