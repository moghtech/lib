# Mogh Encryption

Utilities to encrypt and decrypt data: AEAD data and envelope encryption
(XChaCha20-Poly1305 or AES-256-GCM) under a 32 byte `Key` which is wiped
from memory when dropped. Nonces and keys are read from the OS random source.

```rust
use mogh_encryption::{Cipher, Key, Zeroizing, aead};

let master_key = Key::generate();
let data = b"secret contents";
// Associated data is authenticated but not encrypted,
// eg an id binding the ciphertext to its owner.
let aad = "user-123";

let encrypted = aead::envelope_encrypt(
  data,
  &master_key,
  &aad,
  Cipher::default(),
)?;

// The plaintext is wiped when dropped.
let decrypted: Zeroizing<Vec<u8>> =
  aead::envelope_decrypt(&encrypted, &master_key, &aad)?;
assert_eq!(decrypted.as_slice(), data);

// Text, wiped the same way. Plaintext which is not UTF-8 is an error.
let text: Zeroizing<String> =
  aead::envelope_decrypt_string(&encrypted, &master_key, &aad)?;

// Rotating the master key: only the data key is encrypted again,
// after checking the data still decrypts.
let new_master_key = Key::generate();
let rotated = aead::envelope_rewrap(
  &encrypted,
  &master_key,
  &new_master_key,
  &aad,
  Cipher::default(),
)?;
```

Keys come from `Key::generate()`, or from the text people hand over with
`Key::decode(text)` (a config value, a request field) and `Key::read_file(path)`
(a key file): base64url or standard base64 (eg. `openssl rand -base64 32`),
padded or not, surrounding whitespace ignored. The decoded bytes are wiped,
also when decoding fails part way, and errors never include the key text.
`key.to_base64url()` is the canonical text form.

```rust
let key = Key::read_file("/etc/app/encryption.key")?;
```

To store the result, use the text form (`Display` / `FromStr`), or
enable the `serde` feature for `Serialize` / `Deserialize`:

```rust
let stored: String = encrypted.to_string();
let encrypted: EnvelopeEncryptedData = stored.parse()?;
```
