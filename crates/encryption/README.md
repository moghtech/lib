# Mogh Encryption

Utilities to encrypt and decrypt data.

```rust
let master_key: [u8; 32] = rand::random();
let data: [u8; 128] = rand::random();

let envelope_encrypted = mogh_encryption::xchacha20poly1305::EncryptionProvider::default()
  .envelope_encrypt(&data, master_key, &())?;

let envelope_decrypted: Vec<u8> = mogh_encryption::xchacha20poly1305::envelope_decrypt(
  &envelope_encrypted,
  master_key,
  &()
)?;
```