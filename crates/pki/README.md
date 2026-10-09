# Mogh PKI

Public key identification: Ed25519 signatures, and
[Noise](https://noiseprotocol.org) handshakes over X25519 keys.

```rust
fn main() -> anyhow::Result<()> {
  let mogh_pki::EncodedKeyPair { private, public } =
    mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::Signature)?;
  // The private key is secret: it has no `Display` and its `Debug`
  // is redacted. Take its text explicitly with `as_str`.
  println!("Private: {} | Public: {public}", private.as_str());

  // Whoever has the public key verifies what the private key signed.
  let signature = mogh_pki::signature::sign(&private, b"message")?;
  mogh_pki::signature::verify(&public, b"message", &signature)?;
  Ok(())
}
```

## Kinds

- `PkiKind::Signature` (Ed25519): the client signs a message both
  sides know (the request), and whoever has its public key verifies
  the signature (`signature::sign`, `signature::verify`). The verifier
  needs no key of its own, and nothing it holds lets it make a
  signature for a client. A signature verifies wherever the public key
  is known, and again whenever it is replayed: sign who the message is
  for, and a timestamp or nonce the verifier enforces a window on.
  Signing is deterministic, so only a nonce makes two signatures of
  the same message differ. Each signature has one accepted form
  (strict verification, a canonical `S`, canonical base64).
- `PkiKind::Mutual` (Noise XX over X25519): three messages, after
  which each side knows the other's public key.

The kind decides the algorithm of the keys (`PkiKind::key_algorithm`),
and a key of one kind is not a key of the other: it is refused with
`WrongKeyAlgorithm`, which an error can be downcast to
(`error.downcast_ref::<WrongKeyAlgorithm>()`) to tell such a key from
a malformed one.

## Keys

- A private key is stored as base64 pkcs8 der. It is parsed from pem
  (openssl), from base64 pkcs8 der (v1 or v2), or from raw key bytes:
  input of 32 characters or fewer is used as the key itself (the
  X25519 key, or the Ed25519 seed), with no key derivation, so a short
  value can be brute forced from the public key. Prefer generated
  keys. Raw bytes name no algorithm, so the same input is a different
  key for each kind.
- A private key given inline, as a person writes it down (the key of a
  node's own identity in `from_private_key_spec`, a key somebody
  chose: `Pkcs8PrivateKey::from_inline_key`,
  `EncodedKeyPair::from_inline_key`), must be pkcs8 encoded (pem, or
  base64 der) or exactly 32 raw bytes. A shorter raw value (`changeme`,
  the name of the node) is a key anybody can find from the public key,
  which is no secret, and is refused, as is a value which reads like a
  path. The errors name the accepted forms, never the value.
  `from_maybe_raw_bytes` / `EncodedKeyPair::from_private_key` still take
  shorter raw values, for keys handed out as raw values on purpose
  (onboarding and recovery keys: random, 32 characters).
- `Pkcs8PrivateKey` has no `Display` and a redacted `Debug`, so it
  can't be formatted into a log or error by accident. Take the key
  text explicitly: `as_str`, `into_inner` or `as_pem`.
- An empty private key (or an existing empty key file) is an error:
  it would be the same, publicly known key everywhere.
- A private key file is written with its public key beside it, at
  `path.with_extension("pub")`. So a private key path ending in `.pub`
  (in any case) is refused wherever a private key is written or loaded
  to be used (`from_private_key_spec`, `load_maybe_generate`,
  `generate_write_*`, `Pkcs8PrivateKey::write_pem_*`): the public key
  would overwrite the private key. Reading one (`from_file`) is fine.
- Public keys are stored as base64 spki der. Low order points and non
  canonical encodings are refused, so a key has one string. Its first
  16 characters name the algorithm: `MCowBQYDK2VwAyEA` for Ed25519,
  `MCowBQYDK2VuAyEA` for X25519.
- Signature keys are plain RFC 8410 Ed25519 keys, as
  `openssl genpkey -algorithm ed25519` generates them (and
  `openssl pkey -pubout` derives the public key).
- `RotatableKeyPair::from_private_key_spec` takes the key inline, or
  `file:/path/to/key` (generated there when the file does not exist).
  The key file is created, never written over one
  (`mogh_secret_file::write_new`): of processes starting at once on
  the same missing key file, one creates it and the others load its
  key, so none runs on a key which is no longer on disk. A symlink at
  the path to a file which does not exist is an error, nothing is
  written through it or over it. `EncodedKeyPair::load_maybe_generate`
  does the same, while `generate_write_*` replace a key file.
  Whitespace around the spec, and around the path after `file:`, is
  no part of the path (a stray space or `\r` from an environment
  variable would otherwise name another file, and have a new key
  generated there), and `file:` without a path is an error.
  `SpkiPublicKey::from_spec` reads public key specs the same way, and
  `key_spec_path` gives the path of a spec to apps which need it.
  What reads as a path without the prefix (`/path/to/key`,
  `keys/core.key`, `File:/path`, see `looks_like_a_path`) is an
  error: up to 32 bytes are a raw key, so it would be taken for the
  key itself.
  The pair keeps its kind, every key it rotates to is of the same
  algorithm. `generated()` tells whether the load generated the key
  (there was no file): a key nothing can know yet, eg. not registered
  with the server which has to accept it. Of processes racing to
  create the key file, only the one which created it.
  A rotation file beside the key file (`<path>.next`, `<path>.old`)
  holding a key of the other algorithm is refused (`WrongKeyAlgorithm`,
  with a context naming the file), before a key is generated: it was
  left by a rotation of an earlier key of the other algorithm, and no
  rotation of this key could resume or finish with it there. It is left
  as it is, for the operator to move away (after revoking its key
  wherever it is still registered).
  A file backed pair can rotate: in one step (`rotate`), or in two
  phases for a key registered elsewhere (`begin_rotation`, register
  the candidate, `commit`, revoke `retired`, `finish_rotation`). One
  rotation of a pair at a time, and only one process may rotate a
  given key file. Both write the key file with `mogh_secret_file`:
  an atomic replace keeping its owner, group and mode, or an in
  place write (not atomic) where the file can't be replaced, like a
  docker / kubernetes single file mount. A commit whose write fails
  midway leaves the key in use only at `<path>.old`, which
  `begin_rotation` and `finish_rotation` then keep, until the live
  file holds that key again or a retried commit switches.
  The pair keeps the key path resolved (`path()`: absolute, every
  symlink followed), so a key path which is a symlink (eg. from the
  config directory into a persistent volume) is rotated where it
  points: the link stays, the file it points to holds the new key,
  and the rotation files and the public key file are written beside
  that file. A file it points to named `*.pub` is refused.

## Since 3.0

`PkiKind::OneWay` (one message of a Noise IK handshake over X25519
keys) is replaced by `PkiKind::Signature`. The one way message was
validated with the server's private key, which could therefore also
make one for any client key. A signature is verified with the client's
public key alone.

- Signature keys are Ed25519 keys: the X25519 keys used for
  `PkiKind::OneWay` are refused (`WrongKeyAlgorithm`), generate new
  ones. The keys of `PkiKind::Mutual` are unchanged.
- `one_way::OneWayNoiseHandshake` is gone, use `signature::sign` and
  `signature::verify`. Neither side needs the other's key to sign, so
  what the one way message was bound to implicitly (the server it was
  made for) has to be part of the signed message.
- Whatever parses or derives a key takes the `PkiKind` it is used as:
  `Pkcs8PrivateKey::{from_file, from_maybe_raw_bytes, from_raw_bytes,
  maybe_raw_bytes, raw_bytes, as_raw_bytes}` and
  `SpkiPublicKey::{from_spec, from_file, from_maybe_pem, from_der,
  from_raw_bytes, maybe_pem_to_raw_bytes, der_to_raw_bytes}`.
- `compute_public_key_using_dh` / `from_private_key_using_dh` are
  `Pkcs8PrivateKey::compute_public_key` /
  `SpkiPublicKey::from_private_key`.
- `RotatableKeyPair` keeps its kind (`kind()`): `rotate`,
  `begin_rotation` and `retired` take none.
- `PkiKind::noise_params` is gone.

## Since 3.1

Added `key_spec_path` (the `file:` rule, for apps which need the path
of a spec) and `RotatableKeyPair::generated`. What a deployment can
run into on upgrade:

- `file:` specs (private and public) are read without the whitespace
  around them, also after `file:`, and `file:` without a path is an
  error. A stray space used to name another file, where a new private
  key was generated.
- A private key path ending in `.pub` is an error, also for an
  existing key file: rename it (eg. to `.key`) and change the spec.
- A `<key>.next` / `<key>.old` holding a key of the other algorithm
  stops the load of the key pair: move it away.
- `SpkiPublicKey::from_file` (and so `from_spec`) names the file when
  it holds no valid key.
- A missing key file is created, never written over: processes
  starting at once on the same missing key file all run on the key
  on disk, and only one of them reports `generated()`. A symlink at
  the key path to a file which does not exist is an error: it used to
  be replaced by a new key file.

## Since 4.0

Added `Pkcs8PrivateKey::from_inline_key` / `EncodedKeyPair::from_inline_key`.
What a deployment can run into on upgrade:

- A private key given inline (not `file:`) must be pkcs8 encoded (pem,
  or base64 der) or exactly 32 raw bytes: a shorter raw key, which
  used to be zero padded into the key, stops the start. A short raw key
  must be regenerated (`key generate`, then register its public key
  where the old one was) or given as pkcs8: the pkcs8 form of the same
  key is `EncodedKeyPair::from_private_key(kind, key).private`, but it
  stays as guessable as it was, so regenerate when you can. Key files
  are read in any form, as before.
- A `file:` key path which is a symlink is rotated where it points
  (the link used to be replaced by a file holding the new key, while
  the file it pointed to kept the previous one). `<key>.next`,
  `<key>.old` and the `.pub` file are written beside the file the
  link points to, not beside the link, and `RotatableKeyPair::path`
  is that file. Rotation files an earlier version left beside a link
  (a two phase rotation in flight during the upgrade) stop the load:
  move them where the error says, beside the file the link points
  to.
