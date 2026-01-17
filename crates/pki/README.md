# Mogh PKI

```rust
let mogh_pki::key::EncodedKeyPair { private, public } = 
  mogh_pki::key::EncodedKeyPair::generate(mogh_pki::PkiType::Mutual)?;

println!("Private: {private} | Public: {public}");
```