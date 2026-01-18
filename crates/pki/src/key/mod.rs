use std::{
  path::{Path, PathBuf},
  sync::Arc,
};

use anyhow::Context;
use arc_swap::ArcSwap;
use der::AnyRef;

mod private;
mod public;

pub use private::Pkcs8PrivateKey;
pub use public::SpkiPublicKey;

use crate::PkiKind;

const OID_X25519: spki::ObjectIdentifier =
  spki::ObjectIdentifier::new_unwrap("1.3.101.110");

fn algorithm() -> spki::AlgorithmIdentifier<AnyRef<'static>> {
  spki::AlgorithmIdentifier {
    oid: OID_X25519,
    parameters: None,
  }
}

pub struct EncodedKeyPair {
  /// pkcs8 encoded private key
  pub private: Pkcs8PrivateKey,
  /// spki encoded public key
  pub public: SpkiPublicKey,
}

impl EncodedKeyPair {
  pub fn generate(pki_kind: PkiKind) -> anyhow::Result<Self> {
    let builder =
      snow::Builder::new(pki_kind.noise_params().parse()?);
    let keypair = builder
      .generate_keypair()
      .context("Failed to generate keypair")?;
    let private = Pkcs8PrivateKey::from_raw_bytes(&keypair.private)?;
    let public = SpkiPublicKey::from_raw_bytes(&keypair.public)?;
    Ok(Self { private, public })
  }

  pub fn generate_write_sync(
    pki_kind: PkiKind,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let path = path.as_ref();
    // Generate and write pems to path
    let keys = Self::generate(pki_kind)?;
    keys.private.write_pem_sync(path)?;
    keys.public.write_pem_sync(path.with_extension("pub"))?;
    Ok(keys)
  }

  pub async fn generate_write_async(
    pki_kind: PkiKind,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let path = path.as_ref();
    // Generate and write pems to path
    let keys = Self::generate(pki_kind)?;
    keys.private.write_pem_async(path).await?;
    keys
      .public
      .write_pem_async(path.with_extension("pub"))
      .await?;
    Ok(keys)
  }

  pub fn load_maybe_generate(
    pki_kind: PkiKind,
    private_key_path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let path = private_key_path.as_ref();

    let exists = path.try_exists().with_context(|| {
      format!("Invalid private key path: {path:?}")
    })?;

    if !exists {
      return Self::generate_write_sync(pki_kind, path);
    }

    let private = Pkcs8PrivateKey::from_file(private_key_path)?;
    let public = private.compute_public_key_using_dh(pki_kind)?;

    Ok(Self { private, public })
  }

  pub fn from_private_key(
    pki_kind: PkiKind,
    maybe_pkcs8_private_key: &str,
  ) -> anyhow::Result<Self> {
    let private =
      Pkcs8PrivateKey::from_maybe_raw_bytes(maybe_pkcs8_private_key)?;
    let public = private.compute_public_key_using_dh(pki_kind)?;
    Ok(Self { private, public })
  }

  pub fn private(&self) -> &str {
    self.private.as_str()
  }

  pub fn public(&self) -> &str {
    self.public.as_str()
  }
}

pub struct RotatableKeyPair {
  keys: ArcSwap<EncodedKeyPair>,
  path: Option<PathBuf>,
}

impl RotatableKeyPair {
  /// Parses from either direct private key (raw / der / pem),
  /// or from file containing raw / der / pem.
  /// Use `file:/path/to/private.key` to specify file.
  pub fn from_private_key_spec(
    pki_kind: PkiKind,
    private_key_spec: &str,
  ) -> anyhow::Result<Self> {
    let (keys, path) = if let Some(path) =
      private_key_spec.strip_prefix("file:")
    {
      let path = PathBuf::from(path);
      (
        EncodedKeyPair::load_maybe_generate(pki_kind, &path)?,
        Some(path),
      )
    } else {
      (
        EncodedKeyPair::from_private_key(pki_kind, private_key_spec)?,
        None,
      )
    };
    Ok(Self {
      keys: ArcSwap::new(Arc::new(keys)),
      path,
    })
  }

  /// If 'path' is Some, generates, writes, and stores new key pair.
  /// Returns the public key, maybe new if using file.
  pub async fn rotate(
    &self,
    pki_kind: PkiKind,
  ) -> anyhow::Result<SpkiPublicKey> {
    let Some(path) = self.path.as_deref() else {
      return Ok(self.keys.load().public.clone());
    };
    let keys =
      EncodedKeyPair::generate_write_async(pki_kind, path).await?;
    let public_key = keys.public.clone();
    self.keys.store(Arc::new(keys));
    Ok(public_key)
  }

  pub fn load(&self) -> arc_swap::Guard<Arc<EncodedKeyPair>> {
    self.keys.load()
  }

  pub fn rotatable(&self) -> bool {
    self.path.is_some()
  }
}
