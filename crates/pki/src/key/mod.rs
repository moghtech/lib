use std::{
  path::{Path, PathBuf},
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
};

use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use der::AnyRef;
use zeroize::{Zeroize as _, Zeroizing};

mod private;
mod public;

#[cfg(test)]
mod tests;

pub use private::Pkcs8PrivateKey;
pub use public::SpkiPublicKey;

pub(crate) use public::check_raw_public_key;

use crate::{KeyAlgorithm, PkiKind, WrongKeyAlgorithm};

const OID_X25519: spki::ObjectIdentifier =
  spki::ObjectIdentifier::new_unwrap("1.3.101.110");
const OID_ED25519: spki::ObjectIdentifier =
  spki::ObjectIdentifier::new_unwrap("1.3.101.112");

/// The algorithm identifier the keys of `pki_kind` are encoded
/// with (RFC 8410: the same layout for both, without parameters).
fn algorithm(
  pki_kind: PkiKind,
) -> spki::AlgorithmIdentifier<AnyRef<'static>> {
  spki::AlgorithmIdentifier {
    oid: match pki_kind.key_algorithm() {
      KeyAlgorithm::Ed25519 => OID_ED25519,
      KeyAlgorithm::X25519 => OID_X25519,
    },
    parameters: None,
  }
}

/// Checks that an encoded key (`what`: "Private" / "Public") is of
/// the algorithm `pki_kind` uses. A key of the other algorithm is
/// [WrongKeyAlgorithm], so callers can tell it from a malformed one.
fn check_algorithm(
  pki_kind: PkiKind,
  oid: &spki::ObjectIdentifier,
  what: &str,
) -> anyhow::Result<()> {
  let expected = pki_kind.key_algorithm();
  let found = if *oid == OID_ED25519 {
    KeyAlgorithm::Ed25519
  } else if *oid == OID_X25519 {
    KeyAlgorithm::X25519
  } else {
    return Err(anyhow!(
      "{what} key algorithm {oid} is not supported, expected {expected}"
    ));
  };
  if found != expected {
    return Err(anyhow::Error::new(WrongKeyAlgorithm {
      expected,
      found,
    }));
  }
  Ok(())
}

/// Wraps a base64 body in pem framing,
/// with lines wrapped at 64 characters per RFC 7468.
fn encode_pem(label: &str, base64_body: &str) -> String {
  let begin = format!("-----BEGIN {label}-----\n");
  let end = format!("-----END {label}-----\n");
  // Sized up front: growing would leave copies of a private key
  // body behind in freed memory.
  let lines = base64_body.len().div_ceil(64);
  let mut pem = String::with_capacity(
    begin.len() + base64_body.len() + lines + end.len(),
  );
  pem.push_str(&begin);
  for line in base64_body.as_bytes().chunks(64) {
    pem.push_str(&String::from_utf8_lossy(line));
    pem.push('\n');
  }
  pem.push_str(&end);
  pem
}

/// Refuses a private key path ending in `.pub`, in any case (as a
/// case insensitive filesystem takes it). The public key is written
/// beside the private key, at `path.with_extension("pub")`, which
/// would be the private key file itself: replaced by the public key
/// right after it is written (and again on every rotation), the key
/// in use would exist nowhere on disk, and the next start would
/// fail to load it. A private key also has no place in a file named
/// like a public one, which is meant to be shared.
fn check_private_key_path(path: &Path) -> anyhow::Result<()> {
  if path
    .extension()
    .is_some_and(|extension| extension.eq_ignore_ascii_case("pub"))
  {
    return Err(anyhow!(
      "The private key path {path:?} ends in `.pub`, which names the public key file written beside it: use another extension, eg. `.key`"
    ));
  }
  Ok(())
}

#[derive(Clone)]
pub struct EncodedKeyPair {
  /// pkcs8 encoded private key
  pub private: Pkcs8PrivateKey,
  /// spki encoded public key
  pub public: SpkiPublicKey,
}

impl EncodedKeyPair {
  /// A new key pair of the algorithm `pki_kind` uses
  /// ([PkiKind::key_algorithm]).
  pub fn generate(pki_kind: PkiKind) -> anyhow::Result<Self> {
    match pki_kind.key_algorithm() {
      KeyAlgorithm::X25519 => {
        let builder = snow::Builder::new(PkiKind::MUTUAL.parse()?);
        let mut keypair = builder
          .generate_keypair()
          .context("Failed to generate keypair")?;
        let private =
          Pkcs8PrivateKey::from_raw_bytes(pki_kind, &keypair.private);
        keypair.private.zeroize();
        let private = private?;
        let public =
          SpkiPublicKey::from_raw_bytes(pki_kind, &keypair.public)?;
        Ok(Self { private, public })
      }
      KeyAlgorithm::Ed25519 => {
        use rand::TryRng as _;
        // The seed, read directly from the OS random source.
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::SysRng
          .try_fill_bytes(&mut *seed)
          .context("Failed to read from the OS random source")?;
        let private =
          Pkcs8PrivateKey::from_raw_bytes(pki_kind, &*seed)?;
        let public = private.compute_public_key(pki_kind)?;
        Ok(Self { private, public })
      }
    }
  }

  /// A new key pair, its private key written to `path` (replacing
  /// a key file there) and its public key beside it
  /// (`path.with_extension("pub")`). A `path` ending in `.pub` is
  /// refused, it would be overwritten by the public key. To generate
  /// a key only when there is none, see [Self::load_maybe_generate].
  pub fn generate_write_sync(
    pki_kind: PkiKind,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let path = path.as_ref();
    check_private_key_path(path)?;
    // Generate and write pems to path
    let keys = Self::generate(pki_kind)?;
    keys.private.write_pem_sync(path)?;
    keys.public.write_pem_sync(path.with_extension("pub"))?;
    Ok(keys)
  }

  /// [Self::generate_write_sync], writing with tokio.
  pub async fn generate_write_async(
    pki_kind: PkiKind,
    path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let path = path.as_ref();
    check_private_key_path(path)?;
    // Generate and write pems to path
    let keys = Self::generate(pki_kind)?;
    keys.private.write_pem_async(path).await?;
    keys
      .public
      .write_pem_async(path.with_extension("pub"))
      .await?;
    Ok(keys)
  }

  /// Loads the pair from the private key file, or generates and
  /// writes a new one when there is no file at the path. The new key
  /// file is created, never written over one: of processes starting
  /// at once on the same missing key file, one creates it and the
  /// others load its key, so every one of them runs on the key on
  /// disk. A symlink at the path to a file which does not exist is an
  /// error (no key is written through it, or over it). An existing
  /// file that holds no valid key (an empty file) is an error, never
  /// replaced. A path ending in `.pub` is an error too, whether or
  /// not there is a file: it names the public key file written
  /// beside it (see [Self::generate_write_sync]).
  pub fn load_maybe_generate(
    pki_kind: PkiKind,
    private_key_path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let path = private_key_path.as_ref();
    check_private_key_path(path)?;
    match Self::load_existing(pki_kind, path)? {
      Some(keys) => Ok(keys),
      None => {
        Self::generate_missing(pki_kind, path).map(|(keys, _)| keys)
      }
    }
  }

  /// For a private key file found missing at `path`: generates a
  /// pair, creates the key file with it and writes its public key
  /// beside it, returning it with `true`.
  ///
  /// Processes starting at once on the same missing key file all
  /// find it missing, so the file is created, never written over
  /// (see `mogh_secret_file::write_new`): one process creates it, the
  /// others load the key it holds, returned with `false`. Were it
  /// written over (as before 3.1), each process would run on the key
  /// it generated, of which only the last one written stays on disk:
  /// the others would run on a key no restart loads again (and
  /// register a public key nobody holds anymore).
  ///
  /// Something at the path which holds no key file is an error, a
  /// symlink to a file which does not exist: no key is written
  /// through it (a planted link could point anywhere), or over it.
  fn generate_missing(
    pki_kind: PkiKind,
    path: &Path,
  ) -> anyhow::Result<(Self, bool)> {
    let keys = Self::generate(pki_kind)?;
    if keys.private.write_pem_new_sync(path)? {
      keys.public.write_pem_sync(path.with_extension("pub"))?;
      return Ok((keys, true));
    }
    // Created since it was found missing, eg. by another process
    // starting on the same key file, which writes the public key
    // file too.
    match Self::load_existing(pki_kind, path)? {
      Some(existing) => {
        tracing::info!(
          "Loaded the private key at {path:?}, which another process created while this one was about to"
        );
        Ok((existing, false))
      }
      None if path.is_symlink() => Err(anyhow!(
        "The private key path {path:?} is a symlink to a file which does not exist: create the key file it points to, or remove the link to have a key generated at the path"
      )),
      None => Err(anyhow!(
        "Failed to create the private key file at {path:?}: something was created there meanwhile, and is gone again"
      )),
    }
  }

  /// The pair of the private key file at `path`, `None` when there
  /// is no file, see [Self::load_maybe_generate].
  fn load_existing(
    pki_kind: PkiKind,
    path: &Path,
  ) -> anyhow::Result<Option<Self>> {
    let exists = path.try_exists().with_context(|| {
      format!("Invalid private key path: {path:?}")
    })?;

    if !exists {
      return Ok(None);
    }

    let private = Pkcs8PrivateKey::from_file(pki_kind, path)
      .map_err(|e| {
        // Only an empty file is safe to delete: an unreadable file,
        // or a real key in a form this can't load (the key of
        // another algorithm), is the identity the node is
        // registered under.
        if file_is_blank(path) {
          e.context(format!(
            "Failed to load the private key at {path:?} (the file is empty: delete it to have a new key generated)"
          ))
        } else {
          e.context(format!(
            "Failed to load the private key at {path:?}"
          ))
        }
      })?;
    let public = private.compute_public_key(pki_kind)?;

    Ok(Some(Self { private, public }))
  }

  /// The pair of a private key given inline, in a form
  /// [Pkcs8PrivateKey::from_inline_key] accepts (pkcs8, or exactly 32
  /// raw bytes), deriving the public key.
  pub fn from_inline_key(
    pki_kind: PkiKind,
    private_key: &str,
  ) -> anyhow::Result<Self> {
    let private =
      Pkcs8PrivateKey::from_inline_key(pki_kind, private_key)?;
    let public = private.compute_public_key(pki_kind)?;
    Ok(Self { private, public })
  }

  /// The pair of a private key in any form
  /// [Pkcs8PrivateKey::from_maybe_raw_bytes] accepts, deriving the
  /// public key. For keys handed out as raw values on purpose
  /// (onboarding, recovery keys): a key a person writes down takes
  /// [Self::from_inline_key].
  pub fn from_private_key(
    pki_kind: PkiKind,
    maybe_pkcs8_private_key: &str,
  ) -> anyhow::Result<Self> {
    let private = Pkcs8PrivateKey::from_maybe_raw_bytes(
      pki_kind,
      maybe_pkcs8_private_key,
    )?;
    let public = private.compute_public_key(pki_kind)?;
    Ok(Self { private, public })
  }

  /// Loads the pair from a private key file (raw / der / pem),
  /// deriving the public key.
  pub fn from_file(
    pki_kind: PkiKind,
    private_key_path: impl AsRef<Path>,
  ) -> anyhow::Result<Self> {
    let private =
      Pkcs8PrivateKey::from_file(pki_kind, private_key_path)?;
    let public = private.compute_public_key(pki_kind)?;
    Ok(Self { private, public })
  }

  pub fn private(&self) -> &str {
    self.private.as_str()
  }

  pub fn public(&self) -> &str {
    self.public.as_str()
  }
}

/// Whether the file at `path` reads as empty or whitespace only,
/// as [Pkcs8PrivateKey::from_file] refuses it. False when it can't
/// be read.
fn file_is_blank(path: &Path) -> bool {
  std::fs::read_to_string(path)
    .map(zeroize::Zeroizing::new)
    .is_ok_and(|contents| contents.trim().is_empty())
}

/// Whether the private key file at `path` holds the key of
/// `public`.
fn file_holds_key(
  pki_kind: PkiKind,
  path: &Path,
  public: &SpkiPublicKey,
) -> bool {
  EncodedKeyPair::from_file(pki_kind, path)
    .is_ok_and(|on_disk| on_disk.public == *public)
}

/// `<path><suffix>`: a sibling of the key file, keeping the full
/// file name (`cperiphery.key.next`, not `cperiphery.next`).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
  let mut name = path.as_os_str().to_owned();
  name.push(suffix);
  PathBuf::from(name)
}

/// The candidate of an in-flight [RotatableKeyPair::begin_rotation].
const NEXT_SUFFIX: &str = ".next";
/// The key a committed rotation retired, until
/// [RotatableKeyPair::finish_rotation].
const OLD_SUFFIX: &str = ".old";

/// Refuses a rotation file beside the key file at `path`
/// (`<path>.next`, `<path>.old`) which holds a key of the other
/// algorithm than `pki_kind` uses, with the [WrongKeyAlgorithm] of
/// loading it and a context naming it.
///
/// A pair rotates within its algorithm, so such a file was left by
/// a rotation of an earlier key of the other algorithm (a key file
/// moved away to have a key of this kind generated). It is no part
/// of a rotation of this key, and none could resume or finish with
/// it there: a `.old` reads as a retired key which can't be loaded,
/// so [RotatableKeyPair::begin_rotation] refuses to start, and a
/// `.next` as a pending rotation. Whether its key is still
/// registered somewhere, to be revoked, is for the operator to
/// find out, so the file is left as it is, never removed or
/// replaced.
///
/// A rotation file which doesn't load for another reason (it holds
/// no key) is left to the rotation, see
/// [RotatableKeyPair::begin_rotation].
fn check_rotation_files(
  pki_kind: PkiKind,
  path: &Path,
) -> anyhow::Result<()> {
  for suffix in [NEXT_SUFFIX, OLD_SUFFIX] {
    let file = sibling(path, suffix);
    if let Err(e) = Pkcs8PrivateKey::from_file(pki_kind, &file)
      && e.is::<WrongKeyAlgorithm>()
    {
      return Err(e.context(format!(
        "{file:?}, left by a rotation of an earlier key, holds a key of the other algorithm, with which no rotation of this key can resume or finish: move the file away"
      )));
    }
  }
  Ok(())
}

/// The key file at the configured `path` of a `file:` spec,
/// resolved (`std::fs::canonicalize`): absolute, with every symlink
/// followed. A [RotatableKeyPair] keeps this path, and its rotations
/// write this file, and its rotation files (`.next`, `.old`) and
/// public key file (`.pub`) beside it.
///
/// A key path is often a symlink into where keys are kept, eg. from
/// the config directory into a persistent volume. A rotation replaces
/// the key file through a temporary file renamed over it (see
/// `mogh_secret_file::write`), which over the link itself would
/// replace the link with a file of its own, leaving the previous key
/// where the link pointed: recreated (a container or host
/// provisioned again), the link would bring the retired key back,
/// which the server no longer accepts. Resolved, the rename replaces
/// the file the link points to, and the link stays.
///
/// The resolved file is refused as a private key path ending in
/// `.pub` is ([check_private_key_path]). So are rotation files of an
/// earlier version beside a symlink at `path` (`<path>.next`,
/// `<path>.old`), which rotated the link's path: a rotation in
/// flight would carry on without its candidate, or leave its retired
/// key unrevoked. The operator moves them beside the resolved file
/// (where the error says), or away.
fn resolve_key_file(path: &Path) -> anyhow::Result<PathBuf> {
  let resolved = std::fs::canonicalize(path).with_context(|| {
    format!("Failed to resolve the private key path {path:?}")
  })?;
  check_private_key_path(&resolved)?;
  let is_link = std::fs::symlink_metadata(path)
    .is_ok_and(|metadata| metadata.file_type().is_symlink());
  if is_link {
    for suffix in [NEXT_SUFFIX, OLD_SUFFIX] {
      let left = sibling(path, suffix);
      if left.symlink_metadata().is_ok() {
        return Err(anyhow!(
          "{left:?} was left beside the symlink {path:?} by a key rotation of an earlier version, which rotated the path of the link: rotations now write the key file it points to, {resolved:?}, and keep their files beside it. Move it to {:?} to carry that rotation on (or away, if its key was never registered anywhere)",
          sibling(&resolved, suffix)
        ));
      }
    }
  }
  Ok(resolved)
}

/// Whether a private key given inline reads as the path of a key
/// file: taken as the key it would be the raw key (up to 32 bytes
/// are), one anybody can derive from where key files usually are.
///
/// - The `file:` prefix, also in another case or after a space.
/// - What starts like a path: `./`, `../`, `~/`, a drive (`C:\`),
///   or `/`. A random raw key may start with `/` too (one in 64 of
///   those `openssl rand -base64 24` prints), so a `/` is excused
///   where the rest reads as one: base64 with an uppercase letter,
///   a lowercase letter and a digit in it, which paths rarely are.
/// - What ends like a key file: `.key`, `.pem`, `.der`, `.pk8`,
///   `.p8`, `.priv`.
///
/// It goes by the string alone: a key is never looked up as a file.
/// No pkcs8 key (pem, or base64 der, which starts with `M`) is any
/// of these, so only a raw key is ever refused for it. Other paths
/// are still taken as a raw key: a relative one without such an
/// ending (`keys/device`), one from a variable (`$HOME/key`).
pub fn looks_like_a_path(private_key: &str) -> bool {
  let spec = private_key.trim();
  let bytes = spec.as_bytes();
  let prefix = spec
    .get(..5)
    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("file:"));
  let relative = ["./", "../", "~/", ".\\", "..\\", "~\\"]
    .iter()
    .any(|start| spec.starts_with(start));
  let drive = bytes.len() >= 3
    && bytes[0].is_ascii_alphabetic()
    && bytes[1] == b':'
    && matches!(bytes[2], b'\\' | b'/');
  let ending = [".key", ".pem", ".der", ".pk8", ".p8", ".priv"]
    .iter()
    .any(|ending| {
      bytes.len() > ending.len()
        && bytes[bytes.len() - ending.len()..]
          .eq_ignore_ascii_case(ending.as_bytes())
    });
  // As random base64 of a raw key's length reads, bar one in
  // thousands.
  let random = || {
    bytes.len().is_multiple_of(4)
      && data_encoding::BASE64.decode(bytes).is_ok()
      && bytes.iter().any(u8::is_ascii_uppercase)
      && bytes.iter().any(u8::is_ascii_lowercase)
      && bytes.iter().any(u8::is_ascii_digit)
  };
  prefix
    || relative
    || drive
    || ending
    || (spec.starts_with('/') && !random())
}

/// The key file a key spec names: `Some(path)` for
/// `file:/path/to/key`, `None` for a key given inline. This is how
/// [RotatableKeyPair::from_private_key_spec] and
/// [SpkiPublicKey::from_spec] read a spec, for apps which need the
/// path of a spec themselves (eg. to write a key there later), so
/// they agree on it.
///
/// Whitespace around the spec, and around the path after `file:`,
/// is no part of the path. A spec usually comes from an environment
/// variable or a config line, where a stray space or `\r` is easily
/// left, and taken with it the path names another file: one which
/// doesn't exist, where a new key would be generated in place of
/// the configured one. The prefix is a lowercase `file:`
/// ([RotatableKeyPair::from_private_key_spec] refuses one in
/// another case, see [looks_like_a_path]).
///
/// `file:` without a path is an error.
pub fn key_spec_path(spec: &str) -> anyhow::Result<Option<&Path>> {
  let Some(path) = spec.trim().strip_prefix("file:") else {
    return Ok(None);
  };
  let path = path.trim();
  if path.is_empty() {
    return Err(anyhow!(
      "The key spec `file:` names no key file, use `file:/path/to/key`"
    ));
  }
  Ok(Some(Path::new(path)))
}

/// A key pair loaded from a private key spec, which a file backed
/// pair can replace while in use: [Self::rotate] in one step, or
/// [Self::begin_rotation] in two phases.
///
/// One rotation at a time: [Self::rotate], [Self::begin_rotation]
/// and [Self::finish_rotation] error while another rotation of the
/// pair is in flight. Reads ([Self::load], [Self::retired],
/// [Self::rotation_pending]) never count as one. Nothing
/// coordinates separate processes: only one process may rotate a
/// given key file.
///
/// The pair keeps the [PkiKind] it was loaded as: every key it
/// rotates to is of that kind's algorithm.
pub struct RotatableKeyPair {
  keys: ArcSwap<EncodedKeyPair>,
  pki_kind: PkiKind,
  path: Option<PathBuf>,
  /// See [Self::generated].
  generated: bool,
  /// Whether a rotation is in flight, see [RotationGuard].
  rotating: AtomicBool,
}

impl RotatableKeyPair {
  /// Parses from either direct private key (raw / der / pem),
  /// or from file containing raw / der / pem.
  /// Use `file:/path/to/private.key` to specify file: a key is
  /// generated and written there when the file does not exist. The
  /// file is created, never written over one: of processes starting
  /// at once on the same missing key file, one generates the key and
  /// the others load it (see [EncodedKeyPair::load_maybe_generate]),
  /// and a symlink to a file which does not exist is an error.
  /// Whitespace around the spec and the path is ignored (see
  /// [key_spec_path]), and `file:` without a path is an error.
  /// An empty key, or an existing empty file, is an error, and so
  /// is a key of the other algorithm than `pki_kind` uses
  /// ([WrongKeyAlgorithm]). Whether a key was generated is told by
  /// [Self::generated].
  ///
  /// The pair keeps the path resolved ([Self::path]): absolute, with
  /// every symlink followed. A key path which is a symlink (eg. into
  /// a persistent volume) is rotated where it points: the link stays,
  /// the file it points to is replaced, and the rotation files
  /// (`.next`, `.old`) and the public key file (`.pub`) are written
  /// beside that file. A file it points to whose name ends in `.pub`
  /// is refused, and so are rotation files an earlier version left
  /// beside the link (which rotated the link's path): the error says
  /// where they belong now, beside the file the link points to.
  ///
  /// A rotation file beside the key file (`<path>.next`,
  /// `<path>.old`) which holds a key of the other algorithm is an
  /// error too ([WrongKeyAlgorithm], with a context naming the
  /// file), checked before a key is generated. A pair rotates within
  /// its algorithm, so it was left by a rotation of an earlier key
  /// (one moved away for a key of this kind), and no rotation of
  /// this key could resume or finish with it there. The file is left
  /// as it is: whether its key is still registered somewhere is for
  /// the operator to find out, before moving it away.
  ///
  /// A key given inline is pkcs8 encoded (pem, or base64 der), or
  /// exactly 32 raw bytes ([Pkcs8PrivateKey::from_inline_key]): a
  /// shorter raw value would be the key itself, zero padded, one
  /// anybody can find from the public key (`changeme`, the name of
  /// the node). It is refused, with an error naming the accepted
  /// forms (never the value). A spec which looks like a path but
  /// lacks the `file:` prefix (or has it misspelled) is an error too
  /// ([looks_like_a_path]): taken as raw bytes, the path would be the
  /// key, one anybody can derive.
  pub fn from_private_key_spec(
    pki_kind: PkiKind,
    private_key_spec: &str,
  ) -> anyhow::Result<Self> {
    let (keys, path, generated) = match key_spec_path(
      private_key_spec,
    )? {
      Some(configured) => {
        check_private_key_path(configured)?;
        let (keys, generated) = match EncodedKeyPair::load_existing(
          pki_kind, configured,
        )? {
          Some(keys) => (keys, false),
          None => {
            // Where the key is created: no link (one to a file
            // which does not exist is refused).
            check_rotation_files(pki_kind, configured)?;
            EncodedKeyPair::generate_missing(pki_kind, configured)?
          }
        };
        let path = resolve_key_file(configured)?;
        check_rotation_files(pki_kind, &path)?;
        (keys, Some(path), generated)
      }
      None => {
        if looks_like_a_path(private_key_spec) {
          return Err(anyhow!(
            "The private key looks like a file path, which would be taken for the key itself: use `file:/path/to/key` (a lowercase `file:`) to load a key file. A raw key which reads like a path is not taken: give the key as pkcs8 (base64 der or pem)"
          ));
        }
        // Not trimmed: a raw key is used exactly as given.
        (
          EncodedKeyPair::from_inline_key(
            pki_kind,
            private_key_spec,
          )?,
          None,
          false,
        )
      }
    };
    Ok(Self {
      keys: ArcSwap::new(Arc::new(keys)),
      pki_kind,
      path,
      generated,
      rotating: AtomicBool::new(false),
    })
  }

  /// The kind the pair was loaded as, which its keys are of.
  pub fn kind(&self) -> PkiKind {
    self.pki_kind
  }

  /// Whether [Self::from_private_key_spec] generated the key, as
  /// there was no file at the `file:` path: a key nothing can know
  /// yet, eg. not registered with the server which has to accept
  /// it. False for a key file which existed, and for a key given
  /// inline. Of processes starting at once on the same missing key
  /// file, true for the one which created it only: the others load
  /// its key. It tells what the load did: a later rotation doesn't
  /// change it.
  pub fn generated(&self) -> bool {
    self.generated
  }

  /// If 'path' is Some, generates, writes, and stores new key pair.
  /// Returns the public key, maybe new if using file.
  ///
  /// Writing the private key file is the switch: once it holds the
  /// new key, the pair in memory is the new one too, so this
  /// process and the next start agree. A write can fail after the
  /// new key is in place (syncing the directory after the rename),
  /// so on a failed write the file is read back to decide: holding
  /// the new key, the rotation goes ahead (with a warning),
  /// otherwise the error is returned and memory keeps the previous
  /// key. The `.pub` sidecar is refreshed on a best effort basis.
  /// The write is synchronous (no await, so the future can't be
  /// dropped between the switch and the in-memory swap). Errors
  /// while another rotation is in flight.
  pub async fn rotate(&self) -> anyhow::Result<SpkiPublicKey> {
    self.rotate_with(|private, path| private.write_pem_sync(path))
  }

  /// [Self::rotate], writing the private key file with `write`.
  fn rotate_with(
    &self,
    write: impl FnOnce(&Pkcs8PrivateKey, &Path) -> anyhow::Result<()>,
  ) -> anyhow::Result<SpkiPublicKey> {
    let pki_kind = self.pki_kind;
    let Some(path) = self.path.as_deref() else {
      return Ok(self.keys.load().public.clone());
    };
    let _rotating = RotationGuard::acquire(&self.rotating)?;
    let keys = EncodedKeyPair::generate(pki_kind)?;
    if let Err(e) = write(&keys.private, path) {
      // An error doesn't mean the file is unchanged: memory follows
      // whatever key the file now holds.
      if !file_holds_key(pki_kind, path, &keys.public) {
        return Err(e);
      }
      tracing::warn!(
        "Rotated the private key at {path:?}, though writing it reported an error | {e:#}"
      );
    }
    let public_key = keys.public.clone();
    self.keys.store(Arc::new(keys));
    sync_parent_dir(path);
    if let Err(e) =
      public_key.write_pem_sync(path.with_extension("pub"))
    {
      tracing::warn!(
        "Rotated the private key, but failed to refresh the public key file | {e:#}"
      );
    }
    Ok(public_key)
  }

  pub fn load(&self) -> arc_swap::Guard<Arc<EncodedKeyPair>> {
    self.keys.load()
  }

  pub fn rotatable(&self) -> bool {
    self.path.is_some()
  }

  /// The live private key file, when file backed: the path of the
  /// `file:` spec resolved, absolute and with every symlink followed
  /// (see [Self::from_private_key_spec]). The file rotations replace,
  /// with the rotation files beside it.
  pub fn path(&self) -> Option<&Path> {
    self.path.as_deref()
  }

  /// Starts a two-phase rotation of a file backed pair, for
  /// clients whose public key is registered somewhere (a server
  /// allow list) that must learn the new key before the old one
  /// stops being used: generates a candidate pair written to
  /// `<path>.next`, leaving the live key file untouched, so a crash
  /// at any point before [KeyRotation::commit] still boots with the
  /// registered key. Resumes an existing candidate (a rotation
  /// interrupted before commit; the caller re-registers it, which
  /// must be idempotent). Errors when the pair is not file backed,
  /// while another rotation is in flight (until the returned
  /// [KeyRotation] is committed, aborted or dropped), and while a
  /// [retired][Self::retired] key of an earlier rotation is still
  /// waiting to be finished. A `<path>.old` holding the live key (a
  /// commit interrupted before its switch) is not a retired key, and
  /// is removed while the live file holds that key too (otherwise
  /// kept, as it may be the only copy of the key in use, and
  /// written again by the next commit). A `<path>.next` holding the
  /// live key (a commit interrupted after its switch) is not a
  /// candidate, and is replaced by a new one.
  pub fn begin_rotation(&self) -> anyhow::Result<KeyRotation<'_>> {
    let pki_kind = self.pki_kind;
    let Some(path) = self.path.as_deref() else {
      anyhow::bail!(
        "The private key is not file backed, so it cannot be rotated"
      );
    };
    let guard = RotationGuard::acquire(&self.rotating)?;
    let old_path = sibling(path, OLD_SUFFIX);
    let unfinished = || {
      format!(
        "A previous rotation is not finished: the retired key at {old_path:?} must be revoked and cleaned up first"
      )
    };
    if self
      .load_retired(&old_path, true)
      .with_context(unfinished)?
      .is_some()
    {
      return Err(anyhow!(unfinished()));
    }
    let next_path = sibling(path, NEXT_SUFFIX);
    let candidate = match next_path.try_exists()? {
      true => match EncodedKeyPair::from_file(pki_kind, &next_path) {
        // Left by a commit which switched to it, but did not get to
        // remove it: that rotation is done. Start a new one.
        Ok(candidate)
          if candidate.public == self.keys.load().public =>
        {
          tracing::info!(
            "Replacing the rotation candidate at {next_path:?}: it holds the live key, left by a key rotation which switched to it"
          );
          Self::write_candidate(pki_kind, &next_path)?
        }
        Ok(candidate) => {
          tracing::info!(
            "Resuming key rotation with the candidate at {next_path:?}"
          );
          candidate
        }
        // Unreadable leftover: it was never usable, so nothing can
        // have been registered under it. Start over.
        Err(e) => {
          tracing::warn!(
            "Replacing the unreadable rotation candidate at {next_path:?} | {e:#}"
          );
          Self::write_candidate(pki_kind, &next_path)?
        }
      },
      false => Self::write_candidate(pki_kind, &next_path)?,
    };
    Ok(KeyRotation {
      pair: self,
      pki_kind,
      live_path: path.to_path_buf(),
      next_path,
      old_path,
      candidate,
      _rotating: guard,
    })
  }

  fn write_candidate(
    pki_kind: PkiKind,
    next_path: &Path,
  ) -> anyhow::Result<EncodedKeyPair> {
    let candidate = EncodedKeyPair::generate(pki_kind)?;
    candidate.private.write_pem_sync(next_path)?;
    Ok(candidate)
  }

  /// The pair a committed rotation retired (`<path>.old`), until
  /// [Self::finish_rotation] removes it: the caller revokes its
  /// public key wherever it was registered, then finishes. `None`
  /// when no rotation is waiting to be finished.
  ///
  /// Never the live pair: a `<path>.old` holding the live key was
  /// left by a commit that did not switch (interrupted, or its
  /// write failed), so there is nothing to revoke. `None` is
  /// returned, and the file is left for the next
  /// [begin_rotation][Self::begin_rotation] or
  /// [finish_rotation][Self::finish_rotation] to remove, once the
  /// live file holds that key too (until then
  /// [Self::rotation_pending] stays true).
  ///
  /// Only reads, without the rotation guard: it never makes a
  /// concurrent rotation fail as already in progress.
  pub fn retired(&self) -> anyhow::Result<Option<EncodedKeyPair>> {
    let Some(path) = self.path.as_deref() else {
      return Ok(None);
    };
    // Never settles: during a commit `.old` holds the live key
    // until the switch, so only a holder of the guard may remove
    // it.
    self.load_retired(&sibling(path, OLD_SUFFIX), false)
  }

  /// Loads `<path>.old`, see [Self::retired]. `settle` removes one
  /// holding the live key: only under the rotation guard.
  fn load_retired(
    &self,
    old_path: &Path,
    settle: bool,
  ) -> anyhow::Result<Option<EncodedKeyPair>> {
    let pki_kind = self.pki_kind;
    if !old_path.try_exists()? {
      return Ok(None);
    }
    let retired = match EncodedKeyPair::from_file(pki_kind, old_path)
    {
      Ok(retired) => retired,
      // Finished meanwhile ([Self::retired] loads without the
      // rotation guard).
      Err(_) if !old_path.try_exists()? => return Ok(None),
      Err(e) => {
        return Err(e).with_context(|| {
          format!("Failed to load the retired key at {old_path:?}")
        });
      }
    };
    if retired.public != self.keys.load().public {
      return Ok(Some(retired));
    }
    // Only while the live file holds the key too: otherwise `.old`
    // may be the only copy of the key in use.
    if settle
      && self.path.as_deref().is_some_and(|live| {
        file_holds_key(pki_kind, live, &retired.public)
      })
    {
      tracing::info!(
        "Removing {old_path:?}: it holds the live key, left by a key rotation which did not switch"
      );
      remove_file_if_exists(old_path)?;
    }
    Ok(None)
  }

  /// Whether a rotation was interrupted: a candidate (`<path>.next`)
  /// or a retired key (`<path>.old`) is waiting, see
  /// [Self::begin_rotation] and [Self::retired]. Also true for a
  /// `<path>.old` holding the live key (a commit that did not
  /// switch), until [Self::begin_rotation] or
  /// [Self::finish_rotation] removes it. Not for a
  /// `<path>.next` holding the live key (a commit interrupted after
  /// its switch): there is nothing to resume.
  pub fn rotation_pending(&self) -> bool {
    self.path.as_deref().is_some_and(|path| {
      let next = sibling(path, NEXT_SUFFIX);
      (next.exists()
        && !Pkcs8PrivateKey::from_file(self.pki_kind, &next)
          .is_ok_and(|next| next == self.keys.load().private))
        || sibling(path, OLD_SUFFIX).exists()
    })
  }

  /// Deletes the retired key of a committed rotation. Idempotent.
  /// Errors while a rotation is in flight, as its commit may be
  /// writing `<path>.old` right then.
  ///
  /// A `<path>.old` holding the key in use is no retired key (see
  /// [Self::retired]), and follows the rule of
  /// [begin_rotation][Self::begin_rotation]: removed while the live
  /// file holds that key too, otherwise kept (with a warning, and
  /// `Ok`), as it may be the only copy of the key in use on disk (a
  /// commit whose write failed midway, see [KeyRotation::commit]).
  /// [Self::rotation_pending] then stays true, and the next commit
  /// writes the live file again.
  pub fn finish_rotation(&self) -> anyhow::Result<()> {
    let Some(path) = self.path.as_deref() else {
      return Ok(());
    };
    let _rotating = RotationGuard::acquire(&self.rotating)?;
    let old_path = sibling(path, OLD_SUFFIX);
    // The private keys compare, as in [Self::rotation_pending].
    let holds_key_in_use = |file: &Path| {
      Pkcs8PrivateKey::from_file(self.pki_kind, file)
        .is_ok_and(|key| key == self.keys.load().private)
    };
    if holds_key_in_use(&old_path) && !holds_key_in_use(path) {
      tracing::warn!(
        "Keeping {old_path:?}: it holds the key in use, which the live key file {path:?} does not (a key rotation whose switch failed), so it may be the only copy on disk. Retry the rotation: its commit writes the live key file again"
      );
      return Ok(());
    }
    remove_file_if_exists(&old_path)
  }
}

/// Marks a rotation of a [RotatableKeyPair] in flight, until
/// dropped.
struct RotationGuard<'a>(&'a AtomicBool);

impl<'a> RotationGuard<'a> {
  fn acquire(rotating: &'a AtomicBool) -> anyhow::Result<Self> {
    rotating
      .compare_exchange(
        false,
        true,
        Ordering::Acquire,
        Ordering::Relaxed,
      )
      .map_err(|_| {
        anyhow!("A key rotation is already in progress")
      })?;
    Ok(Self(rotating))
  }
}

impl Drop for RotationGuard<'_> {
  fn drop(&mut self) {
    self.0.store(false, Ordering::Release);
  }
}

/// Deletes the rotation file at `path`, if there is one. The removal
/// is synced to disk (see [sync_parent_dir]), so a finished rotation
/// doesn't offer its retired key again after a power loss.
fn remove_file_if_exists(path: &Path) -> anyhow::Result<()> {
  match std::fs::remove_file(path) {
    Ok(()) => {
      sync_parent_dir(path);
      Ok(())
    }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(e) => {
      Err(e).with_context(|| format!("Failed to delete {path:?}"))
    }
  }
}

/// Flushes the directory entries beside `path` (a rename into
/// place, a removal) to disk, so a switched key survives a power
/// loss before the caller acts on it (revokes the previous key).
/// Best effort: the change already happened, so a failure is only
/// logged. A directory which can't be synced (some filesystems) is
/// skipped, see `mogh_secret_file::sync_parent_dir`.
fn sync_parent_dir(path: &Path) {
  if let Err(e) = mogh_secret_file::sync_parent_dir(path) {
    tracing::warn!(
      "Failed to sync the key directory of {path:?} to disk | {e:#}"
    );
  }
}

/// An in-flight rotation, see [RotatableKeyPair::begin_rotation].
/// Dropping it without [commit][Self::commit] or
/// [abort][Self::abort] ends the rotation and leaves the candidate
/// file for the next
/// [begin_rotation][RotatableKeyPair::begin_rotation] to resume.
pub struct KeyRotation<'a> {
  pair: &'a RotatableKeyPair,
  pki_kind: PkiKind,
  live_path: PathBuf,
  next_path: PathBuf,
  old_path: PathBuf,
  candidate: EncodedKeyPair,
  _rotating: RotationGuard<'a>,
}

impl KeyRotation<'_> {
  /// The new pair, not yet in use.
  pub fn candidate(&self) -> &EncodedKeyPair {
    &self.candidate
  }

  /// The pair in use until commit.
  pub fn previous(&self) -> Arc<EncodedKeyPair> {
    self.pair.load().clone()
  }

  /// Makes the candidate the live pair. The previous private key
  /// is first written to `<path>.old` (to be revoked, see
  /// [RotatableKeyPair::retired]), then the candidate is written
  /// over the live key file the way [RotatableKeyPair::rotate]
  /// writes it (see `mogh_secret_file::write`): an atomic replace
  /// which keeps the file's owner, group and mode, so the live file
  /// never goes missing. A key file which can't be replaced, like a
  /// docker / kubernetes single file mount, is written in place
  /// instead, which is **not atomic**: interrupted midway, the live
  /// file can be left partially written (the previous key is still
  /// at `<path>.old`, the candidate at `<path>.next`). From here
  /// every signature uses the new key, and the switch is synced to
  /// disk before this returns. `<path>.next`, a copy of the live key
  /// from then on, is removed, and the `.pub` sidecar refreshed, on
  /// a best effort basis.
  ///
  /// Refuses (changing nothing) when `<path>.next` no longer holds
  /// the candidate, or a retired key is already waiting (a
  /// `<path>.old` holding the key in use, left by a commit which did
  /// not switch, is none: it is written again). A write can report
  /// an error and have happened anyway, so on a failed write the
  /// live file is read back: holding the candidate, the commit goes
  /// ahead (with a warning). Otherwise nothing switched, and
  /// `<path>.old` is removed again while the live file holds the
  /// previous key (kept when the live file can't be read, as it may
  /// be the only copy: [RotatableKeyPair::begin_rotation] and
  /// [RotatableKeyPair::finish_rotation] keep it too, until the live
  /// file holds that key again or a commit switches).
  pub fn commit(self) -> anyhow::Result<()> {
    self.commit_with(|private, live| private.write_pem_sync(live))
  }

  /// [Self::commit], writing the candidate's private key over the
  /// live key file with `write`.
  fn commit_with(
    self,
    write: impl FnOnce(&Pkcs8PrivateKey, &Path) -> anyhow::Result<()>,
  ) -> anyhow::Result<()> {
    // The candidate file must still hold the key memory switches
    // to: the one the caller registered, which a restart before
    // the switch resumes.
    let on_disk =
      EncodedKeyPair::from_file(self.pki_kind, &self.next_path)
        .with_context(|| {
          format!(
            "Failed to load the rotation candidate at {:?}",
            self.next_path
          )
        })?;
    if on_disk.public != self.candidate.public {
      return Err(anyhow!(
        "The rotation candidate at {:?} changed since the rotation began",
        self.next_path
      ));
    }
    let previous = self.pair.load().clone();
    // A `.old` holding the key in use is no retired key: a commit
    // which did not switch left it, kept while the live file can't
    // be read (a write which failed midway). Written again below.
    if self.old_path.try_exists()?
      && !file_holds_key(
        self.pki_kind,
        &self.old_path,
        &previous.public,
      )
    {
      return Err(anyhow!(
        "A retired key is already waiting at {:?}",
        self.old_path
      ));
    }
    previous
      .private
      .write_pem_sync(&self.old_path)
      .context("Failed to keep the previous key for revocation")?;
    if let Err(e) = write(&self.candidate.private, &self.live_path) {
      // A write can report an error and have happened anyway
      // (syncing the directory after the replace, a retried NFS
      // rename): memory follows whatever key the live file now
      // holds, as in [RotatableKeyPair::rotate].
      if !file_holds_key(
        self.pki_kind,
        &self.live_path,
        &self.candidate.public,
      ) {
        // Nothing switched: `.old` must not offer the live key for
        // revocation. Removed only while the live file holds that
        // key too, so it is never the only copy of the key in use.
        if file_holds_key(
          self.pki_kind,
          &self.live_path,
          &previous.public,
        ) && let Err(e) = std::fs::remove_file(&self.old_path)
        {
          tracing::warn!(
            "Failed to remove {:?} after the failed key switch | {e:#}",
            self.old_path
          );
        }
        return Err(e.context(format!(
          "Failed to move the new key {:?} into place at {:?}",
          self.next_path, self.live_path
        )));
      }
      tracing::warn!(
        "Moved the new key into place at {:?}, though writing it reported an error | {e:#}",
        self.live_path
      );
    }
    let public = self.candidate.public.clone();
    self.pair.keys.store(Arc::new(self.candidate));
    sync_parent_dir(&self.live_path);
    // A copy of the live key now. One left behind is never resumed
    // (see [RotatableKeyPair::begin_rotation]).
    if let Err(e) = remove_file_if_exists(&self.next_path) {
      tracing::warn!(
        "Switched to the new key, but failed to remove the rotation candidate file | {e:#}"
      );
    }
    if let Err(e) =
      public.write_pem_sync(self.live_path.with_extension("pub"))
    {
      tracing::warn!(
        "Rotated the private key, but failed to refresh the public key file | {e:#}"
      );
    }
    Ok(())
  }

  /// Drops the candidate (deletes `<path>.next`). Nothing else
  /// changed.
  pub fn abort(self) -> anyhow::Result<()> {
    remove_file_if_exists(&self.next_path).with_context(|| {
      format!(
        "Failed to delete the rotation candidate at {:?}",
        self.next_path
      )
    })
  }
}
