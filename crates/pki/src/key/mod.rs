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

  /// Loads the pair from the private key file, or generates and
  /// writes a new one when there is no file at the path. An existing
  /// file that holds no valid key (an empty file) is an error, never
  /// replaced.
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

    Ok(Self { private, public })
  }

  /// The pair of a private key in any form
  /// [Pkcs8PrivateKey::from_maybe_raw_bytes] accepts, deriving the
  /// public key.
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
  /// Whether a rotation is in flight, see [RotationGuard].
  rotating: AtomicBool,
}

impl RotatableKeyPair {
  /// Parses from either direct private key (raw / der / pem),
  /// or from file containing raw / der / pem.
  /// Use `file:/path/to/private.key` to specify file: a key is
  /// generated and written there when the file does not exist.
  /// An empty key, or an existing empty file, is an error, and so
  /// is a key of the other algorithm than `pki_kind` uses
  /// ([WrongKeyAlgorithm]).
  ///
  /// A spec which looks like a path but lacks the `file:` prefix (or
  /// has it misspelled) is an error too ([looks_like_a_path]): up to
  /// 32 bytes are a raw key, so the path would be taken for the key
  /// itself, one anybody can derive.
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
      if looks_like_a_path(private_key_spec) {
        return Err(anyhow!(
          "The private key looks like a file path, which would be taken for the key itself: use `file:/path/to/key` (lowercase, nothing before it) to load a key file. A raw key which reads like a path is not taken: give the key as pkcs8 (base64 der or pem)"
        ));
      }
      (
        EncodedKeyPair::from_private_key(pki_kind, private_key_spec)?,
        None,
      )
    };
    Ok(Self {
      keys: ArcSwap::new(Arc::new(keys)),
      pki_kind,
      path,
      rotating: AtomicBool::new(false),
    })
  }

  /// The kind the pair was loaded as, which its keys are of.
  pub fn kind(&self) -> PkiKind {
    self.pki_kind
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

  /// The live private key file, when file backed.
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

fn remove_file_if_exists(path: &Path) -> anyhow::Result<()> {
  match std::fs::remove_file(path) {
    Ok(()) => Ok(()),
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(e) => {
      Err(e).with_context(|| format!("Failed to delete {path:?}"))
    }
  }
}

/// Flushes the directory entries beside `path` (a rename into
/// place) to disk, so a switched key survives a power loss before
/// the caller acts on it (revokes the previous key). Best effort:
/// the switch already happened, so a failure is only logged.
fn sync_parent_dir(path: &Path) {
  #[cfg(unix)]
  {
    let parent = match path.parent() {
      Some(parent) if !parent.as_os_str().is_empty() => parent,
      _ => Path::new("."),
    };
    if let Err(e) =
      std::fs::File::open(parent).and_then(|dir| dir.sync_all())
    {
      tracing::warn!(
        "Failed to sync the key directory {parent:?} to disk | {e:#}"
      );
    }
  }
  #[cfg(not(unix))]
  let _ = path;
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
