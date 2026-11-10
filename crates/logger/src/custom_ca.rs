//! The custom root CAs the TLS clients of the process trust from
//! `SSL_CERT_DIR`, logged on [init](crate::init) (the `custom_ca`
//! feature).
//!
//! The clients built on `rustls-native-certs` (reqwest's verifier
//! on Linux, tokio-tungstenite's native roots) load their root
//! certificates on their own, from the bundle `SSL_CERT_FILE` names
//! and from every file directly inside the directories of
//! `SSL_CERT_DIR`, each time one is built. An image which points
//! `SSL_CERT_DIR` at the directory custom root CAs are mounted to
//! has them trusted as mounted, without `update-ca-certificates`.
//! What the clients skip there (a file unreadable for the
//! container's user, DER encoded, a directory) they skip without a
//! line the app's logger shows, so the logger says on init what
//! they find.

use std::path::Path;

/// The variable naming the certificate directories, separated by
/// `:` (OpenSSL's, which `rustls-native-certs` reads).
const CERT_DIR_ENV: &str = "SSL_CERT_DIR";

/// What the TLS clients find in a certificate directory.
#[derive(Debug, Default, PartialEq)]
struct Found {
  /// Its entries, dot entries aside (the dot directories of a
  /// Kubernetes volume, a `.gitkeep`).
  entries: usize,
  /// The distinct certificates the clients trust from its files.
  trusted: usize,
  /// The PEM certificates rustls refuses as trust anchors.
  invalid: usize,
  /// The loader's own errors: a file it can't read, a PEM block it
  /// can't parse.
  errors: Vec<String>,
}

/// Reads `dir` as the TLS clients do.
fn read(dir: &Path) -> std::io::Result<Found> {
  let entries = std::fs::read_dir(dir)?
    .flatten()
    .filter(|entry| {
      !entry.file_name().as_encoded_bytes().starts_with(b".")
    })
    .count();
  if entries == 0 {
    return Ok(Found::default());
  }
  let loaded =
    rustls_native_certs::load_certs_from_paths(None, Some(dir));
  let (trusted, invalid) = rustls::RootCertStore::empty()
    .add_parsable_certificates(loaded.certs);
  Ok(Found {
    entries,
    trusted,
    invalid,
    errors: loaded.errors.iter().map(ToString::to_string).collect(),
  })
}

/// Logs how many certificates the TLS clients trust from each
/// directory of `SSL_CERT_DIR`, and warns about what they skip
/// there. Nothing is logged without the variable (outside of the
/// images a binary trusts the system's store, which the host's
/// admin maintains), nor for a directory holding no file.
pub(crate) fn log() {
  let Some(dirs) = std::env::var_os(CERT_DIR_ENV) else {
    return;
  };
  for dir in std::env::split_paths(&dirs)
    .filter(|dir| !dir.as_os_str().is_empty())
  {
    let found = match read(&dir) {
      Ok(found) => found,
      Err(e) => {
        tracing::warn!(
          "Custom CAs: failed to read the directory {} \
          ({CERT_DIR_ENV}) | {e}",
          dir.display()
        );
        continue;
      }
    };
    let dir = dir.display();
    for error in found.errors {
      tracing::warn!("Custom CAs: {dir} | {error}");
    }
    if found.invalid > 0 {
      tracing::warn!(
        "Custom CAs: {dir} | {} certificate(s) are no valid trust \
        anchor",
        found.invalid
      );
    }
    if found.trusted > 0 {
      tracing::info!(
        "Custom CAs: {} certificate(s) trusted from {dir}",
        found.trusted
      );
    } else if found.entries > 0 {
      tracing::warn!(
        "Custom CAs: nothing trusted from {dir} | no readable PEM \
        certificate directly inside"
      );
    }
  }
}

#[cfg(all(test, unix))]
mod tests {
  use std::path::PathBuf;

  use super::*;

  const TEST_CA_1: &str = "-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIUUPMsjvVFj6M2uw5fHJLGOoMbbUMwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQQ2ljYWRhIFRlc3QgQ0EgMTAgFw0yNjExMDYyMTEyNDhaGA8y
MTI2MTAxMzIxMTI0OFowGzEZMBcGA1UEAwwQQ2ljYWRhIFRlc3QgQ0EgMTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABPH3KixxJinHs+yewBt1QsIqvZEtacv9mxHG
FqapGHAp7LrKmBxLyrz1xuva+WuvCUccB+4+fb9pDFK0UX/2ZaujYzBhMB0GA1Ud
DgQWBBQGcuV0hkS08IPmKUVDIDUmN9ML5jAfBgNVHSMEGDAWgBQGcuV0hkS08IPm
KUVDIDUmN9ML5jAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggq
hkjOPQQDAgNIADBFAiEA0qnN816yvrnNzZmvLUHmAxPgFdd+XUYSMalAc7jfr8QC
IHkpb1LAfrsn7u5HrNjORXnj0Nx68C1ZQ4reAzD6pToH
-----END CERTIFICATE-----
";

  const TEST_CA_2: &str = "-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIUMcy0d4lNPLAG/Omywv/0kv2Qu8UwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQQ2ljYWRhIFRlc3QgQ0EgMjAgFw0yNjExMDYyMTEyNDhaGA8y
MTI2MTAxMzIxMTI0OFowGzEZMBcGA1UEAwwQQ2ljYWRhIFRlc3QgQ0EgMjBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABL3pbufyqva2slXO2fZcXtWepk91/kB4MZHN
uIw42W5n+MjEjgmGlqhLOV9eEdS2eWskN3O7E4L/sA3JQD++mdWjYzBhMB0GA1Ud
DgQWBBQn7aeXIRdl9OKVqb9ULqQ7tr8RzTAfBgNVHSMEGDAWgBQn7aeXIRdl9OKV
qb9ULqQ7tr8RzTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggq
hkjOPQQDAgNIADBFAiBF0KkR5cCJ++PagbeqFQf05BHgH/dAtm/4LmzIGJ65hwIh
AJ2OlcO6hbpoXoVREDDlNZHIwXtRGCVmAC2NZUpqfzap
-----END CERTIFICATE-----
";

  fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
      "mogh-logger-custom-ca-test-{name}-{}",
      std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
  }

  #[test]
  fn the_files_directly_inside_are_read_whatever_their_name() {
    let dir = scratch("inside");
    std::fs::write(dir.join("root_ca1.crt"), TEST_CA_1).unwrap();
    // Two in one file, one of them again: counted once.
    std::fs::write(
      dir.join("bundle.pem"),
      format!("{TEST_CA_1}{TEST_CA_2}"),
    )
    .unwrap();
    std::fs::write(dir.join(".gitkeep"), "").unwrap();
    // Only the files directly inside.
    std::fs::create_dir(dir.join("team")).unwrap();
    std::fs::write(dir.join("team").join("root_ca2.crt"), TEST_CA_2)
      .unwrap();
    assert_eq!(
      read(&dir).unwrap(),
      Found {
        entries: 3,
        trusted: 2,
        invalid: 0,
        errors: vec![],
      }
    );
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[test]
  fn what_the_clients_skip_shows_as_nothing_trusted_or_an_error() {
    use rustls::pki_types::{CertificateDer, pem::PemObject as _};

    // DER encoded, and a directory: skipped without an error.
    let dir = scratch("skipped");
    let der =
      CertificateDer::from_pem_slice(TEST_CA_1.as_bytes()).unwrap();
    std::fs::write(dir.join("der.crt"), der.as_ref()).unwrap();
    std::fs::create_dir(dir.join("mounted-as-a-directory.crt"))
      .unwrap();
    assert_eq!(
      read(&dir).unwrap(),
      Found {
        entries: 2,
        trusted: 0,
        invalid: 0,
        errors: vec![],
      }
    );
    std::fs::remove_dir_all(dir).unwrap();

    // A broken PEM block: the loader's error, the whole
    // certificates of the file trusted all the same.
    let dir = scratch("broken");
    let broken = TEST_CA_2.replace("-----END CERTIFICATE-----\n", "");
    std::fs::write(
      dir.join("ca.crt"),
      format!("{TEST_CA_1}{broken}"),
    )
    .unwrap();
    let found = read(&dir).unwrap();
    assert_eq!((found.trusted, found.errors.len()), (1, 1));
    assert!(
      found.errors[0].starts_with("failed to read PEM from file"),
      "{}",
      found.errors[0]
    );
    std::fs::remove_dir_all(dir).unwrap();

    // A file this user can't read (root reads everything).
    let dir = scratch("unreadable");
    let unreadable = dir.join("ca.crt");
    std::fs::write(&unreadable, TEST_CA_1).unwrap();
    std::fs::set_permissions(
      &unreadable,
      std::os::unix::fs::PermissionsExt::from_mode(0o000),
    )
    .unwrap();
    let found = read(&dir).unwrap();
    if std::fs::read(&unreadable).is_err() {
      assert_eq!((found.trusted, found.errors.len()), (0, 1));
      assert!(
        found.errors[0].contains("Permission denied"),
        "{}",
        found.errors[0]
      );
    }
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[test]
  fn an_empty_directory_holds_nothing() {
    let dir = scratch("empty");
    std::fs::write(dir.join(".gitkeep"), "").unwrap();
    assert_eq!(read(&dir).unwrap(), Found::default());
    std::fs::remove_dir_all(dir).unwrap();
  }
}
