//! `cicada:` sources, without a Core to load them from. Its own
//! test binary: it sets the process wide `CICADA_...` environment
//! the loader reads once.
// Integration test binaries only use a subset of the library
// dependencies (none without the feature). Before the `cfg`, which
// empties the crate without the feature.
#![allow(unused_crate_dependencies)]
#![cfg(feature = "cicada")]

use std::path::Path;

use mogh_config::{ConfigLoader, Error};

#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct Config {
  #[serde(default)]
  port: u16,
  #[serde(default)]
  db_password: String,
}

/// Skipping a source Core can't serve would start the app with the
/// local defaults where the operator expects their secrets.
#[test]
fn a_cicada_source_which_fails_to_load_is_an_error() {
  let dir = std::env::temp_dir()
    .join(format!("mogh_config_cicada_test_{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&dir);
  std::fs::create_dir_all(&dir).unwrap();
  let defaults = dir.join("defaults.toml");
  std::fs::write(&defaults, "port = 8080\n").unwrap();

  // A path the loader's syntax refuses (nothing after the scheme, a
  // `..`, a query parameter other than `env`) is an error naming the
  // path as listed, before Core is asked anything: here, before the
  // loader is even configured.
  for path in [
    "cicada://",
    "cicada://app/../secrets.env?env=prod",
    "cicada://app/secrets.env?enb=prod",
  ] {
    let err = ConfigLoader {
      paths: &[&defaults, Path::new(path)],
      match_wildcards: &[],
      include_file_name: ".include",
      merge_nested: true,
      extend_array: false,
      debug_print: false,
    }
    .load::<Config>()
    .unwrap_err();
    let Error::CicadaLoad {
      path: listed,
      message,
    } = &err
    else {
      panic!("expected a cicada load error for {path}, got {err}");
    };
    assert_eq!(listed, Path::new(path));
    assert!(message.contains("Invalid cicada path"), "{message}");
  }

  // A file of no config type, told by its name inside Cicada, is
  // refused as the listed path before the device is initialized or
  // the file read: here, before the loader is even configured.
  let err = ConfigLoader {
    paths: &[
      &defaults,
      Path::new("cicada://app/config.txt?env=prod"),
    ],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>()
  .unwrap_err();
  let Error::UnsupportedFileType { path } = &err else {
    panic!("expected an unsupported file type error, got {err}");
  };
  assert_eq!(path, Path::new("cicada://app/config.txt?env=prod"));

  // Safety: the only test in this binary, and the loader reads the
  // environment on the load below.
  unsafe {
    for (name, _) in std::env::vars_os() {
      if name.to_string_lossy().starts_with("CICADA_") {
        std::env::remove_var(name);
      }
    }
    // Nothing listens on port 1: Core is unreachable. The names
    // the loader reads (cicada_loader 0.26 on): with the older
    // `CICADA_CORE_...` ones, the load failed on "CICADA_ADDRESS is
    // not set" before asking Core anything.
    std::env::set_var("CICADA_ADDRESS", "http://127.0.0.1:1");
    std::env::set_var("CICADA_CONNECT_TIMEOUT_SECS", "1");
    std::env::set_var("CICADA_REQUEST_TIMEOUT_SECS", "1");
    // An existing key (inline: exactly 32 raw bytes), which the
    // device asks Core about. A key file generated at this start
    // would be one Core can't know: the device would go straight to
    // onboarding, and fail on the missing onboarding key without a
    // request either.
    std::env::set_var(
      "CICADA_PRIVATE_KEY",
      "mogh-config-cicada-test-key-0001",
    );
  }

  let res = ConfigLoader {
    paths: &[
      &defaults,
      Path::new("cicada://app/secrets.env?env=prod"),
    ],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>();

  // A `cicada:` line in an include file is a cicada source too (it
  // used to be dropped as a missing local path).
  std::fs::write(
    dir.join(".include"),
    "cicada://app/included.env?env=prod # the secrets\n",
  )
  .unwrap();
  let included = ConfigLoader {
    paths: &[&dir],
    match_wildcards: &["*.toml"],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>();
  let _ = std::fs::remove_dir_all(&dir);

  let err = res.unwrap_err();
  let Error::CicadaLoad { path, message } = &err else {
    panic!("expected a cicada load error, got {err}");
  };
  assert_eq!(path, Path::new("cicada://app/secrets.env?env=prod"));
  assert_core_unreachable(message);
  assert!(
    err.to_string().contains("cicada://app/secrets.env"),
    "{err}"
  );

  let err = included.unwrap_err();
  let Error::CicadaLoad { path, message } = &err else {
    panic!("expected a cicada load error, got {err}");
  };
  assert_eq!(path, Path::new("cicada://app/included.env?env=prod"));
  assert_core_unreachable(message);
}

/// The load failed asking Core, not on the loader's configuration.
#[track_caller]
fn assert_core_unreachable(message: &str) {
  assert!(
    message.contains("Failed to reach Cicada Core"),
    "{message}"
  );
  assert!(message.contains("127.0.0.1:1"), "{message}");
  assert!(!message.contains("is not set"), "{message}");
}
