//! A loader configured by the `CONFIG_*` variables
//! (`ConfigLoader::from_env`, `ConfigLoader::from_vars`).

// Integration test binaries only use a subset
// of the library dependencies.
#![allow(unused_crate_dependencies)]

use std::path::PathBuf;

use mogh_config::{ConfigLoader, Error};

/// The fields of a loader, comparable.
#[derive(Debug, PartialEq)]
struct Fields {
  paths: Vec<PathBuf>,
  match_wildcards: Vec<String>,
  include_file_name: String,
  merge_nested: bool,
  extend_array: bool,
  debug_print: bool,
}

impl Fields {
  fn of(loader: &ConfigLoader<'_, '_>) -> Fields {
    Fields {
      paths: loader
        .paths
        .iter()
        .map(|path| path.to_path_buf())
        .collect(),
      match_wildcards: loader
        .match_wildcards
        .iter()
        .map(|wildcard| wildcard.to_string())
        .collect(),
      include_file_name: loader.include_file_name.to_string(),
      merge_nested: loader.merge_nested,
      extend_array: loader.extend_array,
      debug_print: loader.debug_print,
    }
  }

  fn default() -> Fields {
    Fields::of(&ConfigLoader::default())
  }
}

/// The loader `vars` (the whole environment) configure.
fn from_vars(vars: &[(&str, &str)]) -> mogh_config::Result<Fields> {
  ConfigLoader::from_vars(vars.iter().copied())
    .map(|loader| Fields::of(&loader))
}

/// A fresh scratch directory per test.
fn scratch_dir(name: &str) -> PathBuf {
  let dir = std::env::temp_dir().join(format!(
    "mogh_config_from_env_{name}_{}_{}",
    std::process::id(),
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos()
  ));
  std::fs::create_dir_all(&dir).unwrap();
  dir
}

#[test]
fn nothing_set_is_the_default() {
  assert_eq!(from_vars(&[]).unwrap(), Fields::default());
  // Other variables are ignored, `CONFIG_` ones of no field too.
  let fields = from_vars(&[
    ("CONFIG_UNKNOWN", "x"),
    ("CONFIG_PATH", "/etc/app"),
    ("PATHS", "/etc/app"),
    ("APP_CONFIG_PATHS", "/etc/app"),
    ("CONFIG_UNKNOWN_FILE", "/not/read"),
  ])
  .unwrap();
  assert_eq!(fields, Fields::default());
}

#[test]
fn every_field_has_its_variable() {
  let fields = from_vars(&[
    ("CONFIG_PATHS", " /etc/app, ./app.local.toml ,"),
    ("CONFIG_MATCH_WILDCARDS", "*config.*,*.env"),
    ("CONFIG_INCLUDE_FILE_NAME", ".appinclude"),
    ("CONFIG_MERGE_NESTED", "true"),
    ("CONFIG_EXTEND_ARRAY", " TRUE "),
    ("CONFIG_DEBUG_PRINT", "True"),
  ])
  .unwrap();
  assert_eq!(
    fields,
    Fields {
      paths: vec![
        PathBuf::from("/etc/app"),
        PathBuf::from("./app.local.toml")
      ],
      match_wildcards: vec!["*config.*".into(), "*.env".into()],
      include_file_name: ".appinclude".into(),
      merge_nested: true,
      extend_array: true,
      debug_print: true,
    }
  );
  // Names in any case, `false` too.
  let fields = from_vars(&[
    ("config_paths", "/etc/app"),
    ("Config_Merge_Nested", "FALSE"),
  ])
  .unwrap();
  assert_eq!(fields.paths, [PathBuf::from("/etc/app")]);
  assert!(!fields.merge_nested);
}

/// A blank variable counts as unset (a compose file sets
/// `${CONFIG_X:-}` blank): the default stays.
#[test]
fn a_blank_variable_is_unset() {
  let fields = from_vars(&[
    ("CONFIG_PATHS", ""),
    ("CONFIG_MATCH_WILDCARDS", " , "),
    ("CONFIG_INCLUDE_FILE_NAME", "  "),
    ("CONFIG_MERGE_NESTED", ""),
    ("CONFIG_DEBUG_PRINT", "\t"),
  ])
  .unwrap();
  assert_eq!(fields, Fields::default());
}

#[test]
fn a_file_holds_the_value() {
  let dir = scratch_dir("file");
  let paths = dir.join("paths");
  std::fs::write(&paths, " /etc/app,/run/app \n").unwrap();
  let fields = from_vars(&[
    ("CONFIG_PATHS_FILE", paths.to_str().unwrap()),
    ("CONFIG_PATHS", "/ignored"),
  ])
  .unwrap();
  assert_eq!(
    fields.paths,
    [PathBuf::from("/etc/app"), PathBuf::from("/run/app")]
  );
  // One which can't be read names the variable and the path.
  let missing = dir.join("missing");
  let err =
    from_vars(&[("CONFIG_PATHS_FILE", missing.to_str().unwrap())])
      .unwrap_err();
  assert!(
    matches!(
      &err,
      Error::EnvFile { variable, path, .. }
        if variable == "CONFIG_PATHS_FILE" && *path == missing
    ),
    "{err}"
  );
  std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_value_the_field_cant_take_names_the_variable() {
  for (name, value, field) in [
    ("CONFIG_MERGE_NESTED", "hunter2", "merge_nested"),
    ("CONFIG_EXTEND_ARRAY", "yes-hunter2", "extend_array"),
    ("config_debug_print", "1hunter2", "debug_print"),
  ] {
    let err = from_vars(&[(name, value)]).unwrap_err();
    let Error::ParseEnv {
      variable,
      path,
      message,
    } = &err
    else {
      panic!("{name}: {err:?}");
    };
    assert_eq!(variable, name);
    assert_eq!(path, field);
    assert!(
      message.contains("expected a boolean"),
      "{name}: {message}"
    );
    for message in [err.to_string(), format!("{err:?}")] {
      assert!(!message.contains("hunter2"), "{name}: {message}");
    }
  }
  // Set twice, in two cases.
  let err =
    from_vars(&[("CONFIG_PATHS", "/a"), ("config_paths", "/b")])
      .unwrap_err();
  assert!(matches!(err, Error::EnvVarSetTwice { .. }), "{err}");
}

/// The loader loads what the variables name: the paths, with the
/// wildcards, the include file and the merge flags.
#[test]
fn the_loader_loads_what_the_variables_name() {
  let dir = scratch_dir("load");
  let write = |name: &str, contents: &str| {
    std::fs::write(dir.join(name), contents).unwrap();
  };
  write("app.config.toml", "a = 1\n[nested]\nx = 1\n");
  write("local.config.yaml", "nested:\n  y: 2\n");
  write("other.toml", "b = 2\n");
  let extra = dir.join("extra");
  std::fs::create_dir_all(&extra).unwrap();
  std::fs::write(extra.join("more.config.json"), r#"{ "c": 3 }"#)
    .unwrap();
  write(".appinclude", &extra.display().to_string());

  let config = ConfigLoader::from_vars([
    ("CONFIG_PATHS", dir.display().to_string()),
    ("CONFIG_MATCH_WILDCARDS", String::from("*config.*")),
    ("CONFIG_INCLUDE_FILE_NAME", String::from(".appinclude")),
    ("CONFIG_MERGE_NESTED", String::from("true")),
  ])
  .unwrap()
  .load::<serde_json::Value>()
  .unwrap();
  assert_eq!(
    config,
    serde_json::json!({ "a": 1, "c": 3, "nested": { "x": 1, "y": 2 } })
  );

  // The defaults: `*config*`, `.include` (none here), no merging.
  let config = ConfigLoader::from_vars([(
    "CONFIG_PATHS",
    dir.display().to_string(),
  )])
  .unwrap()
  .load::<serde_json::Value>()
  .unwrap();
  assert_eq!(
    config,
    serde_json::json!({ "a": 1, "nested": { "y": 2 } })
  );

  // A wildcard which doesn't compile is the loader's error, as ever.
  let err = ConfigLoader::from_vars([
    ("CONFIG_PATHS", dir.display().to_string()),
    ("CONFIG_MATCH_WILDCARDS", String::from("*config\\.toml")),
  ])
  .unwrap()
  .load::<serde_json::Value>()
  .unwrap_err();
  assert!(matches!(err, Error::InvalidWildcard { .. }), "{err}");
  std::fs::remove_dir_all(dir).unwrap();
}

/// `from_env` reads the process environment: the same loader as
/// `from_vars` given it (whatever `CONFIG_*` this test runs with).
#[test]
fn from_env_reads_the_process_environment() {
  let expected = ConfigLoader::from_vars(std::env::vars_os())
    .map(|loader| Fields::of(&loader))
    .map_err(|e| e.to_string());
  let actual = ConfigLoader::from_env()
    .map(|loader| Fields::of(&loader))
    .map_err(|e| e.to_string());
  assert_eq!(actual, expected);
}
