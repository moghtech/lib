//! The settings of the config loading, read from the environment
//! with an app's prefix (`mogh_config::LoaderEnv`). Each app's table
//! is checked as the app read it with its own copy before.

// Integration test binaries only use a subset
// of the library dependencies.
#![allow(unused_crate_dependencies)]

use std::path::PathBuf;

use mogh_config::{Error, LoaderDebug, LoaderEnv, LoaderSettings};

/// Komodo Core and Cicada Core: the image's `/config` unless the
/// variable says, a blank variable loading no file.
fn core(prefix: &str) -> LoaderEnv {
  LoaderEnv::new(prefix)
    .default_paths(["/config"])
    .allow_empty_paths()
}

/// Komodo Periphery: no config path by default, the debug output
/// set by the `--log-level` argument.
fn komodo_periphery() -> LoaderEnv {
  LoaderEnv::new("PERIPHERY_").debug(LoaderDebug::NoVariable)
}

/// Cicada Periphery: no config path by default, the debug output at
/// `CICADA_LOGGING_LEVEL` debug or trace.
fn cicada_periphery() -> LoaderEnv {
  LoaderEnv::new("CICADA_").debug(LoaderDebug::LoggingLevel)
}

fn read(
  env: &LoaderEnv,
  vars: &[(&str, &str)],
) -> mogh_config::Result<LoaderSettings> {
  env.read_vars(vars.iter().copied())
}

fn paths(paths: &[&str]) -> Vec<PathBuf> {
  paths.iter().map(PathBuf::from).collect()
}

#[test]
fn the_tables_name_the_variables_of_each_app() {
  for prefix in ["KOMODO_", "CICADA_"] {
    let env = core(prefix);
    assert_eq!(
      env.names().unwrap(),
      [
        "CONFIG_PATHS",
        "CONFIG_KEYWORDS",
        "MERGE_NESTED_CONFIG",
        "EXTEND_CONFIG_ARRAYS",
        "CONFIG_DEBUG",
      ]
      .map(|name| format!("{prefix}{name}"))
    );
    assert_eq!(
      env.alias_names(),
      ["CONFIG_PATH", "CONFIG_KEYWORD"]
        .map(|name| format!("{prefix}{name}"))
    );
  }
  assert_eq!(
    komodo_periphery().names().unwrap(),
    [
      "PERIPHERY_CONFIG_PATHS",
      "PERIPHERY_CONFIG_KEYWORDS",
      "PERIPHERY_MERGE_NESTED_CONFIG",
      "PERIPHERY_EXTEND_CONFIG_ARRAYS",
    ]
  );
  assert_eq!(
    cicada_periphery().names().unwrap(),
    [
      "CICADA_CONFIG_PATHS",
      "CICADA_CONFIG_KEYWORDS",
      "CICADA_MERGE_NESTED_CONFIG",
      "CICADA_EXTEND_CONFIG_ARRAYS",
      "CICADA_LOGGING_LEVEL",
    ]
  );
  // The table is an EnvSource, eg. for an app's list of variables.
  assert_eq!(
    core("KOMODO_").env_source().names().unwrap(),
    core("KOMODO_").names().unwrap()
  );
}

#[test]
fn nothing_set_is_the_defaults() {
  for prefix in ["KOMODO_", "CICADA_"] {
    let settings = read(&core(prefix), &[]).unwrap();
    assert_eq!(settings.config_paths, paths(&["/config"]));
    assert_eq!(settings.config_keywords, ["*config.*"]);
    assert!(settings.merge_nested_config);
    assert!(settings.extend_config_arrays);
    assert!(!settings.config_debug);
  }
  for env in [komodo_periphery(), cicada_periphery()] {
    let settings = read(&env, &[]).unwrap();
    assert!(settings.config_paths.is_empty());
    assert_eq!(settings.config_keywords, ["*config.*"]);
    assert!(settings.merge_nested_config);
    assert!(settings.extend_config_arrays);
    assert!(!settings.config_debug);
  }
  // Variables of other prefixes, and of no setting, are ignored.
  let settings = read(
    &core("KOMODO_"),
    &[
      ("CICADA_CONFIG_PATHS", "/cicada"),
      ("CONFIG_PATHS", "/none"),
      ("KOMODO_CONFIG_UNKNOWN", "x"),
    ],
  )
  .unwrap();
  assert_eq!(settings.config_paths, paths(&["/config"]));
}

/// Every setting from its variable, in any case, a list's entries
/// trimmed and blank ones dropped.
#[test]
fn every_setting_has_its_variable() {
  let settings = read(
    &core("KOMODO_"),
    &[
      ("KOMODO_CONFIG_PATHS", " /etc/komodo, ./local.toml ,"),
      ("KOMODO_CONFIG_KEYWORDS", " other.* , none.*,"),
      ("KOMODO_MERGE_NESTED_CONFIG", "FALSE"),
      ("komodo_extend_config_arrays", " false "),
      ("KOMODO_CONFIG_DEBUG", "True"),
    ],
  )
  .unwrap();
  assert_eq!(
    settings.config_paths,
    paths(&["/etc/komodo", "./local.toml"])
  );
  assert_eq!(settings.config_keywords, ["other.*", "none.*"]);
  assert!(!settings.merge_nested_config);
  assert!(!settings.extend_config_arrays);
  assert!(settings.config_debug);
}

/// The singular names are read while the plural ones are unset, a
/// blank one too (the plural wins when both are set).
#[test]
fn the_singular_names_are_read_too() {
  for env in [core("CICADA_"), cicada_periphery()] {
    let settings = read(
      &env,
      &[
        ("CICADA_CONFIG_PATH", "/single"),
        ("CICADA_CONFIG_KEYWORD", "single.*"),
      ],
    )
    .unwrap();
    assert_eq!(settings.config_paths, paths(&["/single"]));
    assert_eq!(settings.config_keywords, ["single.*"]);
    let settings = read(
      &env,
      &[
        ("CICADA_CONFIG_PATHS", "/plural"),
        ("CICADA_CONFIG_PATH", "/single"),
        ("CICADA_CONFIG_KEYWORDS", "plural.*"),
        ("CICADA_CONFIG_KEYWORD", "single.*"),
      ],
    )
    .unwrap();
    assert_eq!(settings.config_paths, paths(&["/plural"]));
    assert_eq!(settings.config_keywords, ["plural.*"]);
  }
  // A blank plural gives way to the singular, where a blank isn't a
  // value of its own.
  let settings = read(
    &cicada_periphery(),
    &[
      ("CICADA_CONFIG_PATHS", " "),
      ("CICADA_CONFIG_PATH", "/single"),
    ],
  )
  .unwrap();
  assert_eq!(settings.config_paths, paths(&["/single"]));
}

/// Blank counts as unset (the default stays), but for the config
/// paths of an app which [allows it empty](LoaderEnv::allow_empty_paths):
/// no config file then.
#[test]
fn blank_is_unset_unless_the_paths_may_be_empty() {
  for prefix in ["KOMODO_", "CICADA_"] {
    let settings = read(
      &core(prefix),
      &[
        (&format!("{prefix}CONFIG_PATHS"), ""),
        (&format!("{prefix}CONFIG_KEYWORDS"), " , "),
        (&format!("{prefix}MERGE_NESTED_CONFIG"), " "),
        (&format!("{prefix}CONFIG_DEBUG"), "\t"),
      ],
    )
    .unwrap();
    assert!(settings.config_paths.is_empty(), "{prefix}");
    assert_eq!(settings.config_keywords, ["*config.*"]);
    assert!(settings.merge_nested_config);
    assert!(!settings.config_debug);
  }
  let settings =
    read(&komodo_periphery(), &[("PERIPHERY_CONFIG_PATHS", " ")])
      .unwrap();
  assert!(settings.config_paths.is_empty());
  let settings = read(
    &LoaderEnv::new("APP_").default_paths(["/default"]),
    &[("APP_CONFIG_PATHS", "")],
  )
  .unwrap();
  assert_eq!(settings.config_paths, paths(&["/default"]));
}

/// The debug output: `<P>CONFIG_DEBUG`, `<P>LOGGING_LEVEL` at debug or
/// trace, or no variable at all (the app decides).
#[test]
fn the_debug_variable_is_the_apps() {
  for (level, debug) in [
    ("debug", true),
    ("trace", true),
    ("info", false),
    ("warn", false),
    ("error", false),
    ("", false),
  ] {
    let settings =
      read(&cicada_periphery(), &[("CICADA_LOGGING_LEVEL", level)])
        .unwrap();
    assert_eq!(settings.config_debug, debug, "{level}");
  }
  // CICADA_CONFIG_DEBUG is no variable of Periphery's table.
  let settings =
    read(&cicada_periphery(), &[("CICADA_CONFIG_DEBUG", "true")])
      .unwrap();
  assert!(!settings.config_debug);
  // A level mogh_logger doesn't read is refused, as the app's own
  // `logging.level` would be, naming the variable.
  let err =
    read(&cicada_periphery(), &[("CICADA_LOGGING_LEVEL", "DEBUG")])
      .unwrap_err();
  let Error::ParseEnv {
    variable,
    path,
    message,
  } = &err
  else {
    panic!("{err:?}");
  };
  assert_eq!(variable, "CICADA_LOGGING_LEVEL");
  assert_eq!(path, "logging.level");
  assert_eq!(
    message,
    "unknown variant [redacted], expected one of `trace`, `debug`, `info`, `warn`, `error`"
  );
  // No variable: false, whatever is set.
  for name in ["PERIPHERY_CONFIG_DEBUG", "PERIPHERY_LOGGING_LEVEL"] {
    let settings =
      read(&komodo_periphery(), &[(name, "true")]).unwrap();
    assert!(!settings.config_debug, "{name}");
  }
}

#[test]
fn the_defaults_are_the_apps() {
  let settings = read(
    &LoaderEnv::new("APP_")
      .default_paths(["/a", "/b"])
      .default_keywords(["*.toml"])
      .default_merge_nested(false)
      .default_extend_arrays(false),
    &[],
  )
  .unwrap();
  assert_eq!(settings.config_paths, paths(&["/a", "/b"]));
  assert_eq!(settings.config_keywords, ["*.toml"]);
  assert!(!settings.merge_nested_config);
  assert!(!settings.extend_config_arrays);
}

/// Errors name the variable and the setting, never the value; a
/// `_FILE` holds the value.
#[test]
fn errors_name_the_variable_and_files_hold_values() {
  for (name, field) in [
    ("KOMODO_MERGE_NESTED_CONFIG", "merge_nested_config"),
    ("KOMODO_EXTEND_CONFIG_ARRAYS", "extend_config_arrays"),
    ("komodo_config_debug", "config_debug"),
  ] {
    let err =
      read(&core("KOMODO_"), &[(name, "hunter2")]).unwrap_err();
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
    assert!(message.contains("expected a boolean"), "{message}");
    for message in [err.to_string(), format!("{err:?}")] {
      assert!(!message.contains("hunter2"), "{name}: {message}");
    }
  }
  let dir = std::env::temp_dir()
    .join(format!("mogh_config_loader_env_{}", std::process::id()));
  std::fs::create_dir_all(&dir).unwrap();
  let file = dir.join("paths");
  std::fs::write(&file, " /from/file \n").unwrap();
  let settings = read(
    &core("KOMODO_"),
    &[
      ("KOMODO_CONFIG_PATHS_FILE", file.to_str().unwrap()),
      ("KOMODO_CONFIG_PATHS", "/ignored"),
    ],
  )
  .unwrap();
  assert_eq!(settings.config_paths, paths(&["/from/file"]));
  let missing = dir.join("missing");
  let err = read(
    &core("KOMODO_"),
    &[("KOMODO_CONFIG_PATHS_FILE", missing.to_str().unwrap())],
  )
  .unwrap_err();
  assert!(
    matches!(
      &err,
      Error::EnvFile { variable, path, .. }
        if variable == "KOMODO_CONFIG_PATHS_FILE" && *path == missing
    ),
    "{err}"
  );
  std::fs::remove_dir_all(dir).unwrap();
}

/// `read` reads the process environment: the settings `read_vars`
/// gives it (whatever this test runs with).
#[test]
fn read_reads_the_process_environment() {
  let env = core("KOMODO_");
  assert_eq!(
    env.read().map_err(|e| e.to_string()),
    env
      .read_vars(std::env::vars_os())
      .map_err(|e| e.to_string())
  );
}
