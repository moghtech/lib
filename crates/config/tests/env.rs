//! The process environment as a config source (`EnvSource`), read
//! from a given set of variables over a config file.

// Integration test binaries only use a subset
// of the library dependencies.
#![allow(unused_crate_dependencies)]

use std::{
  ffi::OsString,
  path::{Path, PathBuf},
};

use mogh_config::{ConfigLoader, EnvSource, Error};
use serde::{Deserialize, Serialize};

#[derive(
  Debug, Clone, PartialEq, Default, Deserialize, Serialize,
)]
#[serde(default)]
struct Config {
  host: String,
  port: u16,
  hosts: Vec<String>,
  ports: Vec<u16>,
  enabled: bool,
  secret: String,
  /// A field whose variable ends in `_FILE` itself.
  health_file: String,
  mode: Mode,
  database: Database,
}

#[derive(
  Debug, Clone, PartialEq, Default, Deserialize, Serialize,
)]
#[serde(default)]
struct Database {
  address: String,
  username: String,
  password: String,
}

#[derive(
  Debug, Clone, PartialEq, Default, Deserialize, Serialize,
)]
#[serde(rename_all = "lowercase")]
enum Mode {
  #[default]
  Safe,
  Fast,
}

/// A fresh scratch directory per test.
fn scratch_dir(name: &str) -> PathBuf {
  let dir = std::env::temp_dir().join(format!(
    "mogh_config_env_{name}_{}_{}",
    std::process::id(),
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos()
  ));
  std::fs::create_dir_all(&dir).unwrap();
  dir
}

/// The config file under the environment.
const FILE: &str = r#"
host = "file-host"
port = 1
hosts = ["a"]
health_file = "/file/health"

[database]
address = "file-db"
username = "file-user"
"#;

/// The config of [FILE] as loaded.
fn from_file() -> Config {
  Config {
    host: String::from("file-host"),
    port: 1,
    hosts: vec![String::from("a")],
    health_file: String::from("/file/health"),
    database: Database {
      address: String::from("file-db"),
      username: String::from("file-user"),
      ..Default::default()
    },
    ..Default::default()
  }
}

/// The table of the tests: a variable per field, and an old name of
/// `APP_HOST`.
fn table() -> EnvSource {
  EnvSource::new("APP_")
    .fields([
      "host",
      "port",
      "hosts",
      "ports",
      "enabled",
      "secret",
      "health_file",
      "mode",
      "database.address",
      "database.username",
      "database.password",
    ])
    .alias("APP_HOSTNAME", "APP_HOST")
}

/// Loads [FILE] (in `dir`) with `env` over it, arrays extended.
fn load_with(
  dir: &Path,
  env: EnvSource,
) -> mogh_config::Result<Config> {
  let file = dir.join("app.config.toml");
  std::fs::write(&file, FILE).unwrap();
  ConfigLoader {
    paths: &[&file],
    match_wildcards: &[],
    include_file_name: "",
    merge_nested: true,
    // Lists from the environment replace the file's all the same.
    extend_array: true,
    debug_print: false,
  }
  .load_with_env::<Config>(&env)
}

type Vars = Vec<(String, String)>;

/// What a case expects: the config, or an error.
enum Expect {
  Config(fn(&mut Config)),
  Error(fn(&Error, &str)),
}

#[test]
fn the_environment_overrides_the_config_file() {
  let dir = scratch_dir("cases");
  let file = |name: &str, contents: &str| {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path.display().to_string()
  };
  let secret = file("secret", "  s3cret \n");
  let empty = file("empty", " ,\n");
  let not_a_port = file("not_a_port", "hunter2-in-a-file\n");
  let missing = dir.join("missing").display().to_string();
  let vars = |vars: &[(&str, &str)]| -> Vars {
    vars
      .iter()
      .map(|(name, value)| (name.to_string(), value.to_string()))
      .collect()
  };

  let cases: Vec<(&str, Vars, Expect)> = vec![
    ("nothing set: the file", vars(&[]), Expect::Config(|_| {})),
    (
      "plain",
      vars(&[("APP_HOST", "env-host")]),
      Expect::Config(|config| config.host = "env-host".into()),
    ),
    (
      "nested, the other fields of the object kept",
      vars(&[("APP_DATABASE_ADDRESS", "env-db")]),
      Expect::Config(|config| {
        config.database.address = "env-db".into()
      }),
    ),
    (
      "typed: numbers and booleans trimmed, a unit variant",
      vars(&[
        ("APP_PORT", " 8080 "),
        ("APP_ENABLED", "true"),
        ("APP_MODE", "fast"),
      ]),
      Expect::Config(|config| {
        config.port = 8080;
        config.enabled = true;
        config.mode = Mode::Fast;
      }),
    ),
    (
      "a list replaces the file's, under extend_array too",
      vars(&[("APP_HOSTS", "b, c,"), ("APP_PORTS", "80,443")]),
      Expect::Config(|config| {
        config.hosts = vec!["b".into(), "c".into()];
        config.ports = vec![80, 443];
      }),
    ),
    (
      "_FILE: the trimmed contents, over the value",
      vars(&[
        ("APP_SECRET_FILE", secret.as_str()),
        ("APP_SECRET", "plain"),
      ]),
      Expect::Config(|config| config.secret = "s3cret".into()),
    ),
    (
      "blank _FILE: unset, the value is read",
      vars(&[("APP_SECRET_FILE", " "), ("APP_SECRET", "plain")]),
      Expect::Config(|config| config.secret = "plain".into()),
    ),
    (
      "blank value: unset, the file's stays",
      vars(&[("APP_HOST", "  "), ("APP_PORT", "")]),
      Expect::Config(|_| {}),
    ),
    (
      "commas only: unset, no empty list (an allow list's everyone)",
      vars(&[("APP_HOSTS", ","), ("APP_PORTS", " , ,")]),
      Expect::Config(|_| {}),
    ),
    (
      "a _FILE holding nothing: unset, the value is read",
      vars(&[
        ("APP_SECRET_FILE", empty.as_str()),
        ("APP_SECRET", "plain"),
        ("APP_HOSTS_FILE", empty.as_str()),
      ]),
      Expect::Config(|config| config.secret = "plain".into()),
    ),
    (
      "alias: an old name is read",
      vars(&[("APP_HOSTNAME", "old-host")]),
      Expect::Config(|config| config.host = "old-host".into()),
    ),
    (
      "alias: its own name wins",
      vars(&[("APP_HOSTNAME", "old-host"), ("APP_HOST", "new-host")]),
      Expect::Config(|config| config.host = "new-host".into()),
    ),
    (
      "alias: its own name blank is unset",
      vars(&[("APP_HOST", ""), ("APP_HOSTNAME", "old-host")]),
      Expect::Config(|config| config.host = "old-host".into()),
    ),
    (
      "alias: its _FILE",
      vars(&[("APP_HOSTNAME_FILE", secret.as_str())]),
      Expect::Config(|config| config.host = "s3cret".into()),
    ),
    (
      "unknown variables are ignored, with the prefix too",
      vars(&[
        ("APP_UNKNOWN", "x"),
        ("APP_CONFIG_PATHS", "/etc/app"),
        ("APP_DATABASE", "not-an-object"),
        ("OTHER_PORT", "x"),
        ("APP_UNKNOWN_FILE", missing.as_str()),
      ]),
      Expect::Config(|_| {}),
    ),
    (
      "names in any case",
      vars(&[("app_port", "9"), ("App_Host", "mixed")]),
      Expect::Config(|config| {
        config.port = 9;
        config.host = "mixed".into();
      }),
    ),
    (
      "a variable named like a _FILE is its own field's",
      vars(&[("APP_HEALTH_FILE", "/env/health")]),
      Expect::Config(|config| {
        config.health_file = "/env/health".into()
      }),
    ),
    (
      "type error: the variable named, never the value",
      vars(&[("APP_PORT", "hunter2")]),
      Expect::Error(|error, message| {
        let Error::ParseEnv { variable, path, .. } = error else {
          panic!("{message}");
        };
        assert_eq!(variable, "APP_PORT");
        assert_eq!(path, "port");
        assert!(!message.contains("hunter2"), "{message}");
      }),
    ),
    (
      "type error of a _FILE: the variable as set",
      vars(&[("APP_PORT_FILE", not_a_port.as_str())]),
      Expect::Error(|error, message| {
        let Error::ParseEnv { variable, .. } = error else {
          panic!("{message}");
        };
        assert_eq!(variable, "APP_PORT_FILE");
        assert!(!message.contains("hunter2"), "{message}");
      }),
    ),
    (
      "type error in a list entry: the list's variable",
      vars(&[("app_ports", "80,hunter2")]),
      Expect::Error(|error, message| {
        let Error::ParseEnv { variable, path, .. } = error else {
          panic!("{message}");
        };
        assert_eq!(variable, "app_ports");
        assert_eq!(path, "ports[1]");
        assert!(!message.contains("hunter2"), "{message}");
      }),
    ),
    (
      "a _FILE which can't be read: the variable and the path",
      vars(&[("APP_SECRET_FILE", missing.as_str())]),
      Expect::Error(|error, message| {
        let Error::EnvFile { variable, .. } = error else {
          panic!("{message}");
        };
        assert_eq!(variable, "APP_SECRET_FILE");
        assert!(message.contains("missing"), "{message}");
      }),
    ),
    (
      "one name set twice, in two cases",
      vars(&[("APP_PORT", "1"), ("app_port", "2")]),
      Expect::Error(|error, message| {
        assert!(
          matches!(error, Error::EnvVarSetTwice { .. }),
          "{message}"
        );
        assert!(message.contains("APP_PORT"), "{message}");
        assert!(message.contains("app_port"), "{message}");
      }),
    ),
  ];

  for (case, vars, expect) in cases {
    let res = load_with(&dir, table().with_vars(vars));
    match expect {
      Expect::Config(change) => {
        let mut expected = from_file();
        change(&mut expected);
        let config = res.unwrap_or_else(|e| panic!("{case}: {e}"));
        assert_eq!(config, expected, "{case}");
      }
      Expect::Error(check) => {
        let error = res.err().unwrap_or_else(|| panic!("{case}: Ok"));
        let message = error.to_string();
        check(&error, &format!("{case}: {message}"));
      }
    }
  }
  std::fs::remove_dir_all(dir).unwrap();
}

/// The `_FILE` of a `file_spec` variable names a key file the app
/// reads (or creates, or rotates the key in) itself: the field gets
/// `file:<path>`, the file is not read (it need not exist).
#[test]
fn a_file_spec_variable_gives_the_path_of_its_file() {
  let dir = scratch_dir("file_spec");
  let key = dir.join("not-there-yet.key").display().to_string();
  let env = || table().file_spec(["APP_SECRET"]);
  let config = load_with(
    &dir,
    env().with_vars([
      ("APP_SECRET_FILE", key.as_str()),
      ("APP_SECRET", "inline"),
    ]),
  )
  .unwrap();
  assert_eq!(config.secret, format!("file:{key}"));
  // Blank: unset, the value is read.
  let config = load_with(
    &dir,
    env().with_vars([
      ("APP_SECRET_FILE", " "),
      ("APP_SECRET", "inline"),
    ]),
  )
  .unwrap();
  assert_eq!(config.secret, "inline");
  // A name the table doesn't have is the app's mistake.
  let error = table().file_spec(["APP_NOPE"]).names().unwrap_err();
  assert!(matches!(error, Error::InvalidEnvSource { .. }), "{error}");
  std::fs::remove_dir_all(dir).unwrap();
}

/// A variable of other programs (`TZ`) is read when the app's own is
/// unset, silently overridden by it, and has no `_FILE`.
#[test]
fn a_fallback_is_read_when_the_variable_is_unset() {
  let dir = scratch_dir("fallback");
  let file = dir.join("host");
  std::fs::write(&file, "from-a-file").unwrap();
  let file = file.display().to_string();
  let env = || table().fallback("HOSTNAME", "APP_HOST");
  for (vars, expected) in [
    (vec![("HOSTNAME", "box")], "box"),
    (vec![("HOSTNAME", "box"), ("APP_HOST", "app")], "app"),
    (vec![("HOSTNAME", "box"), ("APP_HOST", " ")], "box"),
    (vec![("HOSTNAME_FILE", file.as_str())], "file-host"),
  ] {
    let config =
      load_with(&dir, env().with_vars(vars.clone())).unwrap();
    assert_eq!(config.host, expected, "{vars:?}");
  }
  std::fs::remove_dir_all(dir).unwrap();
}

/// A variable allowed to be empty sets the empty value when set
/// blank (from its `_FILE` too), the others count as unset.
#[test]
fn an_empty_value_is_set_where_allowed() {
  let dir = scratch_dir("allow_empty");
  let empty = dir.join("empty");
  std::fs::write(&empty, "\n").unwrap();
  let empty = empty.display().to_string();
  let env = || table().allow_empty(["APP_HOST", "APP_HOSTS"]);
  let config = load_with(
    &dir,
    env().with_vars([("APP_HOST", ""), ("APP_HOSTS", " , ")]),
  )
  .unwrap();
  assert_eq!(config.host, "");
  assert!(config.hosts.is_empty());
  let config = load_with(
    &dir,
    env().with_vars([("APP_HOST_FILE", empty.as_str())]),
  )
  .unwrap();
  assert_eq!(config.host, "");
  // Its own name set blank wins over an alias.
  let config = load_with(
    &dir,
    env().with_vars([("APP_HOST", ""), ("APP_HOSTNAME", "old")]),
  )
  .unwrap();
  assert_eq!(config.host, "");
  // Unset stays unset.
  let config =
    load_with(&dir, env().with_vars([("APP_PORT", "2")])).unwrap();
  assert_eq!(config.host, "file-host");
  std::fs::remove_dir_all(dir).unwrap();
}

/// A config file which gives a field under another key the type
/// takes (a serde alias) keeps its values with the environment's:
/// the other key moves to the field's own, the field isn't there
/// twice (which serde refuses).
#[test]
fn a_key_alias_keeps_the_files_values() {
  #[derive(Debug, Default, Deserialize)]
  #[serde(default)]
  struct Aliased {
    #[serde(alias = "mongo")]
    database: Database,
    #[serde(alias = "first_server")]
    first_server_address: String,
  }
  let dir = scratch_dir("key_alias");
  let file = dir.join("app.config.toml");
  std::fs::write(
    &file,
    "first_server = \"file\"\n[mongo]\naddress = \"file-db\"\nusername = \"file-user\"\n",
  )
  .unwrap();
  let env = || {
    EnvSource::new("APP_")
      .fields([
        "database.address",
        "database.password",
        "first_server_address",
      ])
      .key_alias("database", "mongo")
      .key_alias("first_server_address", "first_server")
  };
  let load = |env: EnvSource| {
    ConfigLoader {
      paths: &[&file],
      match_wildcards: &[],
      include_file_name: "",
      merge_nested: true,
      extend_array: false,
      debug_print: false,
    }
    .load_with_env::<Aliased>(&env)
  };
  let config = load(env().with_vars([
    ("APP_DATABASE_PASSWORD", "pw"),
    ("APP_FIRST_SERVER_ADDRESS", "env"),
  ]))
  .unwrap();
  assert_eq!(config.database.address, "file-db");
  assert_eq!(config.database.username, "file-user");
  assert_eq!(config.database.password, "pw");
  assert_eq!(config.first_server_address, "env");
  // Without the key aliases: the field twice.
  let without = EnvSource::new("APP_")
    .fields(["database.password"])
    .with_vars([("APP_DATABASE_PASSWORD", "pw")]);
  let error = load(without).unwrap_err();
  assert!(error.to_string().contains("duplicate field"), "{error}");
  // Nothing set: the file as it is.
  let config =
    load(env().with_vars(Vec::<(String, String)>::new())).unwrap();
  assert_eq!(config.database.address, "file-db");
  assert_eq!(config.first_server_address, "file");
  std::fs::remove_dir_all(dir).unwrap();
}

/// A field which reads a string itself (its own `deserialize_with`,
/// through `deserialize_any`) gets the variable's whole value: eg. a
/// list whose entries hold commas, split on `;`.
#[test]
fn a_field_can_split_its_list_itself() {
  #[derive(Debug, Default, Deserialize)]
  #[serde(default)]
  struct Specs {
    #[serde(deserialize_with = "semicolon_list")]
    specs: Vec<String>,
  }

  /// A list, or a string of entries separated by `;`.
  fn semicolon_list<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
  ) -> Result<Vec<String>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
      type Value = Vec<String>;
      fn expecting(
        &self,
        f: &mut std::fmt::Formatter,
      ) -> std::fmt::Result {
        f.write_str("a list, or entries separated by ';'")
      }
      fn visit_str<E>(self, list: &str) -> Result<Vec<String>, E> {
        Ok(
          list
            .split(';')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(String::from)
            .collect(),
        )
      }
      fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
      ) -> Result<Vec<String>, A::Error> {
        let mut entries = Vec::new();
        while let Some(entry) = seq.next_element()? {
          entries.push(entry);
        }
        Ok(entries)
      }
    }
    deserializer.deserialize_any(Visitor)
  }

  let specs = ConfigLoader {
    paths: &[],
    match_wildcards: &[],
    include_file_name: "",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load_with_env::<Specs>(
    &EnvSource::new("APP_")
      .fields(["specs"])
      .with_vars([("APP_SPECS", "fs=a,b; fs=c")]),
  )
  .unwrap();
  assert_eq!(specs.specs, ["fs=a,b", "fs=c"]);
}

/// A value which isn't UTF-8 is an error naming the variable.
#[cfg(unix)]
#[test]
fn a_value_which_is_not_utf8_is_an_error() {
  use std::os::unix::ffi::OsStringExt as _;

  let dir = scratch_dir("not_utf8");
  let env = table().with_vars([(
    OsString::from("APP_HOST"),
    OsString::from_vec(vec![0x66, 0xff, 0x6f]),
  )]);
  let error = load_with(&dir, env).unwrap_err();
  assert!(
    matches!(&error, Error::EnvNotUnicode { variable } if variable == "APP_HOST"),
    "{error}"
  );
  std::fs::remove_dir_all(dir).unwrap();
}

/// Without config files, the environment over the type's defaults.
#[test]
fn without_config_files_the_environment_over_the_defaults() {
  let env = table().with_vars([("APP_PORT", "8080")]);
  let config = ConfigLoader {
    paths: &[],
    match_wildcards: &[],
    include_file_name: "",
    merge_nested: false,
    extend_array: false,
    debug_print: false,
  }
  .load_with_env::<Config>(&env)
  .unwrap();
  assert_eq!(
    config,
    Config {
      port: 8080,
      ..Default::default()
    }
  );
}

/// A nested variable sets its field only, also when the files'
/// objects replace each other (`merge_nested: false`).
#[test]
fn a_nested_variable_keeps_the_other_fields_without_merge_nested() {
  let dir = scratch_dir("not_nested");
  let file = dir.join("app.config.toml");
  std::fs::write(&file, FILE).unwrap();
  let config = ConfigLoader {
    paths: &[&file],
    match_wildcards: &[],
    include_file_name: "",
    merge_nested: false,
    extend_array: false,
    debug_print: false,
  }
  .load_with_env::<Config>(
    &table().with_vars([("APP_DATABASE_PASSWORD", "pw")]),
  )
  .unwrap();
  assert_eq!(config.database.address, "file-db");
  assert_eq!(config.database.username, "file-user");
  assert_eq!(config.database.password, "pw");
  std::fs::remove_dir_all(dir).unwrap();
}

/// The names the table gives: derived from the path with `_` (or
/// another separator), or given, `fields_of` covering every field
/// of a value but the ones left out.
#[test]
fn names_come_from_the_paths() {
  assert_eq!(
    table().names().unwrap()[..3],
    ["APP_HOST", "APP_PORT", "APP_HOSTS"]
  );
  let names = EnvSource::new("APP_")
    .nested_separator("__")
    .fields(["database.address", "health_file"])
    .var("APP_DB_URI", "database.uri")
    .names()
    .unwrap();
  assert_eq!(
    names,
    ["APP_DATABASE__ADDRESS", "APP_HEALTH_FILE", "APP_DB_URI"]
  );
  let config = ConfigLoader {
    paths: &[],
    match_wildcards: &[],
    include_file_name: "",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load_with_env::<Config>(
    &EnvSource::new("APP_")
      .nested_separator("__")
      .fields(["database.address"])
      .with_vars([
        ("APP_DATABASE__ADDRESS", "nested"),
        // Not a name of this table.
        ("APP_DATABASE_ADDRESS", "flat"),
      ]),
  )
  .unwrap();
  assert_eq!(config.database.address, "nested");

  // In the order the value serializes its keys (sorted).
  let names = EnvSource::new("APP_")
    .fields_of(&Config::default())
    .without(["database.password", "ports"])
    .names()
    .unwrap();
  assert_eq!(
    names,
    [
      "APP_DATABASE_ADDRESS",
      "APP_DATABASE_USERNAME",
      "APP_ENABLED",
      "APP_HEALTH_FILE",
      "APP_HOST",
      "APP_HOSTS",
      "APP_MODE",
      "APP_PORT",
      "APP_SECRET",
    ]
  );
}

/// A table which doesn't hold together is the app's mistake, an
/// error when it is read.
#[test]
fn an_invalid_table_is_an_error() {
  for (case, env) in [
    (
      "a name twice",
      EnvSource::new("APP_")
        .fields(["port"])
        .var("app_port", "other"),
    ),
    (
      "a path inside another's",
      EnvSource::new("APP_").fields(["database", "database.address"]),
    ),
    ("an empty segment", EnvSource::new("APP_").fields(["a..b"])),
    (
      "an alias of no variable",
      EnvSource::new("APP_")
        .fields(["port"])
        .alias("APP_P", "APP_X"),
    ),
    (
      "an alias which is a variable",
      EnvSource::new("APP_")
        .fields(["port", "host"])
        .alias("APP_HOST", "APP_PORT"),
    ),
    (
      "fields_of a value which is no object",
      EnvSource::new("APP_").fields_of(&8080),
    ),
  ] {
    let error = env.names().unwrap_err();
    assert!(
      matches!(error, Error::InvalidEnvSource { .. }),
      "{case}: {error}"
    );
  }
}

/// The values stay out of the source's `Debug`.
#[test]
fn debug_leaves_out_the_values() {
  let env = table().with_vars([("APP_SECRET", "hunter2")]);
  let debug = format!("{env:?}");
  assert!(!debug.contains("hunter2"), "{debug}");
}
