// Integration test binaries only use a subset
// of the library dependencies.
#![allow(unused_crate_dependencies)]

//! The keys of config files no field of the config type takes
//! (`mogh_config::UnknownKey`).

use std::{
  collections::HashMap,
  path::{Path, PathBuf},
};

use mogh_config::{ConfigLoader, EnvSource, UnknownKey};

/// Creates a unique, empty directory for a test
/// and cleans it up on drop.
struct TestDir(PathBuf);

impl TestDir {
  fn new(name: &str) -> TestDir {
    let path = std::env::temp_dir().join(format!(
      "mogh_config_unknown_test_{}_{name}",
      std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    TestDir(path)
  }

  fn write(&self, file: &str, contents: &str) -> PathBuf {
    let path = self.0.join(file);
    std::fs::write(&path, contents).unwrap();
    path
  }
}

impl Drop for TestDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

#[derive(Debug, Default, PartialEq, serde::Deserialize)]
#[serde(default)]
struct Oidc {
  enabled: bool,
  client_id: String,
}

#[derive(Debug, PartialEq, serde::Deserialize)]
enum Provider {
  Vault { address: String },
  None,
}

#[derive(Debug, Default, PartialEq, serde::Deserialize)]
#[serde(default)]
struct Registry {
  domain: String,
}

#[derive(Debug, Default, PartialEq, serde::Deserialize)]
#[serde(default)]
struct Config {
  title: String,
  disable_user_registration: bool,
  #[serde(alias = "port_number")]
  port: u16,
  oidc: Oidc,
  registries: Vec<Registry>,
  providers: Vec<Provider>,
  secrets: HashMap<String, Registry>,
  database: Option<Oidc>,
}

fn loader<'a>(paths: &'a [&'a Path]) -> ConfigLoader<'a, 'a> {
  ConfigLoader {
    paths,
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: true,
    debug_print: false,
  }
}

/// The `(file, path)` of each unknown key, in order.
fn keys(unknown: &[UnknownKey]) -> Vec<(PathBuf, String)> {
  unknown
    .iter()
    .map(|key| (key.file.clone(), key.path.clone()))
    .collect()
}

/// A typo in a toml / yaml / json file is ignored (the field keeps
/// its default), and reported by its file and path: a nested key
/// too, a key of a list entry by the entry's index in the file, and
/// one inside a map's value or a variant's content. Fields taken
/// under another key (a serde alias) are known.
#[test]
fn unknown_keys_are_reported_by_file_and_path() {
  let dir = TestDir::new("typos");
  let toml = dir.write(
    "config.toml",
    "title = \"t\"\n\
     disable_user_registraton = true\n\
     port_number = 9000\n\
     [oidc]\nenabled = true\nclient_idd = \"hunter2\"\n\
     [[registries]]\ndomain = \"a\"\n\
     [[registries]]\ndomian = \"b\"\n\
     [secrets.main]\ndomain = \"c\"\nextra = 1\n\
     [database]\nenabled = true\nnmae = \"x\"\n",
  );
  let yaml = dir.write(
    "config.yaml",
    "providers:\n  - Vault:\n      address: a\n      adress: b\n\
     registries:\n  - domian: c\n",
  );
  let json = dir.write("config.json", r#"{ "tilte": "j" }"#);
  let loaded = loader(&[&toml, &yaml, &json])
    .load_reporting::<Config>()
    .unwrap();
  assert!(!loaded.config.disable_user_registration);
  assert_eq!(loaded.config.port, 9000);
  assert!(loaded.config.oidc.enabled);
  assert_eq!(loaded.config.registries.len(), 3);
  assert_eq!(
    keys(&loaded.unknown_keys),
    [
      // By file, in the order they load, then by path (as the
      // config type comes across them: in key order).
      (toml.clone(), String::from("database.nmae")),
      (toml.clone(), String::from("disable_user_registraton")),
      (toml.clone(), String::from("oidc.client_idd")),
      (toml.clone(), String::from("registries[1].domian")),
      (toml.clone(), String::from("secrets.main.extra")),
      (yaml.clone(), String::from("providers[0].Vault.adress")),
      // The merged list's third entry, the yaml file's first.
      (yaml.clone(), String::from("registries[0].domian")),
      (json.clone(), String::from("tilte")),
    ]
  );
  // Named by the file and the path, never the value.
  for key in &loaded.unknown_keys {
    let text = key.to_string();
    assert!(text.contains(&format!("{:?}", key.file)), "{text}");
    assert!(text.contains(&format!("'{}'", key.path)), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
  }
  // `load` warns about them, and loads the same config.
  let config =
    loader(&[&toml, &yaml, &json]).load::<Config>().unwrap();
  assert_eq!(config, loaded.config);
}

/// A whole table no field takes is one unknown key, not one per key
/// in it.
#[test]
fn an_unknown_table_is_one_key() {
  let dir = TestDir::new("table");
  let toml =
    dir.write("config.toml", "[oauth]\nenabled = true\nid = \"x\"\n");
  let loaded = loader(&[&toml]).load_reporting::<Config>().unwrap();
  assert_eq!(
    keys(&loaded.unknown_keys),
    [(toml, String::from("oauth"))]
  );
}

/// Env files hold keys of other programs (a compose project's `.env`,
/// the secrets of an environment), the process environment too:
/// neither is reported. A key in both an env file and a toml file is
/// reported for the toml file only.
#[test]
fn env_files_and_the_environment_are_not_reported() {
  let dir = TestDir::new("env-files");
  let env_file = dir.write(
    "app.env",
    "TITLE=e\nCOMPOSE_PROJECT_NAME=app\nDB_PASSWORD=hunter2\n",
  );
  let toml = dir.write("config.toml", "db_password = \"x\"\n");
  let loaded =
    loader(&[&env_file]).load_reporting::<Config>().unwrap();
  assert_eq!(loaded.config.title, "e");
  assert!(
    loaded.unknown_keys.is_empty(),
    "{:?}",
    loaded.unknown_keys
  );
  let loaded = loader(&[&env_file, &toml])
    .load_reporting::<Config>()
    .unwrap();
  assert_eq!(
    keys(&loaded.unknown_keys),
    [(toml.clone(), String::from("db_password"))]
  );

  let env = EnvSource::new("APP_")
    .fields(["title", "oidc.enabled"])
    .with_vars([("APP_TITLE", "v"), ("APP_UNKNOWN", "x")]);
  let loaded = loader(&[&toml])
    .load_with_env_reporting::<Config>(&env)
    .unwrap();
  assert_eq!(loaded.config.title, "v");
  assert_eq!(
    keys(&loaded.unknown_keys),
    [(toml, String::from("db_password"))]
  );
}

/// A file may spell a table flat where the environment source says
/// so ([EnvSource::flat_prefix]): a flat key is known when its field
/// in the table is, and an unknown one is named by its path in the
/// table. Without the rule, the flat keys are unknown as they are.
#[test]
fn flat_keys_are_checked_in_their_table() {
  let dir = TestDir::new("flat");
  let toml = dir.write(
    "config.toml",
    "oidc_enabled = true\noidc_client_idd = \"x\"\n",
  );
  let env = EnvSource::new("APP_")
    .fields(["title", "oidc.enabled", "oidc.client_id"])
    .flat_prefix("oidc", "oidc_")
    .with_vars(Vec::<(String, String)>::new());
  let loaded = loader(&[&toml])
    .load_with_env_reporting::<Config>(&env)
    .unwrap();
  assert!(loaded.config.oidc.enabled);
  assert_eq!(
    keys(&loaded.unknown_keys),
    [(toml.clone(), String::from("oidc.client_idd"))]
  );
  let loaded = loader(&[&toml]).load_reporting::<Config>().unwrap();
  assert_eq!(
    keys(&loaded.unknown_keys),
    [
      (toml.clone(), String::from("oidc_client_idd")),
      (toml, String::from("oidc_enabled")),
    ]
  );
}

/// Each file holding an unknown key is named, the one a later file
/// overrode too while its key is in the merged config. A key a later
/// file replaced (the table not merged) is no longer in the config:
/// not reported.
#[test]
fn every_file_holding_the_key_is_named() {
  let dir = TestDir::new("files");
  let first =
    dir.write("a.toml", "tilte = \"a\"\n[oidc]\nenbled = true\n");
  let second = dir.write("b.yaml", "tilte: b\n");
  let loaded = loader(&[&first, &second])
    .load_reporting::<Config>()
    .unwrap();
  assert_eq!(
    keys(&loaded.unknown_keys),
    [
      (first.clone(), String::from("oidc.enbled")),
      (first.clone(), String::from("tilte")),
      (second.clone(), String::from("tilte")),
    ]
  );
  let replacing = dir.write("c.yaml", "oidc:\n  enabled: true\n");
  let loaded = ConfigLoader {
    merge_nested: false,
    ..loader(&[&first, &replacing])
  }
  .load_reporting::<Config>()
  .unwrap();
  assert_eq!(
    keys(&loaded.unknown_keys),
    [(first, String::from("tilte"))]
  );
}

/// A config which doesn't load is the error `load` returns: the
/// unknown keys found before the failure are only printed by `load`.
#[test]
fn a_config_which_does_not_load_is_an_error() {
  let dir = TestDir::new("error");
  let toml =
    dir.write("config.toml", "tilte = 1\nport = \"hunter2\"\n");
  let error =
    loader(&[&toml]).load_reporting::<Config>().unwrap_err();
  assert!(error.to_string().contains("'port'"), "{error}");
  assert!(!error.to_string().contains("hunter2"), "{error}");
  assert!(loader(&[&toml]).load::<Config>().is_err());
}

/// A config type taking any key (a map, a `serde_json::Value`) has
/// no unknown keys.
#[test]
fn types_taking_any_key_have_none() {
  let dir = TestDir::new("any");
  let toml = dir.write("config.toml", "a = 1\n[b]\nc = 2\n");
  let loaded = loader(&[&toml])
    .load_reporting::<serde_json::Value>()
    .unwrap();
  assert!(loaded.unknown_keys.is_empty());
  let loaded = loader(&[&toml])
    .load_reporting::<HashMap<String, serde_json::Value>>()
    .unwrap();
  assert!(loaded.unknown_keys.is_empty());
}
