// Integration test binaries only use a subset
// of the library dependencies.
#![allow(unused_crate_dependencies)]

use std::path::{Path, PathBuf};

use mogh_config::ConfigLoader;

/// Creates a unique, empty directory for a test
/// and cleans it up on drop.
struct TestDir(PathBuf);

impl TestDir {
  fn new(name: &str) -> TestDir {
    let path = std::env::temp_dir().join(format!(
      "mogh_config_test_{}_{name}",
      std::process::id()
    ));
    // Ensure a clean folder
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

fn load(
  paths: &[&Path],
  match_wildcards: &[&str],
  merge_nested: bool,
  extend_array: bool,
) -> serde_json::Value {
  ConfigLoader {
    paths,
    match_wildcards,
    include_file_name: ".include",
    merge_nested,
    extend_array,
    debug_print: false,
  }
  .load()
  .unwrap()
}

#[test]
fn loads_toml_yaml_and_json_files() {
  let dir = TestDir::new("formats");
  let toml = dir.write("config.toml", "a = 1");
  let yaml = dir.write("config.yaml", "b: 2");
  let yml = dir.write("config.yml", "c: 3");
  let json = dir.write("config.json", r#"{ "d": 4 }"#);

  let config = load(&[&toml, &yaml, &yml, &json], &[], false, false);
  assert_eq!(
    config,
    serde_json::json!({ "a": 1, "b": 2, "c": 3, "d": 4 })
  );
}

#[test]
fn extension_matching_is_case_insensitive() {
  let dir = TestDir::new("upper_ext");
  let toml = dir.write("config.TOML", "a = 1");
  let config = load(&[&toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
}

/// A file named as a path or by an include line is loaded or an
/// error: a `config.txt` used to be skipped with a warning, and the
/// app started without it.
#[test]
fn a_named_file_of_an_unsupported_type_is_an_error() {
  let dir = TestDir::new("unsupported_ext");
  let txt = dir.write("config.txt", "a = 1");
  let toml = dir.write("config.toml", "b = 2");
  let err =
    try_load::<serde_json::Value>(&[&txt, &toml], &[], false, false)
      .unwrap_err();
  assert!(
    matches!(&err, mogh_config::Error::UnsupportedFileType { path } if path == &txt),
    "{err}"
  );
  // Named by an include line.
  let main = TestDir::new("unsupported_ext_include");
  main.write("main.toml", "c = 3");
  main.write(".include", &format!("{}\n", txt.display()));
  let err = try_load::<serde_json::Value>(
    &[&main.0],
    &["*.toml"],
    false,
    false,
  )
  .unwrap_err();
  assert!(
    matches!(&err, mogh_config::Error::UnsupportedFileType { path } if path == &txt),
    "{err}"
  );
}

/// A directory scan picks files by pattern: one it finds which is
/// no config file type (a backup matching `*config.*`) was never
/// asked for in particular, and is skipped with a warning.
#[test]
fn a_scanned_file_of_an_unsupported_type_is_skipped() {
  let dir = TestDir::new("scanned_unsupported");
  dir.write("core.config.toml", "a = 1");
  dir.write("core.config.toml.bak", "a = = broken");
  dir.write("README.md", "# notes");
  let config = load(&[&dir.0], &["*config.*"], false, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
  // Without wildcards a scan finds every file but env files.
  let config = load(&[&dir.0], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
}

/// A path which doesn't exist is skipped (deliberate: an app may
/// list optional paths), listed or named by an include line.
#[test]
fn missing_paths_are_skipped() {
  let dir = TestDir::new("missing_path");
  let toml = dir.write("config.toml", "a = 1");
  let missing = dir.0.join("does_not_exist.toml");
  // Through a file: not a directory, so missing too.
  let through_file = toml.join("nested.toml");
  let config =
    load(&[&missing, &through_file, &toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
  let main = TestDir::new("missing_include");
  main.write("main.toml", "b = 2");
  main.write(
    ".include",
    &format!("{}\n{}\n", missing.display(), through_file.display()),
  );
  let config = load(&[&main.0], &["*.toml"], false, false);
  assert_eq!(config, serde_json::json!({ "b": 2 }));
}

/// A path which is no file or directory, like `/dev/null` listed to
/// load nothing, has no config to load.
#[cfg(unix)]
#[test]
fn a_path_which_is_no_file_or_directory_is_skipped() {
  let dir = TestDir::new("dev_null");
  let toml = dir.write("config.toml", "a = 1");
  let config =
    load(&[Path::new("/dev/null"), &toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
}

#[test]
fn later_paths_override_earlier_paths() {
  let dir = TestDir::new("precedence");
  let base = dir.write(
    "base.toml",
    "a = 1\nb = \"base\"\narr = [1]\n[nested]\nx = 1\ny = 1",
  );
  let override_ = dir.write(
    "override.json",
    r#"{ "b": "override", "arr": [2], "nested": { "y": 2 } }"#,
  );

  // merge_nested + extend_array
  let config = load(&[&base, &override_], &[], true, true);
  assert_eq!(
    config,
    serde_json::json!({
      "a": 1,
      "b": "override",
      "arr": [1, 2],
      "nested": { "x": 1, "y": 2 }
    })
  );

  // replace nested / arrays
  let config = load(&[&base, &override_], &[], false, false);
  assert_eq!(
    config,
    serde_json::json!({
      "a": 1,
      "b": "override",
      "arr": [2],
      "nested": { "y": 2 }
    })
  );
}

#[test]
fn repeated_path_moves_to_highest_priority() {
  let dir = TestDir::new("repeat_path");
  let first = dir.write("first.toml", "a = \"first\"");
  let second = dir.write("second.toml", "a = \"second\"");
  // `first` is repeated after `second`, so it should win.
  let config = load(&[&first, &second, &first], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": "first" }));
}

#[test]
fn directory_loading_respects_wildcard_order() {
  let dir = TestDir::new("wildcards");
  dir.write("01_a.toml", "key = \"a\"\nonly_a = 1");
  dir.write("02_b.toml", "key = \"b\"\nonly_b = 1");
  dir.write("ignored.toml", "ignored = 1");

  // Later wildcards have higher priority, so 01_a wins.
  let config =
    load(&[&dir.0], &["02_*.toml", "01_*.toml"], false, false);
  assert_eq!(
    config,
    serde_json::json!({ "key": "a", "only_a": 1, "only_b": 1 })
  );

  // With a single wildcard, files apply in path order (02_b last).
  let config = load(&[&dir.0], &["0*.toml"], false, false);
  assert_eq!(
    config,
    serde_json::json!({ "key": "b", "only_a": 1, "only_b": 1 })
  );

  // Files not matching any wildcard are excluded entirely.
  let config = load(&[&dir.0], &["0*.toml"], false, false);
  assert_eq!(config.get("ignored"), None);
}

#[test]
fn file_paths_override_directory_paths() {
  let dir = TestDir::new("file_over_dir");
  dir.write("config.toml", "a = \"dir\"");
  let standalone = TestDir::new("file_over_dir_standalone");
  let file = standalone.write("override.toml", "a = \"file\"");

  let config = load(&[&dir.0, &file], &["*.toml"], false, false);
  assert_eq!(config, serde_json::json!({ "a": "file" }));
}

#[test]
fn include_file_pulls_in_other_directories() {
  let included = TestDir::new("included_dir");
  included.write("extra.toml", "extra = 1\nkey = \"included\"");
  let dir = TestDir::new("includes");
  dir.write("main.toml", "key = \"main\"\nmain = 1");
  dir.write(
    ".include",
    &format!(
      "# comment line\n\n{} # end of line comment\n",
      included.0.display()
    ),
  );

  let config = load(&[&dir.0], &["*.toml"], false, false);
  assert_eq!(config.get("extra"), Some(&serde_json::json!(1)));
  assert_eq!(config.get("main"), Some(&serde_json::json!(1)));
  // Includes override the directory's own files.
  assert_eq!(config.get("key"), Some(&serde_json::json!("included")));
}

#[test]
fn includes_apply_in_include_order() {
  // Directory names are chosen so that path order (zz < ...)
  // disagrees with include order, proving include order wins.
  let main = TestDir::new("zz_order_main");
  let first = TestDir::new("yy_order_first");
  let second = TestDir::new("aa_order_second");
  let nested = TestDir::new("bb_order_nested");
  main.write("main.toml", "key = \"main\"\nmain = 1");
  first.write("first.toml", "key = \"first\"\nfirst = 1");
  second.write("second.toml", "key = \"second\"\nsecond = 1");
  nested.write("nested.toml", "key = \"nested\"\nnested = 1");
  // first includes nested, so nested is applied right after
  // first, before second.
  first.write(
    ".include",
    &format!(
      "{}
",
      nested.0.display()
    ),
  );
  main.write(
    ".include",
    &format!(
      "{}
{}
",
      first.0.display(),
      second.0.display()
    ),
  );

  let config = load(&[&main.0], &["*.toml"], false, false);
  assert_eq!(
    config,
    serde_json::json!({
      "key": "second",
      "main": 1,
      "first": 1,
      "nested": 1,
      "second": 1,
    })
  );

  // Reversing the include order reverses the priority.
  main.write(
    ".include",
    &format!(
      "{}
{}
",
      second.0.display(),
      first.0.display()
    ),
  );
  let config = load(&[&main.0], &["*.toml"], false, false);
  assert_eq!(config.get("key"), Some(&serde_json::json!("nested")));
}

#[test]
fn wildcard_priority_is_per_directory() {
  let main = TestDir::new("wc_per_dir_main");
  let included = TestDir::new("wc_per_dir_included");
  main.write("02_high.toml", "key = \"main-high\"");
  included.write("01_low.toml", "key = \"included-low\"");
  main.write(
    ".include",
    &format!(
      "{}
",
      included.0.display()
    ),
  );
  // 02_* is the higher priority wildcard, but only within a
  // directory: the include still overrides the main directory.
  let config =
    load(&[&main.0], &["01_*.toml", "02_*.toml"], false, false);
  assert_eq!(config, serde_json::json!({ "key": "included-low" }));
}

#[test]
fn interpolates_env_vars_into_config() {
  let var = "MOGH_CONFIG_TEST_INTERPOLATION_VAR";
  unsafe { std::env::set_var(var, "interpolated") };
  let dir = TestDir::new("interpolation");
  let toml =
    dir.write("config.toml", &format!("value = \"${{{var}}}\""));
  let config = load(&[&toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "value": "interpolated" }));
}

#[test]
fn interpolates_unset_env_vars_to_empty_string() {
  let dir = TestDir::new("interpolation_unset");
  let toml = dir.write(
    "config.toml",
    "value = \"${MOGH_CONFIG_TEST_DEFINITELY_UNSET_VAR}\"",
  );
  let config = load(&[&toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "value": "" }));
}

#[test]
fn include_cycles_do_not_recurse_forever() {
  let a = TestDir::new("cycle_a");
  // b is nested in a, so `..` from b is a.
  let b = a.0.join("b");
  std::fs::create_dir(&b).unwrap();
  a.write("a.toml", "a = 1");
  std::fs::write(b.join("b.toml"), "b = 2").unwrap();
  // a includes b and itself, b includes a (absolute and relative).
  a.write(".include", &format!("{}\n.\n", b.display()));
  std::fs::write(
    b.join(".include"),
    format!("{}\n..\n", a.0.display()),
  )
  .unwrap();
  let config = load(&[&a.0], &["*.toml"], false, false);
  assert_eq!(config.get("a"), Some(&serde_json::json!(1)));
  assert_eq!(config.get("b"), Some(&serde_json::json!(2)));
}

#[test]
fn diamond_includes_keep_last_occurrence_priority() {
  // main includes first then second, both include shared.
  // shared is applied under second as well, so it overrides
  // second, as the include order rule promises.
  let main = TestDir::new("diamond_main");
  let first = TestDir::new("diamond_first");
  let second = TestDir::new("diamond_second");
  let shared = TestDir::new("diamond_shared");
  main.write("main.toml", "key = \"main\"");
  first.write("first.toml", "key = \"first\"");
  second.write("second.toml", "key = \"second\"");
  shared.write("shared.toml", "key = \"shared\"\nshared = 1");
  first.write(".include", &format!("{}\n", shared.0.display()));
  second.write(".include", &format!("{}\n", shared.0.display()));
  main.write(
    ".include",
    &format!("{}\n{}\n", first.0.display(), second.0.display()),
  );
  let config = load(&[&main.0], &["*.toml"], false, false);
  assert_eq!(
    config,
    serde_json::json!({ "key": "shared", "shared": 1 })
  );
}

#[test]
fn include_file_is_not_loaded_as_config() {
  let dir = TestDir::new("include_not_config");
  dir.write("config.toml", "a = 1");
  dir.write(".include", "# nothing\n");
  // No wildcards: every file would otherwise be attempted.
  let config = load(&[&dir.0], &[], false, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
}

#[test]
fn include_paths_may_contain_hash() {
  let included = TestDir::new("hash#dir");
  included.write("extra.toml", "extra = 1");
  let dir = TestDir::new("hash_include");
  dir.write("main.toml", "main = 1");
  dir.write(
    ".include",
    &format!("{} # trailing comment\n", included.0.display()),
  );
  let config = load(&[&dir.0], &["*.toml"], false, false);
  assert_eq!(config.get("extra"), Some(&serde_json::json!(1)));
}

#[cfg(unix)]
#[test]
fn symlinked_files_in_directories_are_loaded() {
  let real = TestDir::new("symlink_real");
  let target = real.write("real.toml", "linked = 1");
  let dir = TestDir::new("symlink_dir");
  std::os::unix::fs::symlink(&target, dir.0.join("config.toml"))
    .unwrap();
  let config = load(&[&dir.0], &["*.toml"], false, false);
  assert_eq!(config, serde_json::json!({ "linked": 1 }));
}

#[test]
fn interpolated_values_cannot_inject_or_break_json() {
  let var = "MOGH_CONFIG_TEST_INJECTION_VAR";
  let value = "x\",\"admin\":true,\"y\":\"z\\\nline2 $(whoami)";
  unsafe { std::env::set_var(var, value) };
  let dir = TestDir::new("interpolation_injection");
  let toml = dir.write(
    "config.toml",
    &format!("value = \"${{{var}}}\"\n[nested]\ninner = \"${{{var}}}\"\nlist = [\"${{{var}}}\"]"),
  );
  let config = load(&[&toml], &[], false, false);
  assert_eq!(
    config,
    serde_json::json!({
      "value": value,
      "nested": { "inner": value, "list": [value] }
    })
  );
}

#[test]
fn shell_output_and_env_values_are_not_reinterpolated() {
  // The output of $(env) contains this literal `${...}` text,
  // which must be kept verbatim rather than expanded.
  let literal_var = "MOGH_CONFIG_TEST_LITERAL_VAR";
  unsafe {
    std::env::set_var(
      literal_var,
      "keep ${MOGH_CONFIG_TEST_UNSET} literal",
    )
  };
  // An env var whose value references another env var expands
  // one level, but `$(...)` in either value is never executed.
  let outer = "MOGH_CONFIG_TEST_OUTER_VAR";
  let inner = "MOGH_CONFIG_TEST_INNER_VAR";
  unsafe {
    std::env::set_var(outer, format!("outer ${{{inner}}} $(whoami)"));
    std::env::set_var(inner, "inner $(whoami)");
  }
  let dir = TestDir::new("interpolation_no_reinterpolation");
  let toml = dir.write(
    "config.toml",
    &format!("from_shell = \"$(env)\"\nfrom_env = \"${{{outer}}}\""),
  );
  let config = load(&[&toml], &[], false, false);
  let from_shell = config["from_shell"].as_str().unwrap();
  assert!(
    from_shell.contains("keep ${MOGH_CONFIG_TEST_UNSET} literal"),
    "{from_shell}"
  );
  assert_eq!(
    config["from_env"],
    serde_json::json!("outer inner $(whoami) $(whoami)")
  );
}

#[test]
fn interpolates_shell_commands_and_keys() {
  let dir = TestDir::new("interpolation_shell");
  let toml = dir.write(
    "config.toml",
    "value = \"$(true)\"\n\"${MOGH_CONFIG_TEST_DEFINITELY_UNSET_VAR}key\" = 1",
  );
  let config = load(&[&toml], &[], false, false);
  assert_eq!(config, serde_json::json!({ "value": "", "key": 1 }));
}

#[test]
fn errors_do_not_leak_config_values() {
  #[derive(serde::Deserialize, Debug)]
  #[allow(dead_code)]
  struct Typed {
    port: u16,
  }
  let dir = TestDir::new("error_redaction");
  let toml = dir.write("config.toml", "port = \"hunter2secret\"");
  let err = ConfigLoader {
    paths: &[&toml],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: false,
    extend_array: false,
    debug_print: false,
  }
  .load::<Typed>()
  .unwrap_err();
  let message = err.to_string();
  assert!(!message.contains("hunter2secret"), "{message}");
  assert!(message.contains("expected u16"), "{message}");
}

#[cfg(not(feature = "cicada"))]
#[test]
fn cicada_path_without_the_feature_is_an_error() {
  // Skipping it would start the app with defaults.
  let err = (ConfigLoader {
    paths: &[std::path::Path::new(
      "cicada://filesystem/config.yaml?env=prod",
    )],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  })
  .load::<serde_json::Value>()
  .unwrap_err();
  assert!(
    matches!(err, mogh_config::Error::CicadaFeatureDisabled { .. }),
    "{err}"
  );
  assert!(err.to_string().contains("'cicada' feature"));
}

#[derive(serde::Deserialize, Debug, PartialEq)]
struct Typed {
  db_password: String,
  port: u16,
  debug: bool,
  #[serde(default)]
  allowed_hosts: Vec<String>,
  #[serde(default)]
  region: Option<String>,
  #[serde(default = "default_title")]
  title: String,
}

fn default_title() -> String {
  String::from("untitled")
}

fn load_typed(paths: &[&Path]) -> mogh_config::Result<Typed> {
  ConfigLoader {
    paths,
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Typed>()
}

#[test]
fn env_files_are_config_sources_with_envy_semantics() {
  let dir = TestDir::new("env_file_source");
  let toml = dir.write(
    "defaults.toml",
    "port = 1\ndebug = false\ntitle = \"app\"",
  );
  // Names lowercase to the struct's fields, values coerce into
  // their types, comma lists become vectors.
  let env = dir.write(
    ".env",
    "# secrets\nexport DB_PASSWORD=\"hunter2 \\\"quoted\\\"\"\nPORT=8080\nDEBUG=true\nALLOWED_HOSTS=a.example.com, b.example.com\nREGION=eu\n",
  );
  let config = load_typed(&[&toml, &env]).unwrap();
  assert_eq!(
    config,
    Typed {
      db_password: "hunter2 \"quoted\"".into(),
      port: 8080,
      debug: true,
      allowed_hosts: vec![
        "a.example.com".into(),
        "b.example.com".into()
      ],
      region: Some("eu".into()),
      title: "app".into(),
    }
  );
  // Later paths still win: a toml after the env file overrides it.
  let override_toml = dir.write("override.toml", "port = 9090");
  let config = load_typed(&[&toml, &env, &override_toml]).unwrap();
  assert_eq!(config.port, 9090);
  assert_eq!(config.db_password, "hunter2 \"quoted\"");
}

#[test]
fn env_extension_files_are_env_files_too() {
  let dir = TestDir::new("env_extension");
  let env = dir.write(
    "app.env",
    "DB_PASSWORD=x\nPORT=443\nDEBUG=false\nALLOWED_HOSTS=\n",
  );
  let config = load_typed(&[&env]).unwrap();
  assert_eq!(config.port, 443);
  // An empty list value is an empty vector, not one empty entry.
  assert!(config.allowed_hosts.is_empty());
  assert_eq!(config.region, None);
  assert_eq!(config.title, "untitled");
}

#[test]
fn env_file_values_are_never_interpolated() {
  let var = "MOGH_CONFIG_TEST_ENV_FILE_VAR";
  unsafe { std::env::set_var(var, "expanded") };
  let dir = TestDir::new("env_file_verbatim");
  // The toml value interpolates, the env file's does not (a secret
  // holding `$(...)` must not run anything).
  let toml = dir
    .write("config.toml", &format!("interpolated = \"${{{var}}}\""));
  let env = dir
    .write(".env", &format!("VERBATIM=${{{var}}} $(echo) still\n"));
  let config = load(&[&toml, &env], &[], true, false);
  assert_eq!(
    config,
    serde_json::json!({
      "interpolated": "expanded",
      "verbatim": format!("${{{var}}} $(echo) still"),
    })
  );
}

#[test]
fn string_values_coerce_from_interpolation_too() {
  let var = "MOGH_CONFIG_TEST_PORT_VAR";
  unsafe { std::env::set_var(var, "7070") };
  let dir = TestDir::new("interpolated_coercion");
  let toml = dir.write(
    "config.toml",
    &format!(
      "db_password = \"x\"\nport = \"${{{var}}}\"\ndebug = \"true\""
    ),
  );
  let config = load_typed(&[&toml]).unwrap();
  assert_eq!(config.port, 7070);
  assert!(config.debug);
}

#[test]
fn env_file_errors_name_the_line_not_the_value() {
  let dir = TestDir::new("env_file_errors");
  // A malformed file is an error naming the file and the line, like
  // a malformed toml.
  let bad =
    dir.write(".env", "DB_PASSWORD=hunter2secret\nnot an entry\n");
  let good = dir.write(
    "app.env",
    "DB_PASSWORD=hunter2secret\nPORT=notaport\nDEBUG=true\n",
  );
  let err = load_typed(&[&bad, &good]).unwrap_err();
  let mogh_config::Error::ParseEnvFile { e, path } = &err else {
    panic!("expected an env file error, got {err}");
  };
  assert_eq!(e.line, 2);
  assert_eq!(path, &bad);
  for message in [err.to_string(), format!("{err:?}")] {
    assert!(!message.contains("hunter2secret"), "{message}");
  }
  // A value which doesn't coerce names its field, not the value.
  let err = load_typed(&[&good]).unwrap_err().to_string();
  assert!(err.contains("at 'port'"), "{err}");
  assert!(err.contains("expected u16"), "{err}");
  assert!(!err.contains("notaport"), "{err}");
  assert!(!err.contains("hunter2secret"), "{err}");
  let err = mogh_config::parse_env_file("A=1\nnope").unwrap_err();
  assert_eq!(err.line, 2);
}

#[test]
fn dotted_env_names_nest_into_structs() {
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Database {
    address: String,
    username: String,
    password: String,
    #[serde(default)]
    pool_size: u32,
  }
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Config {
    title: String,
    database: Database,
  }
  let dir = TestDir::new("dotted_env_names");
  // Defaults in toml, secrets from the env file; the nested merge
  // keeps the toml keys the env file does not set.
  let toml = dir.write(
    "defaults.toml",
    "title = \"app\"\n[database]\naddress = \"localhost:5432\"\npool_size = 4\n",
  );
  let env = dir.write(
    ".env",
    "DATABASE.ADDRESS=db.example.com:5432\nDATABASE.USERNAME=app\nDATABASE.PASSWORD=\"hunter2\"\n",
  );
  let config = ConfigLoader {
    paths: &[&toml, &env],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>()
  .unwrap();
  assert_eq!(
    config,
    Config {
      title: "app".into(),
      database: Database {
        address: "db.example.com:5432".into(),
        username: "app".into(),
        password: "hunter2".into(),
        pool_size: 4,
      },
    }
  );
  // A conflicting file is an error, like a malformed toml, naming
  // the line, not the value.
  let bad = dir
    .write("bad.env", "DATABASE=secretvalue\nDATABASE.ADDRESS=x\n");
  let err =
    try_load::<serde_json::Value>(&[&toml, &bad], &[], true, false)
      .unwrap_err();
  let mogh_config::Error::ParseEnvFile { e, .. } = &err else {
    panic!("expected an env file error, got {err}");
  };
  assert_eq!(e.line, 2);
  assert!(!err.to_string().contains("secretvalue"), "{err}");
}

/// Cicada accepts secret names which cannot nest on dots (a
/// Kubernetes style `.dockerconfigjson`, `a..b`): each loads as one
/// flat key rather than failing the whole source, and the rest of
/// the file still nests. Only real conflicts fail it.
#[test]
fn env_names_that_cannot_nest_stay_flat_keys() {
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Database {
    address: String,
  }
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Config {
    #[serde(rename = ".dockerconfigjson")]
    docker_config_json: String,
    #[serde(rename = "a..b")]
    a_b: u16,
    database: Database,
  }
  let dir = TestDir::new("flat_env_names");
  let env = dir.write(
    ".env",
    ".dockerconfigjson={\"auths\":{}}\nA..B=7\nDATABASE.ADDRESS=db:5432\n",
  );
  let config = ConfigLoader {
    paths: &[&env],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>()
  .unwrap();
  assert_eq!(
    config,
    Config {
      docker_config_json: "{\"auths\":{}}".into(),
      a_b: 7,
      database: Database {
        address: "db:5432".into(),
      },
    }
  );
  // Two names which collide after lowercasing still fail, naming
  // the line and both names (never a value).
  let conflict =
    dir.write("conflict.env", "DB=secretvalue\ndb=other\n");
  let err =
    try_load::<serde_json::Value>(&[&conflict], &[], true, false)
      .unwrap_err();
  let mogh_config::Error::ParseEnvFile { e, .. } = &err else {
    panic!("expected an env file error, got {err}");
  };
  assert_eq!(
    e.to_string(),
    "line 2: `db` conflicts with `DB` (line 1): names are case insensitive"
  );
  assert!(!err.to_string().contains("secretvalue"), "{err}");
}

#[test]
fn env_lists_extend_arrays_under_extend_array() {
  let dir = TestDir::new("env_list_extend");
  let toml = dir.write("a.toml", "hosts = [\"a\"]\nport = 1\n");
  let env = dir.write("b.env", "HOSTS=b, c\nPORT=2\n");
  // extend_array: the list extends, and the rest of the env file
  // still applies (it used to be dropped with a type mismatch).
  let config = load(&[&toml, &env], &[], true, true);
  assert_eq!(
    config,
    serde_json::json!({ "hosts": ["a", "b", "c"], "port": "2" })
  );
  // Without it, the list replaces.
  let config = load(&[&toml, &env], &[], true, false);
  assert_eq!(
    config,
    serde_json::json!({ "hosts": "b, c", "port": "2" })
  );
}

#[test]
fn directory_scans_only_load_env_files_by_wildcard() {
  let dir = TestDir::new("env_dir_scan");
  dir.write("main.toml", "port = 1\n");
  // A compose style `.env` next to the config.
  dir.write(".env", "PORT=99\nCOMPOSE_PROJECT_NAME=x\n");
  // No wildcards: every toml, no env file.
  let config = load(&[&dir.0], &[], true, false);
  assert_eq!(config, serde_json::json!({ "port": 1 }));
  // Asked for by wildcard: loaded, and later than main.toml (a later
  // wildcard wins within the directory).
  let config = load(&[&dir.0], &["*.toml", ".env"], true, false);
  assert_eq!(
    config,
    serde_json::json!({ "port": "99", "compose_project_name": "x" })
  );
}

#[test]
fn coercion_errors_inside_lists_report_the_string() {
  #[derive(serde::Deserialize, Debug)]
  #[allow(dead_code)]
  struct Pins {
    pins: Vec<u8>,
  }
  let dir = TestDir::new("list_error_path");
  let env = dir.write(".env", "PINS=1, secretx, 3\n");
  let err = ConfigLoader {
    paths: &[&env],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Pins>()
  .unwrap_err()
  .to_string();
  assert!(err.contains("at 'pins[1]'"), "{err}");
  assert!(err.contains("found string"), "{err}");
  assert!(!err.contains("secretx"), "{err}");
}

/// A json key is a string, and it coerces into the map's key type,
/// as it did before the lenient final deserialization: typed toml
/// keys and env file keys alike.
#[test]
fn map_keys_coerce_into_their_types() {
  use std::collections::{BTreeMap, HashMap};

  #[derive(serde::Deserialize, Debug, PartialEq, Eq, Hash)]
  struct Team(String);

  #[derive(serde::Deserialize, Debug, PartialEq, Eq, Hash)]
  #[serde(rename_all = "snake_case")]
  enum Stage {
    PreRelease,
    Stable,
  }

  #[derive(serde::Deserialize, Debug)]
  struct Config {
    ports: HashMap<u16, String>,
    limits: BTreeMap<u64, u32>,
    flags: HashMap<bool, String>,
    owners: HashMap<Team, String>,
    stages: HashMap<Stage, u8>,
  }
  let dir = TestDir::new("map_keys");
  let toml = dir.write(
    "config.toml",
    "[ports]\n8080 = \"api\"\n[limits]\n10 = 1\n[flags]\ntrue = \"on\"\n[owners]\nops = \"max\"\n[stages]\npre_release = 1\n",
  );
  let env = dir.write(
    ".env",
    "PORTS.9090=metrics\nLIMITS.10=2\nSTAGES.STABLE=3\n",
  );
  let config = ConfigLoader {
    paths: &[&toml, &env],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>()
  .unwrap();
  assert_eq!(
    config.ports,
    HashMap::from([(8080, "api".into()), (9090, "metrics".into())])
  );
  assert_eq!(config.limits, BTreeMap::from([(10, 2)]));
  assert_eq!(config.flags, HashMap::from([(true, "on".into())]));
  assert_eq!(
    config.owners,
    HashMap::from([(Team("ops".into()), "max".into())])
  );
  assert_eq!(
    config.stages,
    HashMap::from([(Stage::PreRelease, 1), (Stage::Stable, 3)])
  );
}

fn try_load<T: serde::de::DeserializeOwned>(
  paths: &[&Path],
  match_wildcards: &[&str],
  merge_nested: bool,
  extend_array: bool,
) -> mogh_config::Result<T> {
  ConfigLoader {
    paths,
    match_wildcards,
    include_file_name: ".include",
    merge_nested,
    extend_array,
    debug_print: false,
  }
  .load()
}

/// A yaml section with every line commented out is `null`: it keeps
/// the earlier object / array, and the rest of the file applies (the
/// whole file used to be dropped with a type mismatch).
#[test]
fn yaml_null_sections_keep_earlier_values_and_the_rest_applies() {
  let dir = TestDir::new("yaml_null_section");
  let base = dir.write(
    "base.yaml",
    "port: 1\ndatabase:\n  address: localhost\nhosts:\n  - a\n",
  );
  let override_ = dir.write(
    "override.yaml",
    "port: 9000\ndatabase:\n  # address: x\nhosts:\n  # - b\n",
  );
  let config = load(&[&base, &override_], &[], true, true);
  assert_eq!(
    config,
    serde_json::json!({
      "port": 9000,
      "database": { "address": "localhost" },
      "hosts": ["a"],
    })
  );
  // Without merging, null replaces like any value (as before).
  let config = load(&[&base, &override_], &[], false, false);
  assert_eq!(
    config,
    serde_json::json!({ "port": 9000, "database": null, "hosts": null })
  );
}

/// A value conflicting with an earlier source's type replaces it
/// rather than dropping the source with every secret in it: the
/// final deserialization reports it when the config can't take it.
#[test]
fn type_conflicts_never_drop_a_source() {
  #[derive(serde::Deserialize, Debug)]
  #[allow(dead_code)]
  struct Database {
    address: String,
  }
  #[derive(serde::Deserialize, Debug)]
  #[allow(dead_code)]
  struct Config {
    port: u16,
    db_password: String,
    database: Database,
  }
  let dir = TestDir::new("type_conflict_source");
  let toml = dir.write(
    "defaults.toml",
    "port = 1\ndb_password = \"\"\n[database]\naddress = \"localhost\"\n",
  );
  let env = dir.write(
    ".env",
    "PORT=9000\nDB_PASSWORD=hunter2secret\nDATABASE=postgres://x\n",
  );
  let config =
    try_load::<serde_json::Value>(&[&toml, &env], &[], true, true)
      .unwrap();
  assert_eq!(
    config,
    serde_json::json!({
      "port": "9000",
      "db_password": "hunter2secret",
      "database": "postgres://x",
    })
  );
  // Typed: an error at the conflicting field, never the defaults.
  let err =
    try_load::<Config>(&[&toml, &env], &[], true, true).unwrap_err();
  assert!(
    matches!(&err, mogh_config::Error::ParseFinalJson { path, found: Some("string"), .. } if path == "database"),
    "{err}"
  );
  assert!(!err.to_string().contains("hunter2secret"), "{err}");
  assert!(!err.to_string().contains("postgres"), "{err}");

  // A scalar onto an array under extend_array replaces it too.
  let a = dir.write("a.toml", "ports = [8120]\nsecret = \"a\"\n");
  let b = dir.write("b.yaml", "ports: 8121\nsecret: b\n");
  let config = load(&[&a, &b], &[], true, true);
  assert_eq!(
    config,
    serde_json::json!({ "ports": 8121, "secret": "b" })
  );
}

/// Only an env file's string is a comma separated list extending an
/// array; a toml / yaml / json string replaces it.
#[test]
fn only_env_file_lists_extend_arrays() {
  let dir = TestDir::new("toml_string_onto_array");
  let a = dir.write("a.toml", "hosts = [\"a\"]\n");
  let b = dir.write("b.toml", "hosts = \"b, c\"\n");
  let config = load(&[&a, &b], &[], true, true);
  assert_eq!(config, serde_json::json!({ "hosts": "b, c" }));
  let env = dir.write("c.env", "HOSTS=b, c\n");
  let config = load(&[&a, &env], &[], true, true);
  assert_eq!(config, serde_json::json!({ "hosts": ["a", "b", "c"] }));
}

/// An invalid wildcard used to be dropped, and with none left the
/// directory scan loaded every file in it.
#[test]
fn invalid_wildcards_are_an_error() {
  let dir = TestDir::new("invalid_wildcard");
  dir.write("app.config.toml", "a = 1");
  dir.write("package.json", r#"{ "name": "x", "a": 99 }"#);
  let err = try_load::<serde_json::Value>(
    &[&dir.0],
    &["*config\\.toml"],
    true,
    false,
  )
  .unwrap_err();
  let mogh_config::Error::InvalidWildcard { pattern, message } = &err
  else {
    panic!("expected an invalid wildcard error, got {err}");
  };
  assert_eq!(pattern, "*config\\.toml");
  assert!(!message.is_empty());
  // One invalid pattern among valid ones is an error too.
  assert!(matches!(
    try_load::<serde_json::Value>(
      &[&dir.0],
      &["*config.toml", "*config\\.toml"],
      true,
      false,
    ),
    Err(mogh_config::Error::InvalidWildcard { .. })
  ));
  let config = load(&[&dir.0], &["*config.toml"], true, false);
  assert_eq!(config, serde_json::json!({ "a": 1 }));
}

/// A file matching several wildcards takes the last one's priority,
/// so a later, more specific pattern overrides a general one.
#[test]
fn overlapping_wildcards_rank_files_by_their_last_match() {
  let dir = TestDir::new("overlapping_wildcards");
  dir.write("core.config.toml", "port = 1\nbase = 1");
  dir.write("core.config.local.toml", "port = 2");
  let config =
    load(&[&dir.0], &["*config.*", "*config.local.*"], false, false);
  assert_eq!(config, serde_json::json!({ "port": 2, "base": 1 }));
  // The other order puts the general pattern last: base wins.
  let config =
    load(&[&dir.0], &["*config.local.*", "*config.*"], false, false);
  assert_eq!(config, serde_json::json!({ "port": 1, "base": 1 }));
}

/// A file listed after its directory, through another spelling of
/// the path (a symlinked directory), is loaded once: under
/// extend_array its arrays used to apply twice.
#[cfg(unix)]
#[test]
fn a_file_listed_after_its_directory_loads_once() {
  let dir = TestDir::new("dedupe_real");
  dir.write("a.toml", "arr = [\"x\"]\nkey = \"a\"");
  dir.write("z.toml", "key = \"z\"");
  let link = std::env::temp_dir().join(format!(
    "mogh_config_test_{}_dedupe_link",
    std::process::id()
  ));
  let _ = std::fs::remove_file(&link);
  std::os::unix::fs::symlink(&dir.0, &link).unwrap();
  let file = link.join("a.toml");
  let config = load(&[&link, &file], &["*.toml"], true, true);
  let _ = std::fs::remove_file(&link);
  // Once, and at its later position (over z.toml).
  assert_eq!(config, serde_json::json!({ "arr": ["x"], "key": "a" }));
}

/// A listed file is parsed by the name it is listed as, even when it
/// links to a file named otherwise (a mounted secret).
#[cfg(unix)]
#[test]
fn a_listed_file_is_parsed_by_its_listed_name() {
  let dir = TestDir::new("listed_name");
  let secret = dir.write("secret", "PORT=8080\n");
  let env = dir.0.join("app.env");
  std::os::unix::fs::symlink(&secret, &env).unwrap();
  let config = load(&[&env], &[], true, false);
  assert_eq!(config, serde_json::json!({ "port": "8080" }));
}

/// A symlinked file listed before a directory scan which also finds
/// it is loaded once, by its own name: the scan used to replace it
/// with the link target's canonical path (`secret`, no config
/// extension), skipping the file as an unsupported type.
#[cfg(unix)]
#[test]
fn a_symlinked_file_found_again_by_a_scan_keeps_its_name() {
  let dir = TestDir::new("scan_keeps_name");
  let secret = dir.write("secret", "PORT=8080\n");
  let env = dir.0.join("app.env");
  std::os::unix::fs::symlink(&secret, &env).unwrap();
  for paths in [[env.as_path(), &dir.0], [&dir.0, env.as_path()]] {
    let config = load(&paths, &["*.env"], true, false);
    assert_eq!(config, serde_json::json!({ "port": "8080" }));
  }
}

/// A listed symlink keeps its name when a later scan finds the file
/// under the target's own name (`secret`, no config type): without
/// wildcards the scan skips `app.env` but finds `secret`, and with
/// `*` it finds `secret` after `app.env`. Either used to replace the
/// listed name, dropping the env file as an unsupported type.
#[cfg(unix)]
#[test]
fn a_scan_finding_the_link_target_keeps_the_listed_name() {
  let dir = TestDir::new("scan_finds_target");
  let secret = dir.write("secret", "PORT=8080\n");
  let env = dir.0.join("app.env");
  std::os::unix::fs::symlink(&secret, &env).unwrap();
  for wildcards in [&[][..], &["*"]] {
    for paths in [[env.as_path(), &dir.0], [&dir.0, env.as_path()]] {
      let config = load(&paths, wildcards, true, false);
      assert_eq!(
        config,
        serde_json::json!({ "port": "8080" }),
        "{wildcards:?} {paths:?}"
      );
    }
  }
}

/// A symlinked file listed in an include file is loaded by its
/// listed name: the include used to be replaced with the link
/// target's canonical path (`secret`, no config extension),
/// skipping the file as an unsupported type.
#[cfg(unix)]
#[test]
fn a_symlinked_include_keeps_its_name() {
  let included = TestDir::new("include_keeps_name_target");
  let secret = included.write("secret", "PORT=8080\n");
  std::os::unix::fs::symlink(&secret, included.0.join("app.env"))
    .unwrap();
  let dir = TestDir::new("include_keeps_name");
  dir.write("config.toml", "port = 1");
  // Relative (through '..'), as an include line usually is.
  dir.write(
    ".include",
    &format!(
      "../{}/app.env\n",
      included.0.file_name().unwrap().to_str().unwrap()
    ),
  );
  let config = load(&[&dir.0], &["*.toml"], true, false);
  assert_eq!(config, serde_json::json!({ "port": "8080" }));
}

/// A `cicada:` line in an include file used to be dropped as a
/// missing path, silently, with or without the feature.
#[cfg(not(feature = "cicada"))]
#[test]
fn cicada_include_without_the_feature_is_an_error() {
  let dir = TestDir::new("cicada_include");
  dir.write("config.toml", "port = 1");
  dir.write(
    ".include",
    "cicada://app/secrets.env?env=prod # the secrets\n",
  );
  let err = try_load::<serde_json::Value>(
    &[&dir.0],
    &["*.toml"],
    true,
    false,
  )
  .unwrap_err();
  let mogh_config::Error::CicadaFeatureDisabled { path } = &err
  else {
    panic!("expected a cicada feature error, got {err}");
  };
  assert_eq!(path, Path::new("cicada://app/secrets.env?env=prod"));
}

/// A name with thousands of dots used to nest thousands of levels
/// deep (quadratic memory), and overflow the stack of a 2MB thread
/// (a tokio worker's) walking it.
#[test]
fn deeply_dotted_env_names_do_not_overflow_the_stack() {
  #[derive(serde::Deserialize, Debug)]
  struct Config {
    port: u16,
  }
  let dir = TestDir::new("deep_env_name");
  let name = vec!["a"; 6_000].join(".");
  let env = dir.write(".env", &format!("{name}=1\nPORT=8080\n"));
  let config = std::thread::Builder::new()
    .stack_size(2 * 1024 * 1024)
    .spawn(move || {
      try_load::<Config>(&[&env], &[], true, true).map(|c| c.port)
    })
    .unwrap()
    .join()
    .unwrap()
    .unwrap();
  assert_eq!(config, 8080);
}

/// Arrays merged under extend_array into a tuple used to keep the
/// first entries silently: now too many is an error, as in 2.x.
#[test]
fn extended_arrays_into_a_tuple_must_fit() {
  #[derive(serde::Deserialize, Debug)]
  #[allow(dead_code)]
  struct Config {
    pair: (u8, u8),
  }
  let dir = TestDir::new("tuple_extend");
  let a = dir.write("a.toml", "pair = [1, 2]");
  let b = dir.write("b.toml", "pair = [3, 4]");
  let err =
    try_load::<Config>(&[&a, &b], &[], true, true).unwrap_err();
  assert!(err.to_string().contains("at 'pair'"), "{err}");
  assert!(err.to_string().contains("fewer elements"), "{err}");
  let config =
    try_load::<Config>(&[&a, &b], &[], true, false).unwrap();
  assert_eq!(config.pair, (3, 4));
}

/// `$(command)` runs a single command word: a command with
/// arguments is kept as written (with a warning naming the key),
/// never run through a shell.
#[test]
fn commands_with_arguments_are_kept_as_written() {
  let dir = TestDir::new("interpolation_arguments");
  let toml = dir.write(
    "config.toml",
    "password = \"$(cat /etc/hostname)\"\nfallback = \"${MOGH_CONFIG_TEST_UNSET:-x}\"\nran = \"$(true)\"",
  );
  let config = load(&[&toml], &[], false, false);
  assert_eq!(
    config,
    serde_json::json!({
      "password": "$(cat /etc/hostname)",
      "fallback": "${MOGH_CONFIG_TEST_UNSET:-x}",
      "ran": "",
    })
  );
}

/// A config file which exists but doesn't parse used to be skipped
/// with a warning, starting the app without the settings in it (a
/// key duplicated by an edit dropped the whole file, its
/// `disable_user_registration` with it). Listed, found by a scan or
/// included, it is an error naming the file, never a value in it.
#[test]
fn files_which_do_not_parse_are_an_error() {
  let dir = TestDir::new("unparseable");
  let defaults = dir.write("defaults.toml", "port = 1");
  for (file, contents) in [
    (
      "duplicate.toml",
      "disable_user_registration = true\ndisable_user_registration = \"hunter2\"",
    ),
    ("broken.toml", "secret = \"hunter2"),
    ("broken.yaml", "secret: [hunter2"),
    ("list.yaml", "- hunter2"),
    ("scalar.yaml", "hunter2"),
    ("broken.json", "{ \"secret\": \"hunter2\" "),
    ("list.json", "[\"hunter2\"]"),
    ("broken.env", "SECRET=hunter2\nnot an entry"),
  ] {
    let path = dir.write(file, contents);
    let err = try_load::<serde_json::Value>(
      &[&defaults, &path],
      &[],
      true,
      false,
    )
    .unwrap_err();
    let parsed_path = match &err {
      mogh_config::Error::ParseToml { path, .. }
      | mogh_config::Error::ParseYaml { path, .. }
      | mogh_config::Error::ParseJson { path, .. }
      | mogh_config::Error::ParseEnvFile { path, .. } => path,
      _ => panic!("{file}: expected a parse error, got {err}"),
    };
    assert_eq!(parsed_path, &path, "{file}");
    for message in [err.to_string(), format!("{err:?}")] {
      assert!(!message.contains("hunter2"), "{file}: {message}");
    }
    std::fs::remove_file(&path).unwrap();
  }

  // Found by a directory scan, or through an include file.
  let scanned = TestDir::new("unparseable_scanned");
  scanned.write("core.config.toml", "port = 1");
  let local = scanned.write("local.config.toml", "port = = 2");
  let included = TestDir::new("unparseable_included");
  included.write("core.config.toml", "port = 1");
  included.write(".include", &format!("{}\n", scanned.0.display()));
  for path in [&scanned.0, &included.0] {
    let err = try_load::<serde_json::Value>(
      &[path],
      &["*config.*"],
      true,
      false,
    )
    .unwrap_err();
    assert!(
      matches!(&err, mogh_config::Error::ParseToml { path, .. } if path.file_name() == local.file_name()),
      "{err}"
    );
  }
}

/// A placeholder holds no settings: an empty source, never an
/// error. Blank or comments only in any format, a yaml file whose
/// every line is commented out, a `null` document.
#[test]
fn files_holding_no_settings_are_empty_sources() {
  let dir = TestDir::new("no_settings");
  let defaults = dir.write("defaults.toml", "port = 1");
  for (file, contents) in [
    ("blank.toml", ""),
    ("comments.toml", "# port = 2\n"),
    ("blank.yaml", "\n"),
    ("comments.yaml", "# port: 2\n"),
    ("markers.yaml", "---\n# port: 2\n...\n"),
    ("null.yaml", "~\n"),
    ("null.yml", "--- null\n"),
    ("empty.yaml", "{}"),
    ("blank.json", " \n"),
    ("null.json", "null"),
    ("empty.json", "{}"),
    ("blank.env", ""),
    ("comments.env", "# PORT=2\n"),
  ] {
    let path = dir.write(file, contents);
    let config = try_load::<serde_json::Value>(
      &[&defaults, &path],
      &[],
      true,
      false,
    )
    .unwrap_or_else(|e| panic!("{file}: {e}"));
    assert_eq!(config, serde_json::json!({ "port": 1 }), "{file}");
  }
}

/// A file which can't be read (here not utf-8) used to be skipped.
#[test]
fn a_file_which_can_not_be_read_is_an_error() {
  let dir = TestDir::new("not_utf8");
  let binary = dir.0.join("binary.toml");
  std::fs::write(&binary, [0xff, 0xfe, 0x00]).unwrap();
  let err =
    try_load::<serde_json::Value>(&[&binary], &[], true, false)
      .unwrap_err();
  assert!(
    matches!(&err, mogh_config::Error::ReadFileContents { path, .. } if path == &binary),
    "{err}"
  );
  // Found by a scan.
  let err = try_load::<serde_json::Value>(
    &[&dir.0],
    &["*.toml"],
    true,
    false,
  )
  .unwrap_err();
  assert!(
    matches!(&err, mogh_config::Error::ReadFileContents { path, .. } if path.file_name() == binary.file_name()),
    "{err}"
  );
}

/// Takes all permissions from a path, giving them back on drop (also
/// when an assertion fails, so the test directory can be removed).
#[cfg(unix)]
struct Locked(PathBuf);

#[cfg(unix)]
impl Locked {
  /// `None` when the lock isn't enforced (running as root).
  fn new(path: &Path) -> Option<Locked> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(
      path,
      std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let locked = Locked(path.to_path_buf());
    let enforced = if path.is_dir() {
      std::fs::read_dir(path).is_err()
    } else {
      std::fs::File::open(path).is_err()
    };
    enforced.then_some(locked)
  }
}

#[cfg(unix)]
impl Drop for Locked {
  fn drop(&mut self) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(
      &self.0,
      std::fs::Permissions::from_mode(0o755),
    );
  }
}

/// A file, directory or include file which exists but can't be
/// read, or a path whose metadata can't be (permission denied on a
/// parent), used to be skipped like a missing one, without a word.
#[cfg(unix)]
#[test]
fn paths_without_permission_are_an_error() {
  let dir = TestDir::new("permissions");
  let file = dir.write("locked.toml", "port = 1");
  let Some(_lock) = Locked::new(&file) else {
    println!("permissions aren't enforced (root): skipped");
    return;
  };
  let err = try_load::<serde_json::Value>(&[&file], &[], true, false)
    .unwrap_err();
  assert!(
    matches!(&err, mogh_config::Error::FileOpen { path, .. } if path == &file),
    "{err}"
  );
  drop(_lock);

  // A directory listed, and one included.
  let locked_dir = dir.0.join("locked_dir");
  std::fs::create_dir(&locked_dir).unwrap();
  std::fs::write(locked_dir.join("core.config.toml"), "port = 1")
    .unwrap();
  let main = TestDir::new("permissions_main");
  main.write("core.config.toml", "port = 2");
  main.write(".include", &format!("{}\n", locked_dir.display()));
  let lock = Locked::new(&locked_dir).unwrap();
  for path in [&locked_dir, &main.0] {
    let err = try_load::<serde_json::Value>(
      &[path],
      &["*config.*"],
      true,
      false,
    )
    .unwrap_err();
    assert!(
      matches!(&err, mogh_config::Error::ReadDir { path, .. } if path == &locked_dir),
      "{err}"
    );
  }
  // A path under it: its metadata can't be read. Listed, or named by
  // an include line.
  let under = locked_dir.join("core.config.toml");
  let err =
    try_load::<serde_json::Value>(&[&under], &[], true, false)
      .unwrap_err();
  assert!(
    matches!(&err, mogh_config::Error::ReadPathMetaData { path, .. } if path == &under),
    "{err}"
  );
  main.write(".include", &format!("{}\n", under.display()));
  let err = try_load::<serde_json::Value>(
    &[&main.0],
    &["*config.*"],
    true,
    false,
  )
  .unwrap_err();
  assert!(
    matches!(&err, mogh_config::Error::ReadPathMetaData { path, .. } if path == &under),
    "{err}"
  );
  drop(lock);

  // An include file which can't be read.
  let include = main.0.join(".include");
  let _lock = Locked::new(&include).unwrap();
  let err = try_load::<serde_json::Value>(
    &[&main.0],
    &["*config.*"],
    true,
    false,
  )
  .unwrap_err();
  assert!(
    matches!(&err, mogh_config::Error::FileOpen { path, .. } if path.file_name() == include.file_name()),
    "{err}"
  );
}

/// A scanned file whose name isn't utf-8 used to be skipped without
/// a word: wildcards match it as bytes now.
#[cfg(target_os = "linux")]
#[test]
fn scanned_file_names_need_not_be_utf8() {
  use std::os::unix::ffi::OsStrExt as _;
  let dir = TestDir::new("non_utf8_name");
  let name = std::ffi::OsStr::from_bytes(b"caf\xe9.config.toml");
  std::fs::write(dir.0.join(name), "port = 1").unwrap();
  let config = load(&[&dir.0], &["*config.*"], false, false);
  assert_eq!(config, serde_json::json!({ "port": 1 }));
}

/// A dangling symlink in a scanned directory (a Kubernetes mount
/// mid update) is a missing file, not an error.
#[cfg(unix)]
#[test]
fn dangling_symlinks_in_scanned_directories_are_skipped() {
  let dir = TestDir::new("dangling_symlink");
  dir.write("core.config.toml", "port = 1");
  std::os::unix::fs::symlink(
    dir.0.join("gone.toml"),
    dir.0.join("local.config.toml"),
  )
  .unwrap();
  let config = load(&[&dir.0], &["*config.*"], false, false);
  assert_eq!(config, serde_json::json!({ "port": 1 }));
}

/// What Cicada Core serializes (its `cicada://.env` exports) loads
/// as a config source unchanged: one grammar, in one place.
#[test]
fn serialized_env_files_load_as_config_sources() {
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Database {
    address: String,
  }
  #[derive(serde::Deserialize, Debug, PartialEq)]
  struct Config {
    db_password: String,
    port: u16,
    hosts: Vec<String>,
    template: String,
    note: String,
    database: Database,
  }
  let entry = |name: &str, value: &str, description: &str| {
    mogh_config::EnvFileEntry {
      name: name.to_string(),
      value: value.to_string(),
      description: description.to_string(),
      ..Default::default()
    }
  };
  let env_file = mogh_config::serialize_env_file([
    entry("DB_PASSWORD", " p4ss \"w0rd\" \\ #x\n", "the database"),
    entry("PORT", "8080", ""),
    entry("HOSTS", "a.example.com, b.example.com", ""),
    entry("TEMPLATE", "${HOME} $(whoami)", "kept as written"),
    entry("NOTE", "it's $5", "multi\nline"),
    entry("DATABASE.ADDRESS", "db:5432", ""),
  ])
  .unwrap();
  let dir = TestDir::new("serialized_env_file");
  let env = dir.write(".env", &env_file);
  let config = ConfigLoader {
    paths: &[&env],
    match_wildcards: &[],
    include_file_name: ".include",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  }
  .load::<Config>()
  .unwrap();
  assert_eq!(
    config,
    Config {
      db_password: " p4ss \"w0rd\" \\ #x\n".into(),
      port: 8080,
      hosts: vec!["a.example.com".into(), "b.example.com".into()],
      template: "${HOME} $(whoami)".into(),
      note: "it's $5".into(),
      database: Database {
        address: "db:5432".into()
      },
    }
  );
  // And the entries, descriptions included, parse back.
  let parsed = mogh_config::parse_env_file(&env_file).unwrap();
  assert_eq!(parsed[0].description, "the database");
  assert_eq!(parsed[4].description, "multi\nline");
}
