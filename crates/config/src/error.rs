use std::{path::PathBuf, sync::LazyLock};

use serde::de::DeserializeOwned;

/// The json type name of a value, for error messages
/// which must not include the value itself.
pub(crate) fn value_type(value: &serde_json::Value) -> &'static str {
  match value {
    serde_json::Value::Null => "null",
    serde_json::Value::Bool(_) => "boolean",
    serde_json::Value::Number(_) => "number",
    serde_json::Value::String(_) => "string",
    serde_json::Value::Array(_) => "array",
    serde_json::Value::Object(_) => "object",
  }
}

/// Redacts values from a serde error message, since config values
/// may be secrets and errors are logged: double quoted strings
/// (`invalid type: string "hunter2"`) and backticked tokens
/// (`invalid type: integer `4829``). An unknown enum variant or
/// field is redacted whole, whatever it holds (serde doesn't escape
/// it), keeping the names expected after it:
/// `unknown variant [redacted], expected `fast` or `safe``.
pub(crate) fn redact_serde_error(e: &serde_json::Error) -> String {
  redact_message(&e.to_string(), false)
}

/// [redact_serde_error] for the message of any parser. serde's own
/// message comes first, or with `path_prefix` (yaml) may follow
/// the path of the value it is about (`server.mode: ...`).
fn redact_message(message: &str, path_prefix: bool) -> String {
  // Where serde's message starts. serde writes each value right
  // after its own wording, and the first one comes after the path,
  // so the wording before the first quote / backtick tells where
  // the path ends: the path (yaml keys) may hold anything.
  static WORDING: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
      r"(?:\A|: )((?:invalid (?:type|value): (?:string|character|boolean|integer|floating point)|unknown (?:variant|field)|missing field|duplicate field) )\z",
    )
    .unwrap()
  });
  let start = match message.find(['"', '`']) {
    Some(quote) if path_prefix => {
      match WORDING.captures(&message[..quote]) {
        Some(wording) => wording.get(1).unwrap().start(),
        // A quote or backtick in the path, which can't be told
        // apart from a value's: keep only the text before it, and
        // where the error is.
        None => {
          static LOCATION: LazyLock<regex::Regex> =
            LazyLock::new(|| {
              regex::Regex::new(
                r" at (?:line \d+ column \d+|position \d+)\z",
              )
              .unwrap()
            });
          let location = LOCATION
            .find(&message[quote..])
            .map_or("", |location| location.as_str());
          return format!(
            "{}[redacted]{location}",
            &message[..quote]
          );
        }
      }
    }
    _ => 0,
  };
  // serde writes an unknown enum variant or field name in
  // backticks without escaping it, so it may hold backticks or
  // quotes itself: it runs up to serde's own `, expected` / `, there
  // are no`, the last one, as it may hold these too. The names
  // expected after it are the program's, and stay readable. Only at
  // the start of serde's message: text like it anywhere else is
  // inside a value, eg. `invalid type: string "unknown variant `a`,
  // expected b", expected u16`, whose string is redacted whole
  // below.
  static UNKNOWN: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
      r"(?s)\A(unknown (?:variant|field) )`.*`(, expected|, there are no)",
    )
    .unwrap()
  });
  let (path, rest) = message.split_at(start);
  if let Some(unknown) = UNKNOWN.captures(rest) {
    let end = unknown.get(0).unwrap().end();
    return format!(
      "{path}{}[redacted]{}{}",
      &unknown[1],
      &unknown[2],
      &rest[end..]
    );
  }
  redact_values(message)
}

/// Redacts the values serde writes into its messages: strings
/// escaped in double quotes (`string "a \"b\""`), a character in
/// backticks (which may be a backtick itself), and numbers and
/// booleans in backticks.
fn redact_values(message: &str) -> String {
  static QUOTED: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
      r#"(?s)"(?:[^"\\]|\\.)*"|character `.`|`[^`]*`"#,
    )
    .unwrap()
  });
  QUOTED
    .replace_all(message, |caps: &regex::Captures| {
      if caps[0].starts_with("character ") {
        "character [redacted]"
      } else {
        "[redacted]"
      }
    })
    .into_owned()
}

/// The message of a toml error, redacted like [redact_serde_error],
/// with the line and column of its span in `contents`. Not the
/// error's `Display`, which quotes the offending line, nor its
/// `Debug`, which includes all of `contents`.
pub(crate) fn redact_toml_error(
  e: &toml::de::Error,
  contents: &str,
) -> String {
  let message = redact_message(e.message().trim_end(), false);
  let Some((line, column)) =
    e.span().and_then(|span| line_column(contents, span.start))
  else {
    return message;
  };
  format!("{message} at line {line} column {column}")
}

/// The yaml error message (with its line and column), redacted like
/// [redact_serde_error].
pub(crate) fn redact_yaml_error(e: &serde_yaml_ng::Error) -> String {
  redact_message(&e.to_string(), true)
}

/// The 1 based line and column (in chars) of a byte offset.
fn line_column(
  contents: &str,
  offset: usize,
) -> Option<(usize, usize)> {
  let before = contents.get(..offset)?;
  let line = before.matches('\n').count() + 1;
  let column = before
    .rsplit('\n')
    .next()
    .map_or(0, |line| line.chars().count())
    + 1;
  Some((line, column))
}

/// Deserialize the merged config into the final type, mapping
/// failures to [Error::ParseFinalJson] with the path of the
/// offending field and the type found there, never its value.
///
/// String values coerce into the requested type the way `envy`
/// reads the process environment, since configuration arrives as
/// strings from env file sources and `${VAR}` interpolation, and a
/// `port: u16` field must accept `PORT=8080` all the same:
///
/// - `bool`, integers and floats parse from the (trimmed) string; a
///   `char` is the string's single character, untrimmed.
/// - A sequence (`Vec<T>`, tuples) splits a string on commas,
///   entries trimmed and empty ones dropped, so `""` is an empty
///   list; each entry coerces in turn. A tuple or `[T; N]` given
///   more entries than it has is an error.
/// - `Option<T>` is `Some` (only `null` is `None`).
/// - A unit enum variant matches the string.
/// - A map key coerces into the map's key type the same way, as
///   serde_json reads keys (`{ "8080": "api" }` into a
///   `HashMap<u16, String>`).
///
/// Out of reach: anything serde buffers before deserializing it
/// (`#[serde(flatten)]` fields, untagged and internally / adjacently
/// tagged enums), where a string stays a string, so a numeric field
/// inside them must arrive typed (toml / yaml / json), not from an
/// env file.
pub fn deserialize_final<T: DeserializeOwned>(
  value: &serde_json::Value,
) -> crate::Result<T> {
  deserialize_final_with_env(value, None)
}

/// [deserialize_final], naming the variable of `env` which set the
/// value a failure is about ([Error::ParseEnv]).
pub(crate) fn deserialize_final_with_env<T: DeserializeOwned>(
  value: &serde_json::Value,
  env: Option<&crate::env::EnvValues>,
) -> crate::Result<T> {
  serde_path_to_error::deserialize(crate::lenient::Lenient(
    value.clone(),
  ))
  .map_err(|e| {
    let path = e.path();
    let message = redact_serde_error(e.inner());
    if let Some(variable) = env.and_then(|env| env.variable_at(path))
    {
      return Error::ParseEnv {
        variable: variable.to_string(),
        path: path.to_string(),
        message,
      };
    }
    let found = value_at(value, path).map(value_type);
    Error::ParseFinalJson {
      path: path.to_string(),
      found,
      message,
    }
  })
}

/// The value at a serde error path, if the path resolves.
fn value_at<'a>(
  mut value: &'a serde_json::Value,
  path: &serde_path_to_error::Path,
) -> Option<&'a serde_json::Value> {
  use serde_path_to_error::Segment;
  for segment in path.iter() {
    value = match segment {
      Segment::Map { key } | Segment::Enum { variant: key } => {
        value.get(key)?
      }
      // A sequence split out of a string (see [deserialize_final]):
      // the string is what was found there.
      Segment::Seq { .. } if value.is_string() => return Some(value),
      Segment::Seq { index } => value.get(index)?,
      Segment::Unknown => return None,
    };
  }
  Some(value)
}

/// Config errors never include config values,
/// which may be secrets, only keys and types.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error(
    "Types on field {key} do not match | got {found}, expected object"
  )]
  ObjectFieldTypeMismatch {
    key: String,
    /// The json type name of the value found.
    found: &'static str,
  },

  #[error(
    "Types on field {key} do not match | got {found}, expected array"
  )]
  ArrayFieldTypeMismatch {
    key: String,
    /// The json type name of the value found.
    found: &'static str,
  },

  /// A config file (or include file) which exists but can't be
  /// opened, eg. permission denied. See [crate::ConfigLoader::load].
  #[error("Failed to open file at {path} | {e:?}")]
  FileOpen { e: std::io::Error, path: PathBuf },

  /// A config file (or include file) which opened but can't be read,
  /// eg. not utf-8. See [crate::ConfigLoader::load].
  #[error("Failed to read contents of file at {path} | {e:?}")]
  ReadFileContents { e: std::io::Error, path: PathBuf },

  /// The parser's error is not kept: it quotes the file.
  #[error("Failed to parse toml file at {path} | {message}")]
  ParseToml {
    path: PathBuf,
    /// The parser's message with values redacted (strings,
    /// numbers, an unknown variant or field name), and the line and
    /// column.
    message: String,
  },

  /// The parser's error is not kept, see [Error::ParseToml].
  #[error("Failed to parse yaml file at {path} | {message}")]
  ParseYaml {
    path: PathBuf,
    /// The parser's message with values redacted (strings,
    /// numbers, an unknown variant or field name), and the line and
    /// column.
    message: String,
  },

  /// The parser's error is not kept, see [Error::ParseToml].
  #[error("Failed to parse json file at {path} | {message}")]
  ParseJson {
    path: PathBuf,
    /// The parser's message with values redacted (strings,
    /// numbers, an unknown variant or field name), and the line and
    /// column.
    message: String,
  },

  /// See [crate::parse_env_file]; the message names the line and
  /// what was expected, never a value.
  #[error("Failed to parse env file at {path} | {e}")]
  ParseEnvFile {
    e: crate::env_file::EnvFileError,
    path: PathBuf,
  },

  /// A file named as a config path or by an include line which is
  /// no config file type (toml, yaml, yml, json, or an env file).
  /// One a directory scan finds is skipped with a warning instead.
  #[error(
    "Unsupported file type at {path} | expected a toml, yaml, yml or json extension, or an env file (.env, *.env)"
  )]
  UnsupportedFileType { path: PathBuf },

  /// See [deserialize_final]. The message has values redacted
  /// (strings, numbers, an unknown variant or field name); `found`
  /// is the json type at `path`.
  #[error(
    "Failed to parse merged config into final type at '{path}' | found {} | {message}",
    found.unwrap_or("nothing")
  )]
  ParseFinalJson {
    /// Dot separated path to the offending field, `.` for the root.
    path: String,
    /// The json type name found at `path`, if it resolves.
    found: Option<&'static str>,
    message: String,
  },

  #[error("Failed to serialize config to json string | {e:?}")]
  SerializeJson { e: serde_json::Error },

  /// A config directory which exists but can't be read, eg.
  /// permission denied. See [crate::ConfigLoader::load].
  #[error("Failed to read directory at {path:?} | {e:?}")]
  ReadDir { path: PathBuf, e: std::io::Error },

  /// An entry of a config directory which can't be read while
  /// listing it. See [crate::ConfigLoader::load].
  #[error("Failed to read an entry of directory {path:?} | {e:?}")]
  DirFile { e: std::io::Error, path: PathBuf },

  /// A config path (listed, an include line, or a matching file in
  /// a scanned directory) which may exist but whose metadata can't
  /// be read, eg. permission denied on a parent directory. A path
  /// which doesn't exist is skipped instead. See
  /// [crate::ConfigLoader::load].
  #[error("Failed to get metadata for path {path:?} | {e:?}")]
  ReadPathMetaData { path: PathBuf, e: std::io::Error },

  #[error("Parsed value is not object")]
  ValueIsNotObject,

  /// A [crate::ConfigLoader::match_wildcards] pattern which doesn't
  /// compile. An error rather than a dropped pattern: dropping it
  /// widens the filter (with none left, a directory scan loads every
  /// file in it).
  #[error("Config wildcard '{pattern}' is invalid | {message}")]
  InvalidWildcard { pattern: String, message: String },

  /// A `cicada:` config path (listed in the paths, or in an include
  /// file), without the `cicada` feature to load it. An error rather
  /// than a skipped path: the app would start with defaults where
  /// the operator expects their configuration.
  #[error(
    "Config path {path:?} is a cicada path, which needs the 'cicada' feature of mogh_config to be enabled"
  )]
  CicadaFeatureDisabled { path: PathBuf },

  /// A `cicada:` config path (listed in the paths, or in an include
  /// file) which failed to load from Cicada (Core unreachable, the
  /// device not onboarded or not granted the environments, the file
  /// missing, ...). An error rather than a skipped path, like
  /// [Error::CicadaFeatureDisabled].
  #[error("Failed to load cicada config at {path:?} | {message}")]
  CicadaLoad {
    /// The path as listed, `cicada://...`.
    path: PathBuf,
    /// The loader's error chain.
    message: String,
  },

  /// An [EnvSource][crate::EnvSource] whose table doesn't hold
  /// together: a variable named twice, a config path inside
  /// another's, an alias of no variable of the table. A mistake of
  /// the app, not of the environment.
  #[error("Invalid environment config source | {message}")]
  InvalidEnvSource { message: String },

  /// A variable of the [EnvSource][crate::EnvSource] whose value is
  /// not valid UTF-8.
  #[error("Environment variable {variable} is not valid UTF-8")]
  EnvNotUnicode { variable: String },

  /// A variable of the [EnvSource][crate::EnvSource] set twice, under
  /// names which only differ in case (which `envy` refuses too).
  #[error(
    "Environment variable {variable} is set twice, also as {other}: remove one"
  )]
  EnvVarSetTwice { variable: String, other: String },

  /// The file a `_FILE` variable of the
  /// [EnvSource][crate::EnvSource] names, which can't be read
  /// (missing, permission denied, not UTF-8).
  #[error(
    "Failed to read the file {variable} names at {path:?} | {e:?}"
  )]
  EnvFile {
    variable: String,
    path: PathBuf,
    e: std::io::Error,
  },

  /// A value from the environment (see
  /// [EnvSource][crate::EnvSource]) which the config field it sets
  /// can't take. The message has the value redacted, like
  /// [Error::ParseFinalJson]'s.
  #[error(
    "Failed to parse environment variable {variable} into '{path}' | {message}"
  )]
  ParseEnv {
    /// As it was set, eg. `APP_PORT` or `APP_PORT_FILE`.
    variable: String,
    /// Dot separated path to the offending field.
    path: String,
    message: String,
  },
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn redacts_quoted_values_from_serde_errors() {
    let err = serde_json::from_value::<u16>(serde_json::json!(
      "hunter2 \"quoted\" secret"
    ))
    .unwrap_err();
    let message = redact_serde_error(&err);
    assert!(!message.contains("hunter2"), "{message}");
    assert!(
      message.contains("invalid type: string [redacted]"),
      "{message}"
    );
    assert!(message.contains("expected u16"));
    // Numbers are formatted in backticks by serde.
    let err =
      serde_json::from_value::<String>(serde_json::json!(482913))
        .unwrap_err();
    let message = redact_serde_error(&err);
    assert!(!message.contains("482913"), "{message}");
    // A character is written in backticks unescaped.
    let err = <serde_json::Error as serde::de::Error>::invalid_type(
      serde::de::Unexpected::Char('`'),
      &"a secret",
    );
    let message = redact_serde_error(&err);
    assert_eq!(
      message,
      "invalid type: character [redacted], expected a secret"
    );
  }

  /// serde writes an unknown enum variant (or field name) in
  /// backticks without escaping it: a backtick in the value used to
  /// end the redacted token early, leaking the rest.
  #[test]
  fn redacts_unknown_variants_holding_backticks_and_quotes() {
    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "lowercase")]
    #[allow(dead_code)]
    enum Mode {
      Fast,
      Safe,
    }
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Config {
      mode: Mode,
    }
    #[derive(serde::Deserialize, Debug)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Strict {
      port: u16,
    }
    for value in [
      "x`hunter2secret",
      "a`b`c`hunter2`d",
      "`hunter2`",
      "x\"hunter2\"",
      "x`, expected `hunter2",
      "x`, there are no hunter2",
      "multi\nline`hunter2",
    ] {
      let err = deserialize_final::<Config>(
        &serde_json::json!({ "mode": value }),
      )
      .unwrap_err();
      for message in [err.to_string(), format!("{err:?}")] {
        assert!(!message.contains("hunter2"), "{value:?}: {message}");
      }
      let message = err.to_string();
      assert!(
        message.ends_with(
          "unknown variant [redacted], expected `fast` or `safe`"
        ),
        "{value:?}: {message}"
      );
      // Parse errors too.
      for (file, contents) in [
        ("a.yaml", format!("mode: {}", serde_json::json!(value))),
        ("a.toml", format!("mode = {}", serde_json::json!(value))),
        (
          "a.json",
          format!("{{\"mode\": {}}}", serde_json::json!(value)),
        ),
      ] {
        let err = crate::load::parse_config_contents::<Config>(
          std::path::Path::new(file),
          &contents,
        )
        .unwrap_err();
        for message in [err.to_string(), format!("{err:?}")] {
          assert!(
            !message.contains("hunter2"),
            "{file} {value:?}: {message}"
          );
          assert!(
            message.contains(
              "unknown variant [redacted], expected `fast` or `safe`"
            ),
            "{file} {value:?}: {message}"
          );
        }
      }

      // A key is named by the path, but not by serde's message.
      let err = deserialize_final::<Strict>(
        &serde_json::json!({ "port": 1, value: 1 }),
      )
      .unwrap_err();
      let Error::ParseFinalJson { message, .. } = err else {
        panic!("{err:?}");
      };
      assert_eq!(
        message, "unknown field [redacted], expected `port`",
        "{value:?}"
      );
    }
  }

  /// Text like serde's unknown variant message inside a string
  /// value is part of the value: the string is redacted whole, not
  /// taken for serde's message, which would keep what follows it.
  #[test]
  fn redacts_strings_holding_unknown_variant_text() {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Typed {
      port: u16,
    }
    for value in [
      "unknown variant `a`, expected hunter2",
      "x unknown variant `a`, expected `hunter2` or",
      "unknown field `a`, there are no hunter2",
      "x: unknown variant `a`, expected hunter2",
      "hunter2: unknown variant `a`, expected `b`",
    ] {
      let err = deserialize_final::<Typed>(
        &serde_json::json!({ "port": value }),
      )
      .unwrap_err();
      let Error::ParseFinalJson { message, .. } = &err else {
        panic!("{err:?}");
      };
      assert_eq!(
        message, "invalid value: string [redacted], expected u16",
        "{value:?}"
      );
      for (file, contents) in [
        (
          "a.json",
          format!("{{\"port\": {}}}", serde_json::json!(value)),
        ),
        ("a.toml", format!("port = {}", serde_json::json!(value))),
        ("a.yaml", format!("port: {}", serde_json::json!(value))),
        ("a.yaml", format!("{}", serde_json::json!(value))),
      ] {
        let err = crate::load::parse_config_contents::<Typed>(
          std::path::Path::new(file),
          &contents,
        )
        .unwrap_err();
        for message in [err.to_string(), format!("{err:?}")] {
          assert!(
            !message.contains("hunter2"),
            "{file} {value:?}: {message}"
          );
        }
        if file == "a.json" || contents.starts_with("port") {
          assert!(
            err.to_string().contains("[redacted], expected u16"),
            "{file} {value:?}: {err}"
          );
        }
      }
    }
  }

  /// yaml names the key of the failing value before serde's message:
  /// a key holding a quote or a backtick can't be told from the
  /// value, so only the text before it is kept.
  #[test]
  fn redacts_yaml_errors_under_keys_holding_quotes() {
    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "lowercase")]
    #[allow(dead_code)]
    enum Mode {
      Fast,
      Safe,
    }
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Typed {
      modes: std::collections::HashMap<String, Mode>,
      ports: std::collections::HashMap<String, u16>,
    }
    let parse = |contents: &str| {
      crate::load::parse_config_contents::<Typed>(
        std::path::Path::new("a.yaml"),
        contents,
      )
      .unwrap_err()
    };
    for key in ["a`b", "a\"b", "a`b\"c", "a: b`c", "a: b\"c"] {
      let key = serde_json::json!(key);
      for value in ["x`hunter2", "hunter2", "x\"hunter2"] {
        let value = serde_json::json!(value);
        let err =
          parse(&format!("ports: {{}}\nmodes: {{ {key}: {value} }}"));
        let message = err.to_string();
        assert!(
          !message.contains("hunter2"),
          "{key} {value}: {message}"
        );
        assert!(
          message.contains("at line 2"),
          "{key} {value}: {message}"
        );
      }
      let err =
        parse(&format!("modes: {{}}\nports: {{ {key}: hunter2 }}"));
      let message = err.to_string();
      assert!(!message.contains("hunter2"), "{key}: {message}");
      assert!(message.contains("at line 2"), "{key}: {message}");
    }
    // A plain key stays readable, and so does serde's message.
    let err = parse("ports: {}\nmodes: { a.b: x`hunter2 }");
    assert!(
      err.to_string().ends_with(
        "modes.a.b: unknown variant [redacted], expected `fast` or `safe` at line 2 column 15"
      ),
      "{err}"
    );
    let err = parse("modes: {}\nports: { a.b: hunter2 }");
    assert!(
      err.to_string().ends_with(
        "ports.a.b: invalid type: string [redacted], expected u16 at line 2 column 15"
      ),
      "{err}"
    );
  }

  /// Parse errors are returned to the app, which logs them: a
  /// `cicada:` file carries the secrets Core interpolated into it.
  #[test]
  fn parse_errors_redact_values_and_name_the_line() {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Typed {
      port: u16,
    }
    let assert_redacted = |err: Error, location: Option<&str>| {
      for message in [err.to_string(), format!("{err:?}")] {
        assert!(!message.contains("hunter2"), "{message}");
        if let Some(location) = location {
          assert!(message.contains(location), "{message}");
        }
      }
    };
    let parse = |file: &str, contents: &str| {
      crate::load::parse_config_contents::<serde_json::Value>(
        std::path::Path::new(file),
        contents,
      )
      .unwrap_err()
    };
    let parse_typed = |file: &str, contents: &str| {
      crate::load::parse_config_contents::<Typed>(
        std::path::Path::new(file),
        contents,
      )
      .unwrap_err()
    };

    let err = parse("a.toml", "secret = \"hunter2\"\n[[broken");
    assert!(matches!(err, Error::ParseToml { .. }), "{err:?}");
    assert_redacted(err, Some("at line 2 column"));
    // The column counts chars, not bytes.
    let err = parse("a.toml", "k = \"é\" hunter2");
    assert_redacted(err, Some("at line 1 column 9"));
    let err = parse_typed("a.toml", "port = \"hunter2\"");
    assert_redacted(err, Some("expected u16"));

    let err = parse("a.yaml", "secret: \"hunter2\"\nbroken: [");
    assert!(matches!(err, Error::ParseYaml { .. }), "{err:?}");
    assert_redacted(err, Some("at line"));
    let err = parse_typed("a.yaml", "port: hunter2");
    assert_redacted(err, Some("expected u16"));

    let err = parse("a.json", "{\"secret\": \"hunter2\",");
    assert!(matches!(err, Error::ParseJson { .. }), "{err:?}");
    assert_redacted(err, Some("at line 1 column"));
    let err = parse_typed("a.json", "{\"port\": \"hunter2\"}");
    assert_redacted(err, Some("expected u16"));

    let err = parse_typed(".env", "PORT=hunter2");
    assert!(matches!(err, Error::ParseJson { .. }), "{err:?}");
    assert_redacted(err, Some("expected u16"));
  }

  #[test]
  fn deserialize_final_reports_path_and_type_not_value() {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Server {
      port: u16,
    }
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Config {
      server: Server,
      pins: Vec<u8>,
    }
    let err = deserialize_final::<Config>(&serde_json::json!({
      "server": { "port": "hunter2secret" },
      "pins": [1, 2],
    }))
    .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("at 'server.port'"), "{message}");
    assert!(message.contains("found string"), "{message}");
    assert!(message.contains("expected u16"), "{message}");
    assert!(!message.contains("hunter2secret"), "{message}");

    let err = deserialize_final::<Config>(&serde_json::json!({
      "server": { "port": 1 },
      "pins": [1, 70000],
    }))
    .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("at 'pins[1]'"), "{message}");
    assert!(message.contains("found number"), "{message}");
    assert!(!message.contains("70000"), "{message}");
  }

  #[test]
  fn mismatch_errors_name_key_and_type_only() {
    let err = Error::ObjectFieldTypeMismatch {
      key: "field".into(),
      found: value_type(&serde_json::json!("secret")),
    };
    assert_eq!(
      err.to_string(),
      "Types on field field do not match | got string, expected object"
    );
    assert_eq!(value_type(&serde_json::json!(null)), "null");
    assert_eq!(value_type(&serde_json::json!([1])), "array");
  }
}
