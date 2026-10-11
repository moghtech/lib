//! # Mogh Env Parser
//!
//! Env file (`.env`) syntax, both directions, and the typed reading
//! of what such a file holds. One grammar and one set of coercion
//! rules, shared by `mogh_config` (its `.env` / `*.env` sources and
//! the `cicada://.env` source of its `cicada` feature) and
//! `cicada_loader` (`load_env_as`), so a secret environment reads
//! the same whichever way an application loads it. Cicada Core
//! renders its exports with [serialize_env_file], so an export
//! parses back unchanged.
//!
//! - [parse_env_file] / [serialize_env_file]: the grammar.
//!   `NAME=value` lines, `#` comments (those directly above an entry
//!   are its description), an `export ` prefix accepted, values
//!   unquoted, single quoted (literal) or double quoted with `\n` /
//!   `\r` / `\t` / `\"` / `\\` escapes. Nothing is substituted in a
//!   value: `${VAR}` and `$(cmd)` are kept as written, since env
//!   file values are secrets, not templates.
//! - [parse_env_file_object]: the entries as a configuration
//!   object. Names are lowercased to match struct fields
//!   (`DB_PASSWORD` fills `db_password`) and dots nest
//!   (`DATABASE.ADDRESS` fills `database.address`); a name with an
//!   empty segment (`.dockerconfigjson`) or more than 32 segments
//!   stays one flat key.
//! - [from_str] / [deserialize]: into a serde type, string values
//!   coerced into the field's type the way `envy` reads the process
//!   environment ([Lenient]): numbers and booleans trimmed, a
//!   boolean in any case, comma separated lists with entries trimmed
//!   and empty ones dropped, `Option`, unit enum variants.
//!
//! Every error names a line, a name or a field and what was
//! expected, never a value: env file values are secrets, and errors
//! end up in logs. [redact_serde_error] does the same for the
//! messages of any serde_json deserialization.
//!
//! ```
//! #[derive(serde::Deserialize, Debug, PartialEq)]
//! struct Database {
//!   address: String,
//!   port: u16,
//! }
//!
//! #[derive(serde::Deserialize, Debug, PartialEq)]
//! struct Config {
//!   debug: bool,
//!   hosts: Vec<String>,
//!   database: Database,
//! }
//!
//! let config: Config = mogh_env_parser::from_str(
//!   "DEBUG=True\n\
//!    HOSTS=a.example.com, b.example.com,\n\
//!    DATABASE.ADDRESS=db.example.com\n\
//!    DATABASE.PORT=\" 5432 \"\n",
//! )
//! .unwrap();
//! assert_eq!(
//!   config,
//!   Config {
//!     debug: true,
//!     hosts: vec!["a.example.com".into(), "b.example.com".into()],
//!     database: Database {
//!       address: "db.example.com".into(),
//!       port: 5432,
//!     },
//!   }
//! );
//! ```

use serde::de::DeserializeOwned;

mod env_file;
mod lenient;
mod redact;

pub use env_file::{
  EnvFileEntry, EnvFileError, EnvFileSerializeError, is_env_file,
  normalize_env_description, parse_env_file, parse_env_file_object,
  representable_env_name, serialize_env_file,
};
pub use lenient::Lenient;
pub use redact::{
  redact_prefixed_serde_message, redact_serde_error,
  redact_serde_message,
};

/// Compiles the README's examples, so they keep up with the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// A value the type can't take, see [deserialize]. Names the field
/// and what was expected, never the value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("at '{path}': {message}")]
pub struct DeserializeError {
  /// The path of the field, dot separated with `[i]` for a list
  /// entry (`database.port`, `hosts[1]`); `.` for the root.
  pub path: String,
  /// serde's message with values redacted
  /// ([redact_serde_error]): what was expected, eg. `invalid
  /// value: string [redacted], expected u16`.
  pub message: String,
}

/// What [from_str] can fail with. The inner error's message is part
/// of this one's, so it is not the `source()` too: an `anyhow` chain
/// (`{:#}`) reads it once.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
  /// The file doesn't parse, see [parse_env_file_object]: the
  /// message names the line and what was expected.
  #[error("Failed to parse env file | {0}")]
  Parse(EnvFileError),
  /// A value the type can't take.
  #[error("Failed to deserialize env file | {0}")]
  Deserialize(DeserializeError),
}

impl From<EnvFileError> for Error {
  fn from(e: EnvFileError) -> Self {
    Error::Parse(e)
  }
}

impl From<DeserializeError> for Error {
  fn from(e: DeserializeError) -> Self {
    Error::Deserialize(e)
  }
}

/// Deserializes `value` into `T` with string values coerced into
/// the fields' types ([Lenient]). A failure names the path of the
/// field and what was expected, never the value.
pub fn deserialize<T: DeserializeOwned>(
  value: serde_json::Value,
) -> Result<T, DeserializeError> {
  serde_path_to_error::deserialize(Lenient(value)).map_err(|e| {
    DeserializeError {
      path: e.path().to_string(),
      message: redact_serde_error(e.inner()),
    }
  })
}

/// Reads an env file into `T`: [parse_env_file_object], then
/// [deserialize]. `#[serde(default)]` covers what the file doesn't
/// hold; a file holding nothing (blank, comments only) is the type's
/// defaults.
pub fn from_str<T: DeserializeOwned>(
  content: &str,
) -> Result<T, Error> {
  let object = parse_env_file_object(content)?;
  Ok(deserialize(serde_json::Value::Object(object))?)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[derive(serde::Deserialize, Debug, PartialEq)]
  #[serde(rename_all = "lowercase")]
  enum Mode {
    Fast,
    Safe,
  }

  #[derive(serde::Deserialize, Debug, PartialEq, Default)]
  #[serde(default)]
  struct Database {
    address: String,
    port: u16,
  }

  #[derive(serde::Deserialize, Debug, PartialEq, Default)]
  #[serde(default)]
  struct Config {
    debug: bool,
    port: u16,
    hosts: Vec<String>,
    mode: Option<Mode>,
    database: Database,
    #[serde(rename = ".dockerconfigjson")]
    docker_config: String,
  }

  /// The rules `mogh_config` reads a `cicada://.env` source by, as
  /// `cicada_loader::load_env_as` gets them: names lowercased and
  /// nested on dots, values coerced leniently.
  #[test]
  fn reads_an_env_file_into_a_struct() {
    let config: Config = from_str(
      "# The switches\n\
       export DEBUG=TRUE\n\
       PORT=\" 8080 \"\n\
       HOSTS=a.example.com, b.example.com,,\n\
       Mode=fast\n\
       DATABASE.ADDRESS='db.example.com'\n\
       DATABASE.PORT=5432\n\
       .dockerconfigjson={\"auths\":{}}\n",
    )
    .unwrap();
    assert_eq!(
      config,
      Config {
        debug: true,
        port: 8080,
        hosts: vec!["a.example.com".into(), "b.example.com".into()],
        mode: Some(Mode::Fast),
        database: Database {
          address: "db.example.com".into(),
          port: 5432,
        },
        docker_config: "{\"auths\":{}}".into(),
      }
    );
    // Nothing: the defaults.
    assert_eq!(
      from_str::<Config>("# nothing yet\n\n").unwrap(),
      Config::default()
    );
    // A list can be emptied, an unknown name is ignored.
    let config: Config =
      from_str("HOSTS=\nUNKNOWN=whatever\n").unwrap();
    assert_eq!(config.hosts, Vec::<String>::new());
  }

  #[test]
  fn errors_name_the_field_and_never_the_value() {
    for (file, expected) in [
      (
        "PORT=hunter2",
        "Failed to deserialize env file | at 'port': invalid value: string [redacted], expected u16",
      ),
      (
        "DATABASE.PORT=hunter2",
        "Failed to deserialize env file | at 'database.port': invalid value: string [redacted], expected u16",
      ),
      (
        "DEBUG=hunter2",
        "Failed to deserialize env file | at 'debug': invalid value: string [redacted], expected a boolean",
      ),
      (
        "MODE=hunter2",
        "Failed to deserialize env file | at 'mode': unknown variant [redacted], expected `fast` or `safe`",
      ),
      // A string where an object is: the whole field.
      (
        "DATABASE=hunter2",
        "Failed to deserialize env file | at 'database': invalid type: string [redacted], expected struct Database",
      ),
      // The grammar's errors, with the line.
      (
        "PORT=1\nhunter2",
        "Failed to parse env file | line 2: expected `NAME=value`, a `#` comment, or a blank line",
      ),
      (
        "PORT=hunter2\nport=2",
        "Failed to parse env file | line 2: `port` conflicts with `PORT` (line 1): names are case insensitive",
      ),
    ] {
      let err = from_str::<Config>(file).unwrap_err();
      assert_eq!(err.to_string(), expected, "{file:?}");
      assert!(!format!("{err:?}").contains("hunter2"), "{err:?}");
    }
    // A list entry is named by its index.
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Pins {
      pins: Vec<u8>,
    }
    let err = from_str::<Pins>("PINS=1, hunter2, 3").unwrap_err();
    let Error::Deserialize(err) = err else {
      panic!("{err:?}");
    };
    assert_eq!(err.path, "pins[1]");
    assert!(
      err.message.starts_with("invalid value: string [redacted]"),
      "{}",
      err.message
    );
    // The root, for a type the object itself can't be.
    let err = deserialize::<u16>(serde_json::json!({})).unwrap_err();
    assert_eq!(err.path, ".");
    // The message carries the inner error, which is no source too:
    // a chain prints it once.
    let err = from_str::<Pins>("PINS=x").unwrap_err();
    assert!(std::error::Error::source(&err).is_none());
    assert_eq!(
      format!(
        "{:#}",
        anyhow::Error::from(err.clone()).context("ctx")
      ),
      format!("ctx: {err}")
    );
    // A missing field is named, as it is.
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct Needs {
      db_password: String,
    }
    assert_eq!(
      from_str::<Needs>("").unwrap_err().to_string(),
      "Failed to deserialize env file | at '.': missing field `db_password`"
    );
  }
}
