//! # Mogh Config
//!
//! This library is used to parse Core, Periphery, and CLI config files.
//! It supports interpolating environment variables (`${VAR}`) and
//! command output (`$(command)`, a single command word without
//! arguments) into the values of local toml / yaml / json files, as
//! well as merging together multiple files into a final
//! configuration object.
//!
//! Sources are toml, yaml, json, and env files (`.env`, `*.env`):
//! flat `NAME=value` entries whose names are lowercased to match
//! struct fields, the way `envy` reads the process environment,
//! with dots nesting (`DATABASE.ADDRESS` fills `database.address`;
//! a name with an empty segment, `.dockerconfigjson`, stays one flat
//! key), and whose values are taken verbatim (no interpolation: they are
//! secrets, not templates). The final deserialization coerces
//! string values into the field's type (numbers, booleans, comma
//! separated lists, `Option`, unit enum variants), see
//! [deserialize_final].
//!
//! The process environment is a source too, over the files:
//! [ConfigLoader::load_with_env] with an [EnvSource], whose table
//! names the variable of each field (`APP_DATABASE_ADDRESS` for
//! `database.address`), each also taking a file (`APP_X_FILE`).
//!
//! With the `cicada` feature, `cicada://filesystem/path.yaml?env=a+b`
//! loads a file from Cicada interpolated with the environments, and
//! `cicada://.env?env=a+b` the environments themselves as an env
//! file. That is blocking network I/O, to run outside an async
//! runtime (see [ConfigLoader::load]).
//!
//! The loader (`cicada_loader`) is not re-exported, so its API is no
//! part of this crate's: a loader minor (`0.x`) bump ships as a
//! minor release of this crate, a loader patch as a patch release.
//! An application using the loader's own API (its background,
//! `load_env_as`) depends on `cicada_loader` at the minor this crate
//! uses: two minors would be two loaders in one process, each
//! initializing a device from the same `CICADA_*` environment and
//! key file.

use std::path::{Path, PathBuf};

use colored::Colorize;
use indexmap::IndexMap;
use serde::de::DeserializeOwned;

mod env;
mod env_file;
mod error;
mod includes;
mod interpolate;
mod lenient;
mod load;
mod merge;

pub use env::{EnvSource, FILE_SUFFIX};
pub use env_file::{
  EnvFileEntry, EnvFileError, EnvFileSerializeError,
  normalize_env_description, parse_env_file, representable_env_name,
  serialize_env_file,
};
pub use error::{Error, deserialize_final};
pub use interpolate::interpolate_env_and_shell;
pub use merge::{merge_config, merge_objects};

pub type Result<T> = ::core::result::Result<T, Error>;

/// Compiles the README's examples, so they keep up with the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// The key deduping a file reached by several paths (as given,
/// through a directory scan, an include, a symlink): its canonical
/// path. A cicada source is its own key.
fn dedupe_key(path: &Path) -> PathBuf {
  if load::is_cicada_path(path) {
    return path.to_path_buf();
  }
  path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// Set the configuration for loading config files.
pub struct ConfigLoader<'outer, 'inner> {
  /// Paths to either files or directories
  /// to include in the final configuration.
  ///
  /// Path coming later in the array (higher index) will override
  /// configuration in earlier paths. A path which doesn't exist is
  /// skipped, one which exists must load: see [ConfigLoader::load].
  pub paths: &'outer [&'inner Path],
  /// Wilcard patterns to match file names in given directories.
  ///
  /// Patterns coming later in the array (higher index) will override
  /// configuration added by earlier patterns, however this is
  /// only relavant within an individual directory. Later `paths`
  /// and later includes will still have higher priority. A file
  /// matching several patterns takes the priority of the last one,
  /// so `["*config.*", "*config.local.*"]` applies
  /// `core.config.local.toml` over `core.config.toml`.
  ///
  /// A pattern which doesn't compile is an error
  /// ([Error::InvalidWildcard]). With no patterns, a directory scan
  /// loads every file in it except env files.
  pub match_wildcards: &'outer [&'inner str],
  /// The file name to search for `.include` file.
  ///
  /// Each line of the include file is a path (file or directory)
  /// to load after the directory's own files. Includes are applied
  /// in the order listed, recursively, and later includes override
  /// earlier ones. Every include overrides the directory's own
  /// files, so a directory can include shared defaults which are
  /// then refined by later includes. A `cicada:` line is a source
  /// like a `cicada:` path (an error without the `cicada` feature).
  /// A line naming a missing path is skipped like a missing path,
  /// and an include file which exists but can't be read is an
  /// error. An empty name reads no include file.
  pub include_file_name: &'static str,
  /// Whether to merge nested config objects.
  /// Otherwise, the object will be replaced at
  /// the top-level key by the highest priority config file
  /// in which it is specified.
  ///
  /// When merging, a `null` (a yaml section with every line
  /// commented out) keeps the object, and any other value replaces
  /// it (the final deserialization reports one the config type
  /// can't take): a source is never dropped over a type conflict.
  pub merge_nested: bool,
  /// Whether to extend array in configuration files.
  /// Otherwise, the array will be replaced at
  /// the top-level key by the highest priority config file
  /// in which it is specified.
  ///
  /// When extending, a `null` adds nothing, an env file's comma
  /// separated value (`HOSTS=b,c`) adds its entries, and any other
  /// value replaces the array.
  pub extend_array: bool,
  /// Print some extra information on configuation load.
  ///
  /// Note. This is different than application level log level.
  pub debug_print: bool,
}

impl ConfigLoader<'_, '_> {
  /// Loads the sources in [ConfigLoader::paths] and merges them
  /// into `T`, see [deserialize_final].
  ///
  /// A path which doesn't exist is skipped (deliberate: an app may
  /// list optional paths, eg. a mount which isn't always there).
  /// Every config file which exists must load, listed, found by a
  /// directory scan or named in an include file: one which can't be
  /// read ([Error::FileOpen], [Error::ReadFileContents]) or doesn't
  /// parse ([Error::ParseToml], [Error::ParseYaml],
  /// [Error::ParseJson], [Error::ParseEnvFile]) is an error naming
  /// it, never a value in it. So is a directory which can't be read
  /// ([Error::ReadDir], [Error::DirFile]) or a path whose metadata
  /// can't be ([Error::ReadPathMetaData], eg. permission denied on a
  /// parent directory). Skipping any of these would start the app
  /// without the settings in them.
  ///
  /// A file holding no settings (blank, comments only, a yaml or
  /// json `null` document) is an empty source, so a placeholder
  /// doesn't stop the app. A file a directory scan finds which is
  /// no config file type (a `config.toml.bak` matching
  /// `*config.*`) is skipped with a warning; listed, or named in an
  /// include file, it is an error ([Error::UnsupportedFileType]).
  ///
  /// # Blocking
  ///
  /// A `cicada:` source (the `cicada` feature) is blocking network
  /// I/O: reqwest's blocking client checks the device's key (or
  /// onboards / rotates it) and fetches the file, each request
  /// waiting up to the connect and request timeouts. With such a
  /// source, call `load` outside an async runtime: before building
  /// the runtime (a plain `fn main` loading the config, then
  /// starting tokio), or inside `tokio::task::spawn_blocking`. On a
  /// runtime thread it panics in builds with debug assertions
  /// (reqwest's blocking client drops a runtime there), and blocks
  /// the worker thread in release builds. Local files are blocking
  /// file I/O too, which is short.
  pub fn load<T: DeserializeOwned>(self) -> Result<T> {
    let config = self.load_sources()?;
    error::deserialize_final(&serde_json::Value::Object(config))
  }

  /// [Self::load], with the process environment as the last source:
  /// the variables of `env`'s table override the config files, see
  /// [EnvSource] for the rules. Its errors name the variable (and the
  /// file of a `_FILE` variable), never a value: a value the field
  /// can't take is [Error::ParseEnv].
  ///
  /// With no [Self::paths], the config is the type's defaults
  /// (`#[serde(default)]`) with the environment's values.
  pub fn load_with_env<T: DeserializeOwned>(
    self,
    env: &EnvSource,
  ) -> Result<T> {
    // The environment first: its mistakes (a file which can't be
    // read) stop the load before any file does.
    let env = env.read(self.debug_print)?;
    let mut config = self.load_sources()?;
    env.apply(&mut config);
    error::deserialize_final_with_env(
      &serde_json::Value::Object(config),
      Some(&env),
    )
  }

  /// The sources in [ConfigLoader::paths] merged, see [Self::load].
  fn load_sources(
    self,
  ) -> Result<serde_json::Map<String, serde_json::Value>> {
    let ConfigLoader {
      paths,
      match_wildcards,
      include_file_name,
      merge_nested,
      extend_array,
      debug_print,
    } = self;

    if debug_print {
      println!(
        "{}: {}: {paths:?}",
        "DEBUG".cyan(),
        "Config paths".dimmed()
      );
    }

    // A pattern which doesn't compile is an error: dropping it
    // would widen the filter (to every file, with none left).
    let wildcards = match_wildcards
      .iter()
      .map(|&wc| {
        wildcard::Wildcard::new(wc.as_bytes()).map_err(|e| {
          Error::InvalidWildcard {
            pattern: wc.to_string(),
            message: e.to_string(),
          }
        })
      })
      .collect::<Result<Vec<_>>>()?;

    if debug_print {
      println!(
        "{}: {}: {match_wildcards:?}",
        "DEBUG".cyan(),
        "Config wildcards".dimmed()
      );
    }

    // The files to load in priority order, by the canonical path
    // (so one file reached as given and through a directory scan is
    // loaded once), each loaded from the path it was found at,
    // which names its type (`app.env` may link to a file without
    // the extension).
    let mut all_files = IndexMap::<PathBuf, load::FoundFile>::new();
    // If the same file comes up again later on, it should be
    // removed and reinserted so it maintains higher priority,
    // keeping a name its type is known by: a scan finding the
    // target of a listed `app.env` link as `secret` must not
    // replace the name the file can be parsed by. A file named
    // anywhere (a path, an include line) stays named, so a scan
    // finding it again doesn't soften its errors.
    let mut push = |key: PathBuf, file: load::FoundFile| {
      let file = match all_files.shift_remove(&key) {
        Some(prev) => load::FoundFile {
          path: if !load::has_config_type(&file.path)
            && load::has_config_type(&prev.path)
          {
            prev.path
          } else {
            file.path
          },
          named: prev.named || file.named,
        },
        None => file,
      };
      all_files.insert(key, file);
    };

    for &path in paths {
      let mut files = Vec::new();
      // Guards against include cycles (A includes B includes A,
      // or a directory including itself).
      let mut visiting = std::collections::HashSet::new();
      // Files come back in priority order (later overrides earlier).
      load::load_config_files(
        &mut files,
        &mut visiting,
        path,
        &wildcards,
        include_file_name,
        debug_print,
      )?;
      for file in files {
        push(dedupe_key(&file.path), file);
      }
    }
    let all_files = all_files.into_values().collect::<Vec<_>>();
    if debug_print {
      println!(
        "{}: {}: {:?}",
        "DEBUG".cyan(),
        "Found Files".dimmed(),
        all_files.iter().map(|file| &file.path).collect::<Vec<_>>()
      );
    }
    load::load_parse_config_files(
      &all_files,
      merge_nested,
      extend_array,
    )
  }
}
