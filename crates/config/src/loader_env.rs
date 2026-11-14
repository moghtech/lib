//! The settings of the config loading itself, read from the
//! environment before the config files, see [LoaderEnv].

use std::{ffi::OsString, path::PathBuf};

use crate::{ConfigLoader, EnvSource, Result};

/// The variables an app reads the settings of its config loading
/// from, before its config files (the settings say which files):
/// one table for every app, named with the app's prefix `<P>` (eg.
/// `KOMODO_`, with its underscore).
///
/// | Variable | Setting | Default |
/// | --- | --- | --- |
/// | `<P>CONFIG_PATHS`, or `<P>CONFIG_PATH` | [LoaderSettings::config_paths], a comma separated list | none, see [Self::default_paths] |
/// | `<P>CONFIG_KEYWORDS`, or `<P>CONFIG_KEYWORD` | [LoaderSettings::config_keywords], wildcard patterns, a comma separated list | `*config.*`, see [Self::default_keywords] |
/// | `<P>MERGE_NESTED_CONFIG` | [LoaderSettings::merge_nested_config] | `true` |
/// | `<P>EXTEND_CONFIG_ARRAYS` | [LoaderSettings::extend_config_arrays] | `true` |
/// | `<P>CONFIG_DEBUG` | [LoaderSettings::config_debug] | `false`, see [LoaderDebug] |
///
/// Each variable follows the rules of [EnvSource]: names in any
/// case, `<NAME>_FILE` holding the value in a file, a blank value
/// counting as unset (the default stays), the singular name read
/// when the plural one is unset (with a warning naming both when
/// both are set), a value the setting can't take an error naming
/// the variable, never the value ([crate::Error::ParseEnv]). Other
/// variables are ignored.
///
/// ```
/// let settings = mogh_config::LoaderEnv::new("APP_")
///   // The image's config directory, unless APP_CONFIG_PATHS says.
///   .default_paths(["/config"])
///   // APP_CONFIG_PATHS= (blank) loads no config file.
///   .allow_empty_paths()
///   .read_vars([("APP_CONFIG_KEYWORDS", "*config.*, *.env")])?;
/// assert_eq!(settings.config_paths, [std::path::Path::new("/config")]);
/// assert_eq!(settings.config_keywords, ["*config.*", "*.env"]);
/// assert!(settings.merge_nested_config && settings.extend_config_arrays);
/// # Ok::<(), mogh_config::Error>(())
/// ```
///
/// The app builds its [ConfigLoader] from the settings, with its own
/// include file name. [Self::names] and [Self::alias_names] list the
/// variables (eg. for a test that the documented variables are
/// read).
#[derive(Debug, Clone)]
pub struct LoaderEnv {
  prefix: String,
  default_paths: Vec<PathBuf>,
  allow_empty_paths: bool,
  default_keywords: Vec<String>,
  default_merge_nested: bool,
  default_extend_arrays: bool,
  debug: LoaderDebug,
}

/// Which variable says that the config loading prints what it loads
/// ([ConfigLoader::debug_print]), see [LoaderEnv::debug].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LoaderDebug {
  /// `<P>CONFIG_DEBUG`, `true` or `false` in any case. The default.
  #[default]
  ConfigDebug,
  /// `<P>LOGGING_LEVEL`, the app's own log level variable (the
  /// `logging.level` of mogh_logger's config), read before the
  /// config files too: the loading prints at `debug` and `trace`.
  /// One of `trace`, `debug`, `info`, `warn` and `error`, as
  /// mogh_logger's `LogLevel` reads it, else an error naming the
  /// variable.
  LoggingLevel,
  /// No variable: [LoaderSettings::config_debug] is `false`, and the
  /// app sets [ConfigLoader::debug_print] itself (eg. from a command
  /// line argument).
  NoVariable,
}

/// The settings [LoaderEnv] reads, named after their variables.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LoaderSettings {
  /// `<P>CONFIG_PATHS`: the config files or directories, merged in
  /// order (later ones override earlier ones), the
  /// [ConfigLoader::paths].
  pub config_paths: Vec<PathBuf>,
  /// `<P>CONFIG_KEYWORDS`: the files of the config directories which
  /// load, those whose name matches one of these wildcard patterns,
  /// the [ConfigLoader::match_wildcards].
  pub config_keywords: Vec<String>,
  /// `<P>MERGE_NESTED_CONFIG`: [ConfigLoader::merge_nested].
  pub merge_nested_config: bool,
  /// `<P>EXTEND_CONFIG_ARRAYS`: [ConfigLoader::extend_array].
  pub extend_config_arrays: bool,
  /// Whether the config loading prints what it loads
  /// ([ConfigLoader::debug_print]), see [LoaderDebug].
  pub config_debug: bool,
}

impl LoaderEnv {
  /// The table of the variables starting with `prefix` (eg.
  /// `APP_`, with its underscore), with the defaults: no config
  /// paths (a blank `<P>CONFIG_PATHS` is unset), the keywords
  /// `*config.*`, nested objects merged and arrays extended,
  /// `<P>CONFIG_DEBUG` ([LoaderDebug::ConfigDebug]).
  pub fn new(prefix: impl Into<String>) -> LoaderEnv {
    LoaderEnv {
      prefix: prefix.into(),
      default_paths: Vec::new(),
      allow_empty_paths: false,
      default_keywords: vec![String::from("*config.*")],
      default_merge_nested: true,
      default_extend_arrays: true,
      debug: LoaderDebug::ConfigDebug,
    }
  }

  /// The config paths while `<P>CONFIG_PATHS` is unset (eg. the
  /// image's `/config`). Default: none.
  pub fn default_paths(
    mut self,
    paths: impl IntoIterator<Item = impl Into<PathBuf>>,
  ) -> LoaderEnv {
    self.default_paths = paths.into_iter().map(Into::into).collect();
    self
  }

  /// A blank `<P>CONFIG_PATHS` (or a `_FILE` holding nothing) sets no
  /// config path, so no config file loads, rather than counting as
  /// unset (the [default paths][Self::default_paths]). See
  /// [EnvSource::allow_empty].
  pub fn allow_empty_paths(mut self) -> LoaderEnv {
    self.allow_empty_paths = true;
    self
  }

  /// The keywords while `<P>CONFIG_KEYWORDS` is unset. Default:
  /// `*config.*`.
  pub fn default_keywords(
    mut self,
    keywords: impl IntoIterator<Item = impl Into<String>>,
  ) -> LoaderEnv {
    self.default_keywords =
      keywords.into_iter().map(Into::into).collect();
    self
  }

  /// Whether nested objects merge while `<P>MERGE_NESTED_CONFIG` is
  /// unset. Default: `true`.
  pub fn default_merge_nested(mut self, merge: bool) -> LoaderEnv {
    self.default_merge_nested = merge;
    self
  }

  /// Whether arrays extend while `<P>EXTEND_CONFIG_ARRAYS` is unset.
  /// Default: `true`.
  pub fn default_extend_arrays(mut self, extend: bool) -> LoaderEnv {
    self.default_extend_arrays = extend;
    self
  }

  /// Which variable sets [LoaderSettings::config_debug]. Default:
  /// [LoaderDebug::ConfigDebug].
  pub fn debug(mut self, debug: LoaderDebug) -> LoaderEnv {
    self.debug = debug;
    self
  }

  /// The table of the variables, as an [EnvSource] (aliases
  /// included), eg. to list its [names][EnvSource::names].
  pub fn env_source(&self) -> EnvSource {
    let mut fields = vec![
      "config_paths",
      "config_keywords",
      "merge_nested_config",
      "extend_config_arrays",
    ];
    match self.debug {
      LoaderDebug::ConfigDebug => fields.push("config_debug"),
      LoaderDebug::LoggingLevel => fields.push("logging.level"),
      LoaderDebug::NoVariable => {}
    }
    let paths = self.name("CONFIG_PATHS");
    let env = EnvSource::new(self.prefix.clone())
      .fields(fields)
      .alias(self.name("CONFIG_PATH"), paths.clone())
      .alias(
        self.name("CONFIG_KEYWORD"),
        self.name("CONFIG_KEYWORDS"),
      );
    if self.allow_empty_paths {
      env.allow_empty([paths.as_str()])
    } else {
      env
    }
  }

  /// The names of the variables, uppercase, in the order of the
  /// table above (the singular names and the `_FILE` variants left
  /// out, see [Self::alias_names]).
  pub fn names(&self) -> Result<Vec<String>> {
    self.env_source().names()
  }

  /// The other names the variables are read under:
  /// `<P>CONFIG_PATH` and `<P>CONFIG_KEYWORD`, uppercase.
  pub fn alias_names(&self) -> Vec<String> {
    vec![self.name("CONFIG_PATH"), self.name("CONFIG_KEYWORD")]
  }

  /// The settings from the process environment.
  pub fn read(&self) -> Result<LoaderSettings> {
    self.read_from(&self.env_source())
  }

  /// The settings from `vars` (names and values, the whole
  /// environment) instead of the process environment: an app reading
  /// its environment once, for the loader and then for the config,
  /// or a test.
  pub fn read_vars<K, V>(
    &self,
    vars: impl IntoIterator<Item = (K, V)>,
  ) -> Result<LoaderSettings>
  where
    K: Into<OsString>,
    V: Into<OsString>,
  {
    self.read_from(&self.env_source().with_vars(vars))
  }

  fn read_from(&self, env: &EnvSource) -> Result<LoaderSettings> {
    // No source but the environment: its values over the defaults.
    let read = ConfigLoader {
      paths: &[],
      match_wildcards: &[],
      include_file_name: "",
      merge_nested: true,
      extend_array: false,
      debug_print: false,
    }
    .load_with_env::<ReadSettings>(env)?;
    let config_debug = match self.debug {
      LoaderDebug::ConfigDebug => read.config_debug.unwrap_or(false),
      LoaderDebug::LoggingLevel => matches!(
        read.logging.and_then(|logging| logging.level),
        Some(Level::Debug | Level::Trace)
      ),
      LoaderDebug::NoVariable => false,
    };
    Ok(LoaderSettings {
      config_paths: read
        .config_paths
        .unwrap_or_else(|| self.default_paths.clone()),
      config_keywords: read
        .config_keywords
        .unwrap_or_else(|| self.default_keywords.clone()),
      merge_nested_config: read
        .merge_nested_config
        .unwrap_or(self.default_merge_nested),
      extend_config_arrays: read
        .extend_config_arrays
        .unwrap_or(self.default_extend_arrays),
      config_debug,
    })
  }

  /// `<P>` and `name`, uppercase.
  fn name(&self, name: &str) -> String {
    format!("{}{name}", self.prefix).to_ascii_uppercase()
  }
}

/// The values the environment sets, see [LoaderEnv::read_from]: a
/// setting it doesn't set is `None`, and takes its default.
#[derive(serde::Deserialize)]
struct ReadSettings {
  config_paths: Option<Vec<PathBuf>>,
  config_keywords: Option<Vec<String>>,
  merge_nested_config: Option<bool>,
  extend_config_arrays: Option<bool>,
  config_debug: Option<bool>,
  logging: Option<ReadLogging>,
}

/// [LoaderDebug::LoggingLevel].
#[derive(serde::Deserialize)]
struct ReadLogging {
  level: Option<Level>,
}

/// The levels of mogh_logger's `LogLevel`, read as it reads them, in
/// its order (an error lists them).
#[derive(serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum Level {
  Trace,
  Debug,
  Info,
  Warn,
  Error,
}
