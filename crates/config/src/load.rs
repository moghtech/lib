use std::{
  collections::HashSet,
  fs::File,
  io::Read,
  path::{Path, PathBuf},
};

use colored::Colorize;
use serde::de::DeserializeOwned;

use crate::{
  Error, Result,
  env_file::{is_env_file, parse_env_file_object},
  error::{redact_serde_error, redact_toml_error, redact_yaml_error},
  includes::read_includes,
  interpolate::{interpolate_value, unsupported_interpolations},
  merge::merge_source,
};

/// Whether a config path is a cicada source (`cicada://...`,
/// `cicada:/...` or `cicada:...`), with or without the feature.
///
/// Note. Must compare against the path as a string,
/// Path::starts_with compares whole components and misses
/// the `cicada:some/path` (no slash) form.
pub(crate) fn is_cicada_path(path: &Path) -> bool {
  path.to_string_lossy().starts_with("cicada:")
}

/// A config file found by [load_config_files].
pub(crate) struct FoundFile {
  /// As listed, as an include line names it, or as a directory scan
  /// found it (under the canonical directory). Not canonicalized: a
  /// symlink keeps the name its type is detected from.
  pub(crate) path: PathBuf,
  /// Named as a path or by an include line, rather than found by a
  /// directory scan. A named file is loaded or an error, whatever
  /// its name. A scan skips a file it finds which is no config file
  /// type (a `config.toml.bak` matching `*config.*`), as nobody
  /// asked for that file in particular.
  pub(crate) named: bool,
}

/// Whether an io error means the path doesn't exist (also through a
/// file: `app.toml/x`, or a dangling symlink).
pub(crate) fn is_missing(e: &std::io::Error) -> bool {
  matches!(
    e.kind(),
    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
  )
}

/// The metadata of a path, following symlinks, or `None` when it
/// doesn't exist. A missing path is skipped (deliberate: an app may
/// list optional paths, eg. a mount which isn't always there). Any
/// other failure (permission denied on a parent directory) is an
/// error ([Error::ReadPathMetaData]): the path may well hold
/// configuration, and skipping it would start the app without it.
fn metadata_if_exists(
  path: &Path,
  debug_print: bool,
) -> Result<Option<std::fs::Metadata>> {
  match std::fs::metadata(path) {
    Ok(metadata) => Ok(Some(metadata)),
    Err(e) if is_missing(&e) => {
      if debug_print {
        println!(
          "{}: {}: {path:?} | {e:?}",
          "DEBUG".cyan(),
          "Skipping missing path".dimmed()
        );
      }
      Ok(None)
    }
    Err(e) => Err(Error::ReadPathMetaData {
      path: path.to_path_buf(),
      e,
    }),
  }
}

/// Collects the config files at `path` (a listed path, or an
/// include line) into `files` in priority order (later overrides
/// earlier):
///
/// - A `cicada:` path is a source of its own, an error
///   ([Error::CicadaFeatureDisabled]) without the feature.
/// - A missing path is skipped, see [metadata_if_exists], and so is
///   one which is no file or directory (`/dev/null`).
/// - A file is a file to load.
/// - A directory contributes, in this order:
///   1. Its own matching files, ordered by the matched wildcard
///      (later wildcards override earlier; a file matching several
///      takes the priority of the last one), then by name.
///   2. Each path listed in its include file, in the order listed,
///      recursively. Later includes override earlier ones, and
///      every include overrides the directory's own files.
///
/// A directory which exists but can't be read ([Error::ReadDir],
/// [Error::DirFile]), or a matching entry whose metadata can't be
/// read ([Error::ReadPathMetaData]), is an error rather than a
/// directory without config files.
///
/// A path included more than once (eg two includes sharing a
/// common include) is emitted each time, so its last occurrence
/// takes the highest priority. Only true recursion (a directory
/// including itself, directly or indirectly) is cut.
///
/// Files are emitted at the path they were found at (listed, by the
/// scan, or as an include line names them), not canonicalized, so a
/// symlink is loaded by its own name (which names its type).
/// [crate::ConfigLoader] dedupes them by their canonical path.
pub(crate) fn load_config_files(
  files: &mut Vec<FoundFile>,
  // canonical directories on the current include stack
  visiting: &mut HashSet<PathBuf>,
  path: &Path,
  keywords: &[wildcard::Wildcard],
  include_file_name: &'static str,
  debug_print: bool,
) -> Result<()> {
  // Cicada base case.
  if is_cicada_path(path) {
    #[cfg(not(feature = "cicada"))]
    return Err(Error::CicadaFeatureDisabled {
      path: path.to_path_buf(),
    });
    #[cfg(feature = "cicada")]
    {
      files.push(FoundFile {
        path: path.to_path_buf(),
        named: true,
      });
      return Ok(());
    }
  }

  let Some(metadata) = metadata_if_exists(path, debug_print)? else {
    return Ok(());
  };

  // File base case.
  if metadata.is_file() {
    files.push(FoundFile {
      path: path.to_path_buf(),
      named: true,
    });
    return Ok(());
  }

  // Neither a file nor a directory, eg. `/dev/null` listed to load
  // nothing: no config to load.
  if !metadata.is_dir() {
    if debug_print {
      println!(
        "{}: {}: {path:?}",
        "DEBUG".cyan(),
        "Skipping path which is no file or directory".dimmed()
      );
    }
    return Ok(());
  }

  let folder =
    path.canonicalize().map_err(|e| Error::ReadPathMetaData {
      path: path.to_path_buf(),
      e,
    })?;
  if !visiting.insert(folder.clone()) {
    if debug_print {
      println!(
        "{}: {}: {folder:?}",
        "DEBUG".cyan(),
        "Skipping include cycle".dimmed()
      );
    }
    return Ok(());
  }
  let read_dir =
    std::fs::read_dir(&folder).map_err(|e| Error::ReadDir {
      path: folder.clone(),
      e,
    })?;

  // Collect any config files in the current dir,
  // with the index of the matched wildcard.
  let mut dir_files = Vec::new();
  for dir_entry in read_dir {
    let dir_entry = dir_entry.map_err(|e| Error::DirFile {
      path: folder.clone(),
      e,
    })?;
    let path = dir_entry.path();
    let file_name = dir_entry.file_name();
    // The include file is never a config file.
    if file_name == include_file_name {
      continue;
    }
    // An env file next to the config (a compose `.env`) is only
    // a config source when a wildcard asks for it, or when it is
    // listed as a path itself.
    if keywords.is_empty() && is_env_file(&path) {
      if debug_print {
        println!(
          "{}: {}: {path:?} (match it with a wildcard to load it)",
          "DEBUG".cyan(),
          "Skipping env file".dimmed()
        );
      }
      continue;
    }
    // Ensure file name matches a wildcard keyword. A file
    // matching several takes the last (highest priority) one, so
    // `["*config.*", "*config.local.*"]` puts the local override
    // above the base file. Matched as bytes, so a name which isn't
    // utf-8 is matched (and loaded) like any other.
    let index = if keywords.is_empty() {
      0
    } else if let Some(index) = keywords
      .iter()
      .rposition(|wc| wc.is_match(file_name.as_encoded_bytes()))
    {
      index
    } else {
      continue;
    };
    // Follows symlinks (eg Kubernetes ConfigMap mounts), unlike
    // DirEntry::metadata. A dangling symlink is a missing file.
    let Some(metadata) = metadata_if_exists(&path, debug_print)?
    else {
      continue;
    };
    // Subdirectories are only loaded through an include file.
    if !metadata.is_file() {
      continue;
    }
    // As found (absolute, under the canonical folder), not the
    // canonical path: a symlink (`app.env` -> `secret`) keeps the
    // name its type is detected from.
    dir_files.push((index, path));
  }
  // Wildcard priority only applies within this directory.
  dir_files.sort();
  files.extend(
    dir_files
      .into_iter()
      .map(|(_, path)| FoundFile { path, named: false }),
  );

  // Collect any paths specified in 'includes'
  let includes = read_includes(&folder, include_file_name)?;
  if includes.is_empty() {
    visiting.remove(&folder);
    return Ok(());
  }

  if debug_print {
    println!(
      "{}: {}: {includes:?}",
      "DEBUG".cyan(),
      format_args!(
        "{} {path:?} {}",
        "Config Path".dimmed(),
        "Includes".dimmed()
      ),
    );
  }

  // Add these paths as well recursively.
  for path in includes {
    load_config_files(
      files,
      visiting,
      &path,
      keywords,
      include_file_name,
      debug_print,
    )?;
  }
  visiting.remove(&folder);
  Ok(())
}

/// Splits a cicada path (`cicada://...`, `cicada:/...` or `cicada:...`)
/// into the node path and the list of environments.
/// Returns `None` if the path is not a cicada path.
///
/// Environments are given as a query suffix, using `+` as the
/// list separator (comma is reserved for splitting multiple paths):
///
/// - `cicada://filesystem/config.yaml` -> no environments
/// - `cicada://filesystem/config.yaml?env=prod` -> `["prod"]`
/// - `cicada://filesystem/config.yaml?env=prod+us-east` -> `["prod", "us-east"]`
/// - `cicada://filesystem/config.yaml?env=prod&env=us-east` -> `["prod", "us-east"]`
/// - `cicada://.env?env=prod+us-east` -> the environments themselves,
///   as an env file (the loader's reserved `.env` path)
#[cfg(feature = "cicada")]
pub fn parse_cicada_path(
  path: &Path,
) -> Option<(PathBuf, Vec<String>)> {
  let path_str = path.to_string_lossy();
  let path =
    path_str.strip_prefix("cicada:")?.trim_start_matches('/');
  let Some((path, query)) = path.split_once('?') else {
    return Some((PathBuf::from(path), Vec::new()));
  };
  let environments = query
    .split('&')
    .filter_map(|pair| {
      let (key, value) = pair.split_once('=')?;
      matches!(
        key.trim(),
        "env" | "envs" | "environment" | "environments"
      )
      .then_some(value)
    })
    .flat_map(|value| value.split('+'))
    .map(str::trim)
    .filter(|env| !env.is_empty())
    .map(String::from)
    .collect();
  Some((PathBuf::from(path), environments))
}

/// loads multiple config files.
///
/// If cicada feature is enabled, the files
/// can be cicada paths (`cicada://filesystem/config.yaml?env=prod+us-east`),
/// provided user configures `CICADA_...` env vars.
/// See [parse_cicada_path] for the environment syntax.
///
/// A file which fails to open, read or parse is an error
/// ([Error::FileOpen], [Error::ReadFileContents], [Error::ParseToml]
/// and the other parse errors), named or found by a directory scan:
/// skipping it would start the app without the settings in it (a
/// `disable_user_registration`, the `trusted_proxies`). So is a
/// cicada source which fails to load ([Error::CicadaLoad]), eg.
/// Core briefly unreachable at an exit-on-change restart. A file
/// holding no settings (blank, comments only) is an empty source,
/// see [parse_config_contents]. The one file skipped (with a
/// warning) is one a directory scan finds which is no config file
/// type, such as a `config.toml.bak` matching `*config.*`; named
/// as a path or by an include line, it is an error
/// ([Error::UnsupportedFileType]).
///
/// A source which parsed is never skipped: it merges over the
/// sources before it key by key (see [crate::ConfigLoader]), and a
/// value of a type the config can't take fails the final
/// deserialization ([Error::ParseFinalJson]) instead.
///
/// Each local toml / yaml / json source is interpolated (`${VAR}`,
/// `$(cmd)`) as it is parsed. Env file sources and every cicada
/// source are not: their values are secrets taken verbatim, never
/// templates (Core interpolated a cicada file's `[[SECRET]]`
/// placeholders already), and a secret must not be able to run a
/// command in the process reading it.
///
/// Returns the merged sources, for the final deserialization
/// ([crate::deserialize_final]), after the environment's values
/// when there is an [crate::EnvSource].
pub(crate) fn load_parse_config_files(
  files: &[FoundFile],
  merge_nested: bool,
  extend_array: bool,
) -> Result<serde_json::Map<String, serde_json::Value>> {
  let mut target = serde_json::Map::new();

  for FoundFile { path: file, named } in files {
    // The source, whether to interpolate it, and whether it is an
    // env file (whose comma separated lists extend arrays).
    #[cfg(feature = "cicada")]
    if let Some((node, environments)) = parse_cicada_path(file) {
      let contents = cicada_loader::load(&node, environments)
        .map_err(|e| Error::CicadaLoad {
          path: file.clone(),
          message: format!("{e:#}"),
        })?;
      let source = parse_config_contents(&node, &contents)?;
      merge_source(
        &mut target,
        source,
        merge_nested,
        extend_array,
        is_env_file(&node),
      );
      continue;
    }

    if !has_config_type(file) {
      if *named {
        return Err(Error::UnsupportedFileType {
          path: file.clone(),
        });
      }
      println!(
        "{}: {file:?} is not loaded: it is no config file type (toml, yaml, yml, json, or an env file). Narrow the config wildcards to leave it out.",
        "WARN".yellow(),
      );
      continue;
    }
    let env_file = is_env_file(file);
    let source: serde_json::Map<String, serde_json::Value> =
      load_parse_config_file(file)?;

    // Interpolate each string leaf (and key) individually, rather
    // than the serialized document, so values containing quotes,
    // backslashes or newlines cannot break or inject into the json.
    let source = if env_file {
      source
    } else {
      let mut source = serde_json::Value::Object(source);
      // Named by path, never by value.
      for path in unsupported_interpolations(&source) {
        println!(
          "{}: {file:?} | '{path}' has a '$(...)' or '${{...}}' which is kept as written: only '${{VAR}}' and '$(command)' with a single command word (letters, digits, '_') are interpolated",
          "WARN".yellow(),
        );
      }
      interpolate_value(&mut source);
      match source {
        serde_json::Value::Object(source) => source,
        _ => unreachable!("interpolation keeps the value an object"),
      }
    };

    merge_source(
      &mut target,
      source,
      merge_nested,
      extend_array,
      env_file,
    );
  }

  Ok(target)
}

/// Reads a file to a string: a failure to open it is
/// [Error::FileOpen], to read it (a directory, not utf-8)
/// [Error::ReadFileContents]. Neither carries the contents.
pub(crate) fn read_file(path: &Path) -> Result<String> {
  let mut file = File::open(path).map_err(|e| Error::FileOpen {
    e,
    path: path.to_path_buf(),
  })?;
  let mut contents = String::new();
  file.read_to_string(&mut contents).map_err(|e| {
    Error::ReadFileContents {
      e,
      path: path.to_path_buf(),
    }
  })?;
  Ok(contents)
}

/// Loads and parses a single config file
pub(crate) fn load_parse_config_file<T: DeserializeOwned>(
  file: &Path,
) -> Result<T> {
  parse_config_contents(file, &read_file(file)?)
}

/// Whether [parse_config_contents] can parse the file by its name:
/// an env file, or a toml / yaml / yml / json extension.
pub(crate) fn has_config_type(file: &Path) -> bool {
  is_env_file(file)
    || file.extension().and_then(|e| e.to_str()).is_some_and(|e| {
      matches!(
        e.to_ascii_lowercase().as_str(),
        "toml" | "yaml" | "yml" | "json"
      )
    })
}

/// Parses config contents by the file's name: toml, yaml / yml,
/// json, or an env file (`.env`, `*.env`, see
/// [parse_env_file_object]): a flat set of `NAME=value` entries
/// with names lowercased and dots nesting, so `DB_PASSWORD=x` fills
/// a `db_password` field and `DATABASE.ADDRESS=y` fills
/// `database.address`, the way `envy` would read the process
/// environment. A name with an empty segment (`.dockerconfigjson`)
/// stays one flat key.
///
/// Contents holding no settings are an empty config (`{}`), so a
/// placeholder doesn't stop the app: blank or comments only in any
/// format, and a yaml or json `null` document (`~`, a yaml file
/// whose every line is commented out). Anything else must parse
/// into an object.
pub(crate) fn parse_config_contents<T: DeserializeOwned>(
  file: &Path,
  contents: &str,
) -> Result<T> {
  if is_env_file(file) {
    let object = parse_env_file_object(contents).map_err(|e| {
      Error::ParseEnvFile {
        e,
        path: file.to_path_buf(),
      }
    })?;
    return serde_json::from_value(serde_json::Value::Object(object))
      .map_err(|e| Error::ParseJson {
        path: file.to_path_buf(),
        message: redact_serde_error(&e),
      });
  }
  let extension = file
    .extension()
    .and_then(|e| e.to_str())
    .map(str::to_ascii_lowercase);
  // `None` for a document holding no settings.
  let config: Option<T> = match extension.as_deref() {
    // Blank or comments only is an empty table already.
    Some("toml") => Some(toml::from_str(contents).map_err(|e| {
      Error::ParseToml {
        path: file.to_path_buf(),
        message: redact_toml_error(&e, contents),
      }
    })?),
    // Blank or comments only is an empty document already, `null`
    // (`~`, `--- ~`) is `None`.
    Some("yaml") | Some("yml") => serde_yaml_ng::from_str(contents)
      .map_err(|e| Error::ParseYaml {
      path: file.to_path_buf(),
      message: redact_yaml_error(&e),
    })?,
    // json has no comments: blank is no document at all.
    Some("json") if contents.trim().is_empty() => None,
    Some("json") => serde_json::from_str(contents).map_err(|e| {
      Error::ParseJson {
        path: file.to_path_buf(),
        message: redact_serde_error(&e),
      }
    })?,
    Some(_) | None => {
      return Err(Error::UnsupportedFileType {
        path: file.to_path_buf(),
      });
    }
  };
  match config {
    Some(config) => Ok(config),
    None => serde_json::from_value(serde_json::Value::Object(
      Default::default(),
    ))
    .map_err(|e| Error::ParseJson {
      path: file.to_path_buf(),
      message: redact_serde_error(&e),
    }),
  }
}

#[cfg(all(test, feature = "cicada"))]
mod tests {
  use super::*;

  #[test]
  fn parses_cicada_paths() {
    for prefix in ["cicada:", "cicada:/", "cicada://"] {
      let full = PathBuf::from(format!(
        "{prefix}filesystem/path/config.yaml?env=prod+us-east"
      ));
      let (path, envs) = parse_cicada_path(&full).unwrap();
      assert_eq!(path, PathBuf::from("filesystem/path/config.yaml"));
      assert_eq!(envs, vec!["prod", "us-east"]);
    }
    let (path, envs) = parse_cicada_path(Path::new(
      "cicada://fs/config.yaml?env=a&env=b",
    ))
    .unwrap();
    assert_eq!(path, PathBuf::from("fs/config.yaml"));
    assert_eq!(envs, vec!["a", "b"]);
    let (path, envs) =
      parse_cicada_path(Path::new("cicada://fs/config.yaml"))
        .unwrap();
    assert_eq!(path, PathBuf::from("fs/config.yaml"));
    assert!(envs.is_empty());
    assert!(
      parse_cicada_path(Path::new("/etc/config.yaml")).is_none()
    );
  }
}
