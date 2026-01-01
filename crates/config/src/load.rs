use std::{
  fs::File,
  io::Read,
  path::{Path, PathBuf},
};

use colored::Colorize;
use serde::de::DeserializeOwned;

use crate::{
  Error, Result, includes::IncludesLoader, interpolate_env_and_shell,
  merge::merge_objects,
};

pub fn load_config_files(
  // stores index of matching keyword as well as path
  files: &mut Vec<(usize, PathBuf)>,
  path: &Path,
  keywords: &[wildcard::Wildcard],
  include_file_name: &'static str,
  debug_print: bool,
) {
  // File base case.
  if path.is_file() {
    files.push((0, path.to_path_buf()));
    return;
  }

  if !path.is_dir() {
    return;
  }

  let Ok(folder) = path.canonicalize() else {
    return;
  };
  let Ok(read_dir) = std::fs::read_dir(&folder) else {
    return;
  };

  // Collect any config files in the current dir.
  for dir_entry in read_dir.flatten() {
    let path = dir_entry.path();
    let Ok(metadata) = dir_entry.metadata() else {
      continue;
    };
    if metadata.is_file() {
      let file_name = dir_entry.file_name();
      let Some(file_name) = file_name.to_str() else {
        continue;
      };
      // Ensure file name matches a wildcard keyword
      let index = if keywords.is_empty() {
        0
      } else if let Some(index) = keywords
        .iter()
        .position(|wc| wc.is_match(file_name.as_bytes()))
      {
        // actual config keyword matches will have higher priority than
        // when files are added via the base case.
        index + 1
      } else {
        continue;
      };
      let Ok(path) = path.canonicalize() else {
        continue;
      };
      files.push((index, path));
    }
  }

  // Collect any paths specified in 'includes'
  let includes =
    IncludesLoader::init(&folder, include_file_name).finish();
  if includes.is_empty() {
    return;
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
      &path,
      keywords,
      include_file_name,
      debug_print,
    );
  }
}

/// loads multiple config files
pub fn load_parse_config_files<T: DeserializeOwned>(
  files: &[PathBuf],
  merge_nested: bool,
  extend_array: bool,
) -> Result<T> {
  let mut target = serde_json::Map::new();

  for file in files {
    let source = match load_parse_config_file(file) {
      Ok(source) => source,
      Err(e) => {
        eprintln!("{}: {e}", "WARN".yellow());
        continue;
      }
    };
    target = match merge_objects(
      target.clone(),
      source,
      merge_nested,
      extend_array,
    ) {
      Ok(target) => target,
      Err(e) => {
        eprint!("{}: {e}", "WARN".yellow());
        target
      }
    };
  }

  let json = serde_json::to_string(&target)
    .map_err(|e| Error::SerializeJson { e })?;
  let interpolated = interpolate_env_and_shell(&json);

  serde_json::from_str(&interpolated)
    .map_err(|e| Error::ParseFinalJson { e })
}

/// Loads and parses a single config file
pub fn load_parse_config_file<T: DeserializeOwned>(
  file: &Path,
) -> Result<T> {
  let mut file_handle =
    File::open(file).map_err(|e| Error::FileOpen {
      e,
      path: file.to_path_buf(),
    })?;
  let mut contents = String::new();
  file_handle.read_to_string(&mut contents).map_err(|e| {
    Error::ReadFileContents {
      e,
      path: file.to_path_buf(),
    }
  })?;
  let config = match file.extension().and_then(|e| e.to_str()) {
    Some("toml") => {
      toml::from_str(&contents).map_err(|e| Error::ParseToml {
        e,
        path: file.to_path_buf(),
      })?
    }
    Some("yaml") | Some("yml") => serde_yaml_ng::from_str(&contents)
      .map_err(|e| Error::ParseYaml {
        e,
        path: file.to_path_buf(),
      })?,
    Some("json") => serde_json::from_str(&contents).map_err(|e| {
      Error::ParseJson {
        e,
        path: file.to_path_buf(),
      }
    })?,
    Some(_) | None => {
      return Err(Error::UnsupportedFileType {
        path: file.to_path_buf(),
      });
    }
  };
  Ok(config)
}
