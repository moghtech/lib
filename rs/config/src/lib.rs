//! # Komodo Config
//!
//! This library is used to parse Core, Periphery, and CLI config files.
//! It supports interpolating in environment variables (only '${VAR}' syntax),
//! as well as merging together multiple files into a final configuration object.

use std::path::Path;

use colored::Colorize;
use indexmap::IndexSet;
use serde::de::DeserializeOwned;

mod error;
mod includes;
mod interpolate;
mod load;
mod merge;

pub use error::Error;
pub use interpolate::*;
pub use merge::{merge_config, merge_objects};

pub type Result<T> = ::core::result::Result<T, Error>;

/// Set the configuration for loading config files.
pub struct ConfigLoader<'outer, 'inner> {
  /// Paths to either files or directories
  /// to include in the final configuration.
  ///
  /// Path coming later in the array (higher index) will override
  /// configuration in earlier paths.
  pub paths: &'outer [&'inner Path],
  /// Wilcard patterns to match file names in given directories.
  ///
  /// Patterns coming later in the array (higher index) will override
  /// configuration added by earlier patterns, however this is
  /// only relavant for an individual `path`. Later `paths`
  /// will still have higher priority.
  pub match_wildcards: &'outer [&'inner str],
  /// The file name to search for `.include` file.
  pub include_file_name: &'static str,
  /// Whether to merge nested config objects.
  /// Otherwise, the object will be replaced at
  /// the top-level key by the highest priority config file
  /// in which it is specified.
  pub merge_nested: bool,
  /// Whether to extend array in configuration files.
  /// Otherwise, the array will be replaced at
  /// the top-level key by the highest priority config file
  /// in which it is specified.
  pub extend_array: bool,
  /// Print some extra information on configuation load.
  ///
  /// Note. This is different than application level log level.
  pub debug_print: bool,
}

impl ConfigLoader<'_, '_> {
  pub fn load<T: DeserializeOwned>(self) -> Result<T> {
    let ConfigLoader {
      paths,
      match_wildcards,
      include_file_name,
      merge_nested,
      extend_array,
      debug_print,
    } = self;
    let mut wildcards = Vec::with_capacity(match_wildcards.len());
    for &wc in match_wildcards {
      match wildcard::Wildcard::new(wc.as_bytes()) {
        Ok(wc) => wildcards.push(wc),
        Err(e) => {
          eprintln!(
            "{}: Keyword '{}' is invalid wildcard | {e:?}",
            "ERROR".red(),
            wc.bold(),
          );
        }
      }
    }
    let mut all_files = IndexSet::new();
    for &path in paths {
      let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) => {
          if debug_print {
            println!(
              "{}: {}: {path:?} | {e:?}",
              "DEBUG".cyan(),
              "Skipping Path".dimmed()
            );
          }
          continue;
        }
      };
      if metadata.is_dir() {
        let mut files = Vec::new();
        load::load_config_files(
          &mut files,
          path,
          &wildcards,
          include_file_name,
          debug_print,
        );
        files.sort_by(|(a_index, a_path), (b_index, b_path)| {
          a_index.cmp(b_index).then(a_path.cmp(b_path))
        });
        all_files.extend(files.into_iter().map(|(_, path)| path));
      } else if metadata.is_file() {
        let path = path.to_path_buf();
        // If the same path comes up again later on, it should be removed and
        // reinserted so it maintains higher priority.
        all_files.shift_remove(&path);
        all_files.insert(path);
      }
    }
    if debug_print {
      println!(
        "{}: {}: {all_files:?}",
        "DEBUG".cyan(),
        "Found Files".dimmed()
      );
    }
    load::load_parse_config_files(
      &all_files.into_iter().collect::<Vec<_>>(),
      merge_nested,
      extend_array,
    )
  }
}
