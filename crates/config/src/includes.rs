use std::path::{Path, PathBuf};

use indexmap::IndexMap;

use crate::{
  Error, Result,
  load::{is_cicada_path, is_missing, read_file},
};

/// The paths listed in the include file of `folder` (canonical), in
/// the order they are listed, without duplicates: one per line,
/// `#` comment lines and end of line comments (a `#` after
/// whitespace) left out. Local paths are kept as listed (joined to
/// the folder), so a symlink (`app.env` -> `secret`) keeps the name
/// its type is detected from, and deduped by canonical path; a path
/// listed again keeps its first position and spelling. `cicada:`
/// paths are kept as written. An empty `include_file_name` reads no
/// include file.
///
/// A missing include file includes nothing, and a line naming a
/// missing path is skipped, like a missing config path. An include
/// file which exists but can't be read ([Error::FileOpen],
/// [Error::ReadFileContents]), or a line naming a path which exists
/// but can't be resolved ([Error::ReadPathMetaData]), is an error:
/// skipping it would start the app without the configuration it
/// names.
pub(crate) fn read_includes(
  folder: &Path,
  include_file_name: &str,
) -> Result<Vec<PathBuf>> {
  if include_file_name.is_empty() {
    return Ok(Vec::new());
  }
  let contents = match read_file(&folder.join(include_file_name)) {
    Ok(contents) => contents,
    Err(Error::FileOpen { ref e, .. }) if is_missing(e) => {
      return Ok(Vec::new());
    }
    Err(e) => return Err(e),
  };
  let lines = contents
    .split('\n')
    .map(|line| line.trim())
    // Ignore empty / commented out lines
    .filter(|line| !line.is_empty() && !line.starts_with('#'))
    // Remove end of line comments: a '#' preceded by
    // whitespace. A '#' inside a path is kept.
    .map(|line| {
      line
        .split_once(" #")
        .or_else(|| line.split_once("\t#"))
        .map(|res| res.0.trim())
        .unwrap_or(line)
    });
  // The listed path by its dedupe key (the canonical path, or a
  // `cicada:` path as written).
  let mut includes = IndexMap::<PathBuf, PathBuf>::new();
  for line in lines {
    // A cicada source is no local path: kept as written, for
    // the loader to load it (or refuse it without the
    // feature) rather than dropped as a missing path.
    if is_cicada_path(Path::new(line)) {
      let path = PathBuf::from(line);
      includes.entry(path.clone()).or_insert(path);
      continue;
    }
    // Absolute, as the folder is canonical. Not canonicalized
    // itself: a symlink is loaded by its own name.
    let path = folder.join(line);
    let key = match path.canonicalize() {
      Ok(key) => key,
      Err(e) if is_missing(&e) => continue,
      Err(e) => return Err(Error::ReadPathMetaData { path, e }),
    };
    includes.entry(key).or_insert(path);
  }
  Ok(includes.into_values().collect())
}
