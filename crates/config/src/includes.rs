use std::{
  collections::HashSet,
  path::{Path, PathBuf},
};

pub struct IncludesLoader {
  includes: HashSet<PathBuf>,
  include_file_name: &'static str,
}

impl IncludesLoader {
  pub fn new(include_file_name: &'static str) -> Self {
    Self {
      includes: HashSet::new(),
      include_file_name,
    }
  }

  pub fn init(path: &Path, include_file_name: &'static str) -> Self {
    let mut includes = Self::new(include_file_name);
    includes.load_more(path);
    includes
  }

  pub fn finish(self) -> HashSet<PathBuf> {
    self.includes
  }

  pub fn load_more(&mut self, folder: &Path) {
    if !folder.is_dir() {
      return;
    }
    let Ok(folder) = folder.canonicalize() else {
      return;
    };
    // Add any includes in this folder
    if let Ok(ignore) =
      std::fs::read_to_string(folder.join(self.include_file_name))
    {
      self.includes.extend(
        ignore
          .split('\n')
          .map(|line| line.trim())
          // Ignore empty / commented out lines
          .filter(|line| !line.is_empty() && !line.starts_with('#'))
          // Remove end of line comments
          .map(|line| {
            line
              .split_once('#')
              .map(|res| res.0.trim())
              .unwrap_or(line)
          })
          .flat_map(|line| folder.join(line).canonicalize()),
      );
    };
  }
}
