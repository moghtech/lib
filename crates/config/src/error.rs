use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error(
    "Types on field {key} do not match | got {value:?}, expected object"
  )]
  ObjectFieldTypeMismatch {
    key: String,
    value: serde_json::Value,
  },

  #[error(
    "Types on field {key} do not match | got {value:?}, expected array"
  )]
  ArrayFieldTypeMismatch {
    key: String,
    value: serde_json::Value,
  },

  #[error("Failed to open file at {path} | {e:?}")]
  FileOpen { e: std::io::Error, path: PathBuf },

  #[error("Failed to read contents of file at {path} | {e:?}")]
  ReadFileContents { e: std::io::Error, path: PathBuf },

  #[error("Failed to parse toml file at {path} | {e:?}")]
  ParseToml { e: toml::de::Error, path: PathBuf },

  #[error("Failed to parse yaml file at {path} | {e:?}")]
  ParseYaml {
    e: serde_yaml_ng::Error,
    path: PathBuf,
  },

  #[error("Failed to parse json file at {path} | {e:?}")]
  ParseJson { e: serde_json::Error, path: PathBuf },

  #[error("Unsupported file type at {path}")]
  UnsupportedFileType { path: PathBuf },

  #[error("Failed to parse merged config into final type | {e:?}")]
  ParseFinalJson { e: serde_json::Error },

  #[error("Failed to serialize config to json string | {e:?}")]
  SerializeJson { e: serde_json::Error },

  #[error("Failed to read directory at {path:?}")]
  ReadDir { path: PathBuf, e: std::io::Error },

  #[error("Failed to get file handle for file in directory {path:?}")]
  DirFile { e: std::io::Error, path: PathBuf },

  #[error("Failed to get file name for file at {path:?}")]
  GetFileName { path: PathBuf },

  #[error("Failed to get metadata for path {path:?} | {e:?}")]
  ReadPathMetaData { path: PathBuf, e: std::io::Error },

  #[error("Parsed value is not object")]
  ValueIsNotObject,
}
