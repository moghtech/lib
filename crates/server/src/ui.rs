use std::path::{Path, PathBuf};

use anyhow::Context;
use axum::{
  Router,
  http::{HeaderValue, header},
};
use sha2::Digest as _;
use tower_http::{
  services::{ServeDir, ServeFile},
  set_header::SetResponseHeaderLayer,
  set_status::SetStatus,
};

/// The static UI must have an `index.html` to use as the root.
pub fn serve_static_ui(
  ui_path: &str,
) -> anyhow::Result<ServeDir<SetStatus<Router>>> {
  let directory = PathBuf::from(ui_path);
  let index = directory.join("index.html");
  let index_hash = hash_encode_contents(&index)?;

  let index = Router::new()
    .fallback_service(ServeFile::new(index))
    .layer(SetResponseHeaderLayer::overriding(
      header::ETAG,
      HeaderValue::from_bytes(index_hash.as_bytes())
        .context("Invalid index hash for ETag header value")?,
    ));

  Ok(ServeDir::new(directory).not_found_service(index))
}

fn hash_encode_contents(path: &Path) -> anyhow::Result<String> {
  let contents = std::fs::read(path).context(
    "Failed to read static UI index.html for content hash",
  )?;
  let mut hasher = sha2::Sha256::new();
  hasher.update(&contents);
  let digest = hasher.finalize();
  Ok(data_encoding::BASE64URL.encode(&digest))
}
