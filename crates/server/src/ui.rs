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
use tracing::warn;

/// The static UI must have an `index.html` to use as the root.
///
/// Tries to hash index contents to use as ETag, falls
/// back to 'Cache-Control: no-cache' if this fails.
pub fn serve_static_ui(
  ui_path: &str,
  force_no_cache: bool,
) -> ServeDir<SetStatus<Router>> {
  let directory = PathBuf::from(ui_path);
  let index = directory.join("index.html");

  let index_router =
    Router::new().fallback_service(ServeFile::new(&index));

  if force_no_cache {
    return ServeDir::new(directory)
      .not_found_service(add_no_cache_layer(index_router));
  }

  let index = match hash_encode_contents(&index) {
    Ok(header_value) => {
      index_router
        // The ETag header helps browser know when the
        // contents have changed / invalidate cache.
        .layer(SetResponseHeaderLayer::overriding(
          header::ETAG,
          header_value,
        ))
    }
    Err(e) => {
      warn!(
        "Failed to create ETag header for index.html, using 'Cache-Control: no-cache' | {e:#}"
      );
      add_no_cache_layer(index_router)
    }
  };

  ServeDir::new(directory).not_found_service(index)
}

fn hash_encode_contents(path: &Path) -> anyhow::Result<HeaderValue> {
  let contents = std::fs::read(path).context(
    "Failed to read static UI index.html for content hash",
  )?;
  let mut hasher = sha2::Sha256::new();
  hasher.update(&contents);
  let digest = hasher.finalize();
  let value = data_encoding::BASE64URL.encode(&digest);
  HeaderValue::from_bytes(value.as_bytes())
    .context("Invalid index hash for ETag header value")
}

fn add_no_cache_layer(router: Router) -> Router {
  router.layer(SetResponseHeaderLayer::overriding(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-cache"),
  ))
}
