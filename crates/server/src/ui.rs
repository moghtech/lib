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
};
use tracing::warn;

/// The static UI must have an `index.html` to use as the root.
///
/// Tries to hash index contents to use as ETag, falls
/// back to 'Cache-Control: no-cache' if this fails.
///
/// If `force_no_cache` is passed, the `index.html` will
/// always be served with no-cache header.
pub fn serve_static_ui(
  ui_path: &str,
  force_no_cache: bool,
) -> ServeDir<Router> {
  let directory = PathBuf::from(ui_path);
  let index = directory.join("index.html");

  let index_router =
    Router::new().fallback_service(ServeFile::new(&index));

  if force_no_cache {
    return ServeDir::new(directory)
      .fallback(add_no_cache_layer(index_router));
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

  ServeDir::new(directory).fallback(index)
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

#[cfg(test)]
mod tests {
  use super::*;
  use axum::body::Body;
  use axum::http::{Request, StatusCode};
  use tower::ServiceExt as _;

  fn make_ui_dir(
    index: &'static str,
  ) -> (tempfile::TempDir, &'static str) {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    std::fs::write(dir.path().join("index.html"), index)
      .expect("Failed to write index.html");
    std::fs::write(dir.path().join("asset.txt"), "asset-body")
      .expect("Failed to write asset.txt");
    (dir, index)
  }

  /// Wraps `serve_static_ui` in an axum `Router` fallback, exactly the way
  /// downstream consumers (e.g. komodo) attach it.
  fn make_app(dir: &std::path::Path, force_no_cache: bool) -> Router {
    Router::new().fallback_service(serve_static_ui(
      dir.to_str().expect("Valid path"),
      force_no_cache,
    ))
  }

  async fn get(app: &Router, path: &str) -> axum::response::Response {
    app
      .clone()
      .oneshot(
        Request::builder()
          .uri(path)
          .body(Body::empty())
          .expect("Valid request"),
      )
      .await
      .expect("Service should not fail")
  }

  async fn body_bytes(res: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(res.into_body(), usize::MAX)
      .await
      .expect("Failed to read response body")
      .to_vec()
  }

  #[tokio::test]
  async fn root_returns_index_html_with_etag() {
    let (dir, index) = make_ui_dir("<html><body>index</body></html>");
    let service = make_app(dir.path(), false);

    let res = get(&service, "/").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
      res.headers().contains_key(header::ETAG),
      "Expected ETag header on index.html"
    );
    assert_eq!(body_bytes(res).await, index.as_bytes());
  }

  #[tokio::test]
  async fn spa_route_returns_index_html_with_200() {
    let (dir, index) = make_ui_dir("<html><body>index</body></html>");
    let service = make_app(dir.path(), false);

    let res = get(&service, "/login").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res).await, index.as_bytes());
  }

  #[tokio::test]
  async fn deep_spa_route_returns_index_html_with_200() {
    let (dir, index) = make_ui_dir("<html><body>index</body></html>");
    let service = make_app(dir.path(), false);

    let res = get(&service, "/stacks/abc").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res).await, index.as_bytes());
  }

  #[tokio::test]
  async fn existing_static_file_is_served() {
    let (dir, _index) =
      make_ui_dir("<html><body>index</body></html>");
    let service = make_app(dir.path(), false);

    let res = get(&service, "/asset.txt").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_bytes(res).await, b"asset-body");
  }

  #[tokio::test]
  async fn force_no_cache_spa_route_returns_200_with_no_cache() {
    let (dir, index) = make_ui_dir("<html><body>index</body></html>");
    let service = make_app(dir.path(), true);

    let res = get(&service, "/login").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
      res.headers().get(header::CACHE_CONTROL),
      Some(&HeaderValue::from_static("no-cache")),
      "Expected Cache-Control: no-cache header"
    );
    assert_eq!(body_bytes(res).await, index.as_bytes());
  }
}
