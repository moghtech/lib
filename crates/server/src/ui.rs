use std::path::PathBuf;

use anyhow::Context;
use axum::{
  Router,
  extract::Request,
  http::{HeaderValue, StatusCode, header},
  middleware::{map_request, map_response},
  response::Response,
};
use sha2::Digest as _;
use tower_http::{
  compression::CompressionLayer,
  services::{ServeDir, ServeFile},
  set_header::SetResponseHeaderLayer,
};
use tracing::{error, warn};

/// Where vite puts the content hashed build output (its default
/// `build.assetsDir`), served at `/assets`.
const ASSETS_DIR: &str = "assets";

/// For the content hashed assets: a changed file gets a new name, so
/// browsers may keep each one as long as they like, without asking.
const CACHE_IMMUTABLE: HeaderValue =
  HeaderValue::from_static("public, max-age=31536000, immutable");

/// Serves the index for paths without a file, with the index
/// router's status: 200 when `index.html` is there (the router
/// never answers 304 / 206 / 412, see [strip_conditional_headers]),
/// 404 when it is missing, rather than an empty 200 page.
/// Note. `ServeDir::not_found_service` would force the
/// fallback response status to 404, which breaks browser
/// caching (the ETag / Cache-Control headers on the index)
/// for client side routed paths.
fn with_index_fallback(
  directory: PathBuf,
  index: Router,
) -> ServeDir<Router> {
  ServeDir::new(directory)
    // Otherwise `/` (what browsers actually request) is answered by
    // ServeDir itself with the plain `index.html` file, skipping the
    // index router below and with it the content hash ETag /
    // `no-cache` header. The file ETag is built from mtime and size,
    // which can be identical between two builds of a UI (fixed image
    // timestamps, same length hashed asset names), leaving browsers
    // on a stale index after an upgrade.
    .append_index_html_on_directories(false)
    .fallback(index)
}

/// Serves the static UI directory, which must have an `index.html`
/// to use as the root. Paths without a file (`/`, client side
/// routes) get the index.
///
/// The files under `/assets` (vite's content hashed output) are
/// served with `Cache-Control: public, max-age=31536000, immutable`,
/// so browsers don't download or even revalidate them again until a
/// new UI names new ones. A path there without a file is a 404, not
/// the index, which must never be cached as an asset.
///
/// Responses are compressed (brotli or gzip, as the browser
/// accepts), for the UI's multi-MB scripts: only this service, not
/// the app's api (eg. streamed responses) around it.
///
/// The index is always served in full with `Cache-Control: no-cache`,
/// so browsers revalidate it on every load and never run a stale
/// index (referencing hashed assets which no longer exist) after an
/// upgrade. It carries the content hash of `index.html` (computed on
/// startup) as ETag, the file's mtime based validators
/// (`Last-Modified`, its own ETag) are not sent.
///
/// If `force_no_cache` is passed, or hashing fails, the index is
/// served without ETag, eg when `index.html` changes without a
/// restart.
///
/// Without an `index.html` (eg. a wrong `ui_path`, or an install
/// without the UI) the pages answer 404, and an error naming
/// `ui_path` is logged on startup.
pub fn serve_static_ui(
  ui_path: &str,
  force_no_cache: bool,
) -> Router {
  let directory = PathBuf::from(ui_path);
  let index = directory.join("index.html");

  let mut index_router = Router::new()
    .fallback_service(ServeFile::new(&index))
    .layer(map_response(strip_file_validators))
    .layer(map_request(strip_conditional_headers));

  // Read on startup either way: a UI which isn't there is an
  // error, which a blank page wouldn't tell.
  match std::fs::read(&index) {
    Ok(contents) if !force_no_cache => {
      match hash_encode_contents(&contents) {
        Ok(header_value) => {
          index_router = index_router
            // The ETag header helps browser know when the
            // contents have changed / invalidate cache.
            .layer(SetResponseHeaderLayer::overriding(
              header::ETAG,
              header_value,
            ))
        }
        Err(e) => {
          warn!(
            "Failed to create ETag header for index.html, serving it without | {e:#}"
          );
        }
      }
    }
    Ok(_) => {}
    Err(e) => {
      error!(
        "No static UI at ui_path {ui_path:?}: failed to read its index.html, pages answer 404 until it is there | {e}"
      );
    }
  }

  let assets = Router::new()
    .fallback_service(
      // Files only: a directory is a 404, not its index.html or a
      // redirect (built from the path with `/assets` stripped).
      ServeDir::new(directory.join(ASSETS_DIR))
        .append_index_html_on_directories(false),
    )
    .layer(map_response(cache_immutable));

  Router::new()
    .nest_service(&format!("/{ASSETS_DIR}"), assets)
    .fallback_service(with_index_fallback(
      directory,
      add_no_cache_layer(index_router),
    ))
    // Explicitly the two every browser takes, whatever other
    // tower-http compression features the app's build enables.
    .layer(CompressionLayer::new().no_deflate().no_zstd())
}

/// Marks a served asset (or its 304) as cached for good, see
/// [CACHE_IMMUTABLE]. Not a 404: the file may be there after the
/// rest of an upgrade.
async fn cache_immutable(mut res: Response) -> Response {
  if res.status().is_success()
    || res.status() == StatusCode::NOT_MODIFIED
  {
    res
      .headers_mut()
      .insert(header::CACHE_CONTROL, CACHE_IMMUTABLE);
  }
  res
}

/// Request headers `ServeFile` evaluates against the file mtime /
/// size, answering 304 / 206 / 412. The index is always served in
/// full instead: the mtime / size validators can't tell two UI
/// builds apart (a 304 would keep a stale index after an upgrade),
/// and they are not the content hash ETag the index carries.
const CONDITIONAL_HEADERS: [header::HeaderName; 6] = [
  header::IF_MATCH,
  header::IF_NONE_MATCH,
  header::IF_MODIFIED_SINCE,
  header::IF_UNMODIFIED_SINCE,
  header::IF_RANGE,
  header::RANGE,
];

async fn strip_conditional_headers(mut req: Request) -> Request {
  let headers = req.headers_mut();
  for name in CONDITIONAL_HEADERS {
    headers.remove(name);
  }
  req
}

/// Removes the `ServeFile` validators the index router doesn't
/// honor (see [CONDITIONAL_HEADERS]), so browsers don't send them.
/// The content hash ETag is set after this.
async fn strip_file_validators(mut res: Response) -> Response {
  let headers = res.headers_mut();
  headers.remove(header::ETAG);
  headers.remove(header::LAST_MODIFIED);
  headers.remove(header::ACCEPT_RANGES);
  res
}

fn hash_encode_contents(
  contents: &[u8],
) -> anyhow::Result<HeaderValue> {
  let value = content_hash(contents);
  // ETag values must be wrapped in double quotes (RFC 9110).
  HeaderValue::from_bytes(format!("\"{value}\"").as_bytes())
    .context("Invalid index hash for ETag header value")
}

/// The BASE64URL encoded SHA-256 of `contents`, the ETag scheme of
/// the static UI index and the OpenAPI spec (`openapi` feature).
pub(crate) fn content_hash(contents: &[u8]) -> String {
  let mut hasher = sha2::Sha256::new();
  hasher.update(contents);
  data_encoding::BASE64URL.encode(&hasher.finalize())
}

fn add_no_cache_layer(router: Router) -> Router {
  router.layer(SetResponseHeaderLayer::overriding(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-cache"),
  ))
}
