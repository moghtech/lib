use std::sync::LazyLock;

use axum::http::HeaderValue;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

pub trait CorsConfig {
  fn allowed_origins(&self) -> &[String] {
    &[]
  }
  fn allow_credentials(&self) -> bool {
    true
  }
}

static ANY_ORIGIN: LazyLock<String> =
  LazyLock::new(|| String::from("*"));

/// Creates a CORS layer based on the Core configuration.
///
/// - If the allowed origins contains '*', uses 'Any' allowed origin.
/// - Methods and headers are always allowed (Mirrored)
/// - Credentials are only allowed if `cors_allow_credentials` is true
pub fn cors_layer(config: impl CorsConfig) -> CorsLayer {
  let allowed_origins = config.allowed_origins();
  let allow_credentials = config.allow_credentials();
  let mut cors = CorsLayer::new()
    .allow_methods(tower_http::cors::AllowMethods::mirror_request())
    .allow_headers(tower_http::cors::AllowHeaders::mirror_request())
    .allow_credentials(allow_credentials);
  if allowed_origins.is_empty() {
    info!("CORS using no additional allowed origins.");
  } else if allowed_origins.contains(&ANY_ORIGIN) {
    warn!("CORS using allowed origin 'Any' (*).",);
    cors = cors.allow_origin(tower_http::cors::Any)
  } else {
    let allowed_origins = allowed_origins
      .iter()
      .filter_map(|origin| {
        HeaderValue::from_str(origin)
          .inspect_err(|e| {
            warn!("Invalid CORS allowed origin: {origin} | {e:?}")
          })
          .ok()
      })
      .collect::<Vec<_>>();
    info!("CORS using allowed origin/s: {allowed_origins:?}");
    cors = cors.allow_origin(allowed_origins);
  };
  if allow_credentials {
    info!("CORS allowing credentials");
  }
  cors
}
