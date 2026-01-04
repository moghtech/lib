use axum::http::HeaderValue;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

pub trait CorsConfig {
  fn allowed_origins_env_field(&self) -> &'static str {
    "CORS_ALLOWED_ORIGINS"
  }
  fn allow_credentials(&self) -> bool {
    true
  }
  fn allowed_origins(&self) -> &[String] {
    &[]
  }
}

/// Creates a CORS layer based on the Core configuration.
///
/// - If `cors_allowed_origins` is empty: Allows all origins (backward compatibility)
/// - If `cors_allowed_origins` is set: Only allows the specified origins
/// - Methods and headers are always allowed (Any)
/// - Credentials are only allowed if `cors_allow_credentials` is true
pub fn layer(config: impl CorsConfig) -> CorsLayer {
  let mut cors = CorsLayer::new()
    .allow_methods(tower_http::cors::AllowMethods::mirror_request())
    .allow_headers(tower_http::cors::AllowHeaders::mirror_request())
    .allow_credentials(config.allow_credentials());
  let allowed_origins = config.allowed_origins();
  if allowed_origins.is_empty() {
    warn!(
      "CORS using allowed origin 'Any' (*). Use {} to configure specific origins.",
      config.allowed_origins_env_field()
    );
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
  cors
}
