use axum::{
  Router,
  http::{HeaderValue, header},
};
use tower_http::{
  services::{ServeDir, ServeFile},
  set_header::SetResponseHeaderLayer,
  set_status::SetStatus,
};

/// The static UI must have an `index.html` to use as the root.
pub fn serve_static_ui(ui_path: &str) -> ServeDir<SetStatus<Router>> {
  let ui_index = Router::new()
    .fallback_service(ServeFile::new(format!("{ui_path}/index.html")))
    .layer(SetResponseHeaderLayer::overriding(
      header::CACHE_CONTROL,
      HeaderValue::from_static("no-cache"),
    ));
  ServeDir::new(ui_path).not_found_service(ui_index)
}
