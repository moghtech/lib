use tower_http::{
  services::{ServeDir, ServeFile},
  set_status::SetStatus,
};

/// The static UI must have an `index.html` to use as the root.
pub fn serve_static_ui(
  ui_path: &str,
) -> ServeDir<SetStatus<ServeFile>> {
  let ui_index = ServeFile::new(format!("{ui_path}/index.html"));
  ServeDir::new(ui_path).not_found_service(ui_index.clone())
}
