use anyhow::anyhow;
use axum::{Extension, Router, http::StatusCode, routing::get};
use mogh_auth_server::middleware::authenticate_request;
use mogh_error::{AddStatusCodeError as _, Json};
use mogh_server::{
  cors::cors_layer, session::memory_session_layer,
  ui::serve_static_ui,
};

use crate::{
  auth::{ExampleAuthImpl, RequestUser},
  config::core_config,
};

mod execute;
mod read;
mod write;

#[derive(serde::Deserialize)]
struct Variant {
  variant: String,
}

pub fn app() -> Router {
  let config = core_config();
  let mut app = Router::new()
    .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
    .nest("/auth", mogh_auth_server::api::router::<ExampleAuthImpl>())
    .nest("/user", user_router())
    .nest("/read", read::router())
    .nest("/write", write::router())
    .nest("/execute", execute::router())
    .layer(memory_session_layer(config));
  if !config.ui_path.is_empty() {
    app =
      app.fallback_service(serve_static_ui(&config.ui_path, false));
  }
  app.layer(cors_layer(config))
}

/// Disabled users can still get themselves,
/// so the UI can tell them they are disabled.
fn user_router() -> Router {
  Router::new()
    .route(
      "/",
      get(|Extension(user): Extension<RequestUser>| async move {
        Json(user.user.as_ref().clone().into_user())
      }),
    )
    .layer(axum::middleware::from_fn(
      authenticate_request::<ExampleAuthImpl, false>,
    ))
}

fn admin_only(user: &RequestUser) -> mogh_error::Result<()> {
  if user.user.admin {
    Ok(())
  } else {
    Err(
      anyhow!("This method is admin only")
        .status_code(StatusCode::FORBIDDEN),
    )
  }
}
