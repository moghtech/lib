use axum::{Router, routing::get};

use crate::AuthImpl;

pub mod login;
pub mod manage;
pub mod openapi;

#[derive(serde::Deserialize)]
struct Variant {
  variant: String,
}

/// This router should be nested without any middleware
pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
    .nest("/login", login::router::<I>())
    .nest("/manage", manage::router::<I>())
}
