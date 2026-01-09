use axum::{Router, response::Redirect, routing::get};

use crate::AuthImpl;

pub mod login;
pub mod manage;
pub mod oidc;
pub mod openapi;

#[derive(serde::Deserialize)]
struct Variant {
  variant: String,
}

#[derive(serde::Deserialize)]
pub struct RedirectQuery {
  redirect: Option<String>,
}

/// This router should be nested without any middleware
pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
    .nest("/login", login::router::<I>())
    .nest("/manage", manage::router::<I>())
    .nest("/oidc", oidc::router::<I>())
}

fn format_redirect(
  host: &str,
  redirect: Option<&str>,
  extra: &str,
) -> Redirect {
  let redirect_url = if let Some(redirect) = redirect
    && !redirect.is_empty()
  {
    let splitter = if redirect.contains('?') { '&' } else { '?' };
    format!("{redirect}{splitter}{extra}")
  } else {
    format!("{host}?{extra}")
  };
  Redirect::to(&redirect_url)
}
