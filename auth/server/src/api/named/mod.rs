use axum::Router;

use crate::AuthImpl;

pub mod github;
pub mod google;

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .nest("/github", github::router::<I>())
    .nest("/google", google::router::<I>())
}
