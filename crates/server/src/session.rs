use tower_sessions::{
  Expiry, MemoryStore, SessionManagerLayer,
  cookie::{SameSite, time::Duration},
};
use url::Url;

pub use tower_sessions::Session;

pub trait SessionConfig {
  fn expiry_seconds(&self) -> i64 {
    60
  }
  fn host(&self) -> &str;
  fn host_url(&self) -> Option<&Url>;
}

/// Adds an in memory session manager layer.
///
/// Use [Session] to extract
/// the client session in axum request handlers.
pub fn layer(
  config: impl SessionConfig,
) -> SessionManagerLayer<MemoryStore> {
  let mut layer = SessionManagerLayer::new(MemoryStore::default())
    .with_expiry(Expiry::OnInactivity(Duration::seconds(
      config.expiry_seconds(),
    )))
    .with_secure(config.host().starts_with("https://"))
    // Needs Lax in order for sessions to work
    // accross oauth redirects.
    .with_same_site(SameSite::Lax);
  if let Some(domain) = config.host_url().and_then(|url| url.domain())
  {
    layer = layer.with_domain(domain.to_string());
  }
  layer
}
