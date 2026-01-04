use tower_sessions::{
  Expiry, MemoryStore, SessionManagerLayer,
  cookie::{SameSite, time::Duration},
};
use tracing::warn;

pub use tower_sessions::Session;

pub trait SessionConfig {
  fn expiry_seconds(&self) -> i64 {
    60
  }
  fn host_env_field(&self) -> &str {
    "HOST"
  }
  fn host(&self) -> &str;
}

/// Adds an in memory session manager layer.
///
/// Use [Session] to extract
/// the client session in axum request handlers.
pub fn memory_session_layer(
  config: impl SessionConfig,
) -> SessionManagerLayer<MemoryStore> {
  let host = config.host();
  let mut layer = SessionManagerLayer::new(MemoryStore::default())
    .with_expiry(Expiry::OnInactivity(Duration::seconds(
      config.expiry_seconds(),
    )))
    .with_secure(host.starts_with("https://"))
    // Needs Lax in order for sessions to work
    // accross oauth redirects.
    .with_same_site(SameSite::Lax);
  let host_url = url::Url::parse(host)
    .inspect_err(|e| {
      warn!(
        "Invalid {}: not URL. Passkeys won't work. | {e:?}",
        config.host_env_field(),
      )
    })
    .ok();
  if let Some(domain) =
    host_url.and_then(|url| url.domain().map(str::to_string))
  {
    layer = layer.with_domain(domain);
  }
  layer
}
