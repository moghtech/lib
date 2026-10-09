#[macro_use]
extern crate tracing;

use anyhow::Context as _;

use crate::config::core_config;

mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod state;

async fn app() -> anyhow::Result<()> {
  let config = core_config();
  info!("Example Server version: v{}", env!("CARGO_PKG_VERSION"));

  // Zero max attempts would refuse every authentication attempt.
  if config.auth_rate_limit_max_attempts < 1 {
    return Err(anyhow::anyhow!(
      "Invalid 'auth_rate_limit_max_attempts' config: must be at least 1 (use 'auth_rate_limit_disabled' to turn the limiter off)"
    ));
  }

  // A 'jwt_secret' under 32 bytes stops the example here, rather
  // than at the first request issuing or checking a token.
  state::check_jwt_provider()
    .context("[FATAL] Invalid 'jwt_secret'")?;

  // A request signed with a signing key is made for one of these
  // hosts: an address without one is a startup error, rather than
  // requests which never verify.
  let signed_request_hosts =
    mogh_auth_server::middleware::check_signed_request_hosts(
      &auth::ExampleAuthImpl,
    )
    .context("Invalid 'host' / 'extra_hosts' config")?;
  info!("Signed Request Hosts: {signed_request_hosts:?}");

  db::init().await?;
  // Fails here if the encryption key is invalid.
  crypto::encryption_key();
  // The supporter key in use: the stored one, else the config's.
  mogh_supporter::server::init::<auth::ExampleAuthImpl>()
    .await
    .context("Failed to load the supporter key")?;
  // Static trusted issuers may have changed in the config.
  auth::sync_workload_users_on_startup()
    .await
    .context("Failed to sync the users of trusted issuers")?;

  mogh_server::serve_app(api::app(), config, None).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let config = core_config();
  mogh_logger::init(config.logging.with_app(config::LOG_APP))?;

  let mut term_signal = tokio::signal::unix::signal(
    tokio::signal::unix::SignalKind::terminate(),
  )?;

  tokio::select! {
    res = tokio::spawn(app()) => res?,
    _ = term_signal.recv() => Ok(()),
  }
}

// Dev dependencies used by the integration tests only.
#[cfg(test)]
use {
  example_mock_idp as _, reqwest as _, tempfile as _, totp_rs as _,
};
