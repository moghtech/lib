use std::{net::SocketAddr, str::FromStr as _};

use anyhow::Context as _;
use axum::{
  Router,
  http::{HeaderName, HeaderValue},
};
use axum_server::tls_rustls::RustlsConfig;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::info;

pub mod cors;
pub mod session;
pub mod ui;

pub trait ServerConfig {
  fn bind_ip(&self) -> &str {
    "[::]"
  }
  fn port(&self) -> u16;
  fn ssl_enabled(&self) -> bool {
    false
  }
  fn ssl_key_file(&self) -> &str {
    "/config/ssl/key.pem"
  }
  fn ssl_cert_file(&self) -> &str {
    "/config/ssl/cert.pem"
  }
}

/// Serves the app with socket connect info
pub async fn serve_app(
  app: Router,
  config: impl ServerConfig,
) -> anyhow::Result<()> {
  // Add app standard security layers
  let app = app
    .layer(SetResponseHeaderLayer::overriding(
      HeaderName::from_static("x-content-type-options"),
      HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
      HeaderName::from_static("x-frame-options"),
      HeaderValue::from_static("DENY"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
      HeaderName::from_static("x-xss-protection"),
      HeaderValue::from_static("1; mode=block"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
      HeaderName::from_static("referrer-policy"),
      HeaderValue::from_static("strict-origin-when-cross-origin"),
    ))
    .into_make_service_with_connect_info::<SocketAddr>();

  // Construct the bind socket addr
  let addr = format!("{}:{}", config.bind_ip(), config.port());
  let socket_addr = SocketAddr::from_str(&addr)
    .context("Failed to parse listen address")?;

  // Run the server
  if config.ssl_enabled() {
    // Run the server with TLS (https)
    info!("🔒 Server SSL Enabled");
    info!("Server starting on https://{socket_addr}");
    let ssl_config = RustlsConfig::from_pem_file(
      config.ssl_cert_file(),
      config.ssl_key_file(),
    )
    .await
    .context("Invalid ssl cert / key")?;
    axum_server::bind_rustls(socket_addr, ssl_config)
      .serve(app)
      .await
      .context("Failed to start https server")
  } else {
    // Run the server without TLS (http)
    info!("🔓 Server SSL Disabled");
    info!("Server starting on http://{socket_addr}");
    axum_server::bind(socket_addr)
      .serve(app)
      .await
      .context("Failed to start http server")
  }
}
