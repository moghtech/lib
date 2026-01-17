# Mogh Server

Configurable axum server including Session, CORS, common security headers, and static file hosting.

```rust
struct Config;

impl mogh_server::ServerConfig for Config {
  fn port(&self) -> u16 {
    3100
  }
  fn ssl_enabled(&self) -> bool {
    true
  }
  fn ssl_key_file(&self) -> &str {
    "./ssl/key.pem"
  }
  fn ssl_cert_file(&self) -> &str {
    "./ssl/cert.pem"
  }
}

let app = Router::new()
  .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }));

mogh_server::serve_app(
  app,
  Config,
).await?
```
