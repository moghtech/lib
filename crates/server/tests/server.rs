#![allow(unused_crate_dependencies)]

use std::path::PathBuf;

use axum::{
  Router,
  body::Body,
  http::{Request, StatusCode, header},
  routing::get,
};
use mogh_server::{
  ServerConfig, TrustedProxies,
  cors::{CorsConfig, cors_layer},
  session::{
    ExpiredDeletion as _, MemorySessionStore, SessionConfig,
    memory_session_layer, session_layer,
  },
  ui::serve_static_ui,
};
use tower::ServiceExt as _;

struct Cors {
  origins: Vec<String>,
  credentials: bool,
}

impl CorsConfig for Cors {
  fn allowed_origins(&self) -> &[String] {
    &self.origins
  }
  fn allow_credentials(&self) -> bool {
    self.credentials
  }
}

fn cors_app(origins: &[&str], credentials: bool) -> Router {
  Router::new()
    .route("/", get(async || "ok"))
    .layer(cors_layer(Cors {
      origins: origins.iter().map(|o| o.to_string()).collect(),
      credentials,
    }))
}

fn request_with_origin(origin: &str) -> Request<Body> {
  Request::builder()
    .uri("/")
    .header(header::ORIGIN, origin)
    .body(Body::empty())
    .unwrap()
}

#[tokio::test]
async fn cors_allows_configured_origins_only() {
  let app = cors_app(&["https://example.com"], true);
  let response = app
    .clone()
    .oneshot(request_with_origin("https://example.com"))
    .await
    .unwrap();
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
    "https://example.com"
  );
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
    "true"
  );

  let response = app
    .oneshot(request_with_origin("https://evil.example.org"))
    .await
    .unwrap();
  assert!(
    !response
      .headers()
      .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
  );
}

#[tokio::test]
async fn cors_wildcard_without_credentials_uses_any() {
  let app = cors_app(&["*"], false);
  let response = app
    .oneshot(request_with_origin("https://example.com"))
    .await
    .unwrap();
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
    "*"
  );
}

#[tokio::test]
async fn cors_wildcard_with_credentials_mirrors_origin() {
  // tower-http panics at request time on
  // `Access-Control-Allow-Origin: *` + credentials,
  // so the wildcard origin must be mirrored instead.
  let app = cors_app(&["*"], true);
  let response = app
    .oneshot(request_with_origin("https://example.com"))
    .await
    .unwrap();
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
    "https://example.com"
  );
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_CREDENTIALS],
    "true"
  );
}

#[tokio::test]
async fn cors_invalid_origins_are_skipped() {
  let app = cors_app(&["bad\norigin", "https://example.com"], false);
  let response = app
    .oneshot(request_with_origin("https://example.com"))
    .await
    .unwrap();
  assert_eq!(
    response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
    "https://example.com"
  );
}

/// Creates a unique static ui directory for a test
/// and cleans it up on drop.
struct UiDir(PathBuf);

impl UiDir {
  fn new(name: &str) -> UiDir {
    let path = std::env::temp_dir().join(format!(
      "mogh_server_test_{}_{name}",
      std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("index.html"), "<html>index</html>")
      .unwrap();
    std::fs::write(path.join("asset.js"), "console.log(1)").unwrap();
    UiDir(path)
  }
}

impl Drop for UiDir {
  fn drop(&mut self) {
    let _ = std::fs::remove_dir_all(&self.0);
  }
}

async fn body_string(body: Body) -> String {
  let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
  String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn static_ui_serves_files_and_index_fallback() {
  let dir = UiDir::new("static_ui");
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);

  // Existing files are served directly.
  let response = service
    .clone()
    .oneshot(
      Request::builder()
        .uri("/asset.js")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(
    body_string(Body::new(response.into_body())).await,
    "console.log(1)"
  );

  // Unknown paths fall back to index.html with an ETag.
  let response = service
    .oneshot(
      Request::builder()
        .uri("/unknown/route")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  let etag = response.headers()[header::ETAG].to_str().unwrap();
  // ETag values must be quoted (RFC 9110).
  assert!(etag.starts_with('"') && etag.ends_with('"'));
  assert!(etag.len() > 2);
  assert_eq!(
    body_string(Body::new(response.into_body())).await,
    "<html>index</html>"
  );
}

/// The headers of the index as served for `uri`.
async fn index_headers(
  service: &Router,
  uri: &str,
) -> axum::http::HeaderMap {
  let response = service
    .clone()
    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK, "{uri}");
  let headers = response.headers().clone();
  assert_eq!(
    body_string(Body::new(response.into_body())).await,
    "<html>index</html>",
    "{uri}"
  );
  headers
}

#[tokio::test]
async fn static_ui_root_gets_the_same_cache_headers_as_routes() {
  // `/` is what browsers request, it must not be served
  // around the content hash ETag / no-cache handling.
  let dir = UiDir::new("static_ui_root");
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);
  let route = index_headers(&service, "/unknown/route").await;
  let root = index_headers(&service, "/").await;
  assert_eq!(root[header::ETAG], route[header::ETAG]);

  let service = serve_static_ui(dir.0.to_str().unwrap(), true);
  let root = index_headers(&service, "/").await;
  assert_eq!(root[header::CACHE_CONTROL], "no-cache");
}

#[tokio::test]
async fn static_ui_etag_follows_the_index_contents() {
  let dir = UiDir::new("static_ui_etag");
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);
  let before = index_headers(&service, "/").await;
  // Same contents, same ETag (eg. after a restart).
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);
  assert_eq!(
    index_headers(&service, "/").await[header::ETAG],
    before[header::ETAG]
  );
}

#[tokio::test]
async fn static_ui_force_no_cache_sets_cache_control() {
  let dir = UiDir::new("static_ui_no_cache");
  let service = serve_static_ui(dir.0.to_str().unwrap(), true);
  let response = service
    .oneshot(
      Request::builder()
        .uri("/unknown/route")
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
}

#[tokio::test]
async fn static_ui_index_is_never_cached_heuristically() {
  // Without Cache-Control, browsers reuse the index without asking,
  // for a tenth of its age, and run a stale UI after an upgrade.
  let dir = UiDir::new("static_ui_heuristic");
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);
  for uri in ["/", "/unknown/route"] {
    let headers = index_headers(&service, uri).await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-cache", "{uri}");
    assert!(headers.contains_key(header::ETAG), "{uri}");
    // The mtime isn't a validator the index honors.
    assert!(!headers.contains_key(header::LAST_MODIFIED), "{uri}");
  }
}

#[tokio::test]
async fn static_ui_index_ignores_conditional_and_range_requests() {
  // The index fallback always answers 200: a 304 / 206 from the
  // file server would come out as an empty / partial 200,
  // replacing the browser's cached index with a blank page.
  let dir = UiDir::new("static_ui_conditional");
  for force_no_cache in [false, true] {
    let service =
      serve_static_ui(dir.0.to_str().unwrap(), force_no_cache);
    let etag = index_headers(&service, "/")
      .await
      .get(header::ETAG)
      .map(|etag| etag.to_str().unwrap().to_string());
    let mut conditions = vec![
      (header::IF_NONE_MATCH, "*".to_string()),
      (
        header::IF_MODIFIED_SINCE,
        "Fri, 01 Jan 2100 00:00:00 GMT".to_string(),
      ),
      (header::IF_MATCH, "\"other\"".to_string()),
      (
        header::IF_UNMODIFIED_SINCE,
        "Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
      ),
      (header::RANGE, "bytes=0-3".to_string()),
    ];
    if let Some(etag) = etag {
      conditions.push((header::IF_NONE_MATCH, etag));
    }
    for uri in ["/", "/unknown/route"] {
      for (name, value) in &conditions {
        let response = service
          .clone()
          .oneshot(
            Request::builder()
              .uri(uri)
              .header(name, value)
              .body(Body::empty())
              .unwrap(),
          )
          .await
          .unwrap();
        let context = format!("{uri} {name}: {value}");
        assert_eq!(response.status(), StatusCode::OK, "{context}");
        assert_eq!(
          response.headers()[header::CACHE_CONTROL],
          "no-cache",
          "{context}"
        );
        assert_eq!(
          body_string(Body::new(response.into_body())).await,
          "<html>index</html>",
          "{context}"
        );
      }
    }
  }
}

/// A vite style content hashed asset, big enough to compress.
const ASSET: &str = "assets/index-B3x9QzLm.js";

fn asset_contents() -> String {
  "export const answer = 42;\n".repeat(100)
}

fn get_request(
  uri: &str,
  accept_encoding: Option<&str>,
) -> Request<Body> {
  let mut request = Request::builder().uri(uri);
  if let Some(accept_encoding) = accept_encoding {
    request =
      request.header(header::ACCEPT_ENCODING, accept_encoding);
  }
  request.body(Body::empty()).unwrap()
}

/// Vite's hashed output may be kept for good: a new build names new
/// files. Nothing else may, least of all the index served for an
/// asset path without a file.
#[tokio::test]
async fn static_ui_assets_are_cached_for_good() {
  let dir = UiDir::new("static_ui_assets");
  std::fs::create_dir_all(dir.0.join("assets")).unwrap();
  std::fs::write(dir.0.join(ASSET), asset_contents()).unwrap();
  let service = serve_static_ui(dir.0.to_str().unwrap(), false);

  let response = service
    .clone()
    .oneshot(get_request(&format!("/{ASSET}"), None))
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  assert_eq!(
    response.headers()[header::CACHE_CONTROL],
    "public, max-age=31536000, immutable"
  );
  assert_eq!(
    body_string(response.into_body()).await,
    asset_contents()
  );

  // A missing asset is a 404, never the index, and not cached.
  let response = service
    .clone()
    .oneshot(get_request("/assets/index-Gone1234.js", None))
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::NOT_FOUND);
  assert!(!response.headers().contains_key(header::CACHE_CONTROL));
  assert!(body_string(response.into_body()).await.is_empty());

  // Other files are not hashed: no caching policy.
  let response = service
    .clone()
    .oneshot(get_request("/asset.js", None))
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  assert!(!response.headers().contains_key(header::CACHE_CONTROL));
  // The index keeps its own.
  let response = service
    .clone()
    .oneshot(get_request("/", None))
    .await
    .unwrap();
  assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
  // Directories under it are no files: 404, not an index or a
  // redirect.
  std::fs::create_dir_all(dir.0.join("assets/sub")).unwrap();
  std::fs::write(dir.0.join("assets/sub/index.html"), "sub").unwrap();
  for uri in ["/assets", "/assets/", "/assets/sub", "/assets/sub/"] {
    let response = service
      .clone()
      .oneshot(get_request(uri, None))
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    assert!(
      !response.headers().contains_key(header::CACHE_CONTROL),
      "{uri}"
    );
  }
}

/// The UI's scripts are compressed as the browser accepts, the app's
/// own routes around it are not.
#[tokio::test]
async fn static_ui_is_compressed() {
  use std::io::Read as _;
  let dir = UiDir::new("static_ui_compressed");
  std::fs::create_dir_all(dir.0.join("assets")).unwrap();
  std::fs::write(dir.0.join(ASSET), asset_contents()).unwrap();
  let index = format!("<html>{}</html>", "<p>index</p>".repeat(50));
  std::fs::write(dir.0.join("index.html"), &index).unwrap();
  let app = Router::new()
    .route("/api", get(async || "api ".repeat(100)))
    .fallback_service(serve_static_ui(
      dir.0.to_str().unwrap(),
      false,
    ));

  for (uri, contents) in [
    (format!("/{ASSET}"), asset_contents()),
    ("/".to_string(), index),
  ] {
    let response = app
      .clone()
      .oneshot(get_request(&uri, Some("gzip")))
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
    assert_eq!(response.headers()[header::VARY], "accept-encoding");
    let gzip = axum::body::to_bytes(response.into_body(), usize::MAX)
      .await
      .unwrap();
    assert!(gzip.len() < contents.len(), "{uri}");
    let mut decoded = String::new();
    flate2::read::GzDecoder::new(&gzip[..])
      .read_to_string(&mut decoded)
      .unwrap();
    assert_eq!(decoded, contents, "{uri}");

    // Brotli first, when the browser takes it.
    let response = app
      .clone()
      .oneshot(get_request(&uri, Some("gzip, deflate, br, zstd")))
      .await
      .unwrap();
    assert_eq!(response.headers()[header::CONTENT_ENCODING], "br");

    // Plain for a client asking for nothing.
    let response =
      app.clone().oneshot(get_request(&uri, None)).await.unwrap();
    assert!(
      !response.headers().contains_key(header::CONTENT_ENCODING)
    );
    assert_eq!(body_string(response.into_body()).await, contents);
  }

  let response = app
    .oneshot(get_request("/api", Some("gzip, br")))
    .await
    .unwrap();
  assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
  assert_eq!(
    body_string(response.into_body()).await,
    "api ".repeat(100)
  );
}

/// Collects what a test logs.
#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    self.0.lock().unwrap().extend_from_slice(buf);
    Ok(buf.len())
  }
  fn flush(&mut self) -> std::io::Result<()> {
    Ok(())
  }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
  type Writer = Captured;
  fn make_writer(&'a self) -> Captured {
    self.clone()
  }
}

/// Runs `f`, returning what it logged too.
fn logs_of<T>(f: impl FnOnce() -> T) -> (T, String) {
  let captured = Captured::default();
  let subscriber = tracing_subscriber::fmt()
    .with_writer(captured.clone())
    .with_ansi(false)
    .finish();
  let out = tracing::subscriber::with_default(subscriber, f);
  let logs = String::from_utf8(captured.0.lock().unwrap().clone());
  (out, logs.unwrap())
}

/// A wrong `ui_path` (or an install without the UI) used to answer
/// every page with an empty 200, and log nothing naming the cause.
#[tokio::test]
async fn static_ui_without_index_answers_404_and_logs_the_path() {
  let dir = UiDir::new("static_ui_no_index");
  let ui_path = dir.0.to_str().unwrap();
  let (_, logs) = logs_of(|| serve_static_ui(ui_path, false));
  assert!(!logs.contains("ERROR"), "{logs}");

  std::fs::remove_file(dir.0.join("index.html")).unwrap();
  for force_no_cache in [false, true] {
    let (service, logs) =
      logs_of(|| serve_static_ui(ui_path, force_no_cache));
    assert!(logs.contains("ERROR"), "{logs}");
    assert!(logs.contains(ui_path), "{logs}");
    for uri in ["/", "/unknown/route"] {
      let response = service
        .clone()
        .oneshot(
          Request::builder().uri(uri).body(Body::empty()).unwrap(),
        )
        .await
        .unwrap();
      assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
    // The files which are there are still served.
    let response = service
      .oneshot(
        Request::builder()
          .uri("/asset.js")
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
  }
}

#[derive(Default)]
struct Session {
  host: &'static str,
  cookie_domain: Option<&'static str>,
  allow_cross_site: bool,
  expiry_seconds: Option<i64>,
}

impl SessionConfig for Session {
  fn host(&self) -> &str {
    self.host
  }
  fn cookie_domain(&self) -> Option<&str> {
    self.cookie_domain
  }
  fn allow_cross_site(&self) -> bool {
    self.allow_cross_site
  }
  fn expiry_seconds(&self) -> i64 {
    self.expiry_seconds.unwrap_or(60 * 3)
  }
}

fn session_app(
  layer: mogh_server::session::SessionManagerLayer<
    MemorySessionStore,
  >,
) -> Router {
  Router::new()
    .route(
      "/",
      get(async |session: mogh_server::session::Session| {
        session.insert("counter", 1).await.unwrap();
        "ok"
      }),
    )
    .route(
      "/counter",
      get(async |session: mogh_server::session::Session| {
        session
          .get::<i32>("counter")
          .await
          .unwrap()
          .unwrap_or_default()
          .to_string()
      }),
    )
    .layer(layer)
}

/// The Set-Cookie of a request modifying the session
/// (without a session cookie).
async fn session_cookie(app: &Router) -> String {
  let response = app
    .clone()
    .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
    .await
    .unwrap();
  assert_eq!(response.status(), StatusCode::OK);
  response.headers()[header::SET_COOKIE]
    .to_str()
    .unwrap()
    .to_string()
}

async fn counter(app: &Router, cookie: &str) -> String {
  let cookie = cookie.split(';').next().unwrap();
  let response = app
    .clone()
    .oneshot(
      Request::builder()
        .uri("/counter")
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap(),
    )
    .await
    .unwrap();
  body_string(response.into_body()).await
}

#[tokio::test]
async fn session_layer_sets_cookie_for_modified_sessions() {
  let app = session_app(memory_session_layer(Session {
    host: "https://example.com",
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  // Host-only: not sent to (nor settable by) other subdomains.
  assert!(!cookie.contains("Domain="), "{cookie}");
  assert!(cookie.starts_with("__Host-id="), "{cookie}");
  assert!(cookie.contains("Path=/"), "{cookie}");
  assert!(cookie.contains("HttpOnly"), "{cookie}");
  assert!(cookie.contains("Secure"), "{cookie}");
  assert!(cookie.contains("SameSite=Lax"), "{cookie}");
  assert_eq!(counter(&app, &cookie).await, "1");

  // Plain http: no `__Host-` prefix (needs Secure).
  let app = session_app(memory_session_layer(Session {
    host: "http://example.com",
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  assert!(cookie.starts_with("id="), "{cookie}");
  assert!(!cookie.contains("Domain="), "{cookie}");
  assert!(!cookie.contains("Secure"), "{cookie}");
}

#[tokio::test]
async fn session_cookie_domain_is_opt_in() {
  let app = session_app(memory_session_layer(Session {
    host: "https://app.example.com",
    cookie_domain: Some("example.com"),
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  assert!(cookie.starts_with("id="), "{cookie}");
  assert!(cookie.contains("Domain=example.com"), "{cookie}");
  assert!(cookie.contains("Secure"), "{cookie}");
}

#[tokio::test]
async fn session_cookie_secure_follows_the_host_scheme() {
  let app = session_app(memory_session_layer(Session {
    host: "HTTPS://example.com",
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  assert!(cookie.contains("Secure"), "{cookie}");
}

#[tokio::test]
async fn cross_site_session_cookie_is_secure() {
  // Browsers reject SameSite=None without Secure,
  // and accept Secure cookies from localhost over http.
  let app = session_app(memory_session_layer(Session {
    host: "http://localhost:9220",
    allow_cross_site: true,
    ..Default::default()
  }));
  let cookie = session_cookie(&app).await;
  assert!(cookie.contains("SameSite=None"), "{cookie}");
  assert!(cookie.contains("Secure"), "{cookie}");
}

#[tokio::test]
async fn memory_sessions_are_bounded() {
  // Every request without a session cookie starting a
  // session (eg a login flow) must not grow memory forever.
  let store = MemorySessionStore::new(10);
  let app = session_app(session_layer(
    store.clone(),
    Session {
      host: "https://example.com",
      ..Default::default()
    },
  ));
  for _ in 0..100 {
    session_cookie(&app).await;
    assert!(store.len() <= 10, "{}", store.len());
  }
  // The most recent sessions keep working.
  let cookie = session_cookie(&app).await;
  assert_eq!(counter(&app, &cookie).await, "1");
}

#[tokio::test]
async fn memory_sessions_free_expired_sessions() {
  let store = MemorySessionStore::default();
  let app = session_app(session_layer(
    store.clone(),
    Session {
      host: "https://example.com",
      expiry_seconds: Some(1),
      ..Default::default()
    },
  ));
  let mut cookies = Vec::new();
  for _ in 0..5 {
    cookies.push(session_cookie(&app).await);
  }
  assert_eq!(store.len(), 5);
  tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
  // Loading an expired session removes it.
  assert_eq!(counter(&app, &cookies[0]).await, "0");
  assert_eq!(store.len(), 4);
  // And the sweep removes the rest.
  store.delete_expired().await.unwrap();
  assert!(store.is_empty());
}

struct Server {
  bind_ip: &'static str,
  x_frame_options: &'static str,
}

impl ServerConfig for Server {
  fn bind_ip(&self) -> &str {
    self.bind_ip
  }
  fn port(&self) -> u16 {
    41339
  }
  fn x_frame_options(&self) -> &str {
    self.x_frame_options
  }
}

#[tokio::test]
async fn serve_app_rejects_invalid_bind_address() {
  let error = mogh_server::serve_app(
    Router::new(),
    Server {
      bind_ip: "not an ip",
      x_frame_options: "DENY",
    },
    None,
  )
  .await
  .unwrap_err();
  assert!(
    error.to_string().contains("Failed to parse listen address")
  );
}

#[tokio::test]
async fn serve_app_rejects_invalid_header_values() {
  let error = mogh_server::serve_app(
    Router::new(),
    Server {
      bind_ip: "127.0.0.1",
      x_frame_options: "bad\nvalue",
    },
    None,
  )
  .await
  .unwrap_err();
  assert!(
    error.to_string().contains("Invalid x_frame_options value")
  );
}

struct ProxyServer(TrustedProxies);

impl ServerConfig for ProxyServer {
  fn port(&self) -> u16 {
    0
  }
  fn trusted_proxies(&self) -> anyhow::Result<TrustedProxies> {
    Ok(self.0.clone())
  }
}

/// Serves with the trusted proxies of a config list.
struct ProxyListServer(&'static [&'static str]);

impl ServerConfig for ProxyListServer {
  fn bind_ip(&self) -> &str {
    "127.0.0.1"
  }
  fn port(&self) -> u16 {
    0
  }
  fn trusted_proxies(&self) -> anyhow::Result<TrustedProxies> {
    TrustedProxies::from_config(self.0)
  }
}

/// An invalid list is a startup error naming the setting and the
/// entry, not a fallback (to `None`, a panic inside the server, or
/// a second parse in each app).
#[tokio::test]
async fn invalid_trusted_proxies_fail_the_startup() {
  let error = mogh_server::configure_app(
    Router::new(),
    &ProxyListServer(&["10.0.0.0/8", "not-a-range"]),
  )
  .unwrap_err();
  let error = format!("{error:#}");
  assert!(
    error.starts_with("Invalid 'trusted_proxies' config"),
    "{error}"
  );
  assert!(error.contains("not-a-range"), "{error}");

  let error = mogh_server::serve_app(
    Router::new(),
    ProxyListServer(&["all", "10.0.0.1"]),
    None,
  )
  .await
  .unwrap_err();
  assert!(
    format!("{error:#}")
      .starts_with("Invalid 'trusted_proxies' config"),
    "{error:#}"
  );

  // A valid list serves.
  assert!(
    mogh_server::configure_app(
      Router::new(),
      &ProxyListServer(&["private", "203.0.113.10"]),
    )
    .is_ok()
  );
}

/// Echoes the client ip resolved by the RequestIp extractor.
fn ip_app(trusted: TrustedProxies) -> Router {
  mogh_server::configure_app(
    Router::new().route(
      "/",
      get(async |mogh_request_ip::RequestIp(ip)| ip.to_string()),
    ),
    &ProxyServer(trusted),
  )
  .unwrap()
}

fn forwarded_request(peer: &str) -> Request<Body> {
  Request::builder()
    .uri("/")
    .header("x-forwarded-for", "203.0.113.7")
    .extension(axum::extract::ConnectInfo(
      format!("{peer}:1234")
        .parse::<std::net::SocketAddr>()
        .unwrap(),
    ))
    .body(Body::empty())
    .unwrap()
}

#[tokio::test]
async fn configure_app_attaches_trusted_proxies() {
  // Default: private peer is trusted, headers believed.
  let response = ip_app(TrustedProxies::default())
    .oneshot(forwarded_request("10.0.0.1"))
    .await
    .unwrap();
  assert_eq!(body_string(response.into_body()).await, "203.0.113.7");
  // Default: public peer is not trusted, headers ignored.
  let response = ip_app(TrustedProxies::default())
    .oneshot(forwarded_request("198.51.100.1"))
    .await
    .unwrap();
  assert_eq!(body_string(response.into_body()).await, "198.51.100.1");
  // Configured: the public proxy range is trusted.
  let response =
    ip_app(TrustedProxies::from_config(["198.51.100.0/24"]).unwrap())
      .oneshot(forwarded_request("198.51.100.1"))
      .await
      .unwrap();
  assert_eq!(body_string(response.into_body()).await, "203.0.113.7");
  // Configured none: even private peers are not trusted.
  let response = ip_app(TrustedProxies::None)
    .oneshot(forwarded_request("10.0.0.1"))
    .await
    .unwrap();
  assert_eq!(body_string(response.into_body()).await, "10.0.0.1");
  // Security headers still applied.
  let response = ip_app(TrustedProxies::default())
    .oneshot(forwarded_request("10.0.0.1"))
    .await
    .unwrap();
  assert_eq!(
    response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
    "DENY"
  );
}

struct TlsServer;

impl ServerConfig for TlsServer {
  fn bind_ip(&self) -> &str {
    "127.0.0.1"
  }
  fn port(&self) -> u16 {
    0
  }
  fn ssl_enabled(&self) -> bool {
    true
  }
  fn ssl_cert_file(&self) -> &str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls/cert.pem")
  }
  fn ssl_key_file(&self) -> &str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls/key.pem")
  }
}

#[tokio::test]
async fn serve_app_serves_https_with_both_rustls_providers() {
  // The rustls dev dependency enables 'ring' next to aws-lc-rs, as
  // apps also using mogh_auth_server do. rustls can't pick a crypto
  // provider from its features then, and used to panic on startup.
  let handle = mogh_server::axum_server::Handle::new();
  let mut server = tokio::spawn(mogh_server::serve_app(
    Router::new().route("/", get(async || "ok")),
    TlsServer,
    handle.clone(),
  ));
  let addr = tokio::select! {
    addr = handle.listening() => addr.expect("https server failed to bind"),
    res = &mut server => panic!("https server stopped: {res:?}"),
  };
  let client = reqwest::Client::builder()
    .tls_danger_accept_invalid_certs(true)
    .build()
    .unwrap();
  let response = client
    .get(format!("https://localhost:{}/", addr.port()))
    .send()
    .await
    .unwrap();
  assert_eq!(response.status(), reqwest::StatusCode::OK);
  assert_eq!(response.text().await.unwrap(), "ok");
  handle.shutdown();
  server.await.unwrap().unwrap();
}

#[tokio::test]
async fn serve_app_rejects_invalid_tls_files() {
  struct MissingTls;
  impl ServerConfig for MissingTls {
    fn bind_ip(&self) -> &str {
      "127.0.0.1"
    }
    fn port(&self) -> u16 {
      0
    }
    fn ssl_enabled(&self) -> bool {
      true
    }
    fn ssl_cert_file(&self) -> &str {
      concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls/key.pem")
    }
    fn ssl_key_file(&self) -> &str {
      concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls/missing.pem")
    }
  }
  let error = mogh_server::serve_app(Router::new(), MissingTls, None)
    .await
    .unwrap_err();
  let error = format!("{error:#}");
  assert!(error.contains("Invalid ssl cert / key"), "{error}");
  assert!(error.contains("No certificate"), "{error}");
}

/// Serves with a short header read timeout.
struct TimeoutServer {
  tls: bool,
}

const HEADER_READ_TIMEOUT: std::time::Duration =
  std::time::Duration::from_millis(300);

impl ServerConfig for TimeoutServer {
  fn bind_ip(&self) -> &str {
    "127.0.0.1"
  }
  fn port(&self) -> u16 {
    0
  }
  fn ssl_enabled(&self) -> bool {
    self.tls
  }
  fn ssl_cert_file(&self) -> &str {
    TlsServer.ssl_cert_file()
  }
  fn ssl_key_file(&self) -> &str {
    TlsServer.ssl_key_file()
  }
  fn header_read_timeout(&self) -> Option<std::time::Duration> {
    Some(HEADER_READ_TIMEOUT)
  }
}

/// Serves an app answering slowly (longer than the timeout).
async fn serve_with_timeout(
  tls: bool,
) -> (
  mogh_server::axum_server::Handle<std::net::SocketAddr>,
  std::net::SocketAddr,
) {
  let handle = mogh_server::axum_server::Handle::new();
  let mut server = tokio::spawn(mogh_server::serve_app(
    Router::new().route(
      "/",
      get(async || {
        tokio::time::sleep(HEADER_READ_TIMEOUT * 3).await;
        "ok"
      }),
    ),
    TimeoutServer { tls },
    handle.clone(),
  ));
  let addr = tokio::select! {
    addr = handle.listening() => addr.expect("server failed to bind"),
    res = &mut server => panic!("server stopped: {res:?}"),
  };
  (handle, addr)
}

/// Whether the server disconnected the client, which sent `sent`
/// and then nothing more, once the header read timeout passed.
async fn disconnects_after_sending(
  addr: std::net::SocketAddr,
  sent: &[u8],
) -> bool {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  let mut stream =
    tokio::net::TcpStream::connect(addr).await.unwrap();
  stream.write_all(sent).await.unwrap();
  let start = std::time::Instant::now();
  let mut response = Vec::new();
  let read = tokio::time::timeout(
    std::time::Duration::from_secs(5),
    stream.read_to_end(&mut response),
  )
  .await;
  // Closed (or reset) once the timeout passed, not before.
  read.is_ok() && start.elapsed() >= HEADER_READ_TIMEOUT / 2
}

/// The http/2 connection preface.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// An http/2 frame.
fn h2_frame(
  kind: u8,
  flags: u8,
  stream: u32,
  payload: &[u8],
) -> Vec<u8> {
  let mut frame = (payload.len() as u32).to_be_bytes()[1..].to_vec();
  frame.extend([kind, flags]);
  frame.extend(stream.to_be_bytes());
  frame.extend(payload);
  frame
}

/// An empty http/2 SETTINGS frame.
fn h2_settings() -> Vec<u8> {
  h2_frame(0x4, 0, 0, &[])
}

/// The client connection preface.
fn h2_start() -> Vec<u8> {
  [H2_PREFACE, &h2_settings()].concat()
}

/// A client which never finishes its headers (slowloris), or sends
/// nothing at all, used to hold the connection open forever: hyper
/// only applies a header read timeout with a timer, only to http/1,
/// and only once the server told http/1 from http/2.
#[tokio::test]
async fn serve_app_disconnects_clients_not_sending_headers() {
  let (handle, addr) = serve_with_timeout(false).await;
  for sent in [
    &b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: "[..],
    b"",
    b"P",
    // The start of the http/2 preface.
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n",
    // The http/2 preface, and no request.
    &h2_start(),
    // A HEADERS frame without END_HEADERS, never continued.
    &[h2_start(), h2_frame(0x1, 0x1, 1, &[0x82])].concat(),
    // A HEADERS frame ending the block (GET / over http), whose
    // payload never arrives whole.
    &[
      h2_start(),
      h2_frame(0x1, 0x5, 1, &[0x82, 0x86, 0x84])[..10].to_vec(),
    ]
    .concat(),
  ] {
    assert!(
      disconnects_after_sending(addr, sent).await,
      "{:?}",
      String::from_utf8_lossy(sent)
    );
  }

  // A request sent in time is answered, however long the handler
  // takes, and the connection is kept alive for the next one.
  let client = reqwest::Client::new();
  for _ in 0..2 {
    let response =
      client.get(format!("http://{addr}/")).send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "ok");
  }
  handle.shutdown();
}

/// An http/2 client which keeps sending frames, but never a
/// request's headers (eg. pings), used to hold the connection open.
#[tokio::test]
async fn serve_app_disconnects_http2_clients_only_pinging() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  let (handle, addr) = serve_with_timeout(false).await;
  let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
  let (mut read, mut write) = stream.into_split();
  write.write_all(&h2_start()).await.unwrap();
  let start = std::time::Instant::now();
  let pinging = tokio::spawn(async move {
    for ping in 0u64.. {
      tokio::time::sleep(std::time::Duration::from_millis(20)).await;
      let ping = h2_frame(0x6, 0, 0, &ping.to_be_bytes());
      if write.write_all(&ping).await.is_err() {
        break;
      }
    }
  });
  let mut received = Vec::new();
  let closed = tokio::time::timeout(
    std::time::Duration::from_secs(5),
    read.read_to_end(&mut received),
  )
  .await;
  assert!(closed.is_ok(), "still open");
  assert!(start.elapsed() >= HEADER_READ_TIMEOUT / 2);
  pinging.abort();
  handle.shutdown();
}

/// Requests over http/2 are answered however long the handler
/// takes, and later requests on the same connection too, however
/// long it was idle.
#[tokio::test]
async fn serve_app_answers_http2_requests() {
  let (handle, addr) = serve_with_timeout(false).await;
  let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
  let (client, connection) =
    h2::client::handshake(stream).await.unwrap();
  let connection = tokio::spawn(connection);
  let mut client = client.ready().await.unwrap();
  for idle in [false, true] {
    if idle {
      tokio::time::sleep(HEADER_READ_TIMEOUT * 2).await;
    }
    let request = Request::builder()
      .uri(format!("http://{addr}/"))
      .body(())
      .unwrap();
    let (response, _) = client.send_request(request, true).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let mut text = Vec::new();
    while let Some(data) = body.data().await {
      let data = data.unwrap();
      let _ = body.flow_control().release_capacity(data.len());
      text.extend_from_slice(&data);
    }
    assert_eq!(text, b"ok");
    client = client.ready().await.unwrap();
  }
  connection.abort();
  handle.shutdown();
}

/// Accepts any server certificate, for the self signed test one.
#[derive(Debug)]
struct AcceptAnyCert(std::sync::Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
  fn verify_server_cert(
    &self,
    _end_entity: &rustls::pki_types::CertificateDer<'_>,
    _intermediates: &[rustls::pki_types::CertificateDer<'_>],
    _server_name: &rustls::pki_types::ServerName<'_>,
    _ocsp_response: &[u8],
    _now: rustls::pki_types::UnixTime,
  ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error>
  {
    Ok(rustls::client::danger::ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &rustls::pki_types::CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
  ) -> Result<
    rustls::client::danger::HandshakeSignatureValid,
    rustls::Error,
  > {
    rustls::crypto::verify_tls12_signature(
      message,
      cert,
      dss,
      &self.0.signature_verification_algorithms,
    )
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &rustls::pki_types::CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
  ) -> Result<
    rustls::client::danger::HandshakeSignatureValid,
    rustls::Error,
  > {
    rustls::crypto::verify_tls13_signature(
      message,
      cert,
      dss,
      &self.0.signature_verification_algorithms,
    )
  }

  fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
    self.0.signature_verification_algorithms.supported_schemes()
  }
}

/// [serve_app_disconnects_clients_not_sending_headers], over TLS:
/// the timeout counts from the end of the handshake.
#[tokio::test]
async fn serve_app_disconnects_tls_clients_not_sending_headers() {
  let (handle, addr) = serve_with_timeout(true).await;
  for sent in [
    b"GET / HTTP/1.1\r\nHost: localhost\r\n".to_vec(),
    Vec::new(),
    h2_start(),
  ] {
    let shown = String::from_utf8_lossy(&sent).into_owned();
    let disconnected = tokio::task::spawn_blocking(move || {
      use std::io::{Read as _, Write as _};
      let provider = std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
      );
      let config =
        rustls::ClientConfig::builder_with_provider(provider.clone())
          .with_safe_default_protocol_versions()
          .unwrap()
          .dangerous()
          .with_custom_certificate_verifier(std::sync::Arc::new(
            AcceptAnyCert(provider),
          ))
          .with_no_client_auth();
      let connection = rustls::ClientConnection::new(
        std::sync::Arc::new(config),
        "localhost".try_into().unwrap(),
      )
      .unwrap();
      let socket = std::net::TcpStream::connect(addr).unwrap();
      socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
      let mut stream = rustls::StreamOwned::new(connection, socket);
      // Completes the handshake.
      stream.flush().unwrap();
      while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock).unwrap();
      }
      stream.write_all(&sent).unwrap();
      stream.flush().unwrap();
      let start = std::time::Instant::now();
      let mut response = Vec::new();
      let read = stream.read_to_end(&mut response);
      // Closed (without close_notify, or reset) rather than timing
      // out on the client side.
      let closed = match read {
        Ok(_) => true,
        Err(e) => !matches!(
          e.kind(),
          std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
        ),
      };
      closed && start.elapsed() >= HEADER_READ_TIMEOUT / 2
    })
    .await
    .unwrap();
    assert!(disconnected, "{shown:?}");
  }
  handle.shutdown();
}

/// Serves with a short request body timeout.
struct BodyTimeoutServer;

const REQUEST_BODY_TIMEOUT: std::time::Duration =
  std::time::Duration::from_millis(400);

impl ServerConfig for BodyTimeoutServer {
  fn bind_ip(&self) -> &str {
    "127.0.0.1"
  }
  fn port(&self) -> u16 {
    0
  }
  fn request_body_timeout(&self) -> Option<std::time::Duration> {
    Some(REQUEST_BODY_TIMEOUT)
  }
}

/// Serves an app answering with the length of the body it read.
/// `/late` first works longer than the timeout, then reads it, and
/// `GET /` reads none and takes longer than the timeout too.
async fn serve_with_body_timeout() -> (
  mogh_server::axum_server::Handle<std::net::SocketAddr>,
  std::net::SocketAddr,
) {
  let handle = mogh_server::axum_server::Handle::new();
  let mut server = tokio::spawn(mogh_server::serve_app(
    Router::new()
      .route(
        "/",
        get(async || {
          tokio::time::sleep(REQUEST_BODY_TIMEOUT * 2).await;
          "no body"
        })
        .post(async |body: String| body.len().to_string()),
      )
      .route(
        "/late",
        axum::routing::post(async |body: Body| {
          tokio::time::sleep(REQUEST_BODY_TIMEOUT * 2).await;
          axum::body::to_bytes(body, usize::MAX)
            .await
            .map(|body| body.len().to_string())
            .map_err(|_| StatusCode::BAD_REQUEST)
        }),
      ),
    BodyTimeoutServer,
    handle.clone(),
  ));
  let addr = tokio::select! {
    addr = handle.listening() => addr.expect("server failed to bind"),
    res = &mut server => panic!("server stopped: {res:?}"),
  };
  (handle, addr)
}

/// A client which sends the headers of a request in time, then its
/// body a byte now and then (slowloris one step later), used to hold
/// the connection and the handler reading the body forever: each
/// byte would reset an idle timeout.
#[tokio::test]
async fn serve_app_times_out_trickling_request_bodies() {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  let (handle, addr) = serve_with_body_timeout().await;
  let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
  let (mut read, mut write) = stream.into_split();
  write
    .write_all(
      b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n",
    )
    .await
    .unwrap();
  let start = std::time::Instant::now();
  let trickling = tokio::spawn(async move {
    loop {
      tokio::time::sleep(std::time::Duration::from_millis(50)).await;
      if write.write_all(b"x").await.is_err() {
        break;
      }
    }
  });
  let mut response = Vec::new();
  let closed = tokio::time::timeout(
    std::time::Duration::from_secs(5),
    read.read_to_end(&mut response),
  )
  .await;
  trickling.abort();
  // Answered, and the connection closed, once the deadline passed:
  // not before, and not reset by the bytes still coming.
  assert!(closed.is_ok(), "still open");
  let elapsed = start.elapsed();
  assert!(elapsed >= REQUEST_BODY_TIMEOUT, "{elapsed:?}");
  let response = String::from_utf8_lossy(&response).to_lowercase();
  assert!(
    response.starts_with("http/1.1 408 request timeout\r\n"),
    "{response}"
  );
  assert!(response.contains("connection: close\r\n"), "{response}");
  // The security headers are still applied.
  assert!(
    response.contains("x-frame-options: deny\r\n"),
    "{response}"
  );
  handle.shutdown();
}

/// [serve_app_times_out_trickling_request_bodies], over http/2.
#[tokio::test]
async fn serve_app_times_out_trickling_http2_request_bodies() {
  let (handle, addr) = serve_with_body_timeout().await;
  let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
  let (client, connection) =
    h2::client::handshake(stream).await.unwrap();
  let connection = tokio::spawn(connection);
  let mut client = client.ready().await.unwrap();
  let request = Request::builder()
    .method("POST")
    .uri(format!("http://{addr}/"))
    .body(())
    .unwrap();
  let (response, mut body) =
    client.send_request(request, false).unwrap();
  let start = std::time::Instant::now();
  let trickling = tokio::spawn(async move {
    loop {
      tokio::time::sleep(std::time::Duration::from_millis(50)).await;
      if body
        .send_data(axum::body::Bytes::from_static(b"x"), false)
        .is_err()
      {
        break;
      }
    }
  });
  let response =
    tokio::time::timeout(std::time::Duration::from_secs(5), response)
      .await
      .expect("no answer")
      .unwrap();
  trickling.abort();
  assert!(start.elapsed() >= REQUEST_BODY_TIMEOUT);
  assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
  connection.abort();
  handle.shutdown();
}

/// Bodies which arrive in time are read, even by a handler which
/// only gets to them after the timeout, and requests without a body
/// take as long as their handler does.
#[tokio::test]
async fn serve_app_reads_bodies_which_arrived_in_time() {
  let (handle, addr) = serve_with_body_timeout().await;
  let client = reqwest::Client::new();
  for path in ["/", "/late"] {
    let response = client
      .post(format!("http://{addr}{path}"))
      .body("x".repeat(1000))
      .send()
      .await
      .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK, "{path}");
    assert_eq!(response.text().await.unwrap(), "1000", "{path}");
  }
  let response =
    client.get(format!("http://{addr}/")).send().await.unwrap();
  assert_eq!(response.status(), reqwest::StatusCode::OK);
  assert_eq!(response.text().await.unwrap(), "no body");
  handle.shutdown();
}

/// A request body which never sends anything.
struct Silent;

impl axum::body::HttpBody for Silent {
  type Data = axum::body::Bytes;
  type Error = axum::Error;

  fn poll_frame(
    self: std::pin::Pin<&mut Self>,
    _: &mut std::task::Context<'_>,
  ) -> std::task::Poll<
    Option<Result<http_body::Frame<axum::body::Bytes>, axum::Error>>,
  > {
    std::task::Poll::Pending
  }
}

struct BodyTimeout(Option<std::time::Duration>);

impl ServerConfig for BodyTimeout {
  fn port(&self) -> u16 {
    0
  }
  fn request_body_timeout(&self) -> Option<std::time::Duration> {
    self.0
  }
}

/// [configure_app] applies the deadline (so apps serving the router
/// themselves get it too), and `None` waits without a limit.
#[tokio::test]
async fn configure_app_applies_the_request_body_timeout() {
  let app = |timeout| {
    mogh_server::configure_app(
      Router::new().route(
        "/",
        axum::routing::post(async |body: String| {
          body.len().to_string()
        }),
      ),
      &BodyTimeout(timeout),
    )
    .unwrap()
  };
  let silent = |version| {
    Request::builder()
      .method("POST")
      .uri("/")
      .version(version)
      .body(Body::new(Silent))
      .unwrap()
  };
  let timeout = Some(std::time::Duration::from_millis(50));
  for version in
    [axum::http::Version::HTTP_11, axum::http::Version::HTTP_2]
  {
    let response = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      app(timeout).oneshot(silent(version)),
    )
    .await
    .expect("no answer")
    .unwrap();
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    // http/2 has no connection header, its stream ends.
    assert_eq!(
      response.headers().get(header::CONNECTION).is_some(),
      version == axum::http::Version::HTTP_11
    );
  }
  let waiting = tokio::time::timeout(
    std::time::Duration::from_millis(300),
    app(None).oneshot(silent(axum::http::Version::HTTP_11)),
  )
  .await;
  assert!(waiting.is_err(), "answered without waiting for the body");
}
