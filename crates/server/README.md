# Mogh Server

Configurable axum server including TLS, Session, CORS, common security headers, and static file hosting.

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

// Pass an `axum_server::Handle` instead of `None`
// for graceful shutdown.
mogh_server::serve_app(app, Config, None).await?;
```

`serve_app` applies the security headers (`X-Content-Type-Options`,
`X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, optional
`Content-Security-Policy`) and the `ServerConfig::trusted_proxies` layer, which
decides which socket peers may set the client ip through `X-Forwarded-For` /
`X-Real-IP`. `ServerConfig::trusted_proxies` returns a `Result`: pipe the
config list through `TrustedProxies::from_config`, and an invalid entry fails
the startup ("Invalid 'trusted_proxies' config") instead of falling back to
another policy. Use `configure_app` to apply the same layers when serving the
app yourself.

`serve_app` disconnects clients which don't send the headers of a request within
`ServerConfig::header_read_timeout` (default 30 seconds, `None` to wait without
a limit), so a client can't hold a connection open by sending nothing, or its
headers slowly (slowloris). The first request's headers are due that long after
the connection is accepted (after the TLS handshake), over http/1 and http/2
alike. After that:

- On a kept alive http/1 connection, the next request's headers are due that
  long after the previous response, so idle kept alive connections are closed.
- On an http/2 connection, each later request's headers must arrive whole within
  that long of their start. An idle http/2 connection (no request pending) stays
  open as long as the client answers the keep alive pings `serve_app` sends
  every 20 seconds: hyper's http/2 server has no idle timeout.

The body of a request then has `ServerConfig::request_body_timeout` (default 60
seconds, `None` to wait without a limit) to arrive whole, counted from the end of
its headers. It is a deadline for the whole body, not an idle timeout reset by
each piece, so a client can't hold the connection and the handler reading the
body by sending it a byte now and then. When it passes with the body still
coming, reading the body fails and the request is answered `408 Request Timeout`
(closing an http/1 connection). What already arrived is still read after it, so
a handler which works a while before reading a body that came in time doesn't
fail. Requests without a body and upgraded connections (websockets, CONNECT
tunnels) are not affected. Raise it (or `None`) when clients send large bodies
over slow links, eg. uploads. `configure_app` applies it too.

These bound how long each connection can wait for a request, not how many
connections there are: front the app with a proxy to limit those, and to close
idle http/2 connections.

⚠️ The default trusted proxies are all loopback and private addresses, not only
the proxy. When public clients can reach the app from a private address (a port
published through Docker's userland proxy, rootless Docker / Podman, Kubernetes
SNAT, hosts on the same network / VPN), they choose their own ip. Narrow it to
the proxy address with `TrustedProxies::from_config`, or `TrustedProxies::None`
when nothing is in front of the app.

### TLS

With `ssl_enabled`, the PEM cert / key files are served with rustls, using the
crypto provider the app installed as process default
(`CryptoProvider::install_default`), else aws-lc-rs. This also works when both
of rustls' `ring` and `aws-lc-rs` features end up in the binary (eg together
with `mogh_auth_server`), where rustls can't pick one by itself.

### Session

`session::memory_session_layer` adds the session layer used by the Mogh Auth
login flows, backed by `session::MemorySessionStore`:

- Sessions expire after `expiry_seconds` of inactivity (default 3 minutes).
  Expired sessions are removed from memory (when loaded, and swept at most once
  a minute when sessions are saved).
- The store holds at most `max_sessions` (default 10,000). When full, the
  sessions closest to expiry are evicted, so clients starting sessions without
  authentication (eg login flows) can't grow the memory without limit.
- The cookie is host-only (no `Domain` attribute), and named with the
  `__Host-` prefix on https hosts, so other subdomains neither receive nor
  set it. Set `cookie_domain` only if several subdomains must share the
  session.
- `SameSite=Lax`, or `None` with `allow_cross_site` (UI development), which
  also makes the cookie `Secure` as browsers require. That works on https
  hosts and `localhost`, not on other plain http hosts.

`session::session_layer` configures the same cookie for another
`SessionStore`.

### CORS

`cors::cors_layer` allows the configured origins, with credentials by default.
⚠️ `*` with credentials mirrors any request origin: any site can then make
requests carrying the user's cookies and read the responses. List the exact
origins instead, or disable credentials.

### OpenAPI docs

With the `openapi` feature, `openapi::serve_docs(title, &spec)` serves the
[Scalar](https://github.com/scalar/scalar) API reference at `/docs`, and the
spec it renders (anything serializing to an OpenAPI document, eg utoipa's
`OpenApi`) at `/docs/openapi.json`. The spec is serialized, gzipped and hashed
once, and served with `Cache-Control: no-cache` and the content hash as `ETag`,
so a large spec is revalidated (an empty 304) rather than downloaded on every
load of the docs. The page hides Scalar's models section for the same reason,
and sends "Send request" straight to the server rather than through Scalar's
proxy. See `src/openapi/README.md` to bump the pinned Scalar version.

### Static UI

`ui::serve_static_ui` serves a static UI directory, answering paths without a
file (`/`, client side routes) with its `index.html`. The index is always served
in full with `Cache-Control: no-cache` and the content hash as `ETag`, so
browsers pick up a new UI right after an upgrade. Without an `index.html` (a
wrong `ui_path`, an install without the UI) those paths answer 404, and an error
naming `ui_path` is logged on startup.

The files under `/assets` (vite's content hashed build output, its default
`build.assetsDir`) are served with
`Cache-Control: public, max-age=31536000, immutable`: a new build names new
files, so browsers keep these without revalidating them. A path under `/assets`
without a file is a 404 rather than the index. The static UI's responses are
compressed (brotli or gzip, as the browser accepts), for the UI's multi-MB
scripts. Only the UI service is: the app's api around it (eg. streamed
responses) is left as it is.
