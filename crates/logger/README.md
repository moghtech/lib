# Mogh Logger

Configurable application level logger. Handles internals for multiple output modes including open telemetry.

## Config

`LoggingConfig` is the `logging` section of an application's config file, with
the fields, lowercase values and defaults Komodo and Cicada document (`level`,
`stdio`, `pretty`, `location`, `ansi`, `timestamps`, `otlp_endpoint`,
`opentelemetry_service_name`, `opentelemetry_scope_name`). Deserialize it with
the rest of the config, then add what only the application knows (`LogApp`: its
name, version and the targets to log) to initialize the logger:

```rust
use mogh_logger::{LogApp, LoggingConfig};

/// Usually next to the app's config types, shared by its binaries.
pub const LOG_APP: LogApp = LogApp {
  // The OTEL service / scope name when the config leaves them blank.
  name: "MyApp",
  version: Some(env!("CARGO_PKG_VERSION")),
  // Only these are logged, see `LogConfig::targets`.
  targets: &["my_app", "mogh_server", "mogh_auth_server"],
};

#[derive(serde::Deserialize)]
struct Config {
  #[serde(default)]
  logging: LoggingConfig,
}

// On application startup
mogh_logger::init(config.logging.with_app(LOG_APP))?;
```

`LogLevel` and `StdioLogMode` de/serialize lowercase (`"debug"`, `"json"`), and
`LogLevel` converts from a `tracing::Level` (eg. a `--log-level` argument).

The `init` feature (default) is the logger itself: `init`, `shutdown`, the
OpenTelemetry export and the trace context propagation. A crate which only holds
the config types (eg. an app's API client), or only needs
[`redact_url_credentials`](#urls-in-logs), depends on it with
`default-features = false`, which leaves out the OpenTelemetry crates and
`tracing-subscriber` (only `serde`, `tracing` and `url` remain).

The `LogConfig` trait is what `init` takes, implement it directly for config
from anywhere else:

```rust
struct Config;

// Sets output to JSON
impl mogh_logger::LogConfig for Config {
  fn stdio(&self) -> mogh_logger::StdioLogMode {
    mogh_logger::StdioLogMode::Json
  }

  fn targets(&self) -> &[String] {
    use std::sync::LazyLock;
    static TARGETS: LazyLock<Vec<String>> =
      LazyLock::new(|| {
        ["binary_name"].into_iter().map(str::to_string).collect()
      });
    &TARGETS
  }
}

// On application startup
mogh_logger::init(Config)?;
```

## OpenTelemetry export

`LogConfig::otlp_endpoint` turns on exporting traces to an
OpenTelemetry collector:

- It is the collector's **OTLP/HTTP** (protobuf) traces url, eg.
  `http://localhost:4318/v1/traces`. gRPC (port `4317`) is not
  supported. A url without a path (`http://localhost:4318`) gets the
  standard `/v1/traces`, one with a path is used as given. Empty (or
  whitespace only) disables exporting, and one without a scheme
  (`localhost:4318`) is an `init` error.
- Credentials in the url (`https://user:password@collector:4318`) are sent as
  basic auth (`Authorization: Basic`, percent-decoded, so percent-encode
  `@ : / ? # %` in them) to the url without them. `LoggingConfig`'s `Debug`
  redacts them, and the query, with
  [`redact_url_credentials`](#urls-in-logs). Its serialized form is not
  redacted: an app logging its config shows `otlp_endpoint` through it.
- An endpoint whose credentials url parsers can't tell apart is an `init`
  error, which doesn't quote it: an unencoded `/`, `?` or `#` in them ends the
  authority early, so the url doesn't parse (the password is read as the port)
  or its `@` sits after the host (the credentials are read as the host and the
  path), and extra slashes or a backslash after the scheme, or whitespace in
  them, read differently in different parsers. Exporting would otherwise send
  them in the url, or show them in the exporter's error. The exporter's own
  errors show the url it was given redacted.
- For a collector wanting another header (a bearer token, an api key), set
  `OTEL_EXPORTER_OTLP_HEADERS` (or `OTEL_EXPORTER_OTLP_TRACES_HEADERS`), which
  the exporter reads itself: comma separated `name=value` pairs, values
  percent-encoded, eg. `authorization=Bearer%20<token>`. An `authorization` set
  there wins over credentials in the url.
- Failed exports are logged under the `opentelemetry*` targets (eg.
  `ERROR name="BatchSpanProcessor.ExportError"`). While exporting
  these are let through at WARN, even when not in `targets`.
- Set `opentelemetry_service_version` to report the app's version as
  `service.version` (unset by default):

  ```rust
  fn opentelemetry_service_version(&self) -> Option<String> {
    Some(env!("CARGO_PKG_VERSION").into())
  }
  ```

- Spans are exported in batches every few seconds. Call
  `mogh_logger::shutdown()` before the process exits, including after
  a graceful shutdown signal, or the ones still queued are lost. It
  blocks until the export finishes, and is a no-op without an
  endpoint.

  ```rust
  mogh_logger::init(Config)?;
  let res = app().await;
  mogh_logger::shutdown()?;
  res
  ```

## Urls in logs

`redact_url_credentials` is the one rule for showing a url which may carry
credentials (a config value, an endpoint in an error message): its userinfo
and its query are each replaced whole by the marker the apps' sanitized
configs use, `##############`. Scheme, host, port, path and fragment stay for
debugging, and a url with neither is returned as it is.

```rust
use mogh_logger::redact_url_credentials;

assert_eq!(
  redact_url_credentials("postgres://app:hunter2@db:5432/app?sslmode=require"),
  "postgres://##############@db:5432/app?##############"
);
```

- Urls are read as http clients read them (the WHATWG url parser), so what
  a client would send as credentials is redacted (`http:user:password@host`,
  backslashes), and shown as the parser writes them (eg. a `/` added after the
  host).
- A password with an unencoded `/`, `?` or `#` ends the authority early, so
  the parser takes part of it for the host or the path. A string with an `@`
  past its authority, or which doesn't parse at all, is redacted up to its last
  `@` instead, with the marker left in front of what follows it
  (`https://example.com/users/@me` shows as `https://##############@me`), and
  as a whole when a `?` or `#` comes before that `@`. It redacts more than the
  credentials rather than guess where they end.
- ⚠️ The path is shown: a url whose path is the secret (most webhook urls)
  must not be logged at all.

## Trace context propagation

With `otlp_endpoint` set on both sides of a request, the caller
sends the W3C `traceparent` of its current span and the callee
parents its span under it, so both land in one trace:

```rust
// Caller: attach to the outgoing request, if this process is exporting.
if let Some(traceparent) = mogh_logger::current_traceparent() {
  request = request.header(mogh_logger::TRACEPARENT_HEADER, traceparent);
}

// Callee: before entering the span that handles the request.
// Only for trusted (eg. authenticated service to service) callers.
let span = tracing::info_span!(parent: None, "HandleRequest");
if let Some(traceparent) = headers
  .get(mogh_logger::TRACEPARENT_HEADER)
  .and_then(|value| value.to_str().ok())
{
  mogh_logger::set_remote_parent(&span, traceparent);
}
```

`TRACEPARENT_HEADER` is there without the `init` feature too, for a client
crate which sends the header (the value comes from `current_traceparent` in the
binary).

An inbound `traceparent` is whatever the caller sent: honoring it
lets the caller pick the trace your spans join. Only honor it from
trusted callers (your own services, authenticated as such). Public
traffic (browsers, api keys) should start a fresh trace, as the
[W3C Trace Context security considerations](https://www.w3.org/TR/trace-context/#security-considerations)
recommend.

`opentelemetry` and `tracing_opentelemetry` are re-exported for
anything beyond this, so they always match the layer's version.
