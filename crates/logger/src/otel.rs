use std::{
  collections::HashMap,
  sync::{Mutex, PoisonError},
  time::Duration,
};

use anyhow::{Context as _, anyhow};
use opentelemetry::{KeyValue, global, trace::TracerProvider};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
  Resource,
  trace::{Sampler, SdkTracerProvider},
};
use opentelemetry_semantic_conventions::resource::SERVICE_VERSION;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{Layer, registry::LookupSpan};

use crate::endpoint::{
  parsed_exactly, redact_url_credentials, split_url, split_userinfo,
};

/// The target prefix of the OpenTelemetry crates' own diagnostics
/// (`opentelemetry_sdk`, `opentelemetry-otlp`, ...), eg the batch
/// processor's export errors.
pub const INTERNAL_TARGET: &str = "opentelemetry";

/// The standard OTLP/HTTP traces path.
const TRACES_PATH: &str = "/v1/traces";

/// The OTLP gRPC port, which this exporter can't talk to.
const GRPC_PORT: &str = "4317";

/// How to write credentials which every reader finds where they
/// are, for the refusals of [check_credentials].
const ENCODE_CREDENTIALS: &str =
  "percent-encode '@ : / ? # %' in its user and password";

/// The provider [init](crate::init) installed, kept for
/// [shutdown]. Only the global subscriber holds it otherwise, and
/// that is never dropped.
static PROVIDER: Mutex<Option<SdkTracerProvider>> = Mutex::new(None);

/// Whether the endpoint turns exporting on. A blank one (empty or
/// only whitespace, eg. an unset templated env value) disables it:
/// given to the exporter, it would fall back to
/// `OTEL_EXPORTER_OTLP_ENDPOINT` or localhost instead.
pub fn enabled(endpoint: &str) -> bool {
  !endpoint.trim().is_empty()
}

/// The exporting layer, and its provider to [install] once the
/// subscriber is.
pub fn layer<S>(
  config: &impl crate::LogConfig,
) -> anyhow::Result<(impl Layer<S>, SdkTracerProvider)>
where
  S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
  let endpoint = config.otlp_endpoint();
  anyhow::ensure!(enabled(endpoint), "otlp endpoint is blank");
  let endpoint = endpoint.trim();
  // Without a scheme the credentials can't be told apart, and the
  // exporter's error would quote the endpoint whole. Not quoting it
  // here either.
  anyhow::ensure!(
    split_url(endpoint).is_some(),
    "otlp endpoint has no scheme, it must start with http:// or https://"
  );
  check_credentials(endpoint)?;

  let (url, authorization) = exporter_endpoint(endpoint);
  let mut exporter = opentelemetry_otlp::SpanExporter::builder()
    .with_http()
    .with_endpoint(url.clone())
    .with_timeout(Duration::from_secs(3));
  if let Some(authorization) = authorization {
    // OTEL_EXPORTER_OTLP_(TRACES_)HEADERS are applied after these,
    // an `authorization` there wins.
    exporter = exporter.with_headers(HashMap::from([(
      String::from("authorization"),
      authorization,
    )]));
  }
  let exporter = exporter
    .build()
    .map_err(|e| exporter_build_error(&e, &url))?;

  let provider =
    opentelemetry_sdk::trace::TracerProviderBuilder::default()
      .with_resource(resource(config))
      .with_sampler(Sampler::AlwaysOn)
      .with_batch_exporter(exporter)
      .build();

  let layer = OpenTelemetryLayer::new(
    provider.tracer(config.opentelemetry_scope_name()),
  )
  .with_tracked_inactivity(false)
  .with_threads(false)
  .with_target(false);

  Ok((layer, provider))
}

/// Refuses, without quoting it, an endpoint whose credentials the
/// exporter wouldn't send as the url says.
///
/// An unencoded `/`, `?` or `#` in them ends the authority early, so
/// the `@` after them sits past the host: the url doesn't parse (the
/// password is read as the port), or parses with the credentials as
/// the host and the path. Given to the exporter, they would be in its
/// error, or in the url of every export. Credentials which url parsers
/// read differently from the string split of [exporter_endpoint]
/// (slashes or a backslash after the scheme, a tab) would be sent
/// wrong, or with the url, too. The url crate reads urls as http
/// clients do (the WHATWG url standard), and as
/// [redact_url_credentials] does.
fn check_credentials(endpoint: &str) -> anyhow::Result<()> {
  // The parser's errors name the kind of problem
  // ("invalid port number"), never the input.
  let parsed = url::Url::parse(endpoint).map_err(|e| {
    anyhow!(
      "otlp endpoint is not a valid url ({e}), {ENCODE_CREDENTIALS}"
    )
  })?;
  anyhow::ensure!(
    parsed_exactly(&parsed),
    "otlp endpoint has an '@' after its host, {ENCODE_CREDENTIALS}"
  );
  // Both percent-encoded, as basic_authorization takes them.
  let userinfo = match parsed.password() {
    Some(password) => format!("{}:{password}", parsed.username()),
    None => parsed.username().to_string(),
  };
  anyhow::ensure!(
    exporter_endpoint(endpoint).1 == basic_authorization(&userinfo),
    "otlp endpoint's credentials are read differently by url parsers, write it as scheme://user:password@host:port/path and {ENCODE_CREDENTIALS}"
  );
  Ok(())
}

/// The exporter's build error without the url it was given, which
/// its errors quote (`invalid endpoint '<url>': ..`). [layer] took
/// the credentials out of it, its query may still hold a token:
/// shown as [redact_url_credentials] shows it.
fn exporter_build_error(
  error: &impl std::fmt::Display,
  url: &str,
) -> anyhow::Error {
  anyhow!(
    "failed to build otlp span exporter: {}",
    error.to_string().replace(url, &redact_url_credentials(url))
  )
}

/// Makes `provider` the global tracer provider and keeps it for
/// [shutdown].
pub fn install(provider: SdkTracerProvider) {
  global::set_tracer_provider(provider.clone());
  *PROVIDER.lock().unwrap_or_else(PoisonError::into_inner) =
    Some(provider);
}

/// Exports the spans still queued and stops the exporter. A no-op
/// when nothing is installed, or it already ran.
pub fn shutdown() -> anyhow::Result<()> {
  let provider = PROVIDER
    .lock()
    .unwrap_or_else(PoisonError::into_inner)
    .take();
  match provider {
    Some(provider) => provider
      .shutdown()
      .context("failed to shut down otel exporter"),
    None => Ok(()),
  }
}

/// The resource the traces are exported under. `service.version`
/// is only set when the app gives one: a value set here would also
/// override `OTEL_RESOURCE_ATTRIBUTES`.
fn resource(config: &impl crate::LogConfig) -> Resource {
  let resource = Resource::builder()
    .with_service_name(config.opentelemetry_service_name());
  match config.opentelemetry_service_version() {
    Some(version) => resource
      .with_attribute(KeyValue::new(SERVICE_VERSION, version))
      .build(),
    None => resource.build(),
  }
}

/// The url the exporter posts to ([traces_endpoint]) without the
/// credentials it may carry (`https://user:password@collector`), and
/// the `Authorization` header they become. The exporter sends a url
/// as given, it never turns its userinfo into a header, so a
/// collector behind basic auth would refuse every export.
fn exporter_endpoint(endpoint: &str) -> (String, Option<String>) {
  let url = traces_endpoint(endpoint);
  match split_userinfo(&url) {
    Some((before, userinfo, after)) => {
      (format!("{before}{after}"), basic_authorization(userinfo))
    }
    None => (url, None),
  }
}

/// The `Basic` (RFC 7617) `Authorization` value of a url's
/// userinfo, `user:password` percent-decoded as in a url. `None`
/// when both are empty (`https://@collector`).
fn basic_authorization(userinfo: &str) -> Option<String> {
  let (user, password) =
    userinfo.split_once(':').unwrap_or((userinfo, ""));
  if user.is_empty() && password.is_empty() {
    return None;
  }
  let mut credentials = percent_decode(user);
  credentials.push(b':');
  credentials.extend(percent_decode(password));
  Some(format!(
    "Basic {}",
    data_encoding::BASE64.encode(&credentials)
  ))
}

/// Decodes the `%XX` escapes of `input` into the bytes they stand
/// for. A `%` not followed by two hex digits stays as it is, as in
/// browsers.
fn percent_decode(input: &str) -> Vec<u8> {
  fn hex(digit: u8) -> Option<u8> {
    (digit as char).to_digit(16).map(|value| value as u8)
  }
  let bytes = input.as_bytes();
  let mut decoded = Vec::with_capacity(bytes.len());
  let mut index = 0;
  while index < bytes.len() {
    if bytes[index] == b'%'
      && let Some(&[high, low]) = bytes.get(index + 1..index + 3)
      && let (Some(high), Some(low)) = (hex(high), hex(low))
    {
      decoded.push(high << 4 | low);
      index += 3;
    } else {
      decoded.push(bytes[index]);
      index += 1;
    }
  }
  decoded
}

/// The url the exporter posts to. A base url without a path
/// (`http://localhost:4318`) gets the standard `/v1/traces`, like
/// `OTEL_EXPORTER_OTLP_ENDPOINT` does. One with a path is used as
/// given.
fn traces_endpoint(endpoint: &str) -> String {
  let endpoint = endpoint.trim();
  match split_url(endpoint) {
    Some((base, "" | "/", suffix)) => {
      format!("{base}{TRACES_PATH}{suffix}")
    }
    // Anything else as given, including no scheme (which [layer]
    // refuses).
    _ => endpoint.to_string(),
  }
}

/// Whether the endpoint names the OTLP gRPC port. The exporter
/// speaks OTLP/HTTP only, so it would fail every export.
pub fn uses_grpc_port(endpoint: &str) -> bool {
  let Some((base, _, _)) = split_url(endpoint.trim()) else {
    return false;
  };
  let authority = base
    .split_once("://")
    .map_or(base, |(_, authority)| authority);
  let host = authority
    .rsplit_once('@')
    .map_or(authority, |(_, host)| host);
  // An IPv6 host without a port ends in ']'.
  host
    .rsplit_once(':')
    .is_some_and(|(_, port)| port == GRPC_PORT)
}

#[cfg(test)]
mod tests {
  use opentelemetry::Key;

  use super::*;

  #[test]
  fn traces_endpoint_adds_the_traces_path_to_a_base_url() {
    for (endpoint, expected) in [
      ("http://localhost:4318", "http://localhost:4318/v1/traces"),
      ("http://localhost:4318/", "http://localhost:4318/v1/traces"),
      (" https://otel:4318 ", "https://otel:4318/v1/traces"),
      ("http://[::1]:4318", "http://[::1]:4318/v1/traces"),
      (
        "https://user:pass@otel:4318?key=value",
        "https://user:pass@otel:4318/v1/traces?key=value",
      ),
      // A path is used as given.
      (
        "http://localhost:4318/v1/traces",
        "http://localhost:4318/v1/traces",
      ),
      ("https://vendor/otlp/traces", "https://vendor/otlp/traces"),
      // Without a scheme, as given ([layer] refuses it).
      ("localhost:4318", "localhost:4318"),
      (
        "http://localhost:4318/custom?key=value",
        "http://localhost:4318/custom?key=value",
      ),
    ] {
      assert_eq!(traces_endpoint(endpoint), expected, "{endpoint}");
    }
  }

  /// The credentials leave the url and become basic auth,
  /// percent-decoded.
  #[test]
  fn exporter_endpoint_sends_credentials_as_basic_auth() {
    let basic = |credentials: &[u8]| {
      Some(format!(
        "Basic {}",
        data_encoding::BASE64.encode(credentials)
      ))
    };
    for (endpoint, url, authorization) in [
      (
        "http://localhost:4318",
        "http://localhost:4318/v1/traces",
        None,
      ),
      (
        " https://user:pass@otel:4318?key=value ",
        "https://otel:4318/v1/traces?key=value",
        // RFC 7617's example encoding.
        Some(String::from("Basic dXNlcjpwYXNz")),
      ),
      (
        "https://otel%40corp:hunter%3A2%2F@otel/custom",
        "https://otel/custom",
        basic(b"otel@corp:hunter:2/"),
      ),
      // Only a user (a token), the password is empty.
      (
        "https://token@otel",
        "https://otel/v1/traces",
        basic(b"token:"),
      ),
      // Nothing to send.
      ("https://@otel", "https://otel/v1/traces", None),
      ("https://:@otel", "https://otel/v1/traces", None),
      // Not escapes: kept as they are.
      (
        "https://u:p%zz%4@otel",
        "https://otel/v1/traces",
        basic(b"u:p%zz%4"),
      ),
      // Escaped UTF-8 is sent as its bytes.
      (
        "https://us%C3%A9r:pass@otel",
        "https://otel/v1/traces",
        basic("usér:pass".as_bytes()),
      ),
      // An unencoded `@` in the password still splits at the last.
      (
        "https://user:p@ss@[::1]:4318",
        "https://[::1]:4318/v1/traces",
        basic(b"user:p@ss"),
      ),
    ] {
      assert_eq!(
        exporter_endpoint(endpoint),
        (url.to_string(), authorization),
        "{endpoint}"
      );
    }
  }

  /// An endpoint without a scheme would reach the exporter with its
  /// credentials, whose error quotes it.
  #[test]
  fn endpoint_without_a_scheme_is_refused_unquoted() {
    let Err(error) = layer::<tracing_subscriber::Registry>(
      &EndpointConfig("user:hunter2@otel:4318"),
    ) else {
      panic!("built an exporter for an endpoint without a scheme");
    };
    let error = format!("{error:#}");
    assert!(error.contains("no scheme"), "{error}");
    assert!(!error.contains("hunter2"), "{error}");
  }

  /// An unencoded `/`, `?` or `#` in the credentials ends the
  /// authority early: the `@` after them sits past the host, and
  /// the url doesn't parse (the password is read as the port), or
  /// parses with the credentials as the host and the path. Handed to
  /// the exporter whole, its error (or the requests it sends) would
  /// show them. So would credentials which url parsers find where
  /// the exporter's url isn't split (slashes after the scheme), and
  /// credentials read differently by the two are not sent. Each is
  /// refused before the exporter is built, without quoting the
  /// endpoint.
  #[test]
  fn endpoint_with_unreadable_credentials_is_refused_unquoted() {
    for (endpoint, secrets, reason) in [
      (
        "https://otel:s3cr3t/p4rt@collector:4318",
        &["s3cr3t", "p4rt"][..],
        "invalid port number",
      ),
      (
        "https://otel:s3cr3t?p4rt@collector:4318",
        &["s3cr3t", "p4rt"],
        "invalid port number",
      ),
      (
        "https://otel:s3cr3t#p4rt@collector:4318",
        &["s3cr3t", "p4rt"],
        "invalid port number",
      ),
      (
        "https://otel:1234/s3cr3t@collector:4318",
        &["s3cr3t"],
        "'@' after its host",
      ),
      (
        "https://otel:1234?s3cr3t@collector:4318",
        &["s3cr3t"],
        "'@' after its host",
      ),
      (
        "https://otel:1234#s3cr3t@collector:4318",
        &["s3cr3t"],
        "'@' after its host",
      ),
      (
        "https://s3cr3t/p4rt@collector:4318/v1/traces",
        &["s3cr3t", "p4rt"],
        "'@' after its host",
      ),
      (
        "https:///otel:s3cr3t@collector:4318",
        &["s3cr3t"],
        "read differently",
      ),
      (
        "https://\\otel:s3cr3t@collector:4318",
        &["s3cr3t"],
        "read differently",
      ),
      (
        "https://otel:s3\tcr3t@collector:4318",
        &["s3", "cr3t"],
        "read differently",
      ),
    ] {
      let Err(error) = layer::<tracing_subscriber::Registry>(
        &EndpointConfig(endpoint),
      ) else {
        panic!("built an exporter for {endpoint:?}");
      };
      let error = format!("{error:#}");
      assert!(error.contains(reason), "{endpoint:?}: {error}");
      assert!(
        error.contains("percent-encode"),
        "{endpoint:?}: {error}"
      );
      for secret in secrets {
        assert!(!error.contains(secret), "{endpoint:?}: {error}");
      }
    }
  }

  /// The exporter's own errors quote the url it was given, whose
  /// query may hold a token. The url in them is redacted.
  #[test]
  fn exporter_errors_do_not_quote_the_endpoint() {
    // Url parsers read it (the space percent-encoded), the
    // exporter's refuses it.
    let Err(error) =
      layer::<tracing_subscriber::Registry>(&EndpointConfig(
        "https://collector:4318/v1 traces?token=s3cr3t",
      ))
    else {
      panic!("built an exporter for a path with a space");
    };
    let error = format!("{error:#}");
    assert!(!error.contains("s3cr3t"), "{error}");
    assert!(
      error.contains(
        "https://collector:4318/v1%20traces?##############"
      ),
      "{error}"
    );
  }

  /// The credentials still reach the exporter as basic auth, whatever
  /// their characters, once they are percent-encoded.
  #[test]
  fn endpoint_with_encoded_credentials_builds() {
    for endpoint in [
      "https://otel:s3cr3t@collector:4318",
      "https://otel%40corp:s3%2Fcr%3F3t%23@collector:4318/v1/traces",
      "https://otel:p@ss@collector:4318",
      "https://token@collector",
      "https://:s3cr3t@[::1]:4318?key=value",
      " http://localhost:4318 ",
    ] {
      let built = layer::<tracing_subscriber::Registry>(
        &EndpointConfig(endpoint),
      );
      assert!(
        built.is_ok(),
        "{endpoint:?}: {:#}",
        built.err().unwrap()
      );
    }
  }

  #[test]
  fn uses_grpc_port_detects_port_4317() {
    for endpoint in [
      "http://localhost:4317",
      "http://localhost:4317/v1/traces",
      "https://user:pass@otel:4317?key=value",
      "http://[::1]:4317",
    ] {
      assert!(uses_grpc_port(endpoint), "{endpoint}");
    }
    for endpoint in [
      "http://localhost:4318/v1/traces",
      "http://localhost/4317",
      "http://[2001:db8::4317]",
      "https://otel",
      "localhost:4317",
    ] {
      assert!(!uses_grpc_port(endpoint), "{endpoint}");
    }
  }

  struct EndpointConfig(&'static str);

  impl crate::LogConfig for EndpointConfig {
    fn otlp_endpoint(&self) -> &str {
      self.0
    }
  }

  /// Given a blank endpoint, the exporter falls back to the env or
  /// localhost: blank has to mean off, and never reach it.
  #[test]
  fn blank_endpoint_disables_exporting() {
    for endpoint in ["", " ", "  \t\n"] {
      assert!(!enabled(endpoint), "{endpoint:?}");
      let built = layer::<tracing_subscriber::Registry>(
        &EndpointConfig(endpoint),
      );
      assert!(built.is_err(), "{endpoint:?}");
    }
    assert!(enabled("http://localhost:4318"));
    assert!(enabled(" http://localhost:4318 "));
  }

  struct Config(Option<&'static str>);

  impl crate::LogConfig for Config {
    fn opentelemetry_service_name(&self) -> String {
      String::from("TestApp")
    }
    fn opentelemetry_service_version(&self) -> Option<String> {
      self.0.map(str::to_string)
    }
  }

  #[test]
  fn resource_reports_the_app_service_version() {
    let service_version = Key::from_static_str(SERVICE_VERSION);
    let with_version = resource(&Config(Some("2.3.0")));
    assert_eq!(
      with_version.get(&service_version).map(|v| v.to_string()),
      Some(String::from("2.3.0"))
    );
    assert_eq!(
      with_version
        .get(&Key::from_static_str("service.name"))
        .map(|v| v.to_string()),
      Some(String::from("TestApp"))
    );
    // Not the logger crate's own version.
    assert!(resource(&Config(None)).get(&service_version).is_none());
  }
}
