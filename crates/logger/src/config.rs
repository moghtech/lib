use std::fmt;

use serde::{Deserialize, Serialize};

/// The format of the logs written to stdout / stderr. De /
/// serializes lowercase (`"standard"`, `"json"`, `"none"`), as the
/// apps' config files spell it.
#[derive(
  Debug,
  Clone,
  Copy,
  Default,
  PartialEq,
  Eq,
  Hash,
  Serialize,
  Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum StdioLogMode {
  /// Human readable lines, see [LogConfig::pretty].
  #[default]
  Standard,
  /// One JSON object per log.
  Json,
  /// Nothing is written to stdout / stderr.
  None,
}

/// De/serializable log level enum, lowercase (`"info"`).
/// Converts to and from [tracing::Level].
#[derive(
  Debug,
  Clone,
  Copy,
  Default,
  PartialEq,
  Eq,
  Hash,
  Serialize,
  Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
  Trace,
  Debug,
  #[default]
  Info,
  Warn,
  Error,
}

impl From<LogLevel> for tracing::Level {
  fn from(value: LogLevel) -> Self {
    match value {
      LogLevel::Trace => tracing::Level::TRACE,
      LogLevel::Debug => tracing::Level::DEBUG,
      LogLevel::Info => tracing::Level::INFO,
      LogLevel::Warn => tracing::Level::WARN,
      LogLevel::Error => tracing::Level::ERROR,
    }
  }
}

/// Matches the [tracing::Level] constants, eg. for a `--log-level`
/// CLI argument parsed as a level. Not through
/// [tracing::Level::as_str], which is uppercase (`"DEBUG"`): a
/// lowercase match on it falls through for every level.
impl From<tracing::Level> for LogLevel {
  fn from(value: tracing::Level) -> Self {
    match value {
      tracing::Level::TRACE => LogLevel::Trace,
      tracing::Level::DEBUG => LogLevel::Debug,
      tracing::Level::INFO => LogLevel::Info,
      tracing::Level::WARN => LogLevel::Warn,
      tracing::Level::ERROR => LogLevel::Error,
    }
  }
}

pub trait LogConfig {
  /// The logging level.
  fn level(&self) -> tracing::Level {
    tracing::Level::INFO
  }

  /// Controls logging format to stdout / stderr
  fn stdio(&self) -> StdioLogMode {
    StdioLogMode::Standard
  }

  /// Use tracing-subscriber's pretty logging output option.
  fn pretty(&self) -> bool {
    false
  }

  /// Include information about the log location (ie the function which produced the log).
  /// Tracing refers to this as the 'target'.
  fn location(&self) -> bool {
    false
  }

  /// Logs use ansi colors for readability.
  fn ansi(&self) -> bool {
    true
  }

  /// Include timestamps with logs
  fn timestamps(&self) -> bool {
    true
  }

  /// Enable opentelemetry exporting.
  /// An empty (or whitespace only) string disables exporting.
  ///
  /// The collector's OTLP/HTTP (protobuf) traces url, eg
  /// `http://localhost:4318/v1/traces`. gRPC (port 4317) is not
  /// supported. A url with a path is used as given, and one without
  /// (`http://localhost:4318`) gets the standard `/v1/traces`. One
  /// without a scheme (`localhost:4318`) is an `init` error.
  ///
  /// Credentials in the url (`https://user:password@collector:4318`)
  /// are sent as basic auth (`Authorization: Basic`), not in the url,
  /// percent-decoded: percent-encode `@ : / ? # %` in them. For other
  /// schemes (a bearer token, an api key header) set
  /// `OTEL_EXPORTER_OTLP_HEADERS` (eg.
  /// `authorization=Bearer%20<token>`), which wins over them.
  ///
  /// Failed exports are logged at WARN / ERROR under the
  /// `opentelemetry*` targets (ie `opentelemetry_sdk`), which
  /// `init` lets through while exporting even when they are not in
  /// [targets](LogConfig::targets). Call `shutdown` before exiting,
  /// or the spans still queued are lost.
  fn otlp_endpoint(&self) -> &str {
    ""
  }

  /// Set the OTEL service name for exported traces
  fn opentelemetry_service_name(&self) -> String {
    String::from("MoghApp")
  }

  /// Set the OTEL `service.version` for exported traces, usually
  /// `Some(env!("CARGO_PKG_VERSION").into())` in the application
  /// crate. `None` (the default) leaves it unset, so
  /// `OTEL_RESOURCE_ATTRIBUTES` can still supply it.
  fn opentelemetry_service_version(&self) -> Option<String> {
    None
  }

  /// Set the OTEL scope name for exported traces
  fn opentelemetry_scope_name(&self) -> String {
    String::from("MoghApp")
  }

  /// Specify which module targets (eg the current binary) are included.
  ///
  /// ⚠️ Everything else is filtered out, including the default: with
  /// no targets (the default here) nothing is logged at all.
  ///
  /// ```rust
  /// struct MyConfig;
  ///
  /// impl mogh_logger::LogConfig for MyConfig {
  ///   fn targets(&self) -> &[String] {
  ///     use std::sync::LazyLock;
  ///     static TARGETS: LazyLock<Vec<String>> =
  ///       LazyLock::new(|| {
  ///         ["binary_name"].into_iter().map(str::to_string).collect()
  ///       });
  ///     &TARGETS
  ///   }
  /// }
  /// ```
  fn targets(&self) -> &[String] {
    &[]
  }
}

/// The `logging` section of an application's config file: the
/// operator's side of [LogConfig], with the field names, the
/// lowercase values and the defaults Komodo and Cicada document.
/// Deserialize it with the rest of the config (a missing field gets
/// its default), then pair it with the application's own side
/// ([LogApp]) to initialize the logger:
///
/// ```rust
/// use mogh_logger::{LogApp, LoggingConfig};
///
/// const LOG_APP: LogApp = LogApp {
///   name: "MyApp",
///   version: Some(env!("CARGO_PKG_VERSION")),
///   targets: &["my_app", "mogh_server"],
/// };
///
/// let logging: LoggingConfig =
///   serde_json::from_str(r#"{ "level": "debug", "stdio": "json" }"#)
///     .unwrap();
/// let config = logging.with_app(LOG_APP);
/// // mogh_logger::init(config)?;
/// ```
///
/// Available without the `init` feature (no OpenTelemetry crates),
/// so an API client crate can hold the config types.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
  /// The logging level. Default: `info`.
  pub level: LogLevel,

  /// The format of the logs written to stdout / stderr, `none`
  /// writes none. Default: `standard`.
  pub stdio: StdioLogMode,

  /// Use tracing-subscriber's pretty logging output option, where
  /// one log spans several lines. Default: `false`.
  pub pretty: bool,

  /// Include the location of each log (the module which logged
  /// it), what tracing calls the target. Default: `false`.
  pub location: bool,

  /// Color the logs with ANSI codes. Default: `true`.
  pub ansi: bool,

  /// Start each log with a timestamp. Default: `true`.
  pub timestamps: bool,

  /// The collector's OTLP/HTTP (protobuf) traces url to export
  /// traces to, see [LogConfig::otlp_endpoint]. Empty (the default)
  /// exports nothing. Credentials in it are sent as basic auth, and
  /// redacted from this struct's `Debug` (the query too). Its
  /// serialized form is not redacted: an app logging its config
  /// shows this field with
  /// [redact_url_credentials](crate::redact_url_credentials).
  pub otlp_endpoint: String,

  /// The OTEL service name of the exported traces. Empty (the
  /// default) uses the application's [LogApp::name].
  pub opentelemetry_service_name: String,

  /// The OTEL scope name of the exported traces. Empty (the
  /// default) uses the application's [LogApp::name].
  pub opentelemetry_scope_name: String,
}

impl Default for LoggingConfig {
  fn default() -> Self {
    LoggingConfig {
      level: LogLevel::default(),
      stdio: StdioLogMode::default(),
      pretty: false,
      location: false,
      ansi: true,
      timestamps: true,
      otlp_endpoint: String::new(),
      opentelemetry_service_name: String::new(),
      opentelemetry_scope_name: String::new(),
    }
  }
}

/// The credentials an [otlp_endpoint](LoggingConfig::otlp_endpoint)
/// may carry (`https://user:password@collector`, a key in its query)
/// are redacted, see [redact_url_credentials](crate::redact_url_credentials).
impl fmt::Debug for LoggingConfig {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("LoggingConfig")
      .field("level", &self.level)
      .field("stdio", &self.stdio)
      .field("pretty", &self.pretty)
      .field("location", &self.location)
      .field("ansi", &self.ansi)
      .field("timestamps", &self.timestamps)
      .field(
        "otlp_endpoint",
        &crate::redact_url_credentials(&self.otlp_endpoint),
      )
      .field(
        "opentelemetry_service_name",
        &self.opentelemetry_service_name,
      )
      .field(
        "opentelemetry_scope_name",
        &self.opentelemetry_scope_name,
      )
      .finish()
  }
}

/// What only the application knows about its logging, next to the
/// operator's [LoggingConfig]: usually a `const` in the crate
/// holding the app's config types, shared by its binaries.
#[derive(Debug, Clone, Copy)]
pub struct LogApp<'a> {
  /// The OTEL service and scope name when the config leaves them
  /// blank, eg. `"Komodo"`.
  pub name: &'a str,
  /// The OTEL `service.version`, usually
  /// `Some(env!("CARGO_PKG_VERSION"))`, see
  /// [LogConfig::opentelemetry_service_version].
  pub version: Option<&'a str>,
  /// The module targets logged, everything else is filtered out,
  /// see [LogConfig::targets]. List the binaries and the library
  /// crates whose logs the app wants (eg. `mogh_server`,
  /// `mogh_auth_server`).
  pub targets: &'a [&'a str],
}

impl LoggingConfig {
  /// This config with the application's side, the [LogConfig]
  /// `init` takes.
  pub fn with_app<'a>(&'a self, app: LogApp<'a>) -> AppLogConfig<'a> {
    AppLogConfig {
      config: self,
      app,
      targets: app.targets.iter().map(|t| t.to_string()).collect(),
    }
  }
}

/// A [LoggingConfig] with its [LogApp], see
/// [LoggingConfig::with_app].
#[derive(Debug, Clone)]
pub struct AppLogConfig<'a> {
  config: &'a LoggingConfig,
  app: LogApp<'a>,
  /// [LogApp::targets], in the form [LogConfig::targets] returns.
  targets: Vec<String>,
}

impl AppLogConfig<'_> {
  /// `configured`, unless blank: the app's name then.
  fn name_or_app(&self, configured: &str) -> String {
    match configured.trim() {
      "" => self.app.name.to_string(),
      configured => configured.to_string(),
    }
  }
}

impl LogConfig for AppLogConfig<'_> {
  fn level(&self) -> tracing::Level {
    self.config.level.into()
  }
  fn stdio(&self) -> StdioLogMode {
    self.config.stdio
  }
  fn pretty(&self) -> bool {
    self.config.pretty
  }
  fn location(&self) -> bool {
    self.config.location
  }
  fn ansi(&self) -> bool {
    self.config.ansi
  }
  fn timestamps(&self) -> bool {
    self.config.timestamps
  }
  fn otlp_endpoint(&self) -> &str {
    &self.config.otlp_endpoint
  }
  fn opentelemetry_service_name(&self) -> String {
    self.name_or_app(&self.config.opentelemetry_service_name)
  }
  fn opentelemetry_service_version(&self) -> Option<String> {
    self.app.version.map(str::to_string)
  }
  fn opentelemetry_scope_name(&self) -> String {
    self.name_or_app(&self.config.opentelemetry_scope_name)
  }
  fn targets(&self) -> &[String] {
    &self.targets
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn log_level_parses_lowercase() {
    for (json, expected) in [
      ("\"trace\"", LogLevel::Trace),
      ("\"debug\"", LogLevel::Debug),
      ("\"info\"", LogLevel::Info),
      ("\"warn\"", LogLevel::Warn),
      ("\"error\"", LogLevel::Error),
    ] {
      let parsed: LogLevel = serde_json::from_str(json).unwrap();
      assert_eq!(parsed, expected);
      assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
    }
    // Non lowercase variants are rejected
    assert!(serde_json::from_str::<LogLevel>("\"Info\"").is_err());
  }

  #[test]
  fn log_level_default_is_info() {
    assert_eq!(LogLevel::default(), LogLevel::Info);
  }

  #[test]
  fn log_level_into_tracing_level() {
    assert_eq!(
      tracing::Level::from(LogLevel::Trace),
      tracing::Level::TRACE
    );
    assert_eq!(
      tracing::Level::from(LogLevel::Debug),
      tracing::Level::DEBUG
    );
    assert_eq!(
      tracing::Level::from(LogLevel::Info),
      tracing::Level::INFO
    );
    assert_eq!(
      tracing::Level::from(LogLevel::Warn),
      tracing::Level::WARN
    );
    assert_eq!(
      tracing::Level::from(LogLevel::Error),
      tracing::Level::ERROR
    );
  }

  /// Every level comes back as itself. A match on the uppercase
  /// `as_str` turned all of them into `Info`, so a `--log-level
  /// debug` argument ran at info.
  #[test]
  fn log_level_from_tracing_level() {
    for level in [
      LogLevel::Trace,
      LogLevel::Debug,
      LogLevel::Info,
      LogLevel::Warn,
      LogLevel::Error,
    ] {
      assert_eq!(LogLevel::from(tracing::Level::from(level)), level);
    }
  }

  /// Lowercase, as the apps' config files and environment
  /// variables spell it (`KOMODO_LOGGING_STDIO=json`).
  #[test]
  fn stdio_log_mode_parses_lowercase() {
    for (json, expected) in [
      ("\"standard\"", StdioLogMode::Standard),
      ("\"json\"", StdioLogMode::Json),
      ("\"none\"", StdioLogMode::None),
    ] {
      let parsed: StdioLogMode = serde_json::from_str(json).unwrap();
      assert_eq!(parsed, expected);
      assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
    }
    assert!(
      serde_json::from_str::<StdioLogMode>("\"Standard\"").is_err()
    );
    assert_eq!(StdioLogMode::default(), StdioLogMode::Standard);
  }

  #[test]
  fn log_config_defaults() {
    struct Default_;
    impl LogConfig for Default_ {}
    let config = Default_;
    assert_eq!(config.level(), tracing::Level::INFO);
    assert_eq!(config.stdio(), StdioLogMode::Standard);
    assert!(!config.pretty());
    assert!(!config.location());
    assert!(config.ansi());
    assert!(config.timestamps());
    assert!(config.otlp_endpoint().is_empty());
    assert!(config.opentelemetry_service_version().is_none());
    assert!(config.targets().is_empty());
  }

  /// A missing section, or missing fields, get the defaults the
  /// apps document.
  #[test]
  fn logging_config_defaults_match_the_apps() {
    let parsed: LoggingConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(parsed, LoggingConfig::default());
    assert_eq!(parsed.level, LogLevel::Info);
    assert_eq!(parsed.stdio, StdioLogMode::Standard);
    assert!(!parsed.pretty);
    assert!(!parsed.location);
    assert!(parsed.ansi);
    assert!(parsed.timestamps);
    assert!(parsed.otlp_endpoint.is_empty());
    assert!(parsed.opentelemetry_service_name.is_empty());
    assert!(parsed.opentelemetry_scope_name.is_empty());

    let parsed: LoggingConfig =
      serde_json::from_str(r#"{ "ansi": false, "level": "warn" }"#)
        .unwrap();
    assert!(!parsed.ansi);
    assert!(parsed.timestamps);
    assert_eq!(parsed.level, LogLevel::Warn);
  }

  /// The `logging` section of Komodo's / Cicada's example config
  /// files, every field named as there.
  #[test]
  fn logging_config_parses_the_app_config_section() {
    let parsed: LoggingConfig =
      serde_json::from_value(serde_json::json!({
        "level": "debug",
        "stdio": "json",
        "pretty": true,
        "location": true,
        "ansi": false,
        "timestamps": false,
        "otlp_endpoint": "http://localhost:4318/v1/traces",
        "opentelemetry_service_name": "Periphery",
        "opentelemetry_scope_name": "Komodo",
      }))
      .unwrap();
    assert_eq!(
      parsed,
      LoggingConfig {
        level: LogLevel::Debug,
        stdio: StdioLogMode::Json,
        pretty: true,
        location: true,
        ansi: false,
        timestamps: false,
        otlp_endpoint: String::from(
          "http://localhost:4318/v1/traces"
        ),
        opentelemetry_service_name: String::from("Periphery"),
        opentelemetry_scope_name: String::from("Komodo"),
      }
    );
    // And back.
    let round_trip: LoggingConfig =
      serde_json::from_value(serde_json::to_value(&parsed).unwrap())
        .unwrap();
    assert_eq!(round_trip, parsed);
    // A value in the wrong case is an error, not the default.
    assert!(
      serde_json::from_str::<LoggingConfig>(r#"{ "stdio": "Json" }"#)
        .is_err()
    );
  }

  const APP: LogApp = LogApp {
    name: "TestApp",
    version: Some("1.2.3"),
    targets: &["test_app", "mogh_server"],
  };

  #[test]
  fn with_app_adds_the_application_side() {
    let logging = LoggingConfig {
      level: LogLevel::Debug,
      stdio: StdioLogMode::None,
      pretty: true,
      location: true,
      ansi: false,
      timestamps: false,
      otlp_endpoint: String::from("http://otel:4318"),
      ..Default::default()
    };
    let config = logging.with_app(APP);
    assert_eq!(config.level(), tracing::Level::DEBUG);
    assert_eq!(config.stdio(), StdioLogMode::None);
    assert!(config.pretty());
    assert!(config.location());
    assert!(!config.ansi());
    assert!(!config.timestamps());
    assert_eq!(config.otlp_endpoint(), "http://otel:4318");
    assert_eq!(config.targets(), ["test_app", "mogh_server"]);
    assert_eq!(
      config.opentelemetry_service_version().as_deref(),
      Some("1.2.3")
    );
    // Blank names are the app's.
    assert_eq!(config.opentelemetry_service_name(), "TestApp");
    assert_eq!(config.opentelemetry_scope_name(), "TestApp");
  }

  #[test]
  fn logging_config_debug_redacts_endpoint_credentials() {
    let logging = LoggingConfig {
      otlp_endpoint: String::from(
        "https://otel:hunter2@collector:4318/v1/traces?api_key=s3cr3t",
      ),
      ..Default::default()
    };
    for debug in [
      format!("{logging:?}"),
      format!("{:?}", logging.with_app(APP)),
    ] {
      assert!(!debug.contains("hunter2"), "{debug}");
      assert!(!debug.contains("s3cr3t"), "{debug}");
      assert!(
        debug.contains(
          "https://##############@collector:4318/v1/traces?##############"
        ),
        "{debug}"
      );
    }
  }

  #[test]
  fn with_app_keeps_the_configured_names() {
    let logging = LoggingConfig {
      opentelemetry_service_name: String::from(" Periphery "),
      opentelemetry_scope_name: String::from("Scope"),
      ..Default::default()
    };
    let config = logging.with_app(LogApp {
      version: None,
      ..APP
    });
    assert_eq!(config.opentelemetry_service_name(), "Periphery");
    assert_eq!(config.opentelemetry_scope_name(), "Scope");
    assert!(config.opentelemetry_service_version().is_none());
    // Whitespace only counts as blank.
    let logging = LoggingConfig {
      opentelemetry_service_name: String::from(" \t"),
      ..Default::default()
    };
    assert_eq!(
      logging.with_app(APP).opentelemetry_service_name(),
      "TestApp"
    );
  }
}
