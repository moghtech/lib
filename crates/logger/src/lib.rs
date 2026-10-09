//! Configurable application level logger using tracing: stdio
//! (standard / pretty / json) and an OTLP/HTTP trace export.
//!
//! The `init` feature (default) is the logger itself: `init`,
//! `shutdown` and the trace context propagation. Without it
//! (`default-features = false`) the crate is only the config types
//! ([LoggingConfig], [LogLevel], [StdioLogMode], the [LogConfig]
//! trait) and [redact_url_credentials], without the OpenTelemetry
//! crates, for a crate which holds an application's config without
//! installing its logger (eg. its API client).

#[cfg(feature = "init")]
use {
  anyhow::Context,
  tracing::level_filters::LevelFilter,
  tracing_subscriber::{
    Layer, filter::Targets, layer::SubscriberExt as _,
    util::SubscriberInitExt,
  },
};

mod config;
mod endpoint;
#[cfg(feature = "init")]
mod otel;
#[cfg(feature = "init")]
mod trace_context;

pub use config::*;
pub use endpoint::redact_url_credentials;
#[cfg(feature = "init")]
pub use trace_context::*;

/// The HTTP header a request carries its W3C trace context in, see
/// `current_traceparent` / `set_remote_parent` (`init` feature).
pub const TRACEPARENT_HEADER: &str = "traceparent";

/// The OpenTelemetry crates the exporting layer is built on,
/// re-exported so applications needing more than the helpers above
/// (span attributes, status, links via
/// `tracing_opentelemetry::OpenTelemetrySpanExt`) use the very
/// version the layer does. A second version would not see it.
#[cfg(feature = "init")]
pub use opentelemetry;
#[cfg(feature = "init")]
pub use tracing_opentelemetry;

/// Installs the global logger. Call once, on startup.
///
/// With an [otlp_endpoint](LogConfig::otlp_endpoint), also call
/// [shutdown] before the process exits.
#[cfg(feature = "init")]
pub fn init(config: impl config::LogConfig) -> anyhow::Result<()> {
  let use_otel = otel::enabled(config.otlp_endpoint());

  // Only the configured targets are logged, so without any the app
  // is silent. The logger isn't up yet, this has to go to stderr.
  if config.targets().is_empty()
    && (config.stdio() != StdioLogMode::None || use_otel)
  {
    eprintln!(
      "WARN: mogh_logger: 'LogConfig::targets' is empty, nothing will be logged. Add the targets to include, eg. the name of the binary."
    );
  }

  // Not printing the endpoint, it may carry credentials.
  if use_otel && otel::uses_grpc_port(config.otlp_endpoint()) {
    eprintln!(
      "WARN: mogh_logger: 'LogConfig::otlp_endpoint' uses port 4317, the OTLP gRPC port. mogh_logger exports OTLP/HTTP (protobuf), usually on port 4318, eg. http://localhost:4318/v1/traces."
    );
  }

  let registry = tracing_subscriber::registry()
    .with(filter_targets(&config, use_otel));

  // Boxing the stdio layer keeps a single init path
  // across the different formatter configurations.
  let stdio_layer: Option<Box<dyn Layer<_> + Send + Sync>> =
    match config.stdio() {
      StdioLogMode::Standard => {
        if config.pretty() {
          let layer = tracing_subscriber::fmt::layer()
            .pretty()
            .with_file(false)
            .with_line_number(false)
            .with_target(config.location())
            .with_ansi(config.ansi());
          Some(if config.timestamps() {
            layer.boxed()
          } else {
            layer.without_time().boxed()
          })
        } else {
          let layer = tracing_subscriber::fmt::layer()
            .with_file(false)
            .with_line_number(false)
            .with_target(config.location())
            .with_ansi(config.ansi());
          Some(if config.timestamps() {
            layer.boxed()
          } else {
            layer.without_time().boxed()
          })
        }
      }
      StdioLogMode::Json => {
        let layer = tracing_subscriber::fmt::layer().json();
        Some(if config.timestamps() {
          layer.boxed()
        } else {
          layer.without_time().boxed()
        })
      }
      StdioLogMode::None => None,
    };

  let (otel_layer, otel_provider) = if use_otel {
    let (layer, provider) =
      otel::layer(&config).context("failed to init otel exporter")?;
    (Some(layer), Some(provider))
  } else {
    (None, None)
  };

  if stdio_layer.is_none() && otel_layer.is_none() {
    // Nothing to log to, leave the subscriber uninitialized.
    return Ok(());
  }

  registry
    .with(stdio_layer)
    .with(otel_layer)
    .try_init()
    .context("failed to init logger")?;

  // Only once the subscriber is in: on failure the provider drops,
  // which stops its export thread.
  if let Some(provider) = otel_provider {
    otel::install(provider);
  }

  Ok(())
}

/// Exports the spans still queued for the
/// [otlp_endpoint](LogConfig::otlp_endpoint) and stops the
/// exporter. Call it before the process exits (after a graceful
/// shutdown signal too): the exporter sends in batches every few
/// seconds, and whatever is still queued at exit is lost otherwise.
///
/// Blocks the calling thread until the export finishes (a few
/// seconds at most). Spans after it are not exported. A no-op
/// without an OTLP endpoint, or when already called.
#[cfg(feature = "init")]
pub fn shutdown() -> anyhow::Result<()> {
  otel::shutdown()
}

/// Only the configured targets are logged, at the configured
/// level. While exporting, the OpenTelemetry crates' own warnings
/// and errors (eg. a failed export) are let through too, unless the
/// app configures those targets itself.
#[cfg(feature = "init")]
fn filter_targets(
  config: &impl config::LogConfig,
  use_otel: bool,
) -> Targets {
  let mut filter_targets =
    Targets::new().with_default(LevelFilter::OFF);

  if use_otel
    && !config.targets().iter().any(|target| {
      otel::INTERNAL_TARGET.starts_with(target.as_str())
    })
  {
    filter_targets = filter_targets.with_target(
      otel::INTERNAL_TARGET,
      config.level().min(tracing::Level::WARN),
    );
  }

  for target in config.targets() {
    filter_targets =
      filter_targets.with_target(target, config.level());
  }

  filter_targets
}

#[cfg(all(test, feature = "init"))]
mod tests {
  use tracing::Level;

  use super::*;

  struct Config {
    otlp_endpoint: &'static str,
    level: Level,
    targets: Vec<String>,
  }

  impl LogConfig for Config {
    fn level(&self) -> Level {
      self.level
    }
    fn otlp_endpoint(&self) -> &str {
      self.otlp_endpoint
    }
    fn targets(&self) -> &[String] {
      &self.targets
    }
  }

  fn config(level: Level, targets: &[&str]) -> Config {
    Config {
      otlp_endpoint: "http://localhost:4318/v1/traces",
      level,
      targets: targets.iter().map(|t| t.to_string()).collect(),
    }
  }

  /// A failed export is logged under the SDK's target, which the
  /// app rarely lists: while exporting it must still get through.
  #[test]
  fn filter_lets_otel_diagnostics_through_while_exporting() {
    let config = config(Level::INFO, &["my_app"]);
    let filter = filter_targets(&config, true);
    for target in ["opentelemetry_sdk", "opentelemetry-otlp"] {
      assert!(filter.would_enable(target, &Level::ERROR), "{target}");
      assert!(filter.would_enable(target, &Level::WARN), "{target}");
      assert!(!filter.would_enable(target, &Level::INFO), "{target}");
    }
    assert!(filter.would_enable("my_app", &Level::INFO));
    assert!(!filter.would_enable("other_crate", &Level::ERROR));

    // Not exporting, nothing to report.
    let filter = filter_targets(&config, false);
    assert!(!filter.would_enable("opentelemetry_sdk", &Level::ERROR));
  }

  /// A whitespace endpoint (eg. a blank templated env value) with
  /// stdio off leaves nothing to log to: no exporter to a url the
  /// operator never gave. The only test here calling `init`, keep
  /// it that way (it checks the global dispatcher).
  #[test]
  fn init_with_blank_endpoint_does_not_export() {
    struct Blank;
    impl LogConfig for Blank {
      fn stdio(&self) -> StdioLogMode {
        StdioLogMode::None
      }
      fn otlp_endpoint(&self) -> &str {
        "  \t"
      }
    }
    init(Blank).unwrap();
    assert!(!tracing::dispatcher::has_been_set());
    // Nothing installed to shut down.
    shutdown().unwrap();
  }

  #[test]
  fn filter_otel_diagnostics_respect_the_app_config() {
    // A stricter app level applies to them too.
    let filter =
      filter_targets(&config(Level::ERROR, &["my_app"]), true);
    assert!(filter.would_enable("opentelemetry_sdk", &Level::ERROR));
    assert!(!filter.would_enable("opentelemetry_sdk", &Level::WARN));
    // Targets the app lists itself keep its level.
    let filter = filter_targets(
      &config(Level::DEBUG, &["my_app", "opentelemetry"]),
      true,
    );
    assert!(filter.would_enable("opentelemetry_sdk", &Level::DEBUG));
    let filter = filter_targets(
      &config(Level::DEBUG, &["my_app", "opentelemetry_sdk"]),
      true,
    );
    assert!(filter.would_enable("opentelemetry_sdk", &Level::DEBUG));
    assert!(filter.would_enable("opentelemetry-otlp", &Level::WARN));
    assert!(
      !filter.would_enable("opentelemetry-otlp", &Level::DEBUG)
    );
  }
}
