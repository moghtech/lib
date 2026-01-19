use anyhow::Context;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
  filter::Targets, layer::SubscriberExt as _, util::SubscriberInitExt,
};

mod config;
mod otel;

pub use config::*;

pub fn init(config: impl config::LogConfig) -> anyhow::Result<()> {
  let mut filter_targets =
    Targets::new().with_default(LevelFilter::OFF);

  for target in config.targets() {
    filter_targets =
      filter_targets.with_target(target, config.level());
  }

  let registry = tracing_subscriber::registry().with(filter_targets);

  let use_otel = !config.otlp_endpoint().is_empty();

  match (config.stdio(), use_otel, config.pretty()) {
    (StdioLogMode::Standard, true, true) => registry
      .with(
        tracing_subscriber::fmt::layer()
          .pretty()
          .with_file(false)
          .with_line_number(false)
          .with_target(config.location())
          .with_ansi(config.ansi()),
      )
      .with(otel::layer(config))
      .try_init(),
    (StdioLogMode::Standard, true, false) => registry
      .with(
        tracing_subscriber::fmt::layer()
          .with_file(false)
          .with_line_number(false)
          .with_target(config.location())
          .with_ansi(config.ansi()),
      )
      .with(otel::layer(config))
      .try_init(),

    (StdioLogMode::Json, true, _) => registry
      .with(tracing_subscriber::fmt::layer().json())
      .with(otel::layer(config))
      .try_init(),

    (StdioLogMode::Standard, false, true) => registry
      .with(
        tracing_subscriber::fmt::layer()
          .pretty()
          .with_file(false)
          .with_line_number(false)
          .with_target(config.location())
          .with_ansi(config.ansi()),
      )
      .try_init(),
    (StdioLogMode::Standard, false, false) => registry
      .with(
        tracing_subscriber::fmt::layer()
          .with_file(false)
          .with_line_number(false)
          .with_target(config.location())
          .with_ansi(config.ansi()),
      )
      .try_init(),

    (StdioLogMode::Json, false, _) => registry
      .with(tracing_subscriber::fmt::layer().json())
      .try_init(),

    (StdioLogMode::None, true, _) => {
      registry.with(otel::layer(config)).try_init()
    }
    (StdioLogMode::None, false, _) => Ok(()),
  }
  .context("failed to init logger")
}
