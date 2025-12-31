#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum StdioLogMode {
  #[default]
  Standard,
  Json,
  None,
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

  /// Enable opentelemetry exporting.
  /// Empty string disables exporting.
  fn otlp_endpoint(&self) -> &str {
    ""
  }

  /// Set the OTEL service name for exported traces
  fn opentelemetry_service_name(&self) -> String {
    String::from("MoghApp")
  }

  /// Set the OTEL scope name for exported traces
  fn opentelemetry_scope_name(&self) -> String {
    String::from("MoghApp")
  }
}
