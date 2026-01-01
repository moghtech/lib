use std::time::Duration;

use opentelemetry::{KeyValue, global, trace::TracerProvider};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, trace::Sampler};
use opentelemetry_semantic_conventions::resource::SERVICE_VERSION;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{Layer, registry::LookupSpan};

pub fn layer<S>(config: impl crate::LogConfig) -> impl Layer<S>
where
  S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
  let provider =
    opentelemetry_sdk::trace::TracerProviderBuilder::default()
      .with_resource(
        Resource::builder()
          .with_service_name(config.opentelemetry_service_name())
          .with_attribute(KeyValue::new(
            SERVICE_VERSION,
            env!("CARGO_PKG_VERSION"),
          ))
          .build(),
      )
      .with_sampler(Sampler::AlwaysOn)
      .with_batch_exporter(
        opentelemetry_otlp::SpanExporter::builder()
          .with_http()
          .with_endpoint(config.otlp_endpoint())
          .with_timeout(Duration::from_secs(3))
          .build()
          .unwrap(),
      )
      .build();

  global::set_tracer_provider(provider.clone());

  OpenTelemetryLayer::new(
    provider.tracer(config.opentelemetry_scope_name()),
  )
  .with_tracked_inactivity(false)
  .with_threads(false)
  .with_target(false)
}
