//! W3C Trace Context propagation between processes that log
//! through this crate.
//!
//! With an OTLP endpoint configured on both ends (see
//! [LogConfig::otlp_endpoint](crate::LogConfig::otlp_endpoint)), a
//! caller sends the [`traceparent`](crate::TRACEPARENT_HEADER) of the span
//! it issues a request under (as the standard HTTP header, or as a
//! field of whatever frame the transport uses) and the callee
//! parents its own span under it with [set_remote_parent], so both
//! sides of the request land in one trace. Callees should only do
//! this for trusted callers, see [set_remote_parent]. Without an
//! exporting layer there is no valid span context,
//! [current_traceparent] returns `None`, and nothing is sent.
//!
//! These go through tracing-opentelemetry's span extension, which
//! only sees the layer [init](crate::init) installed when both
//! resolve to the same crate version — the reason they live here,
//! next to the layer, rather than in every application.

use opentelemetry::{
  Context,
  trace::{
    SpanContext, SpanId, TraceContextExt as _, TraceFlags, TraceId,
    TraceState,
  },
};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

/// The `traceparent` of the current span: `Some` only when it has
/// a valid OpenTelemetry context, ie. an exporting layer is
/// installed and the span is enabled. Callers send nothing
/// otherwise.
pub fn current_traceparent() -> Option<String> {
  let cx = tracing::Span::current().context();
  let span = cx.span();
  let span_context = span.span_context();
  span_context
    .is_valid()
    .then(|| format_traceparent(span_context))
}

/// Parents `span` under a remote `traceparent`, so it joins the
/// caller's trace. Must run before the span is entered: a span
/// already started cannot change parent. Returns whether it
/// applied. A malformed value, a span the subscriber disabled, or
/// no exporting layer leave the span as it is.
///
/// ⚠️ The `traceparent` is caller controlled: honoring it lets the
/// caller choose the trace the span joins. Only apply it for
/// trusted callers (eg. authenticated service to service
/// requests). Public traffic (browsers, api keys) should start a
/// fresh trace, per the W3C Trace Context security considerations.
///
/// A header value is not a `&str`, convert it first:
/// `headers.get(TRACEPARENT_HEADER).and_then(|v| v.to_str().ok())`.
pub fn set_remote_parent(
  span: &tracing::Span,
  traceparent: &str,
) -> bool {
  let Some(remote) = parse_traceparent(traceparent) else {
    return false;
  };
  span
    .set_parent(Context::new().with_remote_span_context(remote))
    .is_ok()
}

/// `00-<trace id>-<span id>-<flags>`: the W3C Trace Context
/// `traceparent` value, lowercase hex, fixed widths.
fn format_traceparent(span_context: &SpanContext) -> String {
  format!(
    "00-{:032x}-{:016x}-{:02x}",
    span_context.trace_id(),
    span_context.span_id(),
    span_context.trace_flags().to_u8()
  )
}

/// Parses a W3C `traceparent` into a remote span context. `None`
/// for anything malformed, and for the invalid (all zero) ids.
/// Version `00` has exactly four fields; a future version may
/// append more, which a `00` parser reads past (`ff` is reserved).
fn parse_traceparent(traceparent: &str) -> Option<SpanContext> {
  let mut parts = traceparent.trim().split('-');
  let version = parts.next()?;
  let trace_id = parts.next()?;
  let span_id = parts.next()?;
  let flags = parts.next()?;
  if version.len() != 2
    || !is_lower_hex(version)
    || version == "ff"
    || (version == "00" && parts.next().is_some())
  {
    return None;
  }
  if trace_id.len() != 32
    || span_id.len() != 16
    || flags.len() != 2
    || ![trace_id, span_id, flags].into_iter().all(is_lower_hex)
  {
    return None;
  }
  let span_context = SpanContext::new(
    TraceId::from_hex(trace_id).ok()?,
    SpanId::from_hex(span_id).ok()?,
    TraceFlags::new(u8::from_str_radix(flags, 16).ok()?),
    true,
    TraceState::default(),
  );
  span_context.is_valid().then_some(span_context)
}

fn is_lower_hex(s: &str) -> bool {
  !s.is_empty()
    && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
  use super::*;

  const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
  const SPAN: &str = "00f067aa0ba902b7";

  fn span_context(trace: &str, span: &str, flags: u8) -> SpanContext {
    SpanContext::new(
      TraceId::from_hex(trace).unwrap(),
      SpanId::from_hex(span).unwrap(),
      TraceFlags::new(flags),
      true,
      TraceState::default(),
    )
  }

  #[test]
  fn traceparent_round_trips() {
    let cx = span_context(TRACE, SPAN, 1);
    let header = format_traceparent(&cx);
    assert_eq!(header, format!("00-{TRACE}-{SPAN}-01"));
    let parsed = parse_traceparent(&header).unwrap();
    assert_eq!(parsed.trace_id(), cx.trace_id());
    assert_eq!(parsed.span_id(), cx.span_id());
    assert!(parsed.is_sampled());
    assert!(parsed.is_remote());
    // Small ids keep their fixed width.
    assert_eq!(
      format_traceparent(&span_context("1", "2", 0)),
      "00-00000000000000000000000000000001-0000000000000002-00"
    );
  }

  #[test]
  fn traceparent_rejects_malformed_values() {
    for bad in [
      "",
      "not a traceparent",
      // Missing flags.
      &format!("00-{TRACE}-{SPAN}"),
      // Version 00 with a fifth field.
      &format!("00-{TRACE}-{SPAN}-01-extra"),
      // Reserved version.
      &format!("ff-{TRACE}-{SPAN}-01"),
      // Uppercase hex.
      &format!("00-{}-{SPAN}-01", TRACE.to_uppercase()),
      // Short trace id, short flags.
      &format!("00-{}-{SPAN}-01", &TRACE[1..]),
      &format!("00-{TRACE}-{SPAN}-1"),
      // The invalid ids.
      &format!("00-{}-{SPAN}-01", "0".repeat(32)),
      &format!("00-{TRACE}-{}-01", "0".repeat(16)),
    ] {
      assert!(parse_traceparent(bad).is_none(), "{bad}");
    }
    // A future version with extra fields parses its first four.
    assert!(
      parse_traceparent(&format!("01-{TRACE}-{SPAN}-01-future"))
        .is_some()
    );
  }

  /// Without an exporting layer there is no context to send, and
  /// nothing to parent.
  #[test]
  fn no_layer_no_traceparent() {
    assert!(current_traceparent().is_none());
    let span = tracing::info_span!("orphan");
    assert!(!set_remote_parent(
      &span,
      &format!("00-{TRACE}-{SPAN}-01")
    ));
  }
}
