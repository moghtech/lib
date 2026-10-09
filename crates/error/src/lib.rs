pub use anyhow;

use anyhow::Context;

mod not_an_attempt;
mod serror;

pub use not_an_attempt::NotAnAttempt;
pub use serror::Serror;

#[cfg(feature = "axum")]
mod axum;
#[cfg(feature = "axum")]
pub use crate::axum::*;

// Dev dependencies used by the integration tests only.
#[cfg(test)]
use tokio as _;
#[cfg(test)]
use tracing_subscriber as _;

/// The kinds of serde messages which name the unexpected value:
/// `invalid type: string "hunter2", expected u64`,
/// `unknown variant `hunter2`, expected one of ...`.
const NAMING_A_VALUE: [&str; 3] =
  ["invalid type", "invalid value", "unknown variant"];

/// A serde error message without the unexpected value it may name,
/// keeping what was expected: `invalid type: string "hunter2",
/// expected u64` becomes `invalid type, expected u64`. The other
/// messages (`missing field `name``, `unknown field `x``, the custom
/// ones of Deserialize impls) stay as they are.
///
/// For a parse error of input which can carry secrets (request
/// params, websocket frames), before it is answered or logged.
/// `variant_request` (feature `axum`) applies it. A position the
/// message ends with (`at line 1 column 5`) stays: it names no value.
///
/// ```
/// let e = serde_json::from_str::<u64>(r#""hunter2""#).unwrap_err();
/// assert_eq!(
///   mogh_error::without_values(&e.to_string()),
///   "invalid type, expected u64 at line 1 column 9"
/// );
/// ```
pub fn without_values(message: &str) -> String {
  for kind in NAMING_A_VALUE {
    if message.starts_with(kind) {
      // The expectation comes last, after the value (which may
      // itself contain ", expected ").
      return match message.rfind(", expected ") {
        Some(start) => format!("{kind}{}", &message[start..]),
        None => kind.to_string(),
      };
    }
  }
  message.to_string()
}

/// Serializes the error as a [Serror] (`{ "error", "trace" }`) json.
pub fn serialize_error(e: &anyhow::Error) -> String {
  serde_json::to_string(&Serror::from(e))
    .unwrap_or_else(|_| format!("{e:#?}"))
}

/// [serialize_error], as bytes.
pub fn serialize_error_bytes(e: &anyhow::Error) -> Vec<u8> {
  serde_json::to_vec(&Serror::from(e))
    .unwrap_or_else(|_| format!("{e:#?}").into_bytes())
}

/// Parses a serialized error (see [deserialize_serror]) and
/// rebuilds its anyhow chain with [serror_into_anyhow_error].
pub fn deserialize_error(json: String) -> anyhow::Error {
  serror_into_anyhow_error(deserialize_serror(json))
}

pub fn deserialize_serror(json: String) -> Serror {
  try_deserialize_serror(&json).unwrap_or_else(|_| Serror {
    error: json.clone(),
    trace: Default::default(),
  })
}

pub fn try_deserialize_serror(json: &str) -> anyhow::Result<Serror> {
  serde_json::from_str(json)
    .context("failed to deserialize string into Serror")
}

/// Parses a serialized error (see [deserialize_serror_bytes]) and
/// rebuilds its anyhow chain with [serror_into_anyhow_error].
pub fn deserialize_error_bytes(json: &[u8]) -> anyhow::Error {
  serror_into_anyhow_error(deserialize_serror_bytes(json))
}

/// How many bytes of a body which is neither a [Serror] nor valid
/// utf8 [deserialize_serror_bytes] keeps in its fallback message.
const INVALID_UTF8_PREVIEW_BYTES: usize = 1024;

/// Parses the bytes into a [Serror]. If they are not a [Serror],
/// the whole body becomes the error message when it is valid utf8.
/// Otherwise the message names the utf8 error and carries a lossy
/// preview of the first 1024 bytes.
pub fn deserialize_serror_bytes(json: &[u8]) -> Serror {
  try_deserialize_serror_bytes(json).unwrap_or_else(|_| Serror {
    error: match std::str::from_utf8(json) {
      std::result::Result::Ok(res) => res.to_string(),
      Err(e) => {
        let preview =
          &json[..json.len().min(INVALID_UTF8_PREVIEW_BYTES)];
        let ellipsis = if preview.len() < json.len() {
          "..."
        } else {
          ""
        };
        format!(
          "Bytes are not valid utf8 | {e} | {} bytes: {}{ellipsis}",
          json.len(),
          String::from_utf8_lossy(preview),
        )
      }
    },
    trace: Default::default(),
  })
}

pub fn try_deserialize_serror_bytes(
  json: &[u8],
) -> anyhow::Result<Serror> {
  serde_json::from_slice(json)
    .context("failed to deserialize string into Serror")
}

/// The most `trace` entries [serror_into_anyhow_error] rebuilds
/// into anyhow context layers, so the rebuilt chain has at most
/// `MAX_TRACE_DEPTH + 1` errors including the top-level one.
///
/// anyhow drops a context chain recursively, one stack frame per
/// layer. A `trace` received from a peer has no length limit, so
/// rebuilding every entry as a layer would let the peer overflow
/// the stack when the error is dropped, which aborts the process.
/// Entries past the limit are folded into the last (root cause)
/// entry, joined with ": " like the alternate Display (`{:#}`)
/// joins a chain, so `{:#}` renders the same text either way.
pub const MAX_TRACE_DEPTH: usize = 64;

/// Rebuilds the anyhow error chain, with `error` on top and `trace`
/// as the context chain below it. A `trace` longer than
/// [MAX_TRACE_DEPTH] has its deepest entries folded into one.
pub fn serror_into_anyhow_error(serror: Serror) -> anyhow::Error {
  let Serror { error, mut trace } = serror;

  if trace.len() > MAX_TRACE_DEPTH {
    let folded = trace.split_off(MAX_TRACE_DEPTH - 1).join(": ");
    trace.push(folded);
  }

  let mut e = match trace.pop() {
    None => return anyhow::Error::msg(error),
    Some(msg) => anyhow::Error::msg(msg),
  };

  while let Some(msg) = trace.pop() {
    e = e.context(msg);
  }

  e.context(error)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn without_values_keeps_messages_naming_no_value() {
    for message in [
      "missing field `limit`",
      "unknown field `x`, expected `a` or `b`",
      "invalid length 3, expected a tuple of size 2",
      "relative URL without a base",
    ] {
      assert_eq!(without_values(message), message);
    }
    assert_eq!(
      without_values("invalid type: map, expected a string"),
      "invalid type, expected a string"
    );
    assert_eq!(
      without_values("unknown variant `x`, there are no variants"),
      "unknown variant"
    );
    // The value can't fake the end of the message.
    assert_eq!(
      without_values(
        r#"invalid value: string "a, expected b", expected u8"#
      ),
      "invalid value, expected u8"
    );
  }

  fn chain(e: &anyhow::Error) -> Vec<String> {
    e.chain().map(|e| e.to_string()).collect()
  }

  fn example_error() -> anyhow::Error {
    anyhow::anyhow!("root cause")
      .context("middle context")
      .context("top level")
  }

  #[test]
  fn serror_from_anyhow_error_splits_chain() {
    let serror: Serror = (&example_error()).into();
    assert_eq!(serror.error, "top level");
    assert_eq!(serror.trace, vec!["middle context", "root cause"]);
  }

  #[test]
  fn serror_from_error_without_context() {
    let serror: Serror = anyhow::anyhow!("only error").into();
    assert_eq!(serror.error, "only error");
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn serialize_deserialize_roundtrip_preserves_chain() {
    let e = example_error();
    let serialized = serialize_error(&e);
    // Sanity check the serialized shape
    let value: serde_json::Value =
      serde_json::from_str(&serialized).unwrap();
    assert_eq!(
      value,
      serde_json::json!({
        "error": "top level",
        "trace": ["middle context", "root cause"]
      })
    );
    let deserialized = deserialize_error(serialized);
    assert_eq!(chain(&deserialized), chain(&e));
  }

  #[test]
  fn serialize_error_bytes_matches_string_version() {
    let e = example_error();
    assert_eq!(
      serialize_error(&e).into_bytes(),
      serialize_error_bytes(&e)
    );
    let deserialized =
      deserialize_error_bytes(&serialize_error_bytes(&e));
    assert_eq!(chain(&deserialized), chain(&e));
  }

  #[test]
  fn deserialize_serror_falls_back_to_raw_string() {
    let serror = deserialize_serror(String::from("not json"));
    assert_eq!(serror.error, "not json");
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn deserialize_serror_bytes_falls_back_on_invalid_utf8() {
    let serror = deserialize_serror_bytes(&[0xff, 0xfe]);
    assert!(serror.error.contains("Bytes are not valid utf8"));
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn deserialize_serror_bytes_keeps_valid_utf8_body() {
    let serror = deserialize_serror_bytes(b"plain text error");
    assert_eq!(serror.error, "plain text error");
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn invalid_utf8_fallback_message_is_bounded() {
    let mut body = vec![0xff];
    body.extend(std::iter::repeat_n(b'A', 100_000));
    let serror = deserialize_serror_bytes(&body);
    // Used to Debug format the whole payload as a byte list,
    // about 4x the size of the body.
    assert!(!serror.error.contains("FromUtf8Error"));
    assert!(serror.error.len() < 4 * INVALID_UTF8_PREVIEW_BYTES);
    assert!(serror.error.starts_with(
      "Bytes are not valid utf8 | invalid utf-8 sequence"
    ));
    assert!(serror.error.contains("100001 bytes: \u{FFFD}AAA"));
    assert!(serror.error.ends_with("A..."));
  }

  #[test]
  fn invalid_utf8_fallback_short_body_has_no_ellipsis() {
    let serror = deserialize_serror_bytes(b"ok\xffok");
    assert!(serror.error.ends_with("5 bytes: ok\u{FFFD}ok"));
  }

  fn serror_with_trace(len: usize) -> Serror {
    Serror {
      error: String::from("top level"),
      trace: (0..len).map(|i| format!("trace {i}")).collect(),
    }
  }

  #[test]
  fn serror_into_anyhow_error_keeps_trace_up_to_max_depth() {
    let serror = serror_with_trace(MAX_TRACE_DEPTH);
    let expected: Vec<String> = std::iter::once(serror.error.clone())
      .chain(serror.trace.iter().cloned())
      .collect();
    let e = serror_into_anyhow_error(serror);
    assert_eq!(chain(&e), expected);
  }

  #[test]
  fn serror_into_anyhow_error_folds_trace_past_max_depth() {
    let serror = serror_with_trace(MAX_TRACE_DEPTH + 10);
    let full = std::iter::once(serror.error.clone())
      .chain(serror.trace.iter().cloned())
      .collect::<Vec<_>>()
      .join(": ");
    let e = serror_into_anyhow_error(serror);
    let chain = chain(&e);
    assert_eq!(chain.len(), MAX_TRACE_DEPTH + 1);
    assert_eq!(chain[0], "top level");
    assert_eq!(chain[1], "trace 0");
    assert_eq!(
      chain[MAX_TRACE_DEPTH - 1],
      format!("trace {}", MAX_TRACE_DEPTH - 2)
    );
    // The root cause stays visible in the folded last entry
    let last = chain.last().unwrap();
    assert!(
      last.starts_with(&format!("trace {}: ", MAX_TRACE_DEPTH - 1))
    );
    assert!(
      last.ends_with(&format!("trace {}", MAX_TRACE_DEPTH + 9))
    );
    // The alternate Display renders the same text as before
    assert_eq!(format!("{e:#}"), full);
  }

  /// Dropping an anyhow chain recurses once per layer. Before the
  /// depth cap, a peer sending this trace made the drop overflow
  /// the stack, which aborts the whole process.
  #[test]
  fn deserialize_huge_trace_drops_on_small_stack() {
    let body = serde_json::to_vec(&Serror {
      error: String::from("e"),
      trace: vec![String::from("x"); 1_000_000],
    })
    .unwrap();
    let chain_len = std::thread::Builder::new()
      .stack_size(256 * 1024)
      .spawn(move || {
        let e = deserialize_error_bytes(&body);
        let len = e.chain().count();
        drop(e);
        len
      })
      .unwrap()
      .join()
      .unwrap();
    assert_eq!(chain_len, MAX_TRACE_DEPTH + 1);
  }

  #[test]
  fn serror_into_anyhow_error_rebuilds_chain() {
    let serror = Serror {
      error: String::from("top level"),
      trace: vec![
        String::from("middle context"),
        String::from("root cause"),
      ],
    };
    let e = serror_into_anyhow_error(serror);
    assert_eq!(
      chain(&e),
      vec!["top level", "middle context", "root cause"]
    );
  }

  #[test]
  fn serror_into_anyhow_error_without_trace() {
    let e = serror_into_anyhow_error(Serror {
      error: String::from("only error"),
      trace: Vec::new(),
    });
    assert_eq!(chain(&e), vec!["only error"]);
  }
}
