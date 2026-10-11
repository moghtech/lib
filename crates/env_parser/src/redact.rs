//! Values redacted out of serde's error messages. Env file values
//! are secrets and errors end up in logs, so every message this
//! crate returns keeps what was expected and drops what was found.

use std::sync::LazyLock;

/// A serde_json error's message with its values redacted, see
/// [redact_serde_message].
pub fn redact_serde_error(e: &serde_json::Error) -> String {
  redact_serde_message(&e.to_string())
}

/// Redacts the values from a serde error message, since config
/// values may be secrets and errors are logged: double quoted
/// strings (`invalid type: string "hunter2"`) and backticked tokens
/// (`invalid type: integer `4829``). An unknown enum variant or
/// field is redacted whole, whatever it holds (serde doesn't escape
/// it), keeping the names expected after it:
/// `unknown variant [redacted], expected `fast` or `safe``. A
/// missing or duplicate field keeps its name (`missing field
/// `port``): the program's, never a value.
///
/// For a message which may begin with the path of the value it is
/// about, as serde_yaml's do (`server.mode: unknown variant ...`),
/// see [redact_prefixed_serde_message].
pub fn redact_serde_message(message: &str) -> String {
  redact_message(message, false)
}

/// [redact_serde_message] for a message which may begin with the
/// path of the value it is about, as serde_yaml's do (`server.mode:
/// invalid type: ...`). The path is kept, unless it holds a quote
/// or a backtick which can't be told from a value's: then only the
/// text before it stays, and where the error is (`at line 2 column
/// 15`).
pub fn redact_prefixed_serde_message(message: &str) -> String {
  redact_message(message, true)
}

/// serde's own message comes first, or with `path_prefix` (yaml)
/// may follow the path of the value it is about (`server.mode:
/// ...`).
fn redact_message(message: &str, path_prefix: bool) -> String {
  // Where serde's message starts. serde writes each value right
  // after its own wording, and the first one comes after the path,
  // so the wording before the first quote / backtick tells where
  // the path ends: the path (yaml keys) may hold anything.
  static WORDING: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
      r"(?:\A|: )((?:invalid (?:type|value): (?:string|character|boolean|integer|floating point)|unknown (?:variant|field)|missing field|duplicate field) )\z",
    )
    .unwrap()
  });
  let start = match message.find(['"', '`']) {
    Some(quote) if path_prefix => {
      match WORDING.captures(&message[..quote]) {
        Some(wording) => wording.get(1).unwrap().start(),
        // A quote or backtick in the path, which can't be told
        // apart from a value's: keep only the text before it, and
        // where the error is.
        None => {
          static LOCATION: LazyLock<regex::Regex> =
            LazyLock::new(|| {
              regex::Regex::new(
                r" at (?:line \d+ column \d+|position \d+)\z",
              )
              .unwrap()
            });
          let location = LOCATION
            .find(&message[quote..])
            .map_or("", |location| location.as_str());
          return format!(
            "{}[redacted]{location}",
            &message[..quote]
          );
        }
      }
    }
    _ => 0,
  };
  // serde writes an unknown enum variant or field name in
  // backticks without escaping it, so it may hold backticks or
  // quotes itself: it runs up to serde's own `, expected` / `, there
  // are no`, the last one, as it may hold these too. The names
  // expected after it are the program's, and stay readable. Only at
  // the start of serde's message: text like it anywhere else is
  // inside a value, eg. `invalid type: string "unknown variant `a`,
  // expected b", expected u16`, whose string is redacted whole
  // below.
  static UNKNOWN: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
      r"(?s)\A(unknown (?:variant|field) )`.*`(, expected|, there are no)",
    )
    .unwrap()
  });
  let (path, rest) = message.split_at(start);
  // A missing or duplicate field is named by the program (serde's
  // `missing_field` / `duplicate_field` take a `&'static str`),
  // never by a value, and the name is what the reader needs. Only
  // when it is the whole of serde's message: inside a string value
  // the text is redacted with the string.
  static NAMED: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\A(?:missing|duplicate) field `[^`]*`\z")
      .unwrap()
  });
  if NAMED.is_match(rest) {
    return message.to_string();
  }
  if let Some(unknown) = UNKNOWN.captures(rest) {
    let end = unknown.get(0).unwrap().end();
    return format!(
      "{path}{}[redacted]{}{}",
      &unknown[1],
      &unknown[2],
      &rest[end..]
    );
  }
  redact_values(message)
}

/// Redacts the values serde writes into its messages: strings
/// escaped in double quotes (`string "a \"b\""`), a character in
/// backticks (which may be a backtick itself), and numbers and
/// booleans in backticks.
fn redact_values(message: &str) -> String {
  static QUOTED: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
      r#"(?s)"(?:[^"\\]|\\.)*"|character `.`|`[^`]*`"#,
    )
    .unwrap()
  });
  QUOTED
    .replace_all(message, |caps: &regex::Captures| {
      if caps[0].starts_with("character ") {
        "character [redacted]"
      } else {
        "[redacted]"
      }
    })
    .into_owned()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn redacts_quoted_values_from_serde_errors() {
    let err = serde_json::from_value::<u16>(serde_json::json!(
      "hunter2 \"quoted\" secret"
    ))
    .unwrap_err();
    let message = redact_serde_error(&err);
    assert!(!message.contains("hunter2"), "{message}");
    assert!(
      message.contains("invalid type: string [redacted]"),
      "{message}"
    );
    assert!(message.contains("expected u16"));
    // Numbers are formatted in backticks by serde.
    let err =
      serde_json::from_value::<String>(serde_json::json!(482913))
        .unwrap_err();
    let message = redact_serde_error(&err);
    assert!(!message.contains("482913"), "{message}");
    // A character is written in backticks unescaped.
    let err = <serde_json::Error as serde::de::Error>::invalid_type(
      serde::de::Unexpected::Char('`'),
      &"a secret",
    );
    let message = redact_serde_error(&err);
    assert_eq!(
      message,
      "invalid type: character [redacted], expected a secret"
    );
  }

  /// serde writes an unknown enum variant (or field name) in
  /// backticks without escaping it: a backtick in the value used to
  /// end the redacted token early, leaking the rest.
  #[test]
  fn redacts_unknown_variants_holding_backticks_and_quotes() {
    for value in [
      "x`hunter2secret",
      "a`b`c`hunter2`d",
      "`hunter2`",
      "x\"hunter2\"",
      "x`, expected `hunter2",
      "x`, there are no hunter2",
      "multi\nline`hunter2",
    ] {
      let message = redact_serde_message(&format!(
        "unknown variant `{value}`, expected `fast` or `safe`"
      ));
      assert_eq!(
        message,
        "unknown variant [redacted], expected `fast` or `safe`",
        "{value:?}"
      );
      let message = redact_serde_message(&format!(
        "unknown field `{value}`, there are no fields"
      ));
      assert_eq!(
        message, "unknown field [redacted], there are no fields",
        "{value:?}"
      );
    }
    // Text like it inside a string value is part of the value: the
    // string is redacted whole, not taken for serde's message.
    let message = redact_serde_message(
      "invalid value: string \"unknown variant `a`, expected hunter2\", expected u16",
    );
    assert_eq!(
      message,
      "invalid value: string [redacted], expected u16"
    );
  }

  /// A missing or duplicate field is named by the program: the name
  /// stays, where a value in the same backticks would not.
  #[test]
  fn keeps_the_names_of_missing_and_duplicate_fields() {
    for message in
      ["missing field `db_password`", "duplicate field `port`"]
    {
      assert_eq!(redact_serde_message(message), message);
      assert_eq!(redact_prefixed_serde_message(message), message);
    }
    // After a yaml path, where the prefixed variant knows the path
    // ends and the plain one takes the backticks for a value's.
    let message = "server.port: missing field `port`";
    assert_eq!(redact_prefixed_serde_message(message), message);
    assert_eq!(
      redact_serde_message(message),
      "server.port: missing field [redacted]"
    );
    // Inside a value the text is the value's.
    assert_eq!(
      redact_serde_message(
        "invalid value: string \"missing field `hunter2`\", expected u16"
      ),
      "invalid value: string [redacted], expected u16"
    );
    assert_eq!(
      redact_serde_message("missing field `a`, hunter2 `b`"),
      "missing field [redacted], hunter2 [redacted]"
    );
  }

  /// yaml names the key of the failing value before serde's message:
  /// a plain key stays, one holding a quote or a backtick can't be
  /// told from the value, so only the text before it is kept.
  #[test]
  fn keeps_a_plain_path_prefix_and_drops_a_quoted_one() {
    assert_eq!(
      redact_prefixed_serde_message(
        "modes.a.b: unknown variant `x`hunter2`, expected `fast` or `safe` at line 2 column 15"
      ),
      "modes.a.b: unknown variant [redacted], expected `fast` or `safe` at line 2 column 15"
    );
    assert_eq!(
      redact_prefixed_serde_message(
        "ports.a.b: invalid type: string \"hunter2\", expected u16 at line 2 column 15"
      ),
      "ports.a.b: invalid type: string [redacted], expected u16 at line 2 column 15"
    );
    for key in ["a`b", "a\"b", "a: b`c"] {
      let message = redact_prefixed_serde_message(&format!(
        "modes.{key}: unknown variant `hunter2`, expected `fast` at line 2 column 15"
      ));
      assert!(!message.contains("hunter2"), "{key}: {message}");
      assert!(message.ends_with(" at line 2 column 15"), "{message}");
      assert!(message.starts_with("modes.a"), "{message}");
    }
    // Without a path, the same as the plain redaction.
    assert_eq!(
      redact_prefixed_serde_message(
        "invalid type: string \"hunter2\", expected u16"
      ),
      "invalid type: string [redacted], expected u16"
    );
  }
}
