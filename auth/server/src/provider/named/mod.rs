use anyhow::{Context as _, anyhow};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;

pub mod github;
pub mod google;

/// Length of the random Oauth 'state' token
pub const STATE_LENGTH: usize = 32;

/// How many characters of a provider's text go into an error.
const MAX_ERROR_TEXT_LENGTH: usize = 512;

/// Reads the body of a provider's response, at most
/// [MAX_RESPONSE_LENGTH][crate::provider::oidc::MAX_RESPONSE_LENGTH]:
/// a larger one is refused unread, also when it declares its length
/// up front.
async fn read_body(
  mut res: reqwest::Response,
) -> anyhow::Result<Vec<u8>> {
  use crate::provider::oidc::MAX_RESPONSE_LENGTH;
  let too_large = || {
    anyhow!("The response is larger than {MAX_RESPONSE_LENGTH} bytes")
  };
  if res
    .content_length()
    .is_some_and(|length| length > MAX_RESPONSE_LENGTH as u64)
  {
    return Err(too_large());
  }
  let mut body = Vec::new();
  while let Some(chunk) =
    res.chunk().await.map_err(reqwest::Error::without_url)?
  {
    if body.len() + chunk.len() > MAX_RESPONSE_LENGTH {
      return Err(too_large());
    }
    body.extend_from_slice(&chunk);
  }
  Ok(body)
}

/// Parses a `200 OK` response body, anything else is an
/// error carrying (the start of) the response text.
///
/// The body is read and parsed here rather than with `res.json()`:
/// reqwest's own errors name the request url, and with it anything
/// in its query, which must not end up in the errors (and so in the
/// logs, or the response of an unauthenticated login endpoint).
async fn handle_response<T: DeserializeOwned>(
  res: reqwest::Response,
) -> anyhow::Result<T> {
  let status = res.status();
  let body = read_body(res).await.with_context(|| {
    format!("Status: {status} | Failed to get response body")
  })?;
  if status == StatusCode::OK {
    // Serde's syntax errors only name the position, but its type
    // errors quote the value found (`invalid type: string "..."`),
    // which may be a secret. Only the kind and position are kept.
    serde_json::from_slice(&body).map_err(|e| {
      anyhow!(
        "Failed to parse response body into expected type | {:?} error at line {} column {}",
        e.classify(),
        e.line(),
        e.column()
      )
    })
  } else {
    Err(anyhow!(
      "Status: {status} | Text: {}",
      sanitize_text(&String::from_utf8_lossy(&body))
    ))
  }
}

/// A provider's text as it goes into an error (or the log):
/// without control characters, and bounded.
pub(crate) fn sanitize_text(text: &str) -> String {
  let text = text.trim();
  let mut sanitized = text
    .chars()
    .filter(|c| !c.is_control())
    .take(MAX_ERROR_TEXT_LENGTH)
    .collect::<String>();
  if text
    .chars()
    .filter(|c| !c.is_control())
    .nth(MAX_ERROR_TEXT_LENGTH)
    .is_some()
  {
    sanitized.push_str("...");
  }
  sanitized
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_sanitize_text() {
    assert_eq!(sanitize_text("  bad_code\r\n"), "bad_code");
    assert_eq!(sanitize_text("a\u{1b}[31mb"), "a[31mb");
    let long = "a".repeat(MAX_ERROR_TEXT_LENGTH + 10);
    let sanitized = sanitize_text(&long);
    assert_eq!(sanitized.len(), MAX_ERROR_TEXT_LENGTH + 3);
    assert!(sanitized.ends_with("..."));
    let exact = "a".repeat(MAX_ERROR_TEXT_LENGTH);
    assert_eq!(sanitize_text(&exact), exact);
  }

  fn ok_response(body: &'static str) -> reqwest::Response {
    reqwest::Response::from(
      axum::http::Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .unwrap(),
    )
  }

  #[derive(Debug, serde::Deserialize)]
  #[allow(dead_code)]
  struct TokenResponse {
    access_token: String,
    expires_in: u64,
  }

  /// A response parsed into the wrong type never has its values in
  /// the error: serde's own message would quote them.
  #[tokio::test]
  async fn test_handle_response_parse_error_does_not_quote_the_body()
  {
    for body in [
      r#"{"access_token":"gho_secret","expires_in":"gho_secret"}"#,
      r#"{"access_token":["gho_secret"],"expires_in":1}"#,
      r#"{"access_token":"gho_secret"}"#,
      r#"{"access_token":"gho_secret","#,
      "gho_secret",
    ] {
      let err = handle_response::<TokenResponse>(ok_response(body))
        .await
        .unwrap_err();
      let message = format!("{err:#}");
      assert!(!message.contains("gho_secret"), "{message}");
      assert!(message.contains("line 1 column"), "{message}");
    }
    let parsed = handle_response::<TokenResponse>(ok_response(
      r#"{"access_token":"gho_secret","expires_in":1}"#,
    ))
    .await
    .unwrap();
    assert_eq!(parsed.expires_in, 1);
  }
}
