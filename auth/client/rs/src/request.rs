//! Calling the auth api with [reqwest].
//!
//! The functions here are async and take a [reqwest::Client]. The
//! `blocking` feature adds the same functions for a
//! `reqwest::blocking::Client` in `request::blocking`.
//!
//! `address` is where the auth api is mounted, eg.
//! `https://example.com/auth`. The requests carry no credentials:
//! [manage] needs them added to the client's default headers.
//!
//! That only works for a jwt (`Authorization: Bearer <jwt>`) or an api
//! key (`X-API-KEY` / `X-API-SECRET`). A request with a signing key
//! is signed on its own, with
//! `signature::signed_request_headers_for_url` (`pki` feature) over
//! the host of the server and its exact path, query and body, so
//! [manage] can't send it: send
//! `POST {address}/manage` yourself, with the JSON body
//! `{"type": "<request>", "params": <request>}` and the headers
//! signed for it.

use anyhow::{Context, anyhow};
use mogh_error::deserialize_error;
use mogh_resolver::HasResponse;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::api::{
  login::MoghAuthLoginRequest,
  manage::MoghAuthManageRequest,
  token::{
    TokenExchangeError, TokenExchangeRequest, TokenExchangeResponse,
  },
};

/// Call the unauthenticated login api.
pub async fn login<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthLoginRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/login", request_body(&request)).await
}

/// Call the authenticated management api.
pub async fn manage<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthManageRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/manage", request_body(&request)).await
}

/// RFC 8693 Token Exchange: exchange a token issued by an external
/// login provider for an app token at the `/token` endpoint.
pub async fn token_exchange(
  reqwest: &reqwest::Client,
  address: &str,
  request: &TokenExchangeRequest,
) -> anyhow::Result<TokenExchangeResponse> {
  let res = reqwest
    .post(request_url(address, "/token"))
    .form(request)
    .send()
    .await
    .context("failed to reach Mogh Auth API")?;
  let status = res.status();
  match res.text().await {
    Ok(body) => parse_token_response(status, body),
    Err(e) => Err(anyhow!("{e:?}").context(status)),
  }
}

async fn post<B: Serialize, R: DeserializeOwned>(
  reqwest: &reqwest::Client,
  address: &str,
  endpoint: &str,
  body: B,
) -> anyhow::Result<R> {
  let res = reqwest
    .post(request_url(address, endpoint))
    .json(&body)
    .send()
    .await
    .context("failed to reach Mogh Auth API")?;
  let status = res.status();
  match res.text().await {
    Ok(body) => parse_response(status, body),
    Err(e) => Err(anyhow!("{e:?}").context(status)),
  }
}

/// The request functions for a [reqwest::blocking::Client],
/// with the same names and behavior as the async ones.
#[cfg(feature = "blocking")]
pub mod blocking {
  use anyhow::{Context, anyhow};
  use serde::{Serialize, de::DeserializeOwned};

  use crate::api::{
    login::MoghAuthLoginRequest,
    manage::MoghAuthManageRequest,
    token::{TokenExchangeRequest, TokenExchangeResponse},
  };

  use super::{
    parse_response, parse_token_response, request_body, request_url,
  };

  /// Call the unauthenticated login api.
  pub fn login<T>(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghAuthLoginRequest,
    T::Response: DeserializeOwned,
  {
    post(reqwest, address, "/login", request_body(&request))
  }

  /// Call the authenticated management api.
  pub fn manage<T>(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghAuthManageRequest,
    T::Response: DeserializeOwned,
  {
    post(reqwest, address, "/manage", request_body(&request))
  }

  /// RFC 8693 Token Exchange: exchange a token issued by an external
  /// login provider for an app token at the `/token` endpoint.
  pub fn token_exchange(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    request: &TokenExchangeRequest,
  ) -> anyhow::Result<TokenExchangeResponse> {
    let res = reqwest
      .post(request_url(address, "/token"))
      .form(request)
      .send()
      .context("failed to reach Mogh Auth API")?;
    let status = res.status();
    match res.text() {
      Ok(body) => parse_token_response(status, body),
      Err(e) => Err(anyhow!("{e:?}").context(status)),
    }
  }

  fn post<B: Serialize, R: DeserializeOwned>(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    endpoint: &str,
    body: B,
  ) -> anyhow::Result<R> {
    let res = reqwest
      .post(request_url(address, endpoint))
      .json(&body)
      .send()
      .context("failed to reach Mogh Auth API")?;
    let status = res.status();
    match res.text() {
      Ok(body) => parse_response(status, body),
      Err(e) => Err(anyhow!("{e:?}").context(status)),
    }
  }
}

/// The token endpoint uses the OAuth error format,
/// the returned error can be downcast to [TokenExchangeError].
///
/// A successful response which fails to parse is not included
/// in the error, it carries the app token.
fn parse_token_response(
  status: reqwest::StatusCode,
  body: String,
) -> anyhow::Result<TokenExchangeResponse> {
  if status.is_success() {
    return serde_json::from_str(&body).map_err(|e| {
      success_body_error(&e, &body)
        .context("failed to deserialize token response")
        .context(status)
    });
  }
  match serde_json::from_str::<TokenExchangeError>(&body) {
    Ok(error) => Err(anyhow::Error::new(error).context(status)),
    Err(_) => Err(anyhow!("{body}").context(status)),
  }
}

/// Builds the tagged request body expected by the auth server:
/// `{ "type": "<RequestType>", "params": <request> }`
fn request_body<T: Serialize + HasResponse>(
  request: &T,
) -> serde_json::Value {
  json!({
    "type": T::req_type(),
    "params": request
  })
}

/// Joins the server address and endpoint path,
/// tolerating a trailing slash on the address.
fn request_url(address: &str, endpoint: &str) -> String {
  format!("{}{endpoint}", address.trim_end_matches('/'))
}

/// Parses the response body, or converts it into an error.
///
/// An error status keeps the body (the error message). A successful
/// response carries credentials (a JWT, an api key secret, recovery
/// codes), so when it fails to parse, the error only keeps the body
/// if it isn't json, eg. an html page from a proxy.
fn parse_response<R: DeserializeOwned>(
  status: reqwest::StatusCode,
  body: String,
) -> anyhow::Result<R> {
  if status.is_success() {
    serde_json::from_str(&body).map_err(|e| {
      success_body_error(&e, &body)
        .context("failed to deserialize response body")
        .context(status)
    })
  } else {
    Err(deserialize_error(body).context(status))
  }
}

/// How much of a successful non json body the error keeps.
const BODY_PREVIEW_CHARS: usize = 200;

/// The error for a successful response body which failed to parse,
/// without any of the values it contains. The serde error message
/// quotes values (`invalid type: string "..."`), so they are redacted.
/// A body which doesn't look like json is kept up to
/// [BODY_PREVIEW_CHARS] characters.
fn success_body_error(
  e: &serde_json::Error,
  body: &str,
) -> anyhow::Error {
  let message = redact_serde_message(&e.to_string());
  let trimmed = body.trim_start();
  if trimmed.is_empty()
    || trimmed.starts_with(['{', '[', '"'])
    || matches!(e.classify(), serde_json::error::Category::Data)
  {
    return anyhow!("{message} ({} bytes)", body.len());
  }
  let preview = match body.char_indices().nth(BODY_PREVIEW_CHARS) {
    Some((end, _)) => format!("{}...", &body[..end]),
    None => body.to_string(),
  };
  anyhow!("{message} | body: {preview}")
}

/// Redacts the values of the input from a serde error message,
/// keeping the names which come from the types. serde writes an
/// unknown enum variant or field in backticks without escaping it,
/// so it may hold backticks or quotes itself: it is redacted whole,
/// and the names expected after it stay readable
/// (`unknown variant [redacted], expected `Jwt` or `Totp``). So does
/// the field of a `missing field` / `duplicate field` error. Other
/// values are redacted by [redact_serde_values].
fn redact_serde_message(message: &str) -> String {
  // serde's wording only counts at the start of the message
  // (serde_json appends ` at line N column M`): text like it
  // anywhere else is inside a value.
  for wording in ["unknown variant ", "unknown field "] {
    let Some(name) = message
      .strip_prefix(wording)
      .and_then(|rest| rest.strip_prefix('`'))
    else {
      continue;
    };
    // The name runs up to serde's own `, expected` / `, there are
    // no`, the last one, as the name may hold these too. What
    // follows are the names of the type (`&'static str`).
    let end = ["`, expected ", "`, there are no "]
      .into_iter()
      .filter_map(|marker| name.rfind(marker))
      .max();
    let after = end.map_or("", |end| &name[end + 1..]);
    return format!("{wording}[redacted]{after}");
  }
  for wording in ["missing field `", "duplicate field `"] {
    // serde names these fields with a `&'static str` of the type.
    let Some(end) = message
      .strip_prefix(wording)
      .and_then(|rest| rest.find('`'))
    else {
      continue;
    };
    let (field, rest) = message.split_at(wording.len() + end + 1);
    return format!("{field}{}", redact_serde_values(rest));
  }
  redact_serde_values(message)
}

/// Redacts the values serde writes into its messages: strings in
/// double quotes, escaped (`string "a \"b\""`), a character in
/// backticks, unescaped (it may be a backtick itself), and numbers
/// and booleans in backticks. An unterminated one is redacted to
/// the end.
fn redact_serde_values(message: &str) -> String {
  let mut out = String::with_capacity(message.len());
  let mut rest = message;
  while let Some(start) = rest.find(['"', '`']) {
    let (before, quoted) = rest.split_at(start);
    out.push_str(before);
    out.push_str("[redacted]");
    // Both quotes are ascii, so `quoted[1..]` is on a char boundary,
    // and the end (past the closing quote) is its offset + 2.
    let inner = &quoted[1..];
    let end = if quoted.starts_with('"') {
      // The closing quote, skipping escaped characters.
      let mut escaped = false;
      inner.char_indices().find_map(|(i, c)| {
        if escaped {
          escaped = false;
        } else if c == '\\' {
          escaped = true;
        } else if c == '"' {
          return Some(i + 2);
        }
        None
      })
    } else if before.ends_with("character ") {
      // One char, then the closing backtick.
      inner.chars().next().and_then(|c| {
        let close = c.len_utf8();
        inner[close..].starts_with('`').then_some(close + 2)
      })
    } else {
      inner.find('`').map(|i| i + 2)
    };
    let Some(end) = end else {
      // Unterminated, redact the rest.
      return out;
    };
    rest = &quoted[end..];
  }
  out.push_str(rest);
  out
}

#[cfg(test)]
mod tests {
  use reqwest::StatusCode;
  use serde_json::json;

  use super::*;
  use crate::api::login::{
    GetLoginOptions, JwtOrTwoFactor, JwtResponse, LoginLocalUser,
  };
  use crate::api::manage::{
    ConfirmTotpEnrollmentResponse, CreateApiKeyResponse,
    UpdateUsername,
  };

  #[test]
  fn test_request_body_tags_type_and_params() {
    let body = request_body(&LoginLocalUser {
      username: "user".into(),
      password: "pass".into(),
    });
    assert_eq!(
      body,
      json!({
        "type": "LoginLocalUser",
        "params": {
          "username": "user",
          "password": "pass",
        }
      })
    );
  }

  #[test]
  fn test_request_body_empty_params() {
    let body = request_body(&GetLoginOptions {});
    assert_eq!(
      body,
      json!({
        "type": "GetLoginOptions",
        "params": {}
      })
    );
  }

  #[test]
  fn test_request_body_manage_request() {
    let body = request_body(&UpdateUsername {
      username: "new-name".into(),
    });
    assert_eq!(
      body,
      json!({
        "type": "UpdateUsername",
        "params": { "username": "new-name" }
      })
    );
  }

  #[test]
  fn test_request_url() {
    assert_eq!(
      request_url("http://localhost:9120", "/login"),
      "http://localhost:9120/login"
    );
    // A trailing slash on the address must not
    // produce a double slash in the url.
    assert_eq!(
      request_url("http://localhost:9120/", "/manage"),
      "http://localhost:9120/manage"
    );
  }

  #[test]
  fn test_parse_response_success() {
    let res: JwtResponse =
      parse_response(StatusCode::OK, r#"{"jwt":"abc123"}"#.into())
        .unwrap();
    assert_eq!(res.jwt, "abc123");
  }

  #[test]
  fn test_parse_response_success_status_bad_body_keeps_body() {
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      "unexpected html".into(),
    )
    .unwrap_err();
    // The error keeps a body which isn't json for debugging,
    // eg. the html page of a proxy.
    let msg = format!("{err:#}");
    assert!(msg.contains("unexpected html"), "{msg}");
    assert!(msg.contains("200"), "{msg}");
    // Truncated
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      format!("<html>{}", "é".repeat(1000)),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("<html>"), "{msg}");
    assert!(msg.len() < 800, "{msg}");
  }

  #[test]
  fn test_parse_response_success_status_json_body_is_not_kept() {
    // A 200 with credentials the client can't parse, eg. after a
    // server update changed the response.
    let err = parse_response::<CreateApiKeyResponse>(
      StatusCode::OK,
      r#"{"result":{"key":"K_abc_K","secret":"S_s3cr3t_S"}}"#.into(),
    )
    .unwrap_err();
    for msg in [format!("{err:#}"), format!("{err:?}")] {
      assert!(!msg.contains("s3cr3t"), "{msg}");
      assert!(!msg.contains("K_abc_K"), "{msg}");
      assert!(msg.contains("200"), "{msg}");
      // The missing field helps to debug the mismatch.
      assert!(msg.contains("missing field `key`"), "{msg}");
    }

    // The serde error quotes a scalar of the wrong type
    // (invalid type: integer `1234567`, expected a string).
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      r#"{"jwt":1234567}"#.into(),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("1234567"), "{msg}");
    assert!(msg.contains("invalid type"), "{msg}");
    let err = parse_response::<ConfirmTotpEnrollmentResponse>(
      StatusCode::OK,
      r#"{"recovery_codes":"code-1,code-2"}"#.into(),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("code-1"), "{msg}");
    assert!(msg.contains("invalid type"), "{msg}");

    // Truncated json isn't kept either.
    let err = parse_response::<JwtOrTwoFactor>(
      StatusCode::OK,
      r#"{"type":"Jwt","data":{"jwt":"secret.app.jw"#.into(),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("secret.app"), "{msg}");
  }

  #[test]
  fn test_parse_response_error_status_keeps_body() {
    let err = parse_response::<JwtResponse>(
      StatusCode::UNAUTHORIZED,
      r#"{"error":"invalid token"}"#.into(),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("invalid token"));
    assert!(msg.contains("401"));
  }

  #[test]
  fn test_redact_serde_message() {
    assert_eq!(
      redact_serde_message(
        r#"invalid type: string "a \"quoted\" secret", expected u64 at line 1 column 3"#
      ),
      "invalid type: string [redacted], expected u64 at line 1 column 3"
    );
    assert_eq!(
      redact_serde_message(
        "invalid value: integer `123`, expected x"
      ),
      "invalid value: integer [redacted], expected x"
    );
    // The names expected after an unknown one are the type's.
    assert_eq!(
      redact_serde_message(
        "unknown variant `secret`, expected `Jwt`"
      ),
      "unknown variant [redacted], expected `Jwt`"
    );
    assert_eq!(
      redact_serde_message(
        "unknown field `secret`, there are no fields"
      ),
      "unknown field [redacted], there are no fields"
    );
    assert_eq!(
      redact_serde_message("missing field `jwt` at line 1 column 2"),
      "missing field `jwt` at line 1 column 2"
    );
    assert_eq!(
      redact_serde_message(
        "duplicate field `jwt` at line 1 column 9"
      ),
      "duplicate field `jwt` at line 1 column 9"
    );
    assert_eq!(
      redact_serde_message(r#"unterminated "secret"#),
      "unterminated [redacted]"
    );
    assert_eq!(
      redact_serde_message("unterminated `secret"),
      "unterminated [redacted]"
    );
    assert_eq!(redact_serde_message("no quotes"), "no quotes");
    // A character is written in backticks unescaped.
    let err = <serde_json::Error as serde::de::Error>::invalid_type(
      serde::de::Unexpected::Char('`'),
      &"a secret",
    );
    assert_eq!(
      redact_serde_message(&err.to_string()),
      "invalid type: character [redacted], expected a secret"
    );
  }

  /// serde writes an unknown enum variant (or field) in backticks
  /// without escaping it: a backtick in the value used to end the
  /// redacted part early, leaking the rest, and `missing field`
  /// text in the value was kept as if it were serde's.
  #[test]
  fn test_redact_serde_message_unknown_names_holding_quotes() {
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Strict {
      port: u16,
    }
    for value in [
      "x`s3cr3t",
      "a`b`c`s3cr3t`d",
      "`s3cr3t`",
      "x\"s3cr3t\"",
      "x\"s3cr3t",
      "x`missing field `s3cr3t",
      "x`, missing field `s3cr3t`",
      "x`, expected `s3cr3t",
      "x`, expected `s3cr3t`, expected `x",
      "x`, there are no s3cr3t",
      "multi\nline`s3cr3t",
    ] {
      let body = json!({ "type": value, "data": {} }).to_string();
      let err =
        parse_response::<JwtOrTwoFactor>(StatusCode::OK, body)
          .unwrap_err();
      for msg in [format!("{err:#}"), format!("{err:?}")] {
        assert!(!msg.contains("s3cr3t"), "{value:?}: {msg}");
        assert!(
          msg.contains(
            "unknown variant [redacted], expected one of `Jwt`, `Passkey`, `Totp` at line 1 column"
          ),
          "{value:?}: {msg}"
        );
      }

      let err = serde_json::from_str::<Strict>(
        &json!({ "port": 1, value: 1 }).to_string(),
      )
      .unwrap_err();
      let msg = redact_serde_message(&err.to_string());
      assert!(!msg.contains("s3cr3t"), "{value:?}: {msg}");
      assert!(
        msg.starts_with("unknown field [redacted], expected `port`"),
        "{value:?}: {msg}"
      );

      // A string is redacted whole, whatever it holds.
      let err =
        serde_json::from_str::<u16>(&json!(value).to_string())
          .unwrap_err();
      let msg = redact_serde_message(&err.to_string());
      assert!(
        msg.starts_with(
          "invalid type: string [redacted], expected u16"
        ),
        "{value:?}: {msg}"
      );
    }
    // serde's wording only counts at the start of the message.
    for message in [
      "invalid value: integer `1`, missing field `s3cr3t`",
      "custom: duplicate field `s3cr3t`",
    ] {
      let msg = redact_serde_message(message);
      assert!(!msg.contains("s3cr3t"), "{message:?}: {msg}");
    }
  }

  #[test]
  fn test_parse_token_response_error_is_downcastable() {
    let err = parse_token_response(
      reqwest::StatusCode::BAD_REQUEST,
      r#"{"error":"invalid_grant","error_description":"expired"}"#
        .to_string(),
    )
    .unwrap_err();
    let error = err.downcast_ref::<TokenExchangeError>().unwrap();
    assert_eq!(error.error, "invalid_grant");
    assert_eq!(error.error_description.as_deref(), Some("expired"));
    assert!(
      parse_token_response(
        reqwest::StatusCode::OK,
        "not json".to_string()
      )
      .is_err()
    );
  }

  #[test]
  fn test_parse_token_response_success_status_bad_body() {
    // Does not include the successful response on a parse failure
    let err = parse_token_response(
      reqwest::StatusCode::OK,
      r#"{"access_token":"secret.app.jwt","expires_in":"soon"}"#
        .to_string(),
    )
    .unwrap_err();
    for msg in [format!("{err:#}"), format!("{err:?}")] {
      assert!(!msg.contains("secret.app.jwt"), "{msg}");
      assert!(!msg.contains("soon"), "{msg}");
      assert!(msg.contains("200"), "{msg}");
    }
  }

  #[test]
  fn test_parse_token_response_success() {
    let response = parse_token_response(
      reqwest::StatusCode::OK,
      r#"{"access_token":"jwt","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#.to_string(),
    )
    .unwrap();
    assert_eq!(response.access_token, "jwt");
    assert_eq!(response.expires_in, 3600);
  }

  /// The async functions exist next to the blocking ones, so a
  /// build enabling `blocking` for one crate doesn't break another
  /// using the async functions.
  #[cfg(feature = "blocking")]
  #[allow(unused)]
  fn test_blocking_is_additive() {
    async fn login_async(
      client: &reqwest::Client,
    ) -> anyhow::Result<crate::api::login::GetLoginOptionsResponse>
    {
      login(client, "http://localhost", GetLoginOptions {}).await
    }
    fn login_blocking(
      client: &reqwest::blocking::Client,
    ) -> anyhow::Result<crate::api::login::GetLoginOptionsResponse>
    {
      blocking::login(client, "http://localhost", GetLoginOptions {})
    }
    async fn token_async(
      client: &reqwest::Client,
    ) -> anyhow::Result<TokenExchangeResponse> {
      token_exchange(
        client,
        "http://localhost",
        &TokenExchangeRequest::id_token("t"),
      )
      .await
    }
    fn token_blocking(
      client: &reqwest::blocking::Client,
    ) -> anyhow::Result<TokenExchangeResponse> {
      blocking::token_exchange(
        client,
        "http://localhost",
        &TokenExchangeRequest::id_token("t"),
      )
    }
  }
}
