//! # Mogh Auth Token API
//!
//! The OAuth 2.0 token endpoint, implementing
//! [RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693):
//! a token is exchanged for an app token, without any user
//! interaction. Either a user's token of an external login provider
//! with token exchange enabled (the user must already exist and be
//! linked to it), or a workload's token of a trusted issuer (verified
//! with the issuer's keys, or by the cluster which issued it; the
//! user of the rule it matches is created on the first exchange).
//!
//! Unlike the rest of the API, the request is
//! `application/x-www-form-urlencoded` and errors use the
//! OAuth error format ([TokenExchangeError]), as the RFC requires.

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::U64;

/// The `grant_type` of a token exchange request.
pub const GRANT_TYPE_TOKEN_EXCHANGE: &str =
  "urn:ietf:params:oauth:grant-type:token-exchange";

/// Token type of an OIDC ID token.
pub const TOKEN_TYPE_ID_TOKEN: &str =
  "urn:ietf:params:oauth:token-type:id_token";
/// Token type of a JWT.
pub const TOKEN_TYPE_JWT: &str =
  "urn:ietf:params:oauth:token-type:jwt";
/// Token type of an OAuth access token.
pub const TOKEN_TYPE_ACCESS_TOKEN: &str =
  "urn:ietf:params:oauth:token-type:access_token";

#[allow(unused)]
#[cfg(feature = "utoipa")]
#[utoipa::path(
  post,
  path = "/token",
  security(()),
  description = "RFC 8693 Token Exchange. Exchange a signed token (ID token / JWT) for an app token: a user's token of an external login provider with token exchange enabled (the user must already exist and be linked to the provider), or a workload's token of a trusted issuer (verified with the issuer's keys, or by the cluster which issued it; the user of the rule the token matches is created on the first exchange).",
  request_body(content = TokenExchangeRequest, content_type = "application/x-www-form-urlencoded"),
  responses(
    (status = 200, description = "The app token", body = TokenExchangeResponse),
    (status = 400, description = "The request or the token was rejected", body = TokenExchangeError),
    (status = 429, description = "Too many failed requests, retry later (`temporarily_unavailable`)", body = TokenExchangeError),
    (status = 500, description = "Request failed", body = TokenExchangeError),
    (status = 503, description = "A login provider or trusted issuer of the token's issuer can't be loaded right now, retry later (`temporarily_unavailable`)", body = TokenExchangeError)
  ),
)]
fn token_exchange() {}

/// The form parameters of a token exchange request (RFC 8693 section 2.1).
/// `resource`, `audience` and `scope` are accepted but have no effect.
#[typeshare]
#[derive(Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TokenExchangeRequest {
  /// Must be [GRANT_TYPE_TOKEN_EXCHANGE].
  pub grant_type: String,
  /// The token to exchange: a user's token of an external login
  /// provider, or a workload's token of a trusted issuer.
  pub subject_token: String,
  /// [TOKEN_TYPE_ID_TOKEN] or [TOKEN_TYPE_JWT].
  pub subject_token_type: String,
  /// Optional. [TOKEN_TYPE_ACCESS_TOKEN] (default) or [TOKEN_TYPE_JWT].
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub requested_token_type: Option<String>,
  /// Not supported (delegation), requests including it are rejected.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub actor_token: Option<String>,
  /// Not supported (delegation).
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub actor_token_type: Option<String>,
}

impl TokenExchangeRequest {
  /// Exchange an OIDC ID token.
  pub fn id_token(subject_token: impl Into<String>) -> Self {
    Self {
      grant_type: GRANT_TYPE_TOKEN_EXCHANGE.to_string(),
      subject_token: subject_token.into(),
      subject_token_type: TOKEN_TYPE_ID_TOKEN.to_string(),
      ..Default::default()
    }
  }

  /// Exchange a signed token which is not an OIDC ID token, eg. the
  /// one a CI platform or Kubernetes issues to a workload.
  pub fn jwt(subject_token: impl Into<String>) -> Self {
    Self {
      subject_token_type: TOKEN_TYPE_JWT.to_string(),
      ..Self::id_token(subject_token)
    }
  }
}

/// The tokens are redacted.
impl std::fmt::Debug for TokenExchangeRequest {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("TokenExchangeRequest")
      .field("grant_type", &self.grant_type)
      .field("subject_token", &"##############")
      .field("subject_token_type", &self.subject_token_type)
      .field("requested_token_type", &self.requested_token_type)
      .field("actor_token", &self.actor_token.as_ref().map(|_| "###"))
      .field("actor_token_type", &self.actor_token_type)
      .finish()
  }
}

/// A successful token exchange (RFC 8693 section 2.2.1).
#[typeshare]
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TokenExchangeResponse {
  /// The app token (JWT), sent as `Authorization: Bearer <token>`.
  pub access_token: String,
  /// The `requested_token_type`, or [TOKEN_TYPE_ACCESS_TOKEN].
  pub issued_token_type: String,
  /// Always `Bearer`.
  pub token_type: String,
  /// Seconds until the app token expires.
  pub expires_in: U64,
}

/// The app token is redacted.
impl std::fmt::Debug for TokenExchangeResponse {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("TokenExchangeResponse")
      .field("access_token", &"##############")
      .field("issued_token_type", &self.issued_token_type)
      .field("token_type", &self.token_type)
      .field("expires_in", &self.expires_in)
      .finish()
  }
}

/// A failed token exchange (RFC 6749 section 5.2).
#[typeshare]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TokenExchangeError {
  /// The OAuth error code, and the http status it comes with:
  /// - `invalid_request` (`400`): The request is malformed or uses unsupported parameters.
  /// - `unsupported_grant_type` (`400`): `grant_type` is not token exchange.
  /// - `invalid_grant` (`400`): The subject token was rejected.
  /// - `temporarily_unavailable`: Retry later. Either `429`, too many
  ///   failed requests, or `503`, a login provider or trusted issuer of
  ///   the token's issuer can't be loaded right now (eg. its keys can't
  ///   be fetched). With several of them sharing the issuer, a token the
  ///   others rejected is `503` rather than `invalid_grant` while one is
  ///   unavailable, as that one might have accepted it.
  /// - `server_error` (`500`)
  pub error: String,
  /// Human readable details.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error_description: Option<String>,
}

impl std::fmt::Display for TokenExchangeError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match &self.error_description {
      Some(description) => write!(f, "{}: {description}", self.error),
      None => f.write_str(&self.error),
    }
  }
}

impl std::error::Error for TokenExchangeError {}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_request_debug_redacts_tokens() {
    let mut request =
      TokenExchangeRequest::id_token("secret.id.token");
    request.actor_token = Some("secret.actor.token".into());
    let debug = format!("{request:?}");
    assert!(!debug.contains("secret.id.token"));
    assert!(!debug.contains("secret.actor.token"));
    assert!(debug.contains(TOKEN_TYPE_ID_TOKEN));
  }

  #[test]
  fn test_response_debug_redacts_app_token() {
    let response = TokenExchangeResponse {
      access_token: "secret.app.jwt".into(),
      issued_token_type: TOKEN_TYPE_ACCESS_TOKEN.into(),
      token_type: "Bearer".into(),
      expires_in: 3600,
    };
    let debug = format!("{response:?}");
    assert!(!debug.contains("secret.app.jwt"));
    assert!(debug.contains("3600"));
  }

  #[test]
  fn test_request_constructors() {
    let id_token = TokenExchangeRequest::id_token("token");
    assert_eq!(id_token.grant_type, GRANT_TYPE_TOKEN_EXCHANGE);
    assert_eq!(id_token.subject_token_type, TOKEN_TYPE_ID_TOKEN);
    let jwt = TokenExchangeRequest::jwt("token");
    assert_eq!(jwt.grant_type, GRANT_TYPE_TOKEN_EXCHANGE);
    assert_eq!(jwt.subject_token_type, TOKEN_TYPE_JWT);
    assert_eq!(jwt.subject_token, "token");
  }

  #[test]
  fn test_request_form_roundtrip() {
    let request = TokenExchangeRequest::id_token("a.b.c");
    let form = serde_json::to_value(&request).unwrap();
    // Unset optional parameters are not sent
    assert_eq!(
      form,
      serde_json::json!({
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "subject_token": "a.b.c",
        "subject_token_type": TOKEN_TYPE_ID_TOKEN,
      })
    );
  }

  #[test]
  fn test_error_wire_format() {
    let error = TokenExchangeError {
      error: "invalid_grant".into(),
      error_description: None,
    };
    assert_eq!(
      serde_json::to_value(&error).unwrap(),
      serde_json::json!({ "error": "invalid_grant" })
    );
    assert_eq!(error.to_string(), "invalid_grant");
  }
}
