use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, anyhow};
use axum::{
  extract::{OriginalUri, Request},
  http::{HeaderMap, Method, Uri},
  middleware::Next,
  response::Response,
};
use mogh_error::AddStatusCode;
use mogh_pki::{Pkcs8PrivateKey, one_way::OneWayNoiseHandshake};
use mogh_rate_limit::WithFailureRateLimit;
use reqwest::StatusCode;

use crate::{
  AuthExtractor, AuthImpl, RequestAuthentication,
  provider::jwt::JwtProvider,
};

pub async fn authenticate_request<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
  OriginalUri(uri): OriginalUri,
  req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  let req_auth = extract_request_authentication(
    &auth,
    req.method(),
    &uri,
    req.headers(),
  )?;

  let req = auth
    .handle_request_authentication(req_auth, req)
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &auth.client().ip,
    )
    .await?;

  Ok(next.run(req).await)
}

pub fn extract_request_authentication<I: AuthImpl>(
  auth: &I,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
) -> mogh_error::Result<RequestAuthentication> {
  if let Some(user_id) =
    extract_request_user_id(auth.jwt_provider(), headers)?
  {
    return Ok(RequestAuthentication::UserId(user_id));
  }

  if let Some((key, secret)) =
    extract_request_key_and_secret(headers)?
  {
    return Ok(RequestAuthentication::KeyAndSecret { key, secret });
  }

  if let Some(key) = headers.get("x-api-key") {
    let key = key
      .to_str()
      .context("X-API-KEY is not valid UTF-8")?
      .trim()
      .to_string();
    let secret = headers
      .get("x-api-secret")
      .context(
        "Request headers have X-API-KEY but missing X-API-SECRET",
      )?
      .to_str()
      .context("X-API-KEY is not valid UTF-8")?
      .trim()
      .to_string();
    return Ok(RequestAuthentication::KeyAndSecret { key, secret });
  }

  extract_request_public_key(auth, method, uri, headers).and_then(
    |res| {
      res
        .context("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED)
        .map(RequestAuthentication::PublicKey)
    },
  )
}

pub fn extract_request_user_id(
  jwt_provider: &JwtProvider,
  headers: &HeaderMap,
) -> mogh_error::Result<Option<String>> {
  let Some(authorization) = headers.get("authorization") else {
    return Ok(None);
  };
  let maybe_bearer = authorization
    .to_str()
    .context("AUTHORIZATION is not valid UTF-8")?
    .trim();
  let jwt =
    maybe_bearer.strip_prefix("Bearer ").unwrap_or(maybe_bearer);
  let user_id = jwt_provider.decode_sub(jwt)?;
  Ok(Some(user_id))
}

pub fn extract_request_key_and_secret(
  headers: &HeaderMap,
) -> mogh_error::Result<Option<(String, String)>> {
  let Some(key) = headers.get("x-api-key") else {
    return Ok(None);
  };
  let key = key
    .to_str()
    .context("X-API-KEY is not valid UTF-8")?
    .trim()
    .to_string();
  let secret = headers
    .get("x-api-secret")
    .context(
      "Request headers have X-API-KEY but missing X-API-SECRET",
    )?
    .to_str()
    .context("X-API-KEY is not valid UTF-8")?
    .trim()
    .to_string();
  return Ok(Some((key, secret)));
}

pub fn extract_request_public_key<I: AuthImpl>(
  auth: &I,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
) -> mogh_error::Result<Option<String>> {
  let Some(signature) = headers.get("x-api-signature") else {
    return Ok(None);
  };
  let signature = signature
    .to_str()
    .context("X-API-SIGNATURE is not valid UTF-8")?;
  let timestamp = headers
    .get("x-api-timestamp")
    .context("Request headers have X-API-SIGNATURE but missing X-API-TIMESTAMP")?
    .to_str()
    .context("X-API-TIMESTAMP is not valid UTF-8")?
    .parse::<i64>()?;

  let now =
    SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;

  // Ensure timestamp is ~now
  if (now - timestamp).abs() > 1_000 {
    return Err(anyhow!("Invalid client credentials").into());
  }

  let prologue = pki_auth_prologue(method, uri, timestamp);

  let mut handshake = OneWayNoiseHandshake::new_responder(
    &Pkcs8PrivateKey::maybe_raw_bytes(
      auth
        .server_private_key()
        .context("Missing server private key for request handshake")?
        .load()
        .private(),
    )?,
    prologue.as_bytes(),
  )?;

  let public_key =
    handshake.validate_signature(signature)?.into_inner();

  Ok(Some(public_key))
}

pub fn pki_auth_prologue(
  method: &Method,
  uri: &Uri,
  timestamp: i64,
) -> String {
  format!("{method}|{uri}|{timestamp}")
}
