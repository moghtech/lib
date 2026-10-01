use std::sync::Arc;

use anyhow::{Context, anyhow};
use axum::{
  extract::{FromRequestParts, OriginalUri, Request},
  http::StatusCode,
  middleware::Next,
  response::Response,
};
use mogh_error::{AddStatusCode, AddStatusCodeError as _};
use mogh_rate_limit::WithFailureRateLimit as _;
use mogh_request_ip::RequestIp;

use crate::{
  AuthImpl, RequestAuthentication,
  api::manage::ManageRequest,
  middleware::{
    accept_signed_request, accepted_signature,
    extract_request_authentication_rate_limited,
    get_user_from_request_authentication, read_request_body,
    read_signed_request_body,
  },
  user::BoxAuthUser,
};

#[derive(Clone)]
pub struct UserExtractor(pub Arc<BoxAuthUser>);

impl<S: Send + Sync> FromRequestParts<S> for UserExtractor {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    parts
      .extensions
      .get()
      .cloned()
      .context("Missing authorization credentials")
      .status_code(StatusCode::UNAUTHORIZED)
  }
}

/// When the user logged in to get the token the request is
/// authenticated with (unix seconds), see
/// [JwtClaims::authenticated_at][crate::provider::jwt::JwtClaims::authenticated_at].
/// `None` for credentials without a login: api keys, signing keys,
/// and tokens not issued by [AuthImpl::jwt_provider].
#[derive(Clone, Copy)]
pub struct AuthenticatedAt(pub Option<u64>);

impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedAt {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    parts
      .extensions
      .get()
      .copied()
      .context("Missing authorization credentials")
      .status_code(StatusCode::UNAUTHORIZED)
  }
}

pub async fn attach_user<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  OriginalUri(uri): OriginalUri,
  req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  let auth = I::new();

  // The signature of a signed request covers the body. One which
  // can't verify is refused before it is read.
  let (req, body) = read_signed_request_body(&auth, ip, req).await?;

  let req_auth = extract_request_authentication_rate_limited(
    &auth,
    ip,
    req.method(),
    &uri,
    req.headers(),
    &body,
  )
  .await?;

  let accepted = accepted_signature(&req_auth, req.headers())?;

  let authenticated_at = match &req_auth {
    RequestAuthentication::Jwt(jwt) => auth
      .jwt_provider()
      .decode_claims(jwt)
      .ok()
      // The login, not the token: tokens issued by token exchange
      // carry when the provider authenticated the user.
      .map(|claims| claims.authenticated_at()),
    RequestAuthentication::ApiKey { .. }
    | RequestAuthentication::PublicKey(_) => None,
  };

  // Enforces the api key and user cidr whitelists.
  let user =
    get_user_from_request_authentication(&auth, req_auth, ip)
      .with_failure_rate_limit_using_ip(
        auth.general_rate_limiter(),
        &ip,
      )
      .await?;

  let mut req = if user.is_enabled() {
    req
  } else {
    check_disabled_user_request(req).await?
  };

  // The request goes on to be handled: the app gets to refuse its
  // signature (one it has seen before).
  accept_signed_request(&auth, ip, accepted, &mut req).await?;

  req.extensions_mut().insert(UserExtractor(Arc::new(user)));
  req
    .extensions_mut()
    .insert(AuthenticatedAt(authenticated_at));

  Ok(next.run(req).await)
}

/// Disabled users ([AuthUserImpl::is_enabled][crate::user::AuthUserImpl::is_enabled])
/// may only ask who they are (`GetUserId`, eg. the UI of a user waiting
/// to be enabled). Everything else is refused, including any request
/// added in the future: a disabled admin must not keep managing login
/// providers or trusted issuers, nor a disabled user create credentials.
///
/// `req` is routed within the manage router: `POST /` carries the type
/// in the body, `POST /{variant}` in the path.
async fn check_disabled_user_request(
  req: Request,
) -> mogh_error::Result<Request> {
  let (req, get_user_id) = match req.uri().path() {
    "/GetUserId" => (req, true),
    "/" => {
      let (req, body) = read_request_body(req).await?;
      let get_user_id = matches!(
        serde_json::from_slice(&body),
        Ok(ManageRequest::GetUserId(_))
      );
      (req, get_user_id)
    }
    _ => (req, false),
  };
  if get_user_id {
    Ok(req)
  } else {
    Err(
      anyhow!("User is not enabled")
        .status_code(StatusCode::FORBIDDEN),
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn request(path: &str, body: &str) -> Request {
    Request::post(path).body(body.to_string().into()).unwrap()
  }

  #[tokio::test]
  async fn test_disabled_users_may_only_get_their_id() {
    for (path, body) in [
      ("/GetUserId", "{}"),
      ("/", r#"{"type":"GetUserId","params":{}}"#),
    ] {
      let req = check_disabled_user_request(request(path, body))
        .await
        .unwrap_or_else(|e| panic!("{path} {body}: {:#}", e.error));
      // The body is put back for the handler.
      let (_, handler_body) = read_request_body(req).await.unwrap();
      assert_eq!(handler_body, body);
    }
    for (path, body) in [
      ("/CreateTrustedIssuer", "{}"),
      ("/CreateApiKey", r#"{"name":"x"}"#),
      (
        "/",
        r#"{"type":"CreateApiKey","params":{"name":"x","expires":0}}"#,
      ),
      ("/", r#"{"type":"GetUserId"}"#),
      ("/", "not json"),
      ("/", ""),
      // Not how the manage router sees requests.
      ("/auth/manage/GetUserId", "{}"),
    ] {
      let err = check_disabled_user_request(request(path, body))
        .await
        .err()
        .unwrap_or_else(|| panic!("{path} {body}"));
      assert_eq!(err.status, StatusCode::FORBIDDEN, "{path} {body}");
    }
  }
}
