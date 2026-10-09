use anyhow::anyhow;
use axum::{
  extract::{OriginalUri, Request},
  http::StatusCode,
  middleware::Next,
  response::Response,
};
use mogh_error::AddStatusCodeError as _;
use mogh_request_ip::RequestIp;

use crate::{
  AuthImpl,
  api::manage::ManageRequest,
  middleware::{authenticate_user, read_request_body},
};

/// Authenticates the requests of the auth management api
/// ([authenticate_user]) and attaches the user for the handlers
/// ([UserExtractor][crate::middleware::UserExtractor],
/// [AuthenticatedAt][crate::middleware::AuthenticatedAt]). A disabled
/// user may only ask who they are ([check_disabled_user_request]).
pub async fn attach_user<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  OriginalUri(uri): OriginalUri,
  req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  let auth = I::new();

  let mut authenticated =
    authenticate_user(&auth, ip, &uri, req).await?;

  if !authenticated.user.is_enabled() {
    authenticated.req =
      check_disabled_user_request(authenticated.req).await?;
  }

  // The request goes on to be handled: the app gets to refuse its
  // signature (one it has seen before).
  let req = authenticated.finish(&auth).await?;

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
