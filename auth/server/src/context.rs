//! What the auth server knows of the request it is handling, for the
//! app's hooks to read: who made it, from where, and which request it
//! is. Eg. for the audit rows of the writes the hooks make
//! (`create_external_provider`, `update_trusted_issuer`,
//! `create_api_key`, ...), which take the provider, issuer or key
//! alone.

use std::{cell::RefCell, net::IpAddr};

/// The request the auth server is handling, see [request_context].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RequestContext {
  /// The client ip (forwarding headers believed from the trusted
  /// proxies only).
  pub ip: IpAddr,
  /// The request, by the name it has on the wire:
  /// - a login or management request, its type (`LoginLocalUser`,
  ///   `CreateApiKey`, ...), once its body was read. Until then (eg.
  ///   in [AuthImpl::get_user_id_from_request_authentication][crate::AuthImpl::get_user_id_from_request_authentication],
  ///   which authenticates a management request first) [LOGIN] or
  ///   [MANAGE].
  /// - `ExternalLogin`, `ExternalLink` and `ExternalCallback`: the
  ///   browser routes of external logins (`/external/{slug}/...`).
  /// - `TokenExchange`: `POST /token`.
  pub method: &'static str,
  /// The user the request authenticated as, once it did: a
  /// management request after its credentials (and the user's
  /// cidr whitelist) checked out, the same for a middleware of the
  /// app's own built on
  /// [authenticate_user][crate::middleware::authenticate_user].
  /// `None` for logins: the hooks a login calls take the user as an
  /// argument, and [AuthImpl::record_login][crate::AuthImpl::record_login]
  /// gets the [Login][crate::Login].
  pub user_id: Option<String>,
}

/// [RequestContext::method] of a login request whose body isn't read
/// yet.
pub const LOGIN: &str = "Login";
/// [RequestContext::method] of a management request whose body isn't
/// read yet.
pub const MANAGE: &str = "Manage";
/// [RequestContext::method] of `/external/{slug}/login`.
pub const EXTERNAL_LOGIN: &str = "ExternalLogin";
/// [RequestContext::method] of `/external/{slug}/link`.
pub const EXTERNAL_LINK: &str = "ExternalLink";
/// [RequestContext::method] of `/external/{slug}/callback`.
pub const EXTERNAL_CALLBACK: &str = "ExternalCallback";
/// [RequestContext::method] of `POST /token`.
pub const TOKEN_EXCHANGE: &str = "TokenExchange";

impl RequestContext {
  pub fn new(
    ip: IpAddr,
    method: &'static str,
    user_id: Option<String>,
  ) -> RequestContext {
    RequestContext {
      ip,
      method,
      user_id,
    }
  }
}

tokio::task_local! {
  static REQUEST_CONTEXT: RefCell<RequestContext>;
}

/// The request of the auth server's router this runs in: in its
/// handlers, and so in the [AuthImpl][crate::AuthImpl] hooks they
/// call (also the ones the server runs in a task of its own, the
/// store and sync of a trusted issuer update). `None` outside of one:
/// a request of
/// the app's own api, a background task, or a helper of the server
/// called directly (eg. `api::manage::issuer::update_issuer`, which
/// [scope_request_context] can give one).
///
/// It is a tokio task-local, scoped by the router around each
/// request. A task the app spawns doesn't inherit it: read it before,
/// and move it in.
pub fn request_context() -> Option<RequestContext> {
  REQUEST_CONTEXT
    .try_with(|context| context.borrow().clone())
    .ok()
}

/// Runs `fut` with `context` as its [request_context]: for a task
/// which carries on the work of a request, and for code calling the
/// helpers of the server outside of its router (eg. tests).
pub async fn scope_request_context<F: Future>(
  context: RequestContext,
  fut: F,
) -> F::Output {
  REQUEST_CONTEXT.scope(RefCell::new(context), fut).await
}

/// Sets [RequestContext::method] once the request is known. Nothing
/// outside of a request.
pub(crate) fn set_request_method(method: &'static str) {
  let _ = REQUEST_CONTEXT
    .try_with(|context| context.borrow_mut().method = method);
}

/// Sets [RequestContext::user_id] once the request authenticated.
/// Nothing outside of a request.
pub(crate) fn set_request_user_id(user_id: &str) {
  let _ = REQUEST_CONTEXT.try_with(|context| {
    context.borrow_mut().user_id = Some(user_id.to_string())
  });
}

#[cfg(test)]
mod tests {
  use super::*;

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3));

  #[tokio::test]
  async fn test_request_context_is_scoped() {
    assert_eq!(request_context(), None);
    // Setting it outside of a request does nothing.
    set_request_method("CreateApiKey");
    set_request_user_id("user");
    assert_eq!(request_context(), None);

    let context = scope_request_context(
      RequestContext::new(IP, MANAGE, None),
      async {
        let before = request_context().unwrap();
        set_request_user_id("user");
        set_request_method("CreateApiKey");
        (before, request_context().unwrap())
      },
    )
    .await;
    assert_eq!(context.0, RequestContext::new(IP, MANAGE, None));
    assert_eq!(
      context.1,
      RequestContext::new(IP, "CreateApiKey", Some("user".into()))
    );
    assert_eq!(request_context(), None);
  }
}
