//! Helpers shared by the unit tests: a session, a jwt provider, and
//! stubs of the methods every `AuthImpl` must implement.

use std::sync::{Arc, LazyLock};

use crate::{provider::jwt::JwtProvider, session::Session};

/// A session of its own, in an in memory store.
pub(crate) fn session() -> Session {
  Session(tower_sessions::Session::new(
    None,
    Arc::new(tower_sessions::MemoryStore::default()),
    None,
  ))
}

/// A jwt provider with a test secret and a 60 second ttl.
pub(crate) fn test_jwt_provider() -> &'static JwtProvider {
  static PROVIDER: LazyLock<JwtProvider> =
    LazyLock::new(|| JwtProvider::new(b"secret", 60_000));
  &PROVIDER
}

/// Implements the named methods every `AuthImpl` must implement, for
/// a test implementation which doesn't use them: `get_user` and
/// `handle_request_authentication` fail, `jwt_provider` is
/// [test_jwt_provider]. Inside the `impl AuthImpl` block:
///
/// ```ignore
/// stub_auth_impl!(get_user, handle_request_authentication);
/// ```
macro_rules! stub_auth_impl {
  ($($method:ident),+ $(,)?) => {
    $($crate::test_support::stub_auth_impl!(@ $method);)+
  };
  (@ get_user) => {
    fn get_user(
      &self,
      _user_id: String,
    ) -> $crate::DynFuture<mogh_error::Result<$crate::user::BoxAuthUser>>
    {
      Box::pin(async { Err(anyhow::anyhow!("not implemented").into()) })
    }
  };
  (@ handle_request_authentication) => {
    fn handle_request_authentication(
      &self,
      _auth: $crate::RequestAuthentication,
      _ip: std::net::IpAddr,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> $crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async { Err(anyhow::anyhow!("not implemented").into()) })
    }
  };
  (@ jwt_provider) => {
    fn jwt_provider(&self) -> &$crate::provider::jwt::JwtProvider {
      $crate::test_support::test_jwt_provider()
    }
  };
}

pub(crate) use stub_auth_impl;
