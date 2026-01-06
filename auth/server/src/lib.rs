use std::sync::{Arc, LazyLock};

use axum::{extract::FromRequestParts, http::StatusCode};
use mogh_error::AddStatusCode;
use mogh_rate_limit::RateLimiter;

pub mod api;
pub mod args;
pub mod jwt;
pub mod session;
pub mod user;
pub mod validations;

use crate::{
  args::RequestClientArgs,
  jwt::JwtProvider,
  user::AuthUserImpl,
  validations::{validate_password, validate_username},
};

pub type BoxAuthArgs = Box<dyn AuthImpl>;
pub type DynFuture<O> =
  std::pin::Pin<Box<dyn Future<Output = O> + Send>>;

static DISABLED_RATE_LIMITER: LazyLock<Arc<RateLimiter>> =
  LazyLock::new(|| RateLimiter::new(true, 0, 0));

/// This trait is implemented at the app level
/// to support custom schemas, storage providers, and business logic.
pub trait AuthImpl: Send + Sync + 'static {
  /// Construct the auth implementation
  /// for a request client.
  fn from_client(client: RequestClientArgs) -> Self
  where
    Self: Sized;

  /// Get the request client args.
  fn client(&self) -> &RequestClientArgs;

  /// Provide a static app name for passkeys.
  fn app_name(&self) -> &str;

  /// Disable new user registration.
  fn registration_disabled(&self) -> bool {
    false
  }

  /// Allow user to register even when registration is disabled
  /// when no users exist. If not implemented, this always evaluates
  /// to false and does not change any behavior.
  fn no_users_exist(&self) -> DynFuture<mogh_error::Result<bool>> {
    Box::pin(async { Ok(false) })
  }

  /// Get's the user using the user id, returning UNAUTHORIZED if none exists.
  fn get_user(
    &self,
    user_id: &str,
  ) -> DynFuture<mogh_error::Result<Box<dyn AuthUserImpl>>>;

  // =========
  // = STATE =
  // =========

  /// Get the jwt provider.
  fn jwt_provider(&self) -> &JwtProvider;

  /// Get the webauthn passkey provider
  fn passkey_provider(&self) -> Option<&webauthn_rs::Webauthn> {
    None
  }

  /// Provide a rate limiter for
  /// general authenticated requests.
  fn general_rate_limiter(&self) -> &RateLimiter {
    &DISABLED_RATE_LIMITER
  }

  // ==============
  // = LOCAL AUTH =
  // ==============

  /// Whether local auth is enabled.
  fn local_auth_enabled(&self) -> bool {
    true
  }

  /// Set the password hash bcrypt cost.
  fn local_auth_bcrypt_cost(&self) -> u32 {
    10
  }

  /// Local login method can have it's own rate limiter
  /// for 1 to 1 user feedback on remaining attempts.
  /// By default uses the general rate limiter.
  fn local_login_rate_limiter(&self) -> &RateLimiter {
    self.general_rate_limiter()
  }

  /// Validate usernames.
  fn validate_username(
    &self,
    username: &str,
  ) -> mogh_error::Result<()> {
    validate_username(username).status_code(StatusCode::BAD_REQUEST)
  }

  /// Validate passwords.
  fn validate_password(
    &self,
    password: &str,
  ) -> mogh_error::Result<()> {
    validate_password(password).status_code(StatusCode::BAD_REQUEST)
  }

  /// Returns created user id, or error.
  /// The username and password have already been validated.
  fn sign_up_local_user(
    &self,
    username: String,
    hashed_password: String,
    no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>>;

  /// Finds user using the username, returning UNAUTHORIZED if none exists.
  fn find_user_with_username(
    &self,
    username: &str,
  ) -> DynFuture<mogh_error::Result<Box<dyn AuthUserImpl>>>;

  // ===============
  // = PASSKEY 2FA =
  // ===============
  fn update_user_stored_passkey(
    &self,
    user_id: &str,
    passkey: webauthn_rs::prelude::Passkey,
  ) -> DynFuture<mogh_error::Result<()>>;
}

/// Extract an implementer of AuthImpl from the request body.
pub struct AuthExtractor<I>(pub I);

impl<I: AuthImpl, S: Send + Sync> FromRequestParts<S>
  for AuthExtractor<I>
{
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    state: &S,
  ) -> Result<Self, Self::Rejection> {
    let client =
      RequestClientArgs::from_request_parts(parts, state).await?;
    Ok(AuthExtractor(I::from_client(client)))
  }
}
