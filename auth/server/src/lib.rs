use std::{
  net::IpAddr,
  sync::{Arc, LazyLock},
};

use anyhow::{Context as _, anyhow};
use axum::{extract::FromRequestParts, http::StatusCode};
use mogh_auth_client::{
  api::login::LoginProvider,
  config::{NamedOauthConfig, OidcConfig},
  passkey::Passkey,
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_rate_limit::RateLimiter;
use mogh_request_ip::get_ip_from_headers_and_extensions;
use openidconnect::SubjectIdentifier;

pub mod api;
pub mod provider;
pub mod rand;
pub mod user;
pub mod validations;

mod session;

use crate::{
  provider::{jwt::JwtProvider, passkey::PasskeyProvider},
  session::Session,
  user::BoxAuthUser,
  validations::{validate_password, validate_username},
};

pub mod request_ip {
  pub use mogh_request_ip::*;
}

pub type BoxAuthImpl = Box<dyn AuthImpl>;
pub type DynFuture<O> =
  std::pin::Pin<Box<dyn Future<Output = O> + Send>>;

pub struct RequestClientArgs {
  /// Prefers extraction from headers 'x-forwarded-for', then 'x-real-ip'.
  /// If missing, uses fallback IP extracted directly from request.
  pub ip: IpAddr,
  /// Per-client session state
  pub session: Session,
}

impl<S: Send + Sync> FromRequestParts<S> for RequestClientArgs {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    let ip = get_ip_from_headers_and_extensions(
      &parts.headers,
      &parts.extensions,
    )?;
    let session = parts
      .extensions
      .get::<tower_sessions::Session>()
      .cloned()
      .context("Request context missing Session extension")?;
    Ok(RequestClientArgs {
      ip,
      session: Session(session),
    })
  }
}

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
  fn app_name(&self) -> &'static str;

  /// Provide the app 'host' config
  fn host(&self) -> &str;

  /// Disable new user registration.
  fn registration_disabled(&self) -> bool {
    false
  }

  /// Provide usernames to lock credential updates for,
  /// such as demo users.
  fn locked_usernames(&self) -> &'static [String] {
    &[]
  }

  /// If the locked usernames includes '__ALL__',
  /// this will always error.
  fn check_username_locked(
    &self,
    username: &str,
  ) -> mogh_error::Result<()> {
    if self
      .locked_usernames()
      .iter()
      .any(|locked| locked == username || locked == "__ALL__")
    {
      Err(
        anyhow!("Login credentials are locked for this user")
          .status_code(StatusCode::UNAUTHORIZED),
      )
    } else {
      Ok(())
    }
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
    user_id: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthUser>>;

  // =========
  // = STATE =
  // =========

  /// Get the jwt provider.
  fn jwt_provider(&self) -> &JwtProvider;

  /// Get the webauthn passkey provider
  fn passkey_provider(&self) -> Option<&PasskeyProvider> {
    None
  }

  /// Provide a rate limiter for
  /// general authenticated requests.
  fn general_rate_limiter(&self) -> &RateLimiter {
    static DISABLED_RATE_LIMITER: LazyLock<Arc<RateLimiter>> =
      LazyLock::new(|| RateLimiter::new(true, 0, 0));
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
    username: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>>;

  fn update_user_username(
    &self,
    user_id: String,
    username: String,
  ) -> DynFuture<mogh_error::Result<()>>;

  fn update_user_password(
    &self,
    user_id: String,
    hashed_password: String,
  ) -> DynFuture<mogh_error::Result<()>>;

  // =============
  // = OIDC AUTH =
  // =============

  fn oidc_config(&self) -> &OidcConfig;

  fn find_user_with_oidc_subject(
    &self,
    subject: SubjectIdentifier,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>>;

  /// Returns created user id, or error.
  fn sign_up_oidc_user(
    &self,
    username: String,
    subject: SubjectIdentifier,
    no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>>;

  fn link_oidc_login(
    &self,
    user_id: String,
    subject: SubjectIdentifier,
  ) -> DynFuture<mogh_error::Result<()>>;

  // ==============
  // = NAMED AUTH =
  // ==============

  // = GITHUB =

  fn github_config(&self) -> &NamedOauthConfig;

  fn find_user_with_github_id(
    &self,
    github_id: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>>;

  /// Returns created user id, or error.
  fn sign_up_github_user(
    &self,
    username: String,
    github_id: String,
    no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>>;

  fn link_github_login(
    &self,
    user_id: String,
    github_id: String,
  ) -> DynFuture<mogh_error::Result<()>>;

  // = GOOGLE =

  fn google_config(&self) -> &NamedOauthConfig;

  fn find_user_with_google_id(
    &self,
    google_id: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>>;

  /// Returns created user id, or error.
  fn sign_up_google_user(
    &self,
    username: String,
    google_id: String,
    no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>>;

  fn link_google_login(
    &self,
    user_id: String,
    google_id: String,
  ) -> DynFuture<mogh_error::Result<()>>;

  // ==========
  // = UNLINK =
  // ==========

  fn unlink_login(
    &self,
    user_id: String,
    provider: LoginProvider,
  ) -> DynFuture<mogh_error::Result<()>>;

  // ===============
  // = PASSKEY 2FA =
  // ===============

  /// If Some(Passkey) is passed, it should be stored,
  /// overriding any passkey which was on the User.
  ///
  /// If None is passed, the user passkey should be removed,
  /// unenrolling the user from passkey 2fa.
  fn update_user_stored_passkey(
    &self,
    user_id: String,
    passkey: Option<Passkey>,
  ) -> DynFuture<mogh_error::Result<()>>;

  // ============
  // = TOTP 2FA =
  // ============

  fn update_user_stored_totp(
    &self,
    user_id: String,
    encoded_secret: String,
    hashed_recovery_codes: Vec<String>,
  ) -> DynFuture<mogh_error::Result<()>>;

  fn remove_user_stored_totp(
    &self,
    user_id: String,
  ) -> DynFuture<mogh_error::Result<()>>;

  fn make_totp(
    &self,
    secret_bytes: Vec<u8>,
    account_name: Option<String>,
  ) -> anyhow::Result<totp_rs::TOTP> {
    totp_rs::TOTP::new(
      totp_rs::Algorithm::SHA1,
      6,
      1,
      30,
      secret_bytes,
      Some(String::from(self.app_name())),
      account_name.unwrap_or_default(),
    )
    .context("Failed to construct TOTP")
  }
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
