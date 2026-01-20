use std::{
  net::IpAddr,
  sync::{Arc, LazyLock},
};

use anyhow::{Context as _, anyhow};
use axum::{
  extract::{FromRequestParts, Request},
  http::StatusCode,
};
use mogh_auth_client::{
  api::{login::LoginProvider, manage::CreateApiKey},
  config::{NamedOauthConfig, OidcConfig},
  passkey::Passkey,
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_pki::RotatableKeyPair;
use mogh_rate_limit::RateLimiter;
use mogh_request_ip::get_ip_from_headers_and_extensions;
use openidconnect::SubjectIdentifier;

pub mod api;
pub mod middleware;
pub mod provider;
pub mod rand;
pub mod user;
pub mod validations;

mod session;

use crate::{
  provider::{jwt::JwtProvider, passkey::PasskeyProvider},
  session::Session,
  user::BoxAuthUser,
  validations::{
    validate_api_key_name, validate_password, validate_username,
  },
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

#[derive(Clone)]
pub enum RequestAuthentication {
  /// The user ID comes from JWT, which is already validated by the JwtProvider.
  UserId(String),
  /// X-API-KEY and X-API-SECRET.
  /// DANGER ⚠️ the key and secret must still be validated.
  KeyAndSecret { key: String, secret: String },
  /// X-API-SIGNATURE and X-API-TIMESTAMP. The handshake produces the public key.
  /// DANGER ⚠️ the public key must still be validated as belonging to a particular client.
  PublicKey(String),
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
  fn app_name(&self) -> &'static str {
    panic!(
      "Must implement 'AuthImpl::app_name' in order for passkey 2fa to work."
    )
  }

  /// Provide the app 'host' config.
  /// This should include the path to where the auth server is nested,
  /// Ie if it is nested on /auth, this points to https://example.com/auth
  fn host(&self) -> &str {
    panic!(
      "Must implement 'AuthImpl::host' in order for external logins and other features to work."
    )
  }

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

  /// Handle incoming request authentication in middleware.
  /// Can attach a client struct as request extension here.
  fn handle_request_authentication(
    &self,
    auth: RequestAuthentication,
    req: Request,
  ) -> DynFuture<mogh_error::Result<Request>>;

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

  /// Where to default redirect after linking an external login method.
  fn post_link_redirect(&self) -> &str {
    panic!(
      "Must implement 'AuthImpl::post_link_redirect' in order for linking to work. This is usually the application profile or settings page."
    )
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
    _username: String,
    _hashed_password: String,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    panic!(
      "Must implement 'AuthImpl::sign_up_local_user' in order for local login to work."
    )
  }

  /// Finds user using the username, returning UNAUTHORIZED if none exists.
  fn find_user_with_username(
    &self,
    _username: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    panic!(
      "Must implement 'AuthImpl::find_user_with_username' in order for local login to work."
    )
  }

  fn update_user_username(
    &self,
    _user_id: String,
    _username: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::update_user_username'.")
  }

  fn update_user_password(
    &self,
    _user_id: String,
    _hashed_password: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::update_user_password'.")
  }

  // =============
  // = OIDC AUTH =
  // =============

  fn oidc_config(&self) -> Option<&OidcConfig> {
    None
  }

  fn find_user_with_oidc_subject(
    &self,
    _subject: SubjectIdentifier,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    panic!("Must implement 'AuthImpl::find_user_with_oidc_subject'.")
  }

  /// Returns created user id, or error.
  fn sign_up_oidc_user(
    &self,
    _username: String,
    _subject: SubjectIdentifier,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    panic!("Must implement 'AuthImpl::sign_up_oidc_user'.")
  }

  fn link_oidc_login(
    &self,
    _user_id: String,
    _subject: SubjectIdentifier,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::link_oidc_login'.")
  }

  // ==============
  // = NAMED AUTH =
  // ==============

  // = GITHUB =

  fn github_config(&self) -> Option<&NamedOauthConfig> {
    None
  }

  fn find_user_with_github_id(
    &self,
    _github_id: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    panic!("Must implement 'AuthImpl::find_user_with_github_id'.")
  }

  /// Returns created user id, or error.
  fn sign_up_github_user(
    &self,
    _username: String,
    _github_id: String,
    _avatar_url: String,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    panic!("Must implement 'AuthImpl::sign_up_github_user'.")
  }

  fn link_github_login(
    &self,
    _user_id: String,
    _github_id: String,
    _avatar_url: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::link_github_login'.")
  }

  // = GOOGLE =

  fn google_config(&self) -> Option<&NamedOauthConfig> {
    None
  }

  fn find_user_with_google_id(
    &self,
    _google_id: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    panic!("Must implement 'AuthImpl::find_user_with_google_id'.")
  }

  /// Returns created user id, or error.
  fn sign_up_google_user(
    &self,
    _username: String,
    _google_id: String,
    _avatar_url: String,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    panic!("Must implement 'AuthImpl::sign_up_google_user'.")
  }

  fn link_google_login(
    &self,
    _user_id: String,
    _google_id: String,
    _avatar_url: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::link_google_login'.")
  }

  // ==========
  // = UNLINK =
  // ==========

  fn unlink_login(
    &self,
    _user_id: String,
    _provider: LoginProvider,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::unlink_login'.")
  }

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
    _user_id: String,
    _passkey: Option<Passkey>,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::update_user_stored_passkey'.")
  }

  // ============
  // = TOTP 2FA =
  // ============

  fn update_user_stored_totp(
    &self,
    _user_id: String,
    _encoded_secret: String,
    _hashed_recovery_codes: Vec<String>,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::update_user_stored_totp'.")
  }

  fn remove_user_stored_totp(
    &self,
    _user_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::remove_user_stored_totp'.")
  }

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

  // ============
  // = SKIP 2FA =
  // ============
  fn update_user_external_skip_2fa(
    &self,
    _user_id: String,
    _external_skip_2fa: bool,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!(
      "Must implement 'AuthImpl::update_user_external_skip_2fa'."
    )
  }

  // ============
  // = API KEYS =
  // ============
  /// Validate api key name.
  fn validate_api_key_name(
    &self,
    api_key_name: &str,
  ) -> mogh_error::Result<()> {
    validate_api_key_name(api_key_name)
      .status_code(StatusCode::BAD_REQUEST)
  }

  /// Set custom API key length. Default is 40.
  fn api_key_secret_length(&self) -> usize {
    40
  }

  /// Set the api secret hash bcrypt cost.
  fn api_secret_bcrypt_cost(&self) -> u32 {
    self.local_auth_bcrypt_cost()
  }

  fn create_api_key(
    &self,
    _user_id: String,
    _body: CreateApiKey,
    _key: String,
    _hashed_secret: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::create_api_key'.")
  }

  fn get_api_key_user_id(
    &self,
    _key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    panic!("Must implement 'AuthImpl::get_api_key_user_id'.")
  }

  fn delete_api_key(
    &self,
    _key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    panic!("Must implement 'AuthImpl::delete_api_key'.")
  }

  /// Pass the server private key to use with api key v2 handshakes.
  fn server_private_key(&self) -> Option<&RotatableKeyPair> {
    None
  }

  fn create_api_key_v2(
    &self,
    _user_id: String,
    _body: CreateApiKey,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    panic!("Must implement 'AuthImpl::create_api_key_v2'.")
  }

  fn get_api_key_v2_user_id(
    &self,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    panic!("Must implement 'AuthImpl::get_api_key_v2_user_id'.")
  }

  fn delete_api_key_v2(
    &self,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    panic!("Must implement 'AuthImpl::delete_api_key_v2'.")
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
