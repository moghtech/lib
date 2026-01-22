use std::sync::{Arc, LazyLock};

use anyhow::{Context as _, anyhow};
use axum::{extract::Request, http::StatusCode};
use mogh_auth_client::{
  api::{login::LoginProvider, manage::CreateApiKey},
  config::{NamedOauthConfig, OidcConfig},
  passkey::Passkey,
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_pki::RotatableKeyPair;
use mogh_rate_limit::RateLimiter;
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
  /// Construct the auth implementation for extraction.
  /// Only use this at the top level of a client request.
  fn new() -> Self
  where
    Self: Sized;

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
    require_user_enabled: bool,
    req: Request,
  ) -> DynFuture<mogh_error::Result<Request>>;

  /// Get user id from request authentication
  /// for use in auth management API middleware.
  fn get_user_id_from_request_authentication(
    &self,
    auth: RequestAuthentication,
  ) -> DynFuture<mogh_error::Result<String>> {
    match auth {
      RequestAuthentication::UserId(user_id) => {
        Box::pin(async { Ok(user_id) })
      }
      RequestAuthentication::KeyAndSecret { key, .. } => {
        self.get_api_key_user_id(key)
      }
      RequestAuthentication::PublicKey(public_key) => {
        self.get_api_key_v2_user_id(public_key)
      }
    }
  }

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
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::sign_up_local_user' in order for local login to work."
        )
        .into(),
      )
    })
  }

  /// Finds user using the username, returning UNAUTHORIZED if none exists.
  fn find_user_with_username(
    &self,
    _username: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_user_with_username' in order for local login to work."
        )
        .into(),
      )
    })
  }

  fn update_user_username(
    &self,
    _user_id: String,
    _username: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::update_user_username'.")
          .into(),
      )
    })
  }

  fn update_user_password(
    &self,
    _user_id: String,
    _hashed_password: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::update_user_password'.")
          .into(),
      )
    })
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
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_user_with_oidc_subject'."
        )
        .into(),
      )
    })
  }

  /// Returns created user id, or error.
  fn sign_up_oidc_user(
    &self,
    _username: String,
    _subject: SubjectIdentifier,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::sign_up_oidc_user'.")
          .into(),
      )
    })
  }

  fn link_oidc_login(
    &self,
    _user_id: String,
    _subject: SubjectIdentifier,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::link_oidc_login'.").into(),
      )
    })
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
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_user_with_github_id'."
        )
        .into(),
      )
    })
  }

  /// Returns created user id, or error.
  fn sign_up_github_user(
    &self,
    _username: String,
    _github_id: String,
    _avatar_url: String,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::sign_up_github_user'.")
          .into(),
      )
    })
  }

  fn link_github_login(
    &self,
    _user_id: String,
    _github_id: String,
    _avatar_url: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::link_github_login'.")
          .into(),
      )
    })
  }

  // = GOOGLE =

  fn google_config(&self) -> Option<&NamedOauthConfig> {
    None
  }

  fn find_user_with_google_id(
    &self,
    _google_id: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_user_with_google_id'."
        )
        .into(),
      )
    })
  }

  /// Returns created user id, or error.
  fn sign_up_google_user(
    &self,
    _username: String,
    _google_id: String,
    _avatar_url: String,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::sign_up_google_user'.")
          .into(),
      )
    })
  }

  fn link_google_login(
    &self,
    _user_id: String,
    _google_id: String,
    _avatar_url: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::link_google_login'.")
          .into(),
      )
    })
  }

  // ==========
  // = UNLINK =
  // ==========

  fn unlink_login(
    &self,
    _user_id: String,
    _provider: LoginProvider,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(anyhow!("Must implement 'AuthImpl::unlink_login'.").into())
    })
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
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_user_stored_passkey'."
        )
        .into(),
      )
    })
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
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_user_stored_totp'."
        )
        .into(),
      )
    })
  }

  fn remove_user_stored_totp(
    &self,
    _user_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::remove_user_stored_totp'."
        )
        .into(),
      )
    })
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
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_user_external_skip_2fa'."
        )
        .into(),
      )
    })
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
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::create_api_key'.").into(),
      )
    })
  }

  /// Get the user id for a given API key
  fn get_api_key_user_id(
    &self,
    _key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::get_api_key_user_id'.")
          .into(),
      )
    })
  }

  fn delete_api_key(
    &self,
    _key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::delete_api_key'.").into(),
      )
    })
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
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::create_api_key_v2'.")
          .into(),
      )
    })
  }

  /// Get the user id for a given public key
  fn get_api_key_v2_user_id(
    &self,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::get_api_key_v2_user_id'.")
          .into(),
      )
    })
  }

  fn delete_api_key_v2(
    &self,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::delete_api_key_v2'.")
          .into(),
      )
    })
  }
}
