//! The app side of the Mogh Auth server: storage and business logic.

use std::{net::IpAddr, sync::Arc};

use anyhow::{Context as _, anyhow};
use axum::{extract::Request, http::StatusCode};
use example_client::entities::{ApiKey, ApiKeyKind, AuthMethod};
use mogh_auth_client::{
  api::manage::CreateApiKey,
  config::{
    ExternalLoginKind, ExternalLoginProvider,
    ExternalLoginProviderConfig, TrustedIssuer,
  },
};
use mogh_auth_server::{
  AuthImpl, CredentialChange, DynFuture, RequestAuthentication,
  api_key::{StoredApiKey, StoredSigningKey},
  middleware::{
    get_key_user_id, get_user_from_request_authentication,
  },
  passkey::Passkey,
  provider::{
    external::ExternalLoginInfo,
    jwt::JwtProvider,
    passkey::PasskeyProvider,
    workload::{
      LiveIssuer, WorkloadAccess, WorkloadIdentity,
      sync_all_workload_users,
    },
  },
  user::{AuthUserImpl, BoxAuthUser},
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_rate_limit::RateLimiter;
use mogh_supporter::{
  SupporterBranding, Zeroizing, server::SupporterImpl,
};
use tracing::{info, warn};

use crate::{
  config::core_config,
  db::{self, DbUser, NewUser, UserUpdate},
  state::{self, login_providers_cache, trusted_issuers_cache},
};

/// The authenticated user of a request, attached
/// by [AuthImpl::handle_request_authentication].
#[derive(Clone)]
pub struct RequestUser {
  pub user: Arc<DbUser>,
  pub auth_method: AuthMethod,
}

pub struct AuthUser {
  user: DbUser,
  /// The providers linked to the user, see
  /// [AuthUserImpl::external_login_provider_ids].
  provider_ids: Vec<String>,
}

impl From<DbUser> for AuthUser {
  fn from(user: DbUser) -> AuthUser {
    let provider_ids = user
      .linked_logins
      .iter()
      .map(|login| login.provider_id.clone())
      .collect();
    AuthUser { user, provider_ids }
  }
}

impl AuthUserImpl for AuthUser {
  fn id(&self) -> &str {
    &self.user.id
  }

  fn username(&self) -> &str {
    &self.user.username
  }

  fn hashed_password(&self) -> Option<&str> {
    if self.user.hashed_password.is_empty() {
      None
    } else {
      Some(&self.user.hashed_password)
    }
  }

  fn passkey(&self) -> Option<Passkey> {
    self.user.passkey.clone()
  }

  fn totp_secret(&self) -> Option<&str> {
    if self.user.totp_secret.is_empty() {
      None
    } else {
      Some(&self.user.totp_secret)
    }
  }

  fn hashed_totp_recovery_codes(&self) -> &[String] {
    &self.user.hashed_totp_recovery_codes
  }

  fn external_skip_2fa(&self) -> bool {
    self.user.external_skip_2fa
  }

  fn is_enabled(&self) -> bool {
    self.user.enabled
  }

  fn is_admin(&self) -> bool {
    self.user.admin
  }

  fn is_workload(&self) -> bool {
    self.user.workload.is_some()
  }

  fn cidr_whitelist(&self) -> &[String] {
    &self.user.cidr_whitelist
  }

  /// The auth server refuses to remove the last of them without a
  /// password, or the password without them.
  fn external_login_provider_ids(&self) -> Option<&[String]> {
    Some(&self.provider_ids)
  }
}

fn box_user(user: DbUser) -> BoxAuthUser {
  Box::new(AuthUser::from(user))
}

async fn get_user(user_id: &str) -> mogh_error::Result<DbUser> {
  db::find_user(user_id)
    .await?
    .context("Invalid user credentials")
    .status_code(StatusCode::UNAUTHORIZED)
}

pub struct ExampleAuthImpl;

impl AuthImpl for ExampleAuthImpl {
  fn new() -> Self {
    Self
  }

  fn app_name(&self) -> &'static str {
    state::APP_NAME
  }

  fn host(&self) -> &str {
    &core_config().host
  }

  fn extra_hosts(&self) -> &[String] {
    &core_config().extra_hosts
  }

  fn post_link_redirect(&self) -> &str {
    static POST_LINK_REDIRECT: std::sync::LazyLock<String> =
      std::sync::LazyLock::new(|| {
        format!("{}/profile", core_config().host)
      });
    &POST_LINK_REDIRECT
  }

  fn login_start_limiter(
    &self,
  ) -> &mogh_auth_server::login_start::LoginStartLimiter {
    state::login_start_limiter()
  }

  fn external_login_error_redirect(&self) -> Option<&str> {
    static LOGIN_PAGE: std::sync::LazyLock<String> =
      std::sync::LazyLock::new(|| {
        format!("{}/login", core_config().host)
      });
    core_config()
      .login_error_redirect
      .then_some(LOGIN_PAGE.as_str())
  }

  fn reauthentication_window_secs(&self) -> u64 {
    core_config().reauthentication_window_seconds
  }

  fn registration_disabled(&self) -> bool {
    core_config().disable_user_registration
  }

  fn locked_usernames(&self) -> &'static [String] {
    &core_config().lock_login_credentials_for
  }

  fn no_users_exist(&self) -> DynFuture<mogh_error::Result<bool>> {
    Box::pin(async { db::no_users_exist().await.map_err(Into::into) })
  }

  fn get_user(
    &self,
    user_id: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthUser>> {
    Box::pin(async move { get_user(&user_id).await.map(box_user) })
  }

  fn handle_request_authentication(
    &self,
    auth: RequestAuthentication,
    ip: IpAddr,
    require_user_enabled: bool,
    mut req: Request,
  ) -> DynFuture<mogh_error::Result<Request>> {
    Box::pin(async move {
      let auth_method = match &auth {
        RequestAuthentication::Jwt(_) => AuthMethod::Jwt,
        RequestAuthentication::ApiKey { .. } => AuthMethod::ApiKey,
        RequestAuthentication::PublicKey(_) => AuthMethod::PublicKey,
      };
      // Enforces the api key and the user cidr whitelist.
      let user = get_user_from_request_authentication(
        &ExampleAuthImpl,
        auth,
        ip,
      )
      .await?;
      // Load the full user for the request handlers.
      let user = get_user(user.id()).await?;
      if require_user_enabled && !user.enabled {
        return Err(
          anyhow!("User is not enabled")
            .status_code(StatusCode::FORBIDDEN),
        );
      }
      req.extensions_mut().insert(RequestUser {
        user: Arc::new(user),
        auth_method,
      });
      Ok(req)
    })
  }

  /// The default, plus the ended sessions: a session token issued
  /// before the user's sessions were ended
  /// ([AuthImpl::credentials_changed]) is refused. Both the app's api
  /// and the auth management api authenticate with this.
  fn get_user_id_from_request_authentication(
    &self,
    auth: RequestAuthentication,
    ip: IpAddr,
  ) -> DynFuture<mogh_error::Result<String>> {
    match auth {
      RequestAuthentication::Jwt(jwt) => {
        Box::pin(session_user_id(jwt))
      }
      // As the default authenticates them.
      auth => get_key_user_id(self, auth, ip),
    }
  }

  // =========
  // = STATE =
  // =========

  fn jwt_provider(&self) -> &JwtProvider {
    state::jwt_provider()
  }

  fn passkey_provider(&self) -> Option<&PasskeyProvider> {
    state::passkey_provider()
  }

  fn general_rate_limiter(&self) -> &RateLimiter {
    state::general_rate_limiter()
  }

  // ==============
  // = LOCAL AUTH =
  // ==============

  fn local_auth_enabled(&self) -> bool {
    core_config().local_auth
  }

  fn local_auth_bcrypt_cost(&self) -> u32 {
    core_config().bcrypt_cost
  }

  fn local_login_rate_limiter(&self) -> &RateLimiter {
    state::local_login_rate_limiter()
  }

  fn sign_up_local_user(
    &self,
    username: String,
    hashed_password: String,
    no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async move {
      let (_first_user, first) = first_user_sign_up(
        no_users_exist,
        ExampleAuthImpl.local_registration_disabled(),
      )
      .await?;
      // The first user is the admin.
      let id = db::create_user(NewUser {
        username,
        hashed_password,
        enabled: first || core_config().enable_new_users,
        admin: first,
        workload: None,
      })
      .await?;
      Ok(id)
    })
  }

  fn find_user_with_username(
    &self,
    username: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    Box::pin(async move {
      // Includes workload users, so their usernames stay taken.
      // They have no password, and can't log in with one.
      let user =
        db::find_user_with_username(&username).await?.map(box_user);
      Ok(user)
    })
  }

  fn update_user_username(
    &self,
    user_id: String,
    username: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // The auth server already checked the username is free.
      db::update_user(&user_id, UserUpdate::Username(username))
        .await
        .map_err(Into::into)
    })
  }

  fn update_user_password(
    &self,
    user_id: String,
    hashed_password: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::update_user(&user_id, UserUpdate::Password(hashed_password))
        .await
        .map_err(Into::into)
    })
  }

  /// Ends the user's other sessions: a token which leaked stops
  /// working once the user changes how they log in. The session which
  /// made the change is kept.
  fn credentials_changed(
    &self,
    user_id: String,
    change: CredentialChange,
    kept_jwt: Option<String>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // Tokens carry whole seconds: the ones issued in the second of
      // the change stay valid, so a login right after it works (one
      // issued in that second before the change, too).
      let valid_after = db::unix_timestamp_ms() / 1000;
      db::update_user(
        &user_id,
        UserUpdate::EndSessions {
          valid_after,
          kept: kept_jwt
            .as_deref()
            .map(sha256_hex)
            .unwrap_or_default(),
        },
      )
      .await?;
      info!(user_id, ?change, "Ended the other sessions of the user");
      Ok(())
    })
  }

  // ==================
  // = EXTERNAL LOGIN =
  // ==================

  /// The OIDC provider from the config file / env, using the reserved
  /// `oidc` id so it keeps the `/auth/oidc/callback` redirect uri.
  fn static_external_providers(&self) -> Vec<ExternalLoginProvider> {
    let config = core_config();
    if config.oidc.provider.is_empty() {
      return Vec::new();
    }
    vec![ExternalLoginProvider {
      id: ExternalLoginKind::Oidc.reserved_id().to_string(),
      name: String::from("OIDC"),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: config.oidc_token_exchange.clone(),
      config: ExternalLoginProviderConfig::Oidc(config.oidc.clone()),
    }]
  }

  fn list_external_providers(
    &self,
  ) -> DynFuture<mogh_error::Result<Vec<ExternalLoginProvider>>> {
    Box::pin(async {
      let providers = cached_login_providers().await?;
      Ok(providers.as_ref().clone())
    })
  }

  fn create_external_provider(
    &self,
    provider: ExternalLoginProvider,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::create_login_provider(&provider).await?;
      login_providers_cache().changed();
      Ok(())
    })
  }

  fn update_external_provider(
    &self,
    provider: ExternalLoginProvider,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::update_login_provider(&provider).await?;
      login_providers_cache().changed();
      Ok(())
    })
  }

  fn delete_external_provider(
    &self,
    id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // Also removes the links to the provider from all users.
      db::delete_login_provider(&id).await?;
      login_providers_cache().changed();
      Ok(())
    })
  }

  fn find_user_with_external_login(
    &self,
    provider_id: String,
    external_id: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    Box::pin(async move {
      let user =
        db::find_user_with_external_login(&provider_id, &external_id)
          .await?
          .map(box_user);
      Ok(user)
    })
  }

  fn sign_up_external_user(
    &self,
    username: String,
    info: ExternalLoginInfo,
    no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async move {
      let registration_disabled = if no_users_exist {
        let provider = mogh_auth_server::provider::external::resolve_external_provider(
          &ExampleAuthImpl,
          &info.provider_id,
        )
        .await?;
        ExampleAuthImpl
          .external_registration_disabled(&provider.provider)
      } else {
        // Not let through as the first user: the server
        // checked the registration already.
        false
      };
      let (_first_user, first) =
        first_user_sign_up(no_users_exist, registration_disabled)
          .await?;
      let id = db::create_user(NewUser {
        username,
        hashed_password: String::new(),
        enabled: first || core_config().enable_new_users,
        admin: first,
        workload: None,
      })
      .await?;
      db::link_external_login(
        &id,
        &info.provider_id,
        &info.external_id,
        info.avatar_url.as_deref(),
      )
      .await?;
      Ok(id)
    })
  }

  fn sync_external_user(
    &self,
    user_id: String,
    info: ExternalLoginInfo,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      if let Some(groups) = info.groups {
        db::set_provider_groups(&user_id, &info.provider_id, &groups)
          .await?;
      }
      if let Some(admin) = info.admin {
        db::update_user(&user_id, UserUpdate::Admin(admin)).await?;
      }
      Ok(())
    })
  }

  fn link_external_login(
    &self,
    user_id: String,
    info: ExternalLoginInfo,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::link_external_login(
        &user_id,
        &info.provider_id,
        &info.external_id,
        info.avatar_url.as_deref(),
      )
      .await
      .map_err(Into::into)
    })
  }

  fn unlink_external_login(
    &self,
    user_id: String,
    provider_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::unlink_external_login(&user_id, &provider_id)
        .await
        .map_err(Into::into)
    })
  }

  fn unlink_local_login(
    &self,
    user_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::update_user(&user_id, UserUpdate::Password(String::new()))
        .await
        .map_err(Into::into)
    })
  }

  // =====================
  // = WORKLOAD IDENTITY =
  // =====================

  fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
    core_config().trusted_issuers.clone()
  }

  fn list_trusted_issuers(
    &self,
  ) -> DynFuture<mogh_error::Result<Vec<TrustedIssuer>>> {
    Box::pin(async {
      let issuers = cached_trusted_issuers().await?;
      Ok(issuers.as_ref().clone())
    })
  }

  fn create_trusted_issuer(
    &self,
    issuer: TrustedIssuer,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::create_trusted_issuer(&issuer).await?;
      trusted_issuers_cache().changed();
      Ok(())
    })
  }

  /// The server syncs the users of its rules next.
  fn update_trusted_issuer(
    &self,
    issuer: TrustedIssuer,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::update_trusted_issuer(&issuer).await?;
      trusted_issuers_cache().changed();
      Ok(())
    })
  }

  /// Removes the users of rules which were removed, and gives the
  /// others what their rule says now: a demoted rule's tokens lose
  /// admin on their next request, a disabled one's are refused.
  fn sync_workload_users(
    &self,
    issuer_id: String,
    rules: Vec<WorkloadAccess>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::sync_workload_users(&issuer_id, &rules)
        .await
        .map_err(Into::into)
    })
  }

  /// The users of issuers removed from the config file (and of rules
  /// which are gone), when the app starts. Read, then removed: token
  /// exchanges wait while this runs, and the example creates workload
  /// users nowhere else, so none it reads was created after `live` was
  /// listed (one instance, as the example runs).
  fn remove_workload_users_except(
    &self,
    live: Vec<LiveIssuer>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      let removed = db::delete_workload_users_except(&live).await?;
      if removed > 0 {
        info!(
          "Removed {removed} users of trusted issuers and rules which are gone"
        );
      }
      Ok(())
    })
  }

  fn delete_trusted_issuer(
    &self,
    id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // Along with the users of its rules.
      db::delete_trusted_issuer(&id).await?;
      trusted_issuers_cache().changed();
      Ok(())
    })
  }

  fn get_or_create_workload_user(
    &self,
    identity: WorkloadIdentity,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async move {
      let user = match db::find_workload_user(
        &identity.issuer_id,
        &identity.rule_id,
      )
      .await?
      {
        Some(user) => user,
        None => create_workload_user(&identity).await?,
      };
      // The rule is the full definition of what the user can do.
      // Created enabled, `enabled` is left to sync_workload_users.
      db::update_user(&user.id, UserUpdate::Admin(identity.admin))
        .await?;
      db::update_user(
        &user.id,
        UserUpdate::Groups(identity.groups.clone()),
      )
      .await?;
      let subject = identity
        .claims
        .get("sub")
        .and_then(|sub| sub.as_str())
        .unwrap_or_default()
        .to_string();
      db::update_user(
        &user.id,
        UserUpdate::WorkloadLastSubject(subject),
      )
      .await?;
      Ok(user.id)
    })
  }

  // ===============
  // = PASSKEY 2FA =
  // ===============

  fn update_user_stored_passkey(
    &self,
    user_id: String,
    passkey: Option<Passkey>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::update_user(&user_id, UserUpdate::Passkey(passkey))
        .await
        .map_err(Into::into)
    })
  }

  // ============
  // = TOTP 2FA =
  // ============

  fn update_user_stored_totp(
    &self,
    user_id: String,
    encoded_secret: String,
    hashed_recovery_codes: Vec<String>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::update_user(
        &user_id,
        UserUpdate::Totp {
          secret: encoded_secret,
          hashed_recovery_codes,
        },
      )
      .await
      .map_err(Into::into)
    })
  }

  fn remove_user_stored_totp(
    &self,
    user_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::update_user(
        &user_id,
        UserUpdate::Totp {
          secret: String::new(),
          hashed_recovery_codes: Vec::new(),
        },
      )
      .await
      .map_err(Into::into)
    })
  }

  /// Stored, so a code is only accepted once across restarts.
  fn consume_totp_step(
    &self,
    user_id: String,
    step: u64,
  ) -> DynFuture<mogh_error::Result<bool>> {
    Box::pin(async move {
      db::consume_totp_step(&user_id, step)
        .await
        .map_err(Into::into)
    })
  }

  /// One conditional update, so a code is only used once
  /// across instances.
  fn remove_totp_recovery_code(
    &self,
    user_id: String,
    hashed_code: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // Conditional: a code another login (on any instance)
      // used up in the meantime is refused.
      if db::remove_totp_recovery_code(&user_id, &hashed_code).await?
      {
        Ok(())
      } else {
        Err(
          anyhow!("Invalid recovery code")
            .status_code(StatusCode::UNAUTHORIZED),
        )
      }
    })
  }

  // ============
  // = SKIP 2FA =
  // ============

  fn update_user_external_skip_2fa(
    &self,
    user_id: String,
    external_skip_2fa: bool,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::update_user(
        &user_id,
        UserUpdate::ExternalSkip2fa(external_skip_2fa),
      )
      .await
      .map_err(Into::into)
    })
  }

  // ============
  // = API KEYS =
  // ============

  fn api_secret_bcrypt_cost(&self) -> u32 {
    core_config().bcrypt_cost
  }

  fn create_api_key(
    &self,
    user_id: String,
    body: CreateApiKey,
    key: String,
    hashed_secret: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::create_api_key(
        &new_api_key(user_id, body, key, ApiKeyKind::ApiKey),
        &hashed_secret,
      )
      .await
      .map_err(Into::into)
    })
  }

  /// The auth server verifies the secret and the expiry
  /// (`AuthImpl::get_api_key`), and finds the owner of a key to
  /// delete it (`get_api_key_owner_id`) with this.
  fn find_api_key(
    &self,
    key: String,
  ) -> DynFuture<mogh_error::Result<Option<StoredApiKey>>> {
    Box::pin(async move {
      let api_key = db::find_api_key(&key, ApiKeyKind::ApiKey)
        .await?
        .map(|api_key| StoredApiKey {
          user_id: api_key.api_key.user_id,
          hashed_secret: api_key.hashed_secret,
          expires: stored_expires(api_key.api_key.expires),
          cidr_whitelist: api_key.api_key.cidr_whitelist,
        });
      Ok(api_key)
    })
  }

  fn delete_api_key(
    &self,
    key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::delete_api_key(&key, ApiKeyKind::ApiKey)
        .await
        .map_err(Into::into)
    })
  }

  // ================
  // = SIGNING KEYS =
  // ================

  fn signing_keys_enabled(&self) -> bool {
    true
  }

  fn create_signing_key(
    &self,
    user_id: String,
    body: CreateApiKey,
    public_key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::create_api_key(
        &new_api_key(
          user_id,
          body,
          public_key,
          ApiKeyKind::SigningKey,
        ),
        "",
      )
      .await
      .map_err(Into::into)
    })
  }

  /// The auth server refuses expired keys
  /// (`AuthImpl::get_signing_key`), and finds the owner of a key to
  /// delete it (`get_signing_key_owner_id`) with this.
  fn find_signing_key(
    &self,
    public_key: String,
  ) -> DynFuture<mogh_error::Result<Option<StoredSigningKey>>> {
    Box::pin(async move {
      let api_key =
        db::find_api_key(&public_key, ApiKeyKind::SigningKey)
          .await?
          .map(|api_key| StoredSigningKey {
            user_id: api_key.api_key.user_id,
            expires: stored_expires(api_key.api_key.expires),
            cidr_whitelist: api_key.api_key.cidr_whitelist,
          });
      Ok(api_key)
    })
  }

  fn delete_signing_key(
    &self,
    public_key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::delete_api_key(&public_key, ApiKeyKind::SigningKey)
        .await
        .map_err(Into::into)
    })
  }
}

/// The user of a session token, unless the user's sessions were
/// ended since it was issued (a change of how they log in,
/// [AuthImpl::credentials_changed]) and it isn't the one kept: then
/// refused, uncounted by the rate limiter (no guess: every tab of the
/// user still holds one).
async fn session_user_id(jwt: String) -> mogh_error::Result<String> {
  let claims = state::jwt_provider()
    .decode_claims(&jwt)
    .status_code(StatusCode::UNAUTHORIZED)?;
  let user = get_user(&claims.sub).await?;
  let issued_at = i64::try_from(claims.iat).unwrap_or(i64::MAX);
  let kept = !user.sessions_kept.is_empty()
    && user.sessions_kept == sha256_hex(&jwt);
  if issued_at < user.sessions_valid_after && !kept {
    return Err(
      anyhow!("The session has ended. Log in again.")
        .status_code(StatusCode::UNAUTHORIZED)
        .uncounted(),
    );
  }
  Ok(claims.sub)
}

/// The SHA-256 of `text`, in hex: how a kept session token is stored.
fn sha256_hex(text: &str) -> String {
  use sha2::Digest as _;
  sha2::Sha256::digest(text.as_bytes())
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

/// Serializes the sign ups the auth server let through as the first
/// user: sign ups sent at the same time all see no user
/// (`AuthImpl::no_users_exist` is a pre-check), and would each be
/// created as the admin, also while registration is disabled.
static FIRST_USER_LOCK: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

/// For a sign up the auth server let through as the first user
/// (`no_users_exist`): takes the first user lock and checks again
/// under it. Returns the guard, held over the insert, and whether the
/// sign up still creates the first user. One which doesn't while
/// `registration_disabled` is refused: nobody could register it.
///
/// The lock covers one instance of the app. A replicated app decides
/// it in the insert's transaction instead.
async fn first_user_sign_up(
  no_users_exist: bool,
  registration_disabled: bool,
) -> mogh_error::Result<(
  Option<tokio::sync::MutexGuard<'static, ()>>,
  bool,
)> {
  if !no_users_exist {
    return Ok((None, false));
  }
  let guard = FIRST_USER_LOCK.lock().await;
  let first = db::no_users_exist().await?;
  if !first && registration_disabled {
    return Err(
      anyhow!("User registration is disabled")
        .status_code(StatusCode::FORBIDDEN),
    );
  }
  Ok((Some(guard), first))
}

fn new_api_key(
  user_id: String,
  body: CreateApiKey,
  key: String,
  kind: ApiKeyKind,
) -> ApiKey {
  ApiKey {
    key,
    kind,
    user_id,
    name: body.name,
    expires: i64::try_from(body.expires).unwrap_or(i64::MAX),
    cidr_whitelist: body.cidr_whitelist,
    created_at: db::unix_timestamp_ms(),
  }
}

/// The expiry of a stored key (unix milliseconds, `0` for never) as
/// the auth server takes it. Keys are created with one from a `u64`
/// (`new_api_key`), so a negative one is none the app made: expired
/// rather than never.
fn stored_expires(expires: i64) -> u64 {
  u64::try_from(expires).unwrap_or(1)
}

/// Creates the user of a workload rule, or returns the one another
/// exchange of the rule created at the same time.
///
/// [AuthImpl::get_or_create_workload_user] runs concurrently for the
/// same rule (a CI matrix starting), across instances of the app as
/// well. The insert does nothing if the rule has a user by then, and
/// the user is read back either way. When nothing was inserted and the
/// rule still has no user, the username was taken: the next is tried.
async fn create_workload_user(
  identity: &WorkloadIdentity,
) -> anyhow::Result<DbUser> {
  for username in workload_usernames(identity) {
    // Never the 'first user is admin' signup logic.
    let created = db::insert_workload_user(NewUser {
      username,
      hashed_password: String::new(),
      enabled: true,
      admin: identity.admin,
      workload: Some((
        identity.issuer_id.clone(),
        identity.rule_id.clone(),
      )),
    })
    .await?;
    let Some(user) =
      db::find_workload_user(&identity.issuer_id, &identity.rule_id)
        .await?
    else {
      continue;
    };
    if created {
      info!(
        user_id = user.id,
        issuer_id = identity.issuer_id,
        rule_id = identity.rule_id,
        "Created workload user"
      );
    }
    return Ok(user);
  }
  Err(anyhow!(
    "Failed to create the user of workload rule '{}', its usernames are taken",
    identity.rule_name
  ))
}

/// `workload-{rule name}`, then made unique with the rule id, the issuer
/// id and finally at random, for when a username is taken.
fn workload_usernames(identity: &WorkloadIdentity) -> [String; 4] {
  let name = identity
    .rule_name
    .chars()
    .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
    .collect::<String>()
    .to_lowercase();
  let base = format!("workload-{name}");
  [
    base.clone(),
    format!("{base}-{}", identity.rule_id),
    format!("{base}-{}-{}", identity.issuer_id, identity.rule_id),
    format!("{base}-{}", db::new_id()),
  ]
}

async fn cached_login_providers()
-> anyhow::Result<Arc<Vec<ExternalLoginProvider>>> {
  login_providers_cache()
    .get_or_load(|| async {
      db::list_login_providers().await.inspect_err(|e| {
        warn!("Failed to load login providers | {e:#}")
      })
    })
    .await
}

async fn cached_trusted_issuers()
-> anyhow::Result<Arc<Vec<TrustedIssuer>>> {
  trusted_issuers_cache()
    .get_or_load(|| async {
      db::list_trusted_issuers().await.inspect_err(|e| {
        warn!("Failed to load trusted issuers | {e:#}")
      })
    })
    .await
}

/// Applies the trusted issuers to the users of their rules when the
/// app starts: static issuers change with the config file, not over
/// the API. The users of issuers which are gone are removed
/// (`remove_workload_users_except`).
pub async fn sync_workload_users_on_startup() -> anyhow::Result<()> {
  sync_all_workload_users(&ExampleAuthImpl)
    .await
    .map_err(|e| e.error)
}

/// The supporter key (`mogh_supporter`): the example keeps a key an
/// admin sets in its database, encrypted like its other secrets,
/// and an organization's branding next to it, as JSON.
impl SupporterImpl for ExampleAuthImpl {
  fn supporter_app(&self) -> &'static str {
    state::SUPPORTER_APP
  }

  fn supporter_config_key(&self) -> &str {
    &core_config().supporter_key
  }

  /// The example trusts the test root of the fixture, which a release
  /// must never: an app hardcodes its own root keys of mogh.tech here
  /// (and the same ones in its UI).
  fn supporter_root_keys(&self) -> &'static [&'static str] {
    &[mogh_supporter::fixture::ROOT]
  }

  /// Decrypted into a buffer wiped on drop (`crypto::open` moves
  /// the plaintext out of its own, without a copy).
  fn load_stored_supporter_key(
    &self,
  ) -> DynFuture<mogh_error::Result<Option<Zeroizing<String>>>> {
    Box::pin(async {
      let key = db::load_supporter_key().await?;
      Ok(key.map(Zeroizing::new))
    })
  }

  /// Encrypted from the reference: no plain copy of the key.
  fn store_supporter_key(
    &self,
    key: Option<Zeroizing<String>>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::store_supporter_key(key.as_deref().map(String::as_str))
        .await
        .map_err(Into::into)
    })
  }

  fn load_supporter_branding(
    &self,
  ) -> DynFuture<mogh_error::Result<Option<SupporterBranding>>> {
    Box::pin(async {
      db::load_supporter_branding().await.map_err(Into::into)
    })
  }

  fn store_supporter_branding(
    &self,
    branding: SupporterBranding,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      db::store_supporter_branding(&branding)
        .await
        .map_err(Into::into)
    })
  }
}
