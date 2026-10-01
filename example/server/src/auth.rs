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
  passkey::Passkey,
};
use mogh_auth_server::{
  AuthImpl, DynFuture, RequestAuthentication,
  api_key::{AuthApiKey, BoxAuthApiKey},
  middleware::{
    get_user_from_request_authentication, verify_api_key_secret_async,
  },
  provider::{
    external::ExternalLoginInfo,
    jwt::JwtProvider,
    passkey::PasskeyProvider,
    workload::{
      WorkloadAccess, WorkloadIdentity, list_trusted_issuers,
      sync_all_workload_users,
    },
  },
  user::{AuthUserImpl, BoxAuthUser},
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_rate_limit::RateLimiter;
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

pub struct AuthUser(pub DbUser);

impl AuthUserImpl for AuthUser {
  fn id(&self) -> &str {
    &self.0.id
  }

  fn username(&self) -> &str {
    &self.0.username
  }

  fn hashed_password(&self) -> Option<&str> {
    if self.0.hashed_password.is_empty() {
      None
    } else {
      Some(&self.0.hashed_password)
    }
  }

  fn passkey(&self) -> Option<Passkey> {
    self.0.passkey.clone()
  }

  fn totp_secret(&self) -> Option<&str> {
    if self.0.totp_secret.is_empty() {
      None
    } else {
      Some(&self.0.totp_secret)
    }
  }

  fn hashed_totp_recovery_codes(&self) -> &[String] {
    &self.0.hashed_totp_recovery_codes
  }

  fn external_skip_2fa(&self) -> bool {
    self.0.external_skip_2fa
  }

  fn is_enabled(&self) -> bool {
    self.0.enabled
  }

  fn is_admin(&self) -> bool {
    self.0.admin
  }

  fn is_workload(&self) -> bool {
    self.0.workload.is_some()
  }

  fn cidr_whitelist(&self) -> &[String] {
    &self.0.cidr_whitelist
  }
}

fn box_user(user: DbUser) -> BoxAuthUser {
  Box::new(AuthUser(user))
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
      // The first user is the admin.
      let id = db::create_user(NewUser {
        username,
        hashed_password,
        enabled: no_users_exist || core_config().enable_new_users,
        admin: no_users_exist,
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
      let id = db::create_user(NewUser {
        username,
        hashed_password: String::new(),
        enabled: no_users_exist || core_config().enable_new_users,
        admin: no_users_exist,
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

  fn get_api_key(
    &self,
    key: String,
    secret: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
    Box::pin(async move {
      let api_key =
        db::find_api_key(&key, ApiKeyKind::ApiKey).await?;
      // Also runs for unknown keys, so timing doesn't reveal them.
      // Off the async runtime, bcrypt takes a while.
      verify_api_key_secret_async(
        &ExampleAuthImpl,
        secret,
        api_key.as_ref().map(|key| key.hashed_secret.clone()),
      )
      .await?;
      let api_key = api_key
        .context("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED)?;
      check_not_expired(&api_key)?;
      Ok(
        AuthApiKey {
          user_id: api_key.api_key.user_id,
          cidr_whitelist: api_key.api_key.cidr_whitelist,
        }
        .into(),
      )
    })
  }

  fn get_api_key_owner_id(
    &self,
    key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    // Includes expired keys, so they can be deleted.
    Box::pin(api_key_owner_id(key, ApiKeyKind::ApiKey))
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

  fn get_signing_key(
    &self,
    public_key: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
    Box::pin(async move {
      let api_key =
        db::find_api_key(&public_key, ApiKeyKind::SigningKey)
          .await?
          .context("Invalid client credentials")
          .status_code(StatusCode::UNAUTHORIZED)?;
      check_not_expired(&api_key)?;
      Ok(
        AuthApiKey {
          user_id: api_key.api_key.user_id,
          cidr_whitelist: api_key.api_key.cidr_whitelist,
        }
        .into(),
      )
    })
  }

  fn get_signing_key_owner_id(
    &self,
    public_key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(api_key_owner_id(public_key, ApiKeyKind::SigningKey))
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

async fn api_key_owner_id(
  key: String,
  kind: ApiKeyKind,
) -> mogh_error::Result<String> {
  db::find_api_key(&key, kind)
    .await?
    .map(|api_key| api_key.api_key.user_id)
    .context("No api key found")
    .status_code(StatusCode::NOT_FOUND)
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

fn check_not_expired(
  api_key: &db::DbApiKey,
) -> mogh_error::Result<()> {
  if api_key.expired() {
    return Err(
      anyhow!("Invalid client credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }
  Ok(())
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
/// the API. The users of issuers which are gone are removed.
pub async fn sync_workload_users_on_startup() -> anyhow::Result<()> {
  sync_all_workload_users(&ExampleAuthImpl)
    .await
    .map_err(|e| e.error)?;
  let issuer_ids = list_trusted_issuers(&ExampleAuthImpl)
    .await
    .map_err(|e| e.error)?
    .into_iter()
    .map(|resolved| resolved.issuer.id)
    .collect::<Vec<_>>();
  let removed =
    db::delete_workload_users_of_other_issuers(&issuer_ids).await?;
  if removed > 0 {
    info!(
      "Removed {removed} users of trusted issuers which are gone"
    );
  }
  Ok(())
}
