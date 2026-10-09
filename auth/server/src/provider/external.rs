//! External login providers: resolution from the app,
//! and building / caching of the provider clients.

use std::{
  hash::{DefaultHasher, Hash as _, Hasher as _},
  sync::{Arc, OnceLock},
  time::Duration,
};

use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::config::{
  ExternalLoginKind, ExternalLoginProvider,
  ExternalLoginProviderConfig,
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use openidconnect::{
  CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
  AuthImpl,
  provider::{
    load_cache::LoadCache,
    named::{github::GithubProvider, google::GoogleProvider},
    oidc::{OidcProvider, TokenResponse},
  },
};

/// The length of generated provider ids.
pub const PROVIDER_ID_LENGTH: usize = 16;

const MAX_PROVIDER_ID_LENGTH: usize = 64;

/// OIDC discovery data (endpoints and signing keys) is cached for 1min.
const OIDC_VALID_FOR: Duration = Duration::from_secs(60);
/// Google discovery data (signing keys) is cached for 1hr.
const GOOGLE_VALID_FOR: Duration = Duration::from_secs(60 * 60);

/// Information about the user authenticated with an external login
/// provider, passed to the app level [AuthImpl] on signup, login and link.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExternalLoginInfo {
  /// The id of the [ExternalLoginProvider] the user authenticated with.
  pub provider_id: String,
  /// The kind of the provider.
  pub kind: ExternalLoginKind,
  /// The unique, stable id of the user at the provider
  /// (OIDC subject, Github user id, Google subject).
  ///
  /// ⚠️ This is only unique per provider. Users must always be stored
  /// and looked up by the (`provider_id`, `external_id`) pair,
  /// otherwise another provider can issue the same id
  /// and log in as the user.
  pub external_id: String,
  /// The users avatar at the provider, if available (Github, Google).
  pub avatar_url: Option<String>,
  /// The groups the provider reports for the user (OIDC only).
  ///
  /// - `None`: No group information is available. Either group
  ///   extraction is not configured, or the provider didn't send
  ///   the claim (eg. missing scope, or Azure group overage).
  ///   Apps should leave existing memberships as they are.
  /// - `Some(groups)`: The full list of groups, which may be empty.
  ///
  /// Note. Some providers omit the claim entirely for users
  /// without any groups, which shows up as `None` here.
  pub groups: Option<Vec<String>>,
  /// Whether the user is in one of the configured 'admin_groups' (OIDC only).
  ///
  /// `None` if 'admin_groups' is not configured or no group
  /// information is available, apps should then leave the
  /// users admin status as it is.
  ///
  /// ⚠️ Revoking admin through the provider relies on it sending the
  /// groups claim. A provider which omits the claim for a user left
  /// without any (matching) group reports `None`, and the user keeps
  /// admin. Configure 'allowed_groups' as well: such a user is then
  /// refused the login instead.
  pub admin: Option<bool>,
}

/// The in flight external login or link, stored on the session
/// between the redirect to the provider and its callback.
#[derive(Serialize, Deserialize)]
pub struct SessionExternalLogin {
  /// The provider the flow was started with. The callback
  /// must be for the same provider (mix-up protection).
  pub provider_id: String,
  /// The id of the user linking the login,
  /// or None if this is a login / signup.
  pub link_user_id: Option<String>,
  /// The CSRF token matched against the callback 'state'.
  pub state: String,
  /// OIDC, Google
  pub nonce: Option<String>,
  /// OIDC, Github
  pub pkce_verifier: Option<PkceCodeVerifier>,
  /// Where to send the user after login: an absolute http(s) url
  /// on the app's hostname, sanitized and bounded (2048 characters)
  /// when the login starts.
  /// A session written by an older version may hold the raw query
  /// value, so it is sanitized again when used: do the same when
  /// reading it.
  pub redirect: Option<String>,
}

/// The result of [BuiltProvider::begin_login].
pub struct BeginExternalLogin {
  /// The provider url to redirect the user to.
  pub url: String,
  pub state: String,
  pub nonce: Option<String>,
  pub pkce_verifier: Option<PkceCodeVerifier>,
}

/// The result of [BuiltProvider::complete_login].
pub struct CompletedExternalLogin {
  pub info: ExternalLoginInfo,
  username: UsernameSource,
}

enum UsernameSource {
  Known(String),
  /// OIDC usernames may need the networked user info,
  /// so they are only resolved on signup.
  Oidc {
    token: Box<TokenResponse>,
    nonce: Nonce,
  },
}

impl CompletedExternalLogin {
  #[cfg(test)]
  pub(crate) fn known(
    info: ExternalLoginInfo,
    username: &str,
  ) -> CompletedExternalLogin {
    CompletedExternalLogin {
      info,
      username: UsernameSource::Known(username.to_string()),
    }
  }

  /// The username to sign up a new user with.
  /// Falls back to the external user id if the
  /// provider has no usable name for the user.
  pub async fn username(&self, provider: &BuiltProvider) -> String {
    let username = self.provider_username(provider).await;
    if username.trim().is_empty() {
      self.info.external_id.clone()
    } else {
      username
    }
  }

  async fn provider_username(
    &self,
    provider: &BuiltProvider,
  ) -> String {
    match (&self.username, provider) {
      (UsernameSource::Known(username), _) => username.clone(),
      (
        UsernameSource::Oidc { token, nonce },
        BuiltProvider::Oidc(provider),
      ) => {
        provider
          .get_username(
            &openidconnect::SubjectIdentifier::new(
              self.info.external_id.clone(),
            ),
            token,
            nonce,
          )
          .await
      }
      // Unreachable, the source is created by the same provider.
      (UsernameSource::Oidc { .. }, _) => {
        self.info.external_id.clone()
      }
    }
  }
}

/// The client for a configured [ExternalLoginProvider].
pub enum BuiltProvider {
  Oidc(OidcProvider),
  Github(GithubProvider),
  Google(GoogleProvider),
}

impl BuiltProvider {
  async fn new(
    app_user_agent: &'static str,
    redirect_uri: String,
    config: &ExternalLoginProviderConfig,
  ) -> anyhow::Result<BuiltProvider> {
    let provider = match config {
      ExternalLoginProviderConfig::Oidc(config) => {
        BuiltProvider::Oidc(
          OidcProvider::new(app_user_agent, redirect_uri, config)
            .await?,
        )
      }
      ExternalLoginProviderConfig::Github(config) => {
        BuiltProvider::Github(GithubProvider::new(
          redirect_uri,
          config,
        )?)
      }
      ExternalLoginProviderConfig::Google(config) => {
        BuiltProvider::Google(
          GoogleProvider::new(app_user_agent, redirect_uri, config)
            .await?,
        )
      }
    };
    Ok(provider)
  }

  /// How long a built provider of the kind can be reused,
  /// or None if it never has to be rebuilt.
  fn valid_for(kind: ExternalLoginKind) -> Option<Duration> {
    match kind {
      ExternalLoginKind::Oidc => Some(OIDC_VALID_FOR),
      ExternalLoginKind::Github => None,
      ExternalLoginKind::Google => Some(GOOGLE_VALID_FOR),
    }
  }

  /// Generates the provider login url,
  /// and the state to validate its callback with.
  pub fn begin_login(&self) -> BeginExternalLogin {
    match self {
      BuiltProvider::Oidc(provider) => {
        let (pkce_challenge, pkce_verifier) =
          PkceCodeChallenge::new_random_sha256();
        let (url, csrf_token, nonce) =
          provider.authorize_url(pkce_challenge);
        BeginExternalLogin {
          url: url.to_string(),
          state: csrf_token.secret().clone(),
          nonce: Some(nonce.secret().clone()),
          pkce_verifier: Some(pkce_verifier),
        }
      }
      BuiltProvider::Github(provider) => {
        let (pkce_challenge, pkce_verifier) =
          PkceCodeChallenge::new_random_sha256();
        let (state, url) =
          provider.get_state_and_login_redirect_url(&pkce_challenge);
        BeginExternalLogin {
          url,
          state,
          nonce: None,
          pkce_verifier: Some(pkce_verifier),
        }
      }
      BuiltProvider::Google(provider) => {
        let (state, nonce, url) =
          provider.get_state_and_login_redirect_url();
        BeginExternalLogin {
          url,
          state,
          nonce: Some(nonce.secret().clone()),
          pkce_verifier: None,
        }
      }
    }
  }

  /// Verifies a token presented for RFC 8693 token exchange and
  /// returns the identity it belongs to. The token must be signed by
  /// the provider and issued to an accepted audience, see
  /// [TokenExchangeConfig][mogh_auth_client::config::TokenExchangeConfig].
  /// For OIDC, this enforces 'allowed_groups'.
  pub fn verify_exchange_token(
    &self,
    provider: &ExternalLoginProvider,
    token: &str,
  ) -> mogh_error::Result<ExternalLoginInfo> {
    let base_info = |external_id: String| ExternalLoginInfo {
      provider_id: provider.id.clone(),
      kind: provider.kind(),
      external_id,
      avatar_url: None,
      groups: None,
      admin: None,
    };
    let exchange = &provider.token_exchange;
    match (self, &provider.config) {
      (
        BuiltProvider::Oidc(oidc),
        ExternalLoginProviderConfig::Oidc(config),
      ) => {
        let info =
          oidc.verify_exchange_token(config, exchange, token)?;
        Ok(ExternalLoginInfo {
          groups: info.groups,
          admin: info.admin,
          ..base_info(info.subject.to_string())
        })
      }
      (
        BuiltProvider::Google(google),
        ExternalLoginProviderConfig::Google(_),
      ) => {
        let user = google
          .verify_exchange_token(exchange, token)
          .status_code(StatusCode::BAD_REQUEST)?;
        Ok(ExternalLoginInfo {
          avatar_url: Some(user.picture),
          ..base_info(user.id)
        })
      }
      (BuiltProvider::Github(_), _) => Err(
        anyhow!(
          "Github does not issue tokens which can be exchanged"
        )
        .status_code(StatusCode::BAD_REQUEST),
      ),
      _ => Err(
        anyhow!("Built provider does not match the provider kind")
          .into(),
      ),
    }
  }

  /// Exchanges the callback code and validates the users identity.
  /// For OIDC, this enforces 'allowed_groups'.
  ///
  /// The callback state must already be
  /// validated against `login.state`.
  pub async fn complete_login(
    &self,
    provider: &ExternalLoginProvider,
    login: SessionExternalLogin,
    client_state: String,
    code: String,
  ) -> mogh_error::Result<CompletedExternalLogin> {
    let base_info = |external_id: String| ExternalLoginInfo {
      provider_id: provider.id.clone(),
      kind: provider.kind(),
      external_id,
      avatar_url: None,
      groups: None,
      admin: None,
    };
    match (self, &provider.config) {
      (
        BuiltProvider::Oidc(oidc),
        ExternalLoginProviderConfig::Oidc(config),
      ) => {
        let nonce = Nonce::new(
          login.nonce.context("Session is missing OIDC nonce")?,
        );
        let pkce_verifier = login
          .pkce_verifier
          .context("Session is missing OIDC pkce verifier")?;
        let (oidc_info, token) = oidc
          .validate_extract_login_info_and_token(
            config,
            (CsrfToken::new(client_state), login.state),
            code,
            pkce_verifier,
            &nonce,
          )
          .await?;
        Ok(CompletedExternalLogin {
          info: ExternalLoginInfo {
            groups: oidc_info.groups,
            admin: oidc_info.admin,
            ..base_info(oidc_info.subject.to_string())
          },
          username: UsernameSource::Oidc {
            token: Box::new(token),
            nonce,
          },
        })
      }
      (
        BuiltProvider::Github(github),
        ExternalLoginProviderConfig::Github(_),
      ) => {
        // Logins begun before Github used PKCE have no verifier.
        let pkce_verifier = login
          .pkce_verifier
          .context(
            "Session is missing Github pkce verifier, log in again",
          )
          .status_code(StatusCode::UNAUTHORIZED)?;
        let token =
          github.get_access_token(&code, &pkce_verifier).await?;
        let user =
          github.get_github_user(&token.access_token).await?;
        Ok(CompletedExternalLogin {
          info: ExternalLoginInfo {
            avatar_url: Some(user.avatar_url),
            ..base_info(user.id.to_string())
          },
          username: UsernameSource::Known(user.login),
        })
      }
      (
        BuiltProvider::Google(google),
        ExternalLoginProviderConfig::Google(_),
      ) => {
        let nonce =
          login.nonce.context("Session is missing Google nonce")?;
        let user = google.get_google_user(code, nonce).await?;
        let username = user
          .email
          .split('@')
          .next()
          .unwrap_or_default()
          .to_string();
        Ok(CompletedExternalLogin {
          info: ExternalLoginInfo {
            avatar_url: Some(user.picture),
            ..base_info(user.id)
          },
          username: UsernameSource::Known(username),
        })
      }
      _ => Err(
        anyhow!("Built provider does not match the provider kind")
          .into(),
      ),
    }
  }
}

// =========
// = CACHE =
// =========

/// The built provider clients by provider id.
///
/// This is never the source of truth: the provider is always
/// resolved from the app first, and the cached client is only
/// used if it was built from that same configuration.
///
/// Building a client means discovery requests to the provider, see
/// [LoadCache] for how concurrent logins and outages are handled.
#[derive(Default)]
struct BuiltProviderCache(LoadCache<BuiltProvider>);

fn provider_cache() -> &'static BuiltProviderCache {
  static CACHE: OnceLock<BuiltProviderCache> = OnceLock::new();
  CACHE.get_or_init(Default::default)
}

/// Only used to detect configuration changes, the
/// configuration (and its secret) are not recoverable from it.
fn fingerprint(
  redirect_uri: &str,
  provider: &ExternalLoginProvider,
) -> u64 {
  let mut hasher = DefaultHasher::new();
  redirect_uri.hash(&mut hasher);
  provider.hash(&mut hasher);
  hasher.finish()
}

/// The redirect / callback URI which must be registered at the provider.
pub fn redirect_uri(
  host: &str,
  path: &str,
  provider: &ExternalLoginProvider,
) -> String {
  format!("{host}{path}{}", provider.callback_path())
}

impl BuiltProviderCache {
  /// Returns the cached client for the provider, building it
  /// if it doesn't exist, the provider configuration changed,
  /// or the discovery data is outdated.
  async fn load(
    &self,
    app_user_agent: &'static str,
    host: &str,
    path: &str,
    provider: &ExternalLoginProvider,
  ) -> anyhow::Result<Arc<BuiltProvider>> {
    if host.is_empty() {
      return Err(anyhow!(
        "External login requires 'host' to be configured"
      ));
    }

    let redirect_uri = redirect_uri(host, path, provider);

    self
      .0
      .load(
        &provider.id,
        fingerprint(&redirect_uri, provider),
        BuiltProvider::valid_for(provider.kind()),
        || {
          BuiltProvider::new(
            app_user_agent,
            redirect_uri,
            &provider.config,
          )
        },
      )
      .await
  }

  fn evict(&self, provider_id: &str) {
    self.0.evict(provider_id);
  }

  /// Drops the clients of providers which can no longer be logged in
  /// with (deleted or disabled), so their secrets don't stay in memory.
  /// `providers` must be the complete list of providers.
  fn prune(&self, providers: &[ResolvedProvider]) {
    self.0.retain(|provider_id| {
      providers.iter().any(|resolved| {
        resolved.provider.id == provider_id
          && resolved.provider.enabled()
      })
    });
  }
}

/// Returns the cached client for the provider, building it
/// if it doesn't exist, the provider configuration changed,
/// or the discovery data is outdated.
pub async fn load_built_provider(
  app_user_agent: &'static str,
  host: &str,
  path: &str,
  provider: &ExternalLoginProvider,
) -> anyhow::Result<Arc<BuiltProvider>> {
  provider_cache()
    .load(app_user_agent, host, path, provider)
    .await
}

/// Drops the cached client of a deleted / updated provider.
pub fn evict_built_provider(provider_id: &str) {
  provider_cache().evict(provider_id);
}

// ==============
// = RESOLUTION =
// ==============

/// Provider ids are part of urls, only allow `a-z A-Z 0-9 - _`.
pub fn validate_provider_id(id: &str) -> anyhow::Result<()> {
  if id.is_empty() {
    return Err(anyhow!("Provider id cannot be empty"));
  }
  if id.len() > MAX_PROVIDER_ID_LENGTH {
    return Err(anyhow!(
      "Provider id cannot be longer than {MAX_PROVIDER_ID_LENGTH} characters"
    ));
  }
  if !id
    .chars()
    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
  {
    return Err(anyhow!(
      "Provider id can only contain alphanumeric characters, '-' and '_'"
    ));
  }
  Ok(())
}

/// An [ExternalLoginProvider] and where it comes from.
pub struct ResolvedProvider {
  pub provider: ExternalLoginProvider,
  /// Whether the provider comes from
  /// [AuthImpl::static_external_providers],
  /// and can't be managed over the API.
  pub is_static: bool,
}

/// Finds the provider with the given id. Static providers
/// take precedence over stored ones. Returns 404 if not found.
pub async fn resolve_external_provider<I: AuthImpl + ?Sized>(
  auth: &I,
  provider_id: &str,
) -> mogh_error::Result<ResolvedProvider> {
  validate_provider_id(provider_id)
    .status_code(StatusCode::NOT_FOUND)?;

  if let Some(provider) = auth
    .static_external_providers()
    .into_iter()
    .find(|provider| provider.id == provider_id)
  {
    return Ok(ResolvedProvider {
      provider,
      is_static: true,
    });
  }

  auth
    .get_external_provider(provider_id.to_string())
    .await?
    // Don't trust the app to match the id exactly
    .filter(|provider| provider.id == provider_id)
    .map(|provider| ResolvedProvider {
      provider,
      is_static: false,
    })
    .with_context(|| {
      format!("No external login provider with id '{provider_id}'")
    })
    .status_code(StatusCode::NOT_FOUND)
}

/// Finds the provider whose urls use the slug (a provider without
/// one is known by its id, see [ExternalLoginProvider::slug]).
/// Static providers take precedence. Returns 404 if not found.
pub async fn resolve_external_provider_by_slug<
  I: AuthImpl + ?Sized,
>(
  auth: &I,
  slug: &str,
) -> mogh_error::Result<ResolvedProvider> {
  validate_provider_id(slug).status_code(StatusCode::NOT_FOUND)?;
  list_external_providers(auth)
    .await?
    .into_iter()
    .find(|resolved| resolved.provider.slug() == slug)
    .with_context(|| {
      format!("No external login provider with slug '{slug}'")
    })
    .status_code(StatusCode::NOT_FOUND)
}

/// Lists all the providers, static ones first.
/// Providers with invalid or duplicate ids or slugs are skipped.
pub async fn list_external_providers<I: AuthImpl + ?Sized>(
  auth: &I,
) -> mogh_error::Result<Vec<ResolvedProvider>> {
  list_providers_pruning(auth, provider_cache()).await
}

/// The complete list is the chance to drop the clients
/// of providers deleted elsewhere (another instance, or
/// directly on the database) from the cache.
async fn list_providers_pruning<I: AuthImpl + ?Sized>(
  auth: &I,
  cache: &BuiltProviderCache,
) -> mogh_error::Result<Vec<ResolvedProvider>> {
  let stored = auth.list_external_providers().await?;
  let providers =
    merge_providers(auth.static_external_providers(), stored);
  cache.prune(&providers);
  Ok(providers)
}

/// Lists only the static providers if the stored ones can't be loaded,
/// so eg. a database outage doesn't take down the login page.
pub async fn list_external_providers_lossy<I: AuthImpl + ?Sized>(
  auth: &I,
) -> Vec<ResolvedProvider> {
  list_providers_pruning_lossy(auth, provider_cache()).await
}

async fn list_providers_pruning_lossy<I: AuthImpl + ?Sized>(
  auth: &I,
  cache: &BuiltProviderCache,
) -> Vec<ResolvedProvider> {
  match list_providers_pruning(auth, cache).await {
    Ok(providers) => providers,
    // The list is incomplete, so it can't be
    // used to drop leftover provider clients.
    Err(e) => {
      warn!(
        "Failed to list stored external login providers | {:#}",
        e.error
      );
      merge_providers(auth.static_external_providers(), Vec::new())
    }
  }
}

fn merge_providers(
  static_providers: Vec<ExternalLoginProvider>,
  stored_providers: Vec<ExternalLoginProvider>,
) -> Vec<ResolvedProvider> {
  let mut providers = Vec::<ResolvedProvider>::new();
  let all = static_providers
    .into_iter()
    .map(|provider| (provider, true))
    .chain(
      stored_providers
        .into_iter()
        .map(|provider| (provider, false)),
    );
  for (provider, is_static) in all {
    if let Err(e) = validate_provider_id(&provider.id) {
      warn!(
        "Skipping external login provider '{}' with invalid id '{}' | {e:#}",
        provider.name, provider.id
      );
      continue;
    }
    if providers
      .iter()
      .any(|existing| existing.provider.id == provider.id)
    {
      warn!(
        "Skipping external login provider '{}' with duplicate id '{}'",
        provider.name, provider.id
      );
      continue;
    }
    // The urls would be ambiguous. Slugs are checked when a provider
    // is stored; this catches static ones and rows edited directly.
    if providers
      .iter()
      .any(|existing| existing.provider.slug() == provider.slug())
    {
      warn!(
        "Skipping external login provider '{}' with duplicate slug '{}'",
        provider.name,
        provider.slug()
      );
      continue;
    }
    providers.push(ResolvedProvider {
      provider,
      is_static,
    });
  }
  providers
}

#[cfg(test)]
mod tests {
  use mogh_auth_client::config::NamedOauthConfig;

  use super::*;

  fn github(id: &str, client_secret: &str) -> ExternalLoginProvider {
    ExternalLoginProvider {
      id: id.to_string(),
      name: format!("Github {id}"),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Github(NamedOauthConfig {
        enabled: true,
        client_id: "client-id".to_string(),
        client_secret: client_secret.to_string(),
      }),
    }
  }

  #[test]
  fn test_validate_provider_id() {
    for id in ["oidc", "a1B2c3", "my-provider_2"] {
      assert!(validate_provider_id(id).is_ok(), "{id}");
    }
    for id in ["", "a/b", "a b", "../x", "a?b", "ä", &"a".repeat(65)]
    {
      assert!(validate_provider_id(id).is_err(), "{id}");
    }
  }

  #[test]
  fn test_redirect_uri() {
    assert_eq!(
      redirect_uri(
        "https://example.com",
        "/auth",
        &github("github", "secret")
      ),
      "https://example.com/auth/github/callback"
    );
    assert_eq!(
      redirect_uri(
        "https://example.com",
        "/auth",
        &github("abc", "secret")
      ),
      "https://example.com/auth/external/abc/callback"
    );
  }

  #[test]
  fn test_merge_static_providers_take_precedence() {
    let providers = merge_providers(
      vec![github("github", "static")],
      vec![
        github("github", "stored"),
        github("abc", "stored"),
        github("not valid", "stored"),
      ],
    );
    assert_eq!(providers.len(), 2);
    assert!(providers[0].is_static);
    assert_eq!(
      providers[0].provider.config.client_secret(),
      "static"
    );
    assert!(!providers[1].is_static);
    assert_eq!(providers[1].provider.id, "abc");
  }

  async fn load(
    cache: &BuiltProviderCache,
    provider: &ExternalLoginProvider,
  ) -> Arc<BuiltProvider> {
    cache
      .load("test", "https://example.com", "/auth", provider)
      .await
      .unwrap()
  }

  fn resolved(provider: &ExternalLoginProvider) -> ResolvedProvider {
    ResolvedProvider {
      provider: provider.clone(),
      is_static: false,
    }
  }

  #[tokio::test]
  async fn test_built_provider_cached_until_config_changes() {
    let cache = BuiltProviderCache::default();
    let provider = github("abc", "secret");
    let first = load(&cache, &provider).await;
    let second = load(&cache, &provider).await;
    assert!(Arc::ptr_eq(&first, &second));

    // Changed config is rebuilt
    let updated = github("abc", "new-secret");
    let third = load(&cache, &updated).await;
    assert!(!Arc::ptr_eq(&first, &third));

    // Evicted provider is rebuilt
    cache.evict("abc");
    let fourth = load(&cache, &updated).await;
    assert!(!Arc::ptr_eq(&third, &fourth));
  }

  #[tokio::test]
  async fn test_prune_drops_deleted_and_disabled_providers() {
    let cache = BuiltProviderCache::default();
    let kept = github("kept", "secret");
    let deleted = github("deleted", "secret");
    let disabled = github("disabled", "secret");
    let kept_client = load(&cache, &kept).await;
    let deleted_client = load(&cache, &deleted).await;
    load(&cache, &disabled).await;

    let mut now_disabled = disabled.clone();
    let ExternalLoginProviderConfig::Github(config) =
      &mut now_disabled.config
    else {
      unreachable!()
    };
    config.enabled = false;

    cache.prune(&[resolved(&kept), resolved(&now_disabled)]);

    assert_eq!(cache.0.keys(), ["kept"]);
    // The kept client is reused, the cache held the last
    // reference to the dropped ones (wiping the Github secret).
    assert!(Arc::ptr_eq(&kept_client, &load(&cache, &kept).await));
    assert_eq!(Arc::strong_count(&deleted_client), 1);

    // Nothing to drop leaves the cache as is
    cache.prune(&[resolved(&kept)]);
    assert_eq!(cache.0.keys().len(), 1);
  }

  struct TestAuth {
    static_providers: Vec<ExternalLoginProvider>,
    /// None fails the listing
    stored_providers: Option<Vec<ExternalLoginProvider>>,
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      unreachable!()
    }

    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      self.static_providers.clone()
    }

    fn list_external_providers(
      &self,
    ) -> crate::DynFuture<
      mogh_error::Result<Vec<ExternalLoginProvider>>,
    > {
      let providers = self.stored_providers.clone();
      Box::pin(async move {
        providers
          .ok_or_else(|| anyhow!("database unavailable").into())
      })
    }

    crate::test_support::stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
  }

  #[tokio::test]
  async fn test_listing_drops_clients_of_providers_deleted_elsewhere()
  {
    let cache = BuiltProviderCache::default();
    let static_provider = github("github", "secret");
    let stored = github("stored", "secret");
    let deleted = github("deleted", "secret");
    for provider in [&static_provider, &stored, &deleted] {
      load(&cache, provider).await;
    }

    // 'deleted' was removed from the database by another instance
    let auth = TestAuth {
      static_providers: vec![static_provider],
      stored_providers: Some(vec![stored]),
    };
    let providers = list_providers_pruning_lossy(&auth, &cache).await;
    assert_eq!(providers.len(), 2);

    assert_eq!(cache.0.keys(), ["github", "stored"]);
  }

  /// When the stored providers can't be loaded the list is incomplete,
  /// their clients must survive eg. a short database outage.
  #[tokio::test]
  async fn test_failed_listing_keeps_all_clients() {
    let cache = BuiltProviderCache::default();
    let static_provider = github("github", "secret");
    let stored = github("stored", "secret");
    for provider in [&static_provider, &stored] {
      load(&cache, provider).await;
    }

    let auth = TestAuth {
      static_providers: vec![static_provider],
      stored_providers: None,
    };
    assert!(list_providers_pruning(&auth, &cache).await.is_err());
    let providers = list_providers_pruning_lossy(&auth, &cache).await;
    // Only the static provider is listed
    assert_eq!(providers.len(), 1);

    assert_eq!(cache.0.keys().len(), 2);
  }

  #[tokio::test]
  async fn test_load_built_provider_requires_host() {
    let provider = github("host-test", "secret");
    assert!(
      load_built_provider("test", "", "/auth", &provider)
        .await
        .is_err()
    );
  }

  /// A Github login through a mock of Github: the verifier of
  /// the challenge in the login url is sent with the code.
  #[tokio::test]
  async fn test_github_complete_login() {
    use crate::provider::named::github::mock;
    let github_mock = mock::spawn(
      r#"{"access_token":"gho_token","token_type":"bearer"}"#,
    )
    .await;
    let provider = github("mock-github", "secret");
    let built = mock_github_client(&provider, &github_mock.url);
    let begin = built.begin_login();
    let challenge = begin
      .url
      .split("code_challenge=")
      .nth(1)
      .unwrap()
      .split('&')
      .next()
      .unwrap()
      .to_string();
    let login = session_login(&provider, &begin);
    let Ok(completed) = built
      .complete_login(&provider, login, begin.state, "code".into())
      .await
    else {
      panic!("expected the login to complete")
    };
    assert_eq!(completed.info.provider_id, "mock-github");
    assert_eq!(completed.info.external_id, "42");
    assert_eq!(completed.username(&built).await, "octocat");

    let received = github_mock.received.lock().unwrap().clone();
    let form = mock::form(&received[0].body);
    let verifier =
      PkceCodeVerifier::new(form["code_verifier"].clone());
    assert_eq!(
      PkceCodeChallenge::from_code_verifier_sha256(&verifier)
        .as_str(),
      challenge
    );
  }

  /// A login begun before Github used PKCE has no verifier on the
  /// session, and a refused code is the user's failed login. Neither
  /// error carries the client secret.
  #[tokio::test]
  async fn test_github_failed_login() {
    use crate::provider::named::github::mock;
    const SECRET: &str = "the-github-client-secret";
    let github_mock =
      mock::spawn(r#"{"error":"bad_verification_code"}"#).await;
    let provider = github("mock-github", SECRET);
    let built = mock_github_client(&provider, &github_mock.url);

    let begin = built.begin_login();
    let mut login = session_login(&provider, &begin);
    login.pkce_verifier = None;
    let Err(err) = built
      .complete_login(&provider, login, begin.state, "code".into())
      .await
    else {
      panic!("expected the login to fail")
    };
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // Refused before the code is redeemed.
    assert!(github_mock.received.lock().unwrap().is_empty());

    let begin = built.begin_login();
    let login = session_login(&provider, &begin);
    let Err(err) = built
      .complete_login(&provider, login, begin.state, "code".into())
      .await
    else {
      panic!("expected the code to be refused")
    };
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let message = format!("{:#}", err.error);
    assert!(message.contains("bad_verification_code"), "{message}");
    for rendered in [message, mogh_error::serialize_error(&err.error)]
    {
      assert!(!rendered.contains(SECRET), "{rendered}");
    }
  }

  fn mock_github_client(
    provider: &ExternalLoginProvider,
    url: &str,
  ) -> BuiltProvider {
    let ExternalLoginProviderConfig::Github(config) =
      &provider.config
    else {
      unreachable!()
    };
    BuiltProvider::Github(
      GithubProvider::new(
        redirect_uri("https://example.com", "/auth", provider),
        config,
      )
      .unwrap()
      .with_base_urls(url, url),
    )
  }

  fn session_login(
    provider: &ExternalLoginProvider,
    begin: &BeginExternalLogin,
  ) -> SessionExternalLogin {
    SessionExternalLogin {
      provider_id: provider.id.clone(),
      link_user_id: None,
      state: begin.state.clone(),
      nonce: begin.nonce.clone(),
      pkce_verifier: begin.pkce_verifier.as_ref().map(|verifier| {
        PkceCodeVerifier::new(verifier.secret().clone())
      }),
      redirect: None,
    }
  }

  #[test]
  fn test_github_begin_login() {
    let built = BuiltProvider::Github(
      GithubProvider::new(
        "https://example.com/auth/github/callback".to_string(),
        &NamedOauthConfig {
          enabled: true,
          client_id: "client-id".to_string(),
          client_secret: "secret".to_string(),
        },
      )
      .unwrap(),
    );
    let begin = built.begin_login();
    assert!(begin.url.contains(&begin.state));
    assert!(begin.nonce.is_none());
    // The code is bound to the session with PKCE.
    let verifier = begin.pkce_verifier.unwrap();
    let challenge =
      PkceCodeChallenge::from_code_verifier_sha256(&verifier);
    assert!(begin.url.contains(&format!(
      "code_challenge={}&code_challenge_method=S256",
      challenge.as_str()
    )));
  }
}
