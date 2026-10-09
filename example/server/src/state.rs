use std::{
  sync::{Arc, LazyLock, Mutex, OnceLock},
  time::Duration,
};

use example_client::api::read::GetStatsResponse;
use mogh_auth_client::config::{
  ExternalLoginProvider, TrustedIssuer,
};
use mogh_auth_server::{
  login_start::LoginStartLimiter,
  provider::{jwt::JwtProvider, passkey::PasskeyProvider},
  rand::random_string,
};
use mogh_cache::TimeoutCache;
use mogh_rate_limit::RateLimiter;
use tracing::warn;

use crate::config::core_config;

pub const APP_NAME: &str = "MoghExample";

/// The provider of the app tokens, built from `jwt_secret` with
/// `JwtProvider::try_new`: a configured secret under 32 bytes is
/// refused, and the example doesn't start ([check_jwt_provider]).
/// Anyone who knows the secret, or guesses it offline from any token
/// they got, can issue tokens for any user.
static JWT_PROVIDER: LazyLock<anyhow::Result<JwtProvider>> =
  LazyLock::new(|| {
    let config = core_config();
    let secret = if config.jwt_secret.is_empty() {
      warn!(
        "No 'jwt_secret' configured, users are logged out on restart"
      );
      random_string(40)
    } else {
      config.jwt_secret.clone()
    };
    Ok(
      JwtProvider::try_new(
        secret.as_bytes(),
        config.jwt_ttl_seconds as u128 * 1000,
      )?
      // Tokens of another app sharing the secret are not accepted.
      .with_iss(config.host.clone())
      .with_aud(APP_NAME),
    )
  });

/// Refuses a configured `jwt_secret` under 32 bytes, so the example
/// stops at startup, before anything issues or checks a token: built
/// on the first request needing it, the refusal would only show once
/// the app serves. The error names the minimum and the length, never
/// the secret.
pub fn check_jwt_provider() -> anyhow::Result<()> {
  match JWT_PROVIDER.as_ref() {
    Ok(_) => Ok(()),
    Err(e) => Err(anyhow::anyhow!("{e:#}")),
  }
}

/// Checked at startup ([check_jwt_provider]), before any request.
pub fn jwt_provider() -> &'static JwtProvider {
  JWT_PROVIDER
    .as_ref()
    .expect("The jwt provider is checked at startup")
}

pub fn passkey_provider() -> Option<&'static PasskeyProvider> {
  static PASSKEY_PROVIDER: LazyLock<Option<PasskeyProvider>> =
    LazyLock::new(|| {
      PasskeyProvider::new(&core_config().host)
        .inspect_err(|e| {
          warn!("Invalid 'host' for passkey provider | {e:#}")
        })
        .ok()
    });
  PASSKEY_PROVIDER.as_ref()
}

fn rate_limiter() -> Arc<RateLimiter> {
  let config = core_config();
  RateLimiter::new(
    config.auth_rate_limit_disabled,
    config.auth_rate_limit_max_attempts,
    Duration::from_secs(config.auth_rate_limit_window_seconds),
  )
}

/// Failed authentication of any kind, by ip.
pub fn general_rate_limiter() -> &'static RateLimiter {
  static LIMITER: OnceLock<Arc<RateLimiter>> = OnceLock::new();
  LIMITER.get_or_init(rate_limiter)
}

/// Failed password logins have their own budget, so the
/// remaining attempts shown to the user are accurate.
pub fn local_login_rate_limiter() -> &'static RateLimiter {
  static LIMITER: OnceLock<Arc<RateLimiter>> = OnceLock::new();
  LIMITER.get_or_init(rate_limiter)
}

/// External login starts per client ip, and login sessions begun per
/// user. Off along with the rate limiter, like Komodo's.
pub fn login_start_limiter() -> &'static LoginStartLimiter {
  static LIMITER: OnceLock<LoginStartLimiter> = OnceLock::new();
  LIMITER.get_or_init(|| {
    let config = core_config();
    let limit = if config.auth_rate_limit_disabled {
      0
    } else {
      config.auth_login_start_limit
    };
    let user_limit = if limit == 0 {
      0
    } else {
      LoginStartLimiter::DEFAULT_USER_LIMIT
    };
    LoginStartLimiter::new(
      limit,
      user_limit,
      Duration::from_secs(config.auth_login_start_window_seconds),
    )
  })
}

/// A value loaded from the database, kept in memory until it changes.
///
/// The stored login providers / trusted issuers are read by
/// unauthenticated requests (the login options, every token exchange),
/// so they are served from memory and only reloaded after a change.
pub struct ReloadCache<T> {
  /// The changes made so far, and the value loaded since the last.
  state: Mutex<(u64, Option<Arc<T>>)>,
}

impl<T> Default for ReloadCache<T> {
  fn default() -> Self {
    Self {
      state: Mutex::new((0, None)),
    }
  }
}

impl<T> ReloadCache<T> {
  /// The value in memory, else loads it.
  ///
  /// A load which a change ran during is used, but not kept: it may
  /// have read what was there before, and would otherwise be served
  /// until the next change. A disabled workload rule would then keep
  /// accepting tokens.
  pub async fn get_or_load<F>(
    &self,
    load: impl FnOnce() -> F,
  ) -> anyhow::Result<Arc<T>>
  where
    F: Future<Output = anyhow::Result<T>>,
  {
    let changes = {
      let state =
        self.state.lock().unwrap_or_else(|e| e.into_inner());
      if let Some(value) = &state.1 {
        return Ok(value.clone());
      }
      state.0
    };
    let value = Arc::new(load().await?);
    let mut state =
      self.state.lock().unwrap_or_else(|e| e.into_inner());
    if state.0 == changes {
      state.1 = Some(value.clone());
    }
    Ok(value)
  }

  /// Call once a change is stored, the next read loads it.
  pub fn changed(&self) {
    let mut state =
      self.state.lock().unwrap_or_else(|e| e.into_inner());
    state.0 += 1;
    state.1 = None;
  }
}

pub fn login_providers_cache()
-> &'static ReloadCache<Vec<ExternalLoginProvider>> {
  static CACHE: OnceLock<ReloadCache<Vec<ExternalLoginProvider>>> =
    OnceLock::new();
  CACHE.get_or_init(Default::default)
}

pub fn trusted_issuers_cache()
-> &'static ReloadCache<Vec<TrustedIssuer>> {
  static CACHE: OnceLock<ReloadCache<Vec<TrustedIssuer>>> =
    OnceLock::new();
  CACHE.get_or_init(Default::default)
}

/// The app the supporter key is for (`SupporterImpl::supporter_app`
/// in `auth.rs`). The example plays `komodo`: the key of
/// `mogh_supporter::fixture`, which its tests configure, is for it.
/// An app passes its own name.
pub const SUPPORTER_APP: &str = "komodo";

/// How long [GetStatsResponse] is reused for.
pub const STATS_VALID_FOR: Duration = Duration::from_secs(2);

pub fn stats_cache() -> &'static TimeoutCache<(), GetStatsResponse> {
  static CACHE: OnceLock<TimeoutCache<(), GetStatsResponse>> =
    OnceLock::new();
  CACHE.get_or_init(|| TimeoutCache::new(STATS_VALID_FOR))
}
