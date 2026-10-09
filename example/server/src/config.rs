use std::{path::PathBuf, sync::OnceLock};

use anyhow::Context as _;
use mogh_auth_client::config::{
  OidcConfig, TokenExchangeConfig, TrustedIssuer,
};
use mogh_config::{ConfigLoader, EnvSource};
use mogh_logger::{LogApp, LoggingConfig};
use serde::{Deserialize, Serialize};

/// The variables which say where the config files are, read before
/// them. The others override the config, see [env_source].
#[derive(Debug, Deserialize)]
struct LoaderEnv {
  /// Config files / directories, later ones override earlier ones.
  #[serde(default)]
  example_config_paths: Vec<PathBuf>,
  #[serde(default = "default_config_keywords")]
  example_config_keywords: Vec<String>,
}

/// The `EXAMPLE_*` environment variables, which override the config
/// files: one for every field of [CoreConfig], named after its path
/// (`EXAMPLE_PORT`, `EXAMPLE_OIDC_CLIENT_ID` for `oidc.client_id`,
/// `EXAMPLE_LOGGING_LEVEL`), each also taking a file
/// (`EXAMPLE_JWT_SECRET_FILE`, eg. a docker secret). A blank variable
/// counts as unset. See `mogh_config::EnvSource` for the rules.
pub fn env_source() -> EnvSource {
  EnvSource::new("EXAMPLE_")
    .fields_of(&CoreConfig::default())
    // A list of objects: config files only.
    .without(["trusted_issuers"])
}

fn default_config_keywords() -> Vec<String> {
  vec![String::from("*config.*")]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreConfig {
  /// The app name, eg. the TOTP issuer.
  pub title: String,
  /// The address users reach the app at, eg. `https://example.com`.
  pub host: String,
  /// More addresses the app is reached at, eg.
  /// `http://10.0.0.5:9220` inside the network. A request signed
  /// with a signing key is made for the host it is sent to, and
  /// accepted for `host` and these.
  pub extra_hosts: Vec<String>,
  pub port: u16,
  pub bind_ip: String,
  /// Path of the sqlite database file.
  pub database_path: PathBuf,
  /// Directory of the built UI to serve. Not served if empty.
  pub ui_path: String,

  /// Signs the app tokens: at least 32 random bytes (eg.
  /// `openssl rand -base64 48`), a shorter one stops the startup.
  /// Random on every start if empty, which logs out all users on
  /// restart.
  pub jwt_secret: String,
  pub jwt_ttl_seconds: u64,
  /// Base64url 32 byte key to encrypt secrets in the database with.
  /// If empty, one is generated next to the database.
  pub encryption_key: String,
  /// The Mogh supporter key of this instance, which makes the UI
  /// show a supporter badge (`mogh_supporter`). Empty for none.
  /// Whitespace in it (a wrapped key) is ignored.
  pub supporter_key: String,

  pub local_auth: bool,
  pub disable_user_registration: bool,
  /// Whether new users are enabled without an admin doing it.
  pub enable_new_users: bool,
  pub lock_login_credentials_for: Vec<String>,
  pub bcrypt_cost: u32,
  /// Changes to how a user logs in (password, 2fa, api keys, ...) need
  /// a login at most this long ago. 0 disables the check for
  /// sessions; api keys are refused them either way.
  pub reauthentication_window_seconds: u64,
  /// Send the browser back to the login page when an external
  /// login fails, instead of answering with the JSON error.
  pub login_error_redirect: bool,

  /// The static OIDC provider, using the reserved `oidc` id.
  /// More providers can be added by admins in the UI.
  pub oidc: OidcConfig,
  /// Whether tokens of the static OIDC provider can be
  /// exchanged for app tokens (RFC 8693). Off by default.
  pub oidc_token_exchange: TokenExchangeConfig,
  /// The static workload identity issuers.
  pub trusted_issuers: Vec<TrustedIssuer>,

  pub auth_rate_limit_disabled: bool,
  pub auth_rate_limit_max_attempts: usize,
  pub auth_rate_limit_window_seconds: u64,
  /// How many external logins (and links) each client ip can start
  /// at once, refilled evenly over `auth_login_start_window_seconds`.
  /// The requests of a logged in user which begin a login session (a
  /// link, a 2fa enrollment) are limited to 10 at once per user over
  /// the same window. `0` disables both, as does
  /// `auth_rate_limit_disabled`. Keep it well below `max_sessions`.
  pub auth_login_start_limit: u32,
  pub auth_login_start_window_seconds: u64,
  /// The most sessions (logins in progress) held in memory. When full,
  /// the ones closest to expiry are dropped.
  pub max_sessions: usize,

  pub trusted_proxies: Vec<String>,
  pub cors_allowed_origins: Vec<String>,
  pub cors_allow_credentials: bool,
  pub session_allow_cross_site: bool,
  /// How long a session (a login in progress) is kept after the last
  /// request which changed it. The auth server keeps it longer while
  /// a step of a login waits for the user (eg. the second factor:
  /// 10 minutes).
  pub session_expiry_seconds: i64,

  pub logging: LoggingConfig,
}

impl Default for CoreConfig {
  fn default() -> Self {
    Self {
      title: String::from("Mogh Example"),
      host: String::from("http://localhost:9220"),
      extra_hosts: Vec::new(),
      port: 9220,
      bind_ip: String::from("[::]"),
      // `.dev` is git ignored in this repository.
      database_path: PathBuf::from("./.dev/example/example.db"),
      ui_path: String::new(),
      jwt_secret: String::new(),
      jwt_ttl_seconds: 24 * 60 * 60,
      encryption_key: String::new(),
      supporter_key: String::new(),
      local_auth: true,
      disable_user_registration: false,
      enable_new_users: true,
      lock_login_credentials_for: Vec::new(),
      bcrypt_cost: 10,
      reauthentication_window_seconds: 15 * 60,
      login_error_redirect: true,
      oidc: Default::default(),
      oidc_token_exchange: Default::default(),
      trusted_issuers: Vec::new(),
      auth_rate_limit_disabled: false,
      auth_rate_limit_max_attempts: 5,
      auth_rate_limit_window_seconds: 15,
      auth_login_start_limit:
        mogh_auth_server::login_start::LoginStartLimiter::DEFAULT_CLIENT_LIMIT,
      auth_login_start_window_seconds: 60,
      max_sessions: mogh_server::session::DEFAULT_MAX_SESSIONS,
      trusted_proxies: Vec::new(),
      cors_allowed_origins: Vec::new(),
      cors_allow_credentials: false,
      session_allow_cross_site: false,
      session_expiry_seconds: 3 * 60,
      // Plain text: the api suite reads the logs back.
      logging: LoggingConfig {
        ansi: false,
        ..Default::default()
      },
    }
  }
}

/// The example server's side of its logging config: what
/// `mogh_logger::init` takes with the operator's [LoggingConfig].
pub const LOG_APP: LogApp = LogApp {
  name: "MoghExample",
  version: Some(env!("CARGO_PKG_VERSION")),
  // Only these targets are logged, everything else is filtered out.
  targets: &[
    "example_server",
    "mogh_pki",
    "mogh_server",
    "mogh_auth_server",
    "mogh_supporter",
  ],
};

pub fn core_config() -> &'static CoreConfig {
  static CORE_CONFIG: OnceLock<CoreConfig> = OnceLock::new();
  CORE_CONFIG.get_or_init(|| match load_config() {
    Ok(config) => config,
    Err(e) => panic!("{e:?}"),
  })
}

fn load_config() -> anyhow::Result<CoreConfig> {
  let env: LoaderEnv = envy::from_env()
    .context("Failed to parse Example Server environment")?;
  (ConfigLoader {
    paths: &env
      .example_config_paths
      .iter()
      .map(PathBuf::as_path)
      .collect::<Vec<_>>(),
    match_wildcards: &env
      .example_config_keywords
      .iter()
      .map(String::as_str)
      .collect::<Vec<_>>(),
    include_file_name: ".exampleinclude",
    merge_nested: true,
    extend_array: false,
    debug_print: false,
  })
  // Without config paths, the defaults with the environment.
  .load_with_env::<CoreConfig>(&env_source())
  .context("Failed to load the config")
}

impl mogh_server::ServerConfig for &CoreConfig {
  fn bind_ip(&self) -> &str {
    &self.bind_ip
  }
  fn port(&self) -> u16 {
    self.port
  }
  /// The client ip drives the auth rate limiter and the cidr
  /// whitelists, so an invalid entry fails `serve_app` (the
  /// startup) rather than falling back to another policy.
  fn trusted_proxies(
    &self,
  ) -> anyhow::Result<mogh_server::TrustedProxies> {
    mogh_server::TrustedProxies::from_config(&self.trusted_proxies)
  }
}

impl mogh_server::cors::CorsConfig for &CoreConfig {
  fn allowed_origins(&self) -> &[String] {
    &self.cors_allowed_origins
  }
  fn allow_credentials(&self) -> bool {
    self.cors_allow_credentials
  }
}

impl mogh_server::session::SessionConfig for &CoreConfig {
  fn host(&self) -> &str {
    &self.host
  }
  fn host_env_field(&self) -> &str {
    "EXAMPLE_HOST"
  }
  fn max_sessions(&self) -> usize {
    self.max_sessions
  }
  fn allow_cross_site(&self) -> bool {
    self.session_allow_cross_site
  }
  fn expiry_seconds(&self) -> i64 {
    self.session_expiry_seconds
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Every variable the server read before its environment was a
  /// `mogh_config::EnvSource` (its own `Env` struct), by the same
  /// name. `_FILE` variants are the rule's.
  #[test]
  fn the_environment_keeps_its_variable_names() {
    let names = env_source().names().unwrap();
    for name in [
      "EXAMPLE_TITLE",
      "EXAMPLE_HOST",
      "EXAMPLE_EXTRA_HOSTS",
      "EXAMPLE_PORT",
      "EXAMPLE_BIND_IP",
      "EXAMPLE_DATABASE_PATH",
      "EXAMPLE_UI_PATH",
      "EXAMPLE_JWT_SECRET",
      "EXAMPLE_JWT_TTL_SECONDS",
      "EXAMPLE_ENCRYPTION_KEY",
      "EXAMPLE_SUPPORTER_KEY",
      "EXAMPLE_LOCAL_AUTH",
      "EXAMPLE_DISABLE_USER_REGISTRATION",
      "EXAMPLE_ENABLE_NEW_USERS",
      "EXAMPLE_LOCK_LOGIN_CREDENTIALS_FOR",
      "EXAMPLE_BCRYPT_COST",
      "EXAMPLE_REAUTHENTICATION_WINDOW_SECONDS",
      "EXAMPLE_LOGIN_ERROR_REDIRECT",
      "EXAMPLE_OIDC_ENABLED",
      "EXAMPLE_OIDC_PROVIDER",
      "EXAMPLE_OIDC_CLIENT_ID",
      "EXAMPLE_OIDC_CLIENT_SECRET",
      "EXAMPLE_AUTH_RATE_LIMIT_DISABLED",
      "EXAMPLE_AUTH_RATE_LIMIT_MAX_ATTEMPTS",
      "EXAMPLE_AUTH_RATE_LIMIT_WINDOW_SECONDS",
      "EXAMPLE_AUTH_LOGIN_START_LIMIT",
      "EXAMPLE_AUTH_LOGIN_START_WINDOW_SECONDS",
      "EXAMPLE_MAX_SESSIONS",
      "EXAMPLE_TRUSTED_PROXIES",
      "EXAMPLE_CORS_ALLOWED_ORIGINS",
      "EXAMPLE_CORS_ALLOW_CREDENTIALS",
      "EXAMPLE_SESSION_ALLOW_CROSS_SITE",
      "EXAMPLE_SESSION_EXPIRY_SECONDS",
      "EXAMPLE_LOGGING_LEVEL",
      "EXAMPLE_LOGGING_STDIO",
      "EXAMPLE_LOGGING_PRETTY",
    ] {
      assert!(names.iter().any(|n| n == name), "{name}: {names:?}");
    }
    // The loader's own variables are no config field's.
    for name in ["EXAMPLE_CONFIG_PATHS", "EXAMPLE_CONFIG_KEYWORDS"] {
      assert!(!names.iter().any(|n| n == name), "{name}");
    }
  }
}
