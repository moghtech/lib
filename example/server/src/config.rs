use std::{path::PathBuf, sync::OnceLock};

use anyhow::Context as _;
use mogh_auth_client::config::{
  OidcConfig, TokenExchangeConfig, TrustedIssuer,
};
use mogh_config::ConfigLoader;
use mogh_logger::{LogLevel, StdioLogMode};
use mogh_secret_file::maybe_read_item_from_file;
use serde::Deserialize;

/// The environment variables, which override the config files.
/// Secrets can also be passed as a file with the `_FILE` variants.
#[derive(Debug, Deserialize)]
pub struct Env {
  /// Config files / directories, later ones override earlier ones.
  #[serde(default)]
  pub example_config_paths: Vec<PathBuf>,
  #[serde(default = "default_config_keywords")]
  pub example_config_keywords: Vec<String>,

  pub example_title: Option<String>,
  pub example_host: Option<String>,
  pub example_extra_hosts: Option<Vec<String>>,
  pub example_port: Option<u16>,
  pub example_bind_ip: Option<String>,
  pub example_database_path: Option<PathBuf>,
  pub example_ui_path: Option<String>,

  pub example_jwt_secret: Option<String>,
  pub example_jwt_secret_file: Option<PathBuf>,
  pub example_jwt_ttl_seconds: Option<u64>,
  pub example_encryption_key: Option<String>,
  pub example_encryption_key_file: Option<PathBuf>,

  pub example_local_auth: Option<bool>,
  pub example_disable_user_registration: Option<bool>,
  pub example_enable_new_users: Option<bool>,
  pub example_lock_login_credentials_for: Option<Vec<String>>,
  pub example_bcrypt_cost: Option<u32>,
  pub example_reauthentication_window_seconds: Option<u64>,
  pub example_login_error_redirect: Option<bool>,

  pub example_oidc_enabled: Option<bool>,
  pub example_oidc_provider: Option<String>,
  pub example_oidc_client_id: Option<String>,
  pub example_oidc_client_secret: Option<String>,
  pub example_oidc_client_secret_file: Option<PathBuf>,

  pub example_auth_rate_limit_disabled: Option<bool>,
  pub example_auth_rate_limit_max_attempts: Option<usize>,
  pub example_auth_rate_limit_window_seconds: Option<u64>,

  pub example_trusted_proxies: Option<Vec<String>>,
  pub example_cors_allowed_origins: Option<Vec<String>>,
  pub example_cors_allow_credentials: Option<bool>,
  pub example_session_allow_cross_site: Option<bool>,

  pub example_logging_level: Option<LogLevel>,
  pub example_logging_stdio: Option<StdioLogMode>,
  pub example_logging_pretty: Option<bool>,
}

fn default_config_keywords() -> Vec<String> {
  vec![String::from("*config.*")]
}

#[derive(Debug, Clone, Deserialize)]
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

  /// Signs the app tokens. Random on every start if empty,
  /// which logs out all users on restart.
  pub jwt_secret: String,
  pub jwt_ttl_seconds: u64,
  /// Base64url 32 byte key to encrypt secrets in the database with.
  /// If empty, one is generated next to the database.
  pub encryption_key: String,

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

  pub trusted_proxies: Vec<String>,
  pub cors_allowed_origins: Vec<String>,
  pub cors_allow_credentials: bool,
  pub session_allow_cross_site: bool,

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
      trusted_proxies: Vec::new(),
      cors_allowed_origins: Vec::new(),
      cors_allow_credentials: false,
      session_allow_cross_site: false,
      logging: Default::default(),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
  pub level: LogLevel,
  pub stdio: StdioLogMode,
  pub pretty: bool,
}

pub fn core_config() -> &'static CoreConfig {
  static CORE_CONFIG: OnceLock<CoreConfig> = OnceLock::new();
  CORE_CONFIG.get_or_init(|| match load_config() {
    Ok(config) => config,
    Err(e) => panic!("{e:?}"),
  })
}

fn load_config() -> anyhow::Result<CoreConfig> {
  let env: Env = envy::from_env()
    .context("Failed to parse Example Server environment")?;

  let config = if env.example_config_paths.is_empty() {
    CoreConfig::default()
  } else {
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
    .load::<CoreConfig>()
    .context("Failed to parse config from paths")?
  };

  // Recreating the config makes sure all env overrides are applied.
  Ok(CoreConfig {
    title: env.example_title.unwrap_or(config.title),
    host: env.example_host.unwrap_or(config.host),
    extra_hosts: env
      .example_extra_hosts
      .unwrap_or(config.extra_hosts),
    port: env.example_port.unwrap_or(config.port),
    bind_ip: env.example_bind_ip.unwrap_or(config.bind_ip),
    database_path: env
      .example_database_path
      .unwrap_or(config.database_path),
    ui_path: env.example_ui_path.unwrap_or(config.ui_path),
    jwt_secret: maybe_read_item_from_file(
      env.example_jwt_secret_file,
      env.example_jwt_secret,
    )
    .unwrap_or(config.jwt_secret),
    jwt_ttl_seconds: env
      .example_jwt_ttl_seconds
      .unwrap_or(config.jwt_ttl_seconds),
    encryption_key: maybe_read_item_from_file(
      env.example_encryption_key_file,
      env.example_encryption_key,
    )
    .unwrap_or(config.encryption_key),
    local_auth: env.example_local_auth.unwrap_or(config.local_auth),
    disable_user_registration: env
      .example_disable_user_registration
      .unwrap_or(config.disable_user_registration),
    enable_new_users: env
      .example_enable_new_users
      .unwrap_or(config.enable_new_users),
    lock_login_credentials_for: env
      .example_lock_login_credentials_for
      .unwrap_or(config.lock_login_credentials_for),
    bcrypt_cost: env
      .example_bcrypt_cost
      .unwrap_or(config.bcrypt_cost),
    reauthentication_window_seconds: env
      .example_reauthentication_window_seconds
      .unwrap_or(config.reauthentication_window_seconds),
    login_error_redirect: env
      .example_login_error_redirect
      .unwrap_or(config.login_error_redirect),
    oidc: OidcConfig {
      enabled: env
        .example_oidc_enabled
        .unwrap_or(config.oidc.enabled),
      provider: env
        .example_oidc_provider
        .unwrap_or(config.oidc.provider),
      client_id: env
        .example_oidc_client_id
        .unwrap_or(config.oidc.client_id),
      client_secret: maybe_read_item_from_file(
        env.example_oidc_client_secret_file,
        env.example_oidc_client_secret,
      )
      .unwrap_or(config.oidc.client_secret),
      ..config.oidc
    },
    oidc_token_exchange: config.oidc_token_exchange,
    trusted_issuers: config.trusted_issuers,
    auth_rate_limit_disabled: env
      .example_auth_rate_limit_disabled
      .unwrap_or(config.auth_rate_limit_disabled),
    auth_rate_limit_max_attempts: env
      .example_auth_rate_limit_max_attempts
      .unwrap_or(config.auth_rate_limit_max_attempts),
    auth_rate_limit_window_seconds: env
      .example_auth_rate_limit_window_seconds
      .unwrap_or(config.auth_rate_limit_window_seconds),
    trusted_proxies: env
      .example_trusted_proxies
      .unwrap_or(config.trusted_proxies),
    cors_allowed_origins: env
      .example_cors_allowed_origins
      .unwrap_or(config.cors_allowed_origins),
    cors_allow_credentials: env
      .example_cors_allow_credentials
      .unwrap_or(config.cors_allow_credentials),
    session_allow_cross_site: env
      .example_session_allow_cross_site
      .unwrap_or(config.session_allow_cross_site),
    logging: LoggingConfig {
      level: env
        .example_logging_level
        .unwrap_or(config.logging.level),
      stdio: env
        .example_logging_stdio
        .unwrap_or(config.logging.stdio),
      pretty: env
        .example_logging_pretty
        .unwrap_or(config.logging.pretty),
    },
  })
}

impl mogh_server::ServerConfig for &CoreConfig {
  fn bind_ip(&self) -> &str {
    &self.bind_ip
  }
  fn port(&self) -> u16 {
    self.port
  }
  /// Invalid entries are a startup error, see `main`.
  fn trusted_proxies(&self) -> mogh_server::TrustedProxies {
    mogh_server::TrustedProxies::from_config(&self.trusted_proxies)
      .unwrap_or(mogh_server::TrustedProxies::None)
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
  fn allow_cross_site(&self) -> bool {
    self.session_allow_cross_site
  }
}

impl mogh_logger::LogConfig for &LoggingConfig {
  fn level(&self) -> tracing::Level {
    self.level.into()
  }
  fn stdio(&self) -> StdioLogMode {
    self.stdio
  }
  fn pretty(&self) -> bool {
    self.pretty
  }
  fn ansi(&self) -> bool {
    false
  }
  /// Only these targets are logged, everything else is filtered out.
  fn targets(&self) -> &[String] {
    static TARGETS: std::sync::LazyLock<Vec<String>> =
      std::sync::LazyLock::new(|| {
        [
          "example_server",
          "mogh_pki",
          "mogh_server",
          "mogh_auth_server",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
      });
    &TARGETS
  }
}
