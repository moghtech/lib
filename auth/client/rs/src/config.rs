use serde::{Deserialize, Serialize};

pub fn empty_or_redacted(src: &str) -> String {
  if src.is_empty() {
    String::new()
  } else {
    String::from("##############")
  }
}

/// Configuration for OIDC provider
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OidcConfig {
  /// Enable login with configured OIDC provider.
  #[serde(default)]
  pub enabled: bool,
  /// Configure OIDC provider address for
  /// communcation directly with the app server.
  ///
  /// Note. Needs to be reachable from the app server.
  ///
  /// `https://accounts.example.internal/application/o/appname`
  #[serde(default)]
  pub provider: String,
  /// Configure OIDC user redirect host.
  ///
  /// This is the host address users are redirected to in their browser,
  /// and may be different from the `provider` host.
  /// DO NOT include the `path` part, this must be inferred from the above provider path.
  /// If not provided, the host will be the same as `oidc_provider`.
  /// Eg. `https://accounts.example.external`
  #[serde(default)]
  pub redirect_host: String,
  /// Set OIDC client id
  ///
  /// Alias: 'id'
  #[serde(default)]
  #[serde(alias = "id")]
  pub client_id: String,
  /// Set OIDC client secret
  ///
  /// Alias: 'secret'
  #[serde(default)]
  #[serde(alias = "secret")]
  pub client_secret: String,
  /// Use the full email for usernames.
  /// Otherwise, the @address will be stripped,
  /// making usernames more concise.
  #[serde(default)]
  pub use_full_email: bool,
  /// Your OIDC provider may set additional audiences other than `client_id`,
  /// they must be added here to make claims verification work.
  #[serde(default)]
  pub additional_audiences: Vec<String>,
  /// Automatically redirect unauthenticated users to the OIDC provider
  /// instead of showing the login page.
  #[serde(default)]
  pub auto_redirect: bool,
  /// Claim that holds the user's group memberships (eg `groups`).
  /// When set, the user's group memberships are synced on each
  /// OIDC login. Empty (default) disables group syncing.
  ///
  /// The claim value may be an array of strings or a single string.
  #[serde(default)]
  pub groups_claim: String,
  /// Claim that signals whether the user is an admin.
  /// When set, the user's admin status is synced on each OIDC login.
  /// Empty (default) disables admin syncing via claim.
  ///
  /// The claim value may be a boolean, or a string / number
  /// interpreted as truthy (`"true"`, `"1"`, non-zero).
  #[serde(default)]
  pub admin_claim: String,
  /// Group whose members are granted admin status.
  /// When set, a user is treated as admin if this group is present
  /// in their `groups_claim`. Empty (default) disables this.
  ///
  /// Combined with `admin_claim` via OR: admin when either the
  /// claim is truthy or the user is a member of this group.
  /// Requires `groups_claim` to be configured.
  #[serde(default)]
  pub admin_group: String,
  /// Additional OAuth scopes to request beyond `openid`, `profile`
  /// and `email`. Some providers only include the groups claim when
  /// its scope (eg `groups`) is explicitly requested.
  #[serde(default)]
  pub additional_scopes: Vec<String>,
}

impl OidcConfig {
  pub fn enabled(&self) -> bool {
    self.enabled
      && !self.provider.is_empty()
      && !self.client_id.is_empty()
  }

  pub fn sanitize(&mut self) {
    self.client_id = empty_or_redacted(&self.client_id);
    self.client_secret = empty_or_redacted(&self.client_secret);
  }
}

/// Configuration for a named Oauth2 provider,
/// like Github or Google.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamedOauthConfig {
  /// Whether this login provider is enabled.
  #[serde(default)]
  pub enabled: bool,
  /// The Oauth client id.
  ///
  /// Alias: 'id'
  #[serde(default)]
  #[serde(alias = "id")]
  pub client_id: String,
  /// The Oauth client secret.
  ///
  /// Alias: 'secret'
  #[serde(default)]
  #[serde(alias = "secret")]
  pub client_secret: String,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_oidc_config_default_auto_redirect_false() {
    let config = OidcConfig::default();
    assert!(!config.auto_redirect);
  }

  #[test]
  fn test_oidc_config_serde_roundtrip_with_auto_redirect() {
    let config = OidcConfig {
      enabled: true,
      provider: "https://idp.example.com".into(),
      client_id: "test-id".into(),
      client_secret: "test-secret".into(),
      auto_redirect: true,
      ..Default::default()
    };
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: OidcConfig =
      serde_json::from_str(&json).unwrap();
    assert!(deserialized.auto_redirect);
    assert!(deserialized.enabled());
  }

  #[test]
  fn test_oidc_config_deserialize_without_auto_redirect() {
    // Backwards compatibility: old configs without auto_redirect
    let json = r#"{"enabled":true,"provider":"https://idp.example.com","client_id":"test-id","client_secret":"s","use_full_email":false,"additional_audiences":[]}"#;
    let config: OidcConfig = serde_json::from_str(json).unwrap();
    assert!(!config.auto_redirect);
  }

  #[test]
  fn test_oidc_config_claim_sync_defaults_disabled() {
    // Group / admin syncing is opt-in: defaults are empty.
    let config = OidcConfig::default();
    assert!(config.groups_claim.is_empty());
    assert!(config.admin_claim.is_empty());
    assert!(config.admin_group.is_empty());
    assert!(config.additional_scopes.is_empty());
  }

  #[test]
  fn test_oidc_config_deserialize_without_claim_sync_fields() {
    // Backwards compatibility: old configs without the new
    // group / admin claim fields still deserialize.
    let json = r#"{"enabled":true,"provider":"https://idp.example.com","client_id":"test-id","client_secret":"s","use_full_email":false,"additional_audiences":[],"auto_redirect":true}"#;
    let config: OidcConfig = serde_json::from_str(json).unwrap();
    assert!(config.groups_claim.is_empty());
    assert!(config.admin_claim.is_empty());
    assert!(config.admin_group.is_empty());
    assert!(config.additional_scopes.is_empty());
  }

  #[test]
  fn test_oidc_config_deserialize_with_claim_sync_fields() {
    let json = r#"{"enabled":true,"provider":"https://idp.example.com","client_id":"test-id","groups_claim":"groups","admin_claim":"komodo_admin","admin_group":"komodo-admins","additional_scopes":["groups"]}"#;
    let config: OidcConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.groups_claim, "groups");
    assert_eq!(config.admin_claim, "komodo_admin");
    assert_eq!(config.admin_group, "komodo-admins");
    assert_eq!(config.additional_scopes, vec!["groups".to_string()]);
  }
}

impl NamedOauthConfig {
  pub fn enabled(&self) -> bool {
    self.enabled && !self.client_id.is_empty()
  }

  pub fn sanitize(&mut self) {
    self.client_id = empty_or_redacted(&self.client_id);
    self.client_secret = empty_or_redacted(&self.client_secret);
  }
}
