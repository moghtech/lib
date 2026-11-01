use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use typeshare::typeshare;
use zeroize::Zeroize;

use crate::U64;

/// Replaces secrets in sanitized configs.
pub const REDACTED: &str = "##############";

pub fn empty_or_redacted(src: &str) -> String {
  if src.is_empty() {
    String::new()
  } else {
    String::from(REDACTED)
  }
}

/// The kind of an external login provider.
#[typeshare]
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Hash,
  Serialize,
  Deserialize,
  Display,
  EnumString,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum ExternalLoginKind {
  Oidc,
  Github,
  Google,
}

impl ExternalLoginKind {
  /// The reserved provider id for this kind: `oidc`, `github` or `google`.
  ///
  /// A provider using the reserved id of its kind keeps the
  /// original login / callback paths (eg. `/oidc/callback`),
  /// so redirect URIs already registered at the provider keep working.
  /// All other providers use `/external/{slug}/callback`,
  /// see [ExternalLoginProvider::slug].
  pub fn reserved_id(&self) -> &'static str {
    match self {
      ExternalLoginKind::Oidc => "oidc",
      ExternalLoginKind::Github => "github",
      ExternalLoginKind::Google => "google",
    }
  }
}

/// An external login provider users can use to log in.
/// Any number of these can be configured, either statically
/// by the app (file / env) or stored by the app and managed over the API.
#[typeshare]
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ExternalLoginProvider {
  /// The unique id of the provider, stored alongside the external
  /// user id on linked users. The login / callback urls name the
  /// provider by its [slug][ExternalLoginProvider::slug] instead,
  /// which is the id only for providers without a slug.
  ///
  /// External user ids are only unique per provider,
  /// so an id must never be reused for another provider.
  pub id: String,
  /// The display name, eg. shown on the login button.
  pub name: String,
  /// The part of the login / callback urls naming the provider
  /// (`/external/{slug}/callback`), see [ExternalLoginProvider::slug]:
  /// lowercase letters, digits and single hyphens, unique among all
  /// providers, defaulting to the name ([slugify]). Empty on providers
  /// stored before slugs existed, which keep their id in the urls.
  #[serde(default)]
  pub slug: String,
  /// Disable new user registration using this provider.
  #[serde(default)]
  pub registration_disabled: bool,
  /// Allow tokens issued by this provider to be
  /// exchanged for an app token (RFC 8693). Disabled by default.
  #[serde(default)]
  pub token_exchange: TokenExchangeConfig,
  /// The kind specific provider configuration.
  pub config: ExternalLoginProviderConfig,
}

/// Settings to exchange tokens issued by an [ExternalLoginProvider]
/// for an app token at the token endpoint (RFC 8693 Token Exchange).
///
/// Only signed ID tokens / JWTs are accepted, which excludes
/// Github. The user the token belongs to must already exist.
///
/// ⚠️ Whoever holds a valid token of a user can log in as that user
/// without any interaction, only enable this where it is needed.
#[typeshare]
#[derive(
  Debug, Clone, Default, PartialEq, Hash, Serialize, Deserialize,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TokenExchangeConfig {
  /// Whether tokens of this provider can be exchanged.
  #[serde(default)]
  pub enabled: bool,
  /// Audiences (`aud`) accepted on exchanged tokens in
  /// addition to the client id of the provider. These are the client
  /// ids of other apps (eg. a CLI) registered at the same provider.
  ///
  /// ⚠️ Tokens the provider issues to every app listed
  /// here can be used to log in to this app.
  ///
  /// Note. Users are found by the subject (`sub`) of the token. A
  /// provider using pairwise subject identifiers gives the same user
  /// a different subject per app, so their tokens won't match a user.
  #[serde(default)]
  pub audiences: Vec<String>,
  /// Only accept tokens issued (`iat`) at most this many seconds
  /// ago. `0` (default) accepts tokens until they expire.
  ///
  /// A captured token can be exchanged by anyone until then, and some
  /// providers issue tokens which are valid for hours. Clients are
  /// expected to exchange a token right after receiving it and keep
  /// the app token, so a few minutes is enough.
  #[serde(default)]
  pub max_token_age_secs: U64,
}

/// A token issuer trusted for workload identity: machines (CI jobs,
/// Kubernetes service accounts, ...) exchange the token their platform
/// issues them for an app token at the token endpoint (RFC 8693),
/// so they don't need a long lived api key.
///
/// Unlike an [ExternalLoginProvider] nobody logs in here.
/// The issuer only has to publish the keys it signs tokens with,
/// and [WorkloadRule]s decide which tokens are accepted.
#[typeshare]
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TrustedIssuer {
  /// The unique id of the issuer.
  pub id: String,
  /// The display name.
  pub name: String,
  /// Whether tokens of this issuer are accepted.
  #[serde(default)]
  pub enabled: bool,
  /// The issuer (`iss`) of the tokens, eg.
  /// `https://token.actions.githubusercontent.com`
  /// or the issuer url of a Kubernetes cluster.
  pub issuer: String,
  /// Where the keys to verify tokens come from.
  #[serde(default)]
  pub keys: TrustedIssuerKeys,
  /// The audiences (`aud`) accepted on tokens. At least one is required.
  ///
  /// ⚠️ Use an audience specific to this app, eg. its url, which the
  /// workload requests its token for. The default audience of a
  /// platform is shared with every other service trusting that
  /// platform, and any of them could replay the tokens they receive.
  #[serde(default)]
  pub audiences: Vec<String>,
  /// Only accept tokens issued (`iat`) at most this many seconds ago.
  /// `0` (default) accepts tokens until they expire.
  #[serde(default)]
  pub max_token_age_secs: U64,
  /// Which tokens of the issuer are accepted, and who they act as.
  /// The first enabled rule matching a token decides.
  #[serde(default)]
  pub rules: Vec<WorkloadRule>,
}

/// Where the keys to verify the tokens of a [TrustedIssuer] come from.
#[typeshare]
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "source", content = "params")]
pub enum TrustedIssuerKeys {
  /// OpenID discovery: `{issuer}/.well-known/openid-configuration`
  /// points to the key set (`jwks_uri`). Works for Github Actions,
  /// Gitlab, and clusters which expose their discovery publicly.
  Discovery {},
  /// Fetch the key set (JWKS) from this url.
  JwksUri(String),
  /// A fixed key set (JWKS json), for issuers the app server can't
  /// reach or which require authentication, like most Kubernetes
  /// clusters: `kubectl get --raw /openid/v1/jwks`.
  /// Has to be updated when the issuer rotates its keys.
  Static(String),
  /// The cluster which issues the tokens verifies them itself,
  /// through its TokenReview API. For Kubernetes clusters, instead
  /// of exporting their keys: no keys are stored, so key rotation
  /// needs no update, and a token bound to a deleted pod is
  /// refused at once.
  TokenReview(TokenReviewConfig),
}

impl Default for TrustedIssuerKeys {
  fn default() -> Self {
    TrustedIssuerKeys::Discovery {}
  }
}

impl TrustedIssuerKeys {
  /// The reviewer credential of a [TrustedIssuerKeys::TokenReview]
  /// source.
  pub fn review_token(&self) -> Option<&str> {
    match self {
      TrustedIssuerKeys::TokenReview(config) => {
        Some(&config.token)
      }
      _ => None,
    }
  }

  pub fn review_token_mut(&mut self) -> Option<&mut String> {
    match self {
      TrustedIssuerKeys::TokenReview(config) => {
        Some(&mut config.token)
      }
      _ => None,
    }
  }
}

impl TrustedIssuer {
  /// Redacts the reviewer credential of a
  /// [TrustedIssuerKeys::TokenReview] issuer, leaving everything
  /// else visible so the issuer can be shown in an edit form.
  pub fn redact_secrets(&mut self) {
    if let Some(token) = self.keys.review_token_mut() {
      let redacted = empty_or_redacted(token);
      token.zeroize();
      *token = redacted;
    }
  }
}

/// Verification of a [TrustedIssuer]'s tokens through the Kubernetes
/// TokenReview API of the cluster which issues them. The cluster is
/// asked whether each presented token is valid for the issuer's
/// audiences, with the signature, expiry and the token's binding to
/// its pod checked by the cluster itself.
#[typeshare]
#[derive(Clone, Default, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TokenReviewConfig {
  /// The url of the cluster's api server, eg. `https://10.0.0.1:6443`.
  /// Empty: the review goes through the app's own channel named by
  /// `device` instead.
  #[serde(default)]
  pub url: String,
  /// The PEM bundle the api server's certificate is verified
  /// against. Empty: the system roots.
  #[serde(default)]
  pub ca: String,
  /// The bearer credential of a reviewer service account bound to
  /// the `system:auth-delegator` cluster role. Required with `url`.
  /// Redacted on reads; an empty or redacted update keeps the
  /// stored one.
  #[serde(default)]
  pub token: String,
  /// Review through the app's own channel instead of `url`. For
  /// Cicada this names the device (periphery) running in the
  /// cluster, by id: its own service account reviews the tokens,
  /// so the server needs no reach to the cluster and stores no
  /// credential.
  #[serde(default)]
  pub device: String,
}

/// The reviewer credential is redacted.
impl std::fmt::Debug for TokenReviewConfig {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("TokenReviewConfig")
      .field("url", &self.url)
      .field("ca", &self.ca)
      .field("token", &empty_or_redacted(&self.token))
      .field("device", &self.device)
      .finish()
  }
}

/// Wipes the reviewer credential from memory.
impl Zeroize for TokenReviewConfig {
  fn zeroize(&mut self) {
    self.token.zeroize();
  }
}

/// Accepts the tokens of a [TrustedIssuer] which match all of
/// `claims`, and defines the user those workloads act as.
///
/// Each rule has its own user, created on first use by
/// `AuthImpl::get_or_create_workload_user`, with `groups` and
/// `admin` applied on every exchange and whenever the issuer is
/// saved (`AuthImpl::sync_workload_users`). Disabling the rule or
/// its issuer disables the user, which refuses the app tokens it
/// was already issued; enabling it again brings the same user back.
/// Narrowing `claims` only affects new exchanges.
#[typeshare]
#[derive(
  Debug, Clone, Default, PartialEq, Hash, Serialize, Deserialize,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct WorkloadRule {
  /// The unique id of the rule, which identifies its user.
  /// Generated by the server for rules managed over the API.
  ///
  /// ⚠️ Rules of static issuers must be given one (`a-z A-Z 0-9 - _`),
  /// unique within the issuer. Rules sharing an id would share a user,
  /// so tokens matching such a rule are refused.
  #[serde(default)]
  pub id: String,
  /// The display name, used to name the user.
  pub name: String,
  #[serde(default)]
  pub enabled: bool,
  /// The conditions a token has to meet. All of them have to
  /// match, and at least one is required.
  ///
  /// ⚠️ Prefer claims which can't be changed or reused over names, eg.
  /// Github's `repository_id` / `repository_owner_id` over `repository`,
  /// and keep wildcards narrow: `repo:my-org/*` trusts every
  /// repository of the org, including ones created later.
  #[serde(default)]
  pub claims: Vec<WorkloadClaim>,
  /// The app groups of the user, which the app gives meaning to.
  #[serde(default)]
  pub groups: Vec<String>,
  /// Whether the user is an admin.
  #[serde(default)]
  pub admin: bool,
  /// How long the issued app token is valid for, in seconds.
  /// `0` (default) and anything longer use the app default.
  /// Workloads should get short lived tokens, eg. `900`.
  #[serde(default)]
  pub token_ttl_secs: U64,
}

/// A condition on a claim of a workload token.
#[typeshare]
#[derive(
  Debug, Clone, Default, PartialEq, Hash, Serialize, Deserialize,
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct WorkloadClaim {
  /// The name of the claim, eg. `sub` or `repository_id`.
  /// Nested claims are reached with a dotted path,
  /// eg. `kubernetes.io.namespace`.
  pub claim: String,
  /// The value the claim must have. `*` matches any run of
  /// characters, eg. `refs/heads/release/*`. If the claim
  /// is a list, one of its values has to match.
  pub pattern: String,
}

impl ExternalLoginProvider {
  pub fn kind(&self) -> ExternalLoginKind {
    self.config.kind()
  }

  pub fn enabled(&self) -> bool {
    self.config.enabled()
  }

  /// The slug the provider's urls use: `slug`, or for a provider
  /// without one (stored before slugs existed, or a static provider
  /// which never needs one) its id.
  pub fn slug(&self) -> &str {
    if self.slug.is_empty() {
      &self.id
    } else {
      &self.slug
    }
  }

  /// Whether the provider is addressed by the reserved id of its
  /// kind (no slug of its own), see [ExternalLoginKind::reserved_id].
  pub fn uses_reserved_id(&self) -> bool {
    self.slug.is_empty() && self.id == self.kind().reserved_id()
  }

  /// The path the provider redirects users back to after login,
  /// relative to the auth api path.
  pub fn callback_path(&self) -> String {
    if self.uses_reserved_id() {
      format!("/{}/callback", self.slug())
    } else {
      format!("/external/{}/callback", self.slug())
    }
  }
}

/// The longest slug accepted.
pub const MAX_SLUG_LENGTH: usize = 64;

/// The slug a name makes: lowercased, every run of other characters
/// a single hyphen, no hyphens at the ends, at most [MAX_SLUG_LENGTH]
/// characters. Empty if the name has no letters or digits.
pub fn slugify(name: &str) -> String {
  let mut slug = String::new();
  for c in name.chars().flat_map(|c| c.to_lowercase()) {
    if c.is_ascii_alphanumeric() {
      slug.push(c);
    } else if !slug.is_empty() && !slug.ends_with('-') {
      slug.push('-');
    }
  }
  slug.truncate(MAX_SLUG_LENGTH);
  slug.trim_end_matches('-').to_string()
}

/// Checks a slug given explicitly: what [slugify] produces, ie.
/// lowercase ascii letters and digits separated by single hyphens.
pub fn validate_slug(slug: &str) -> Result<(), String> {
  if slug.is_empty() {
    return Err(String::from("Slug cannot be empty"));
  }
  if slug.len() > MAX_SLUG_LENGTH {
    return Err(format!(
      "Slug cannot be longer than {MAX_SLUG_LENGTH} characters"
    ));
  }
  if slug != slugify(slug) {
    return Err(String::from(
      "Slug can only contain lowercase letters, digits and single hyphens between them",
    ));
  }
  Ok(())
}

/// The kind specific configuration of an [ExternalLoginProvider].
#[typeshare]
#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "kind", content = "params")]
pub enum ExternalLoginProviderConfig {
  Oidc(OidcConfig),
  Github(NamedOauthConfig),
  Google(NamedOauthConfig),
}

impl ExternalLoginProviderConfig {
  pub fn kind(&self) -> ExternalLoginKind {
    match self {
      ExternalLoginProviderConfig::Oidc(_) => ExternalLoginKind::Oidc,
      ExternalLoginProviderConfig::Github(_) => {
        ExternalLoginKind::Github
      }
      ExternalLoginProviderConfig::Google(_) => {
        ExternalLoginKind::Google
      }
    }
  }

  pub fn enabled(&self) -> bool {
    match self {
      ExternalLoginProviderConfig::Oidc(config) => config.enabled(),
      ExternalLoginProviderConfig::Github(config)
      | ExternalLoginProviderConfig::Google(config) => {
        config.enabled()
      }
    }
  }

  pub fn client_secret(&self) -> &str {
    match self {
      ExternalLoginProviderConfig::Oidc(config) => {
        &config.client_secret
      }
      ExternalLoginProviderConfig::Github(config)
      | ExternalLoginProviderConfig::Google(config) => {
        &config.client_secret
      }
    }
  }

  pub fn client_secret_mut(&mut self) -> &mut String {
    match self {
      ExternalLoginProviderConfig::Oidc(config) => {
        &mut config.client_secret
      }
      ExternalLoginProviderConfig::Github(config)
      | ExternalLoginProviderConfig::Google(config) => {
        &mut config.client_secret
      }
    }
  }

  /// Redacts only the client secret, leaving the client id
  /// visible so the config can be shown in an edit form.
  pub fn redact_secret(&mut self) {
    let secret = self.client_secret_mut();
    let redacted = empty_or_redacted(secret);
    secret.zeroize();
    *secret = redacted;
  }
}

/// Wipes the client secret from memory.
impl Zeroize for ExternalLoginProviderConfig {
  fn zeroize(&mut self) {
    self.client_secret_mut().zeroize();
  }
}

/// Configuration for OIDC provider
#[typeshare]
#[derive(Clone, Default, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
  /// Additional scopes to request from the provider,
  /// on top of `openid`, `profile` and `email`.
  ///
  /// The `groups` scope is requested automatically when the
  /// `groups` claim is used and the provider advertises the scope
  /// (`scopes_supported`). Other scopes needed for the groups
  /// claim, eg. `roles`, must be added here.
  #[serde(default)]
  pub additional_scopes: Vec<String>,
  /// The claim containing the groups the user belongs to, eg. `groups`.
  /// Nested claims can be reached with a dotted path,
  /// eg. `realm_access.roles`.
  ///
  /// Group extraction is disabled if this is empty (default),
  /// unless `allowed_groups` or `admin_groups` are set,
  /// in which case it falls back to `groups`.
  #[serde(default)]
  pub groups_claim: String,
  /// Only allow OIDC login, signup and account linking for
  /// users in at least one of these groups, or in `admin_groups`.
  /// Empty allows all users (default).
  ///
  /// If the provider does not send any group information
  /// for the user, they are rejected.
  #[serde(default)]
  pub allowed_groups: Vec<String>,
  /// Users in at least one of these groups are
  /// reported to the app as admins on OIDC login / signup.
  /// This can be used to onboard new admins through the provider.
  #[serde(default)]
  pub admin_groups: Vec<String>,
}

impl OidcConfig {
  pub fn enabled(&self) -> bool {
    self.enabled
      && !self.provider.is_empty()
      && !self.client_id.is_empty()
  }

  /// The claim to extract user groups from,
  /// or None if group extraction is disabled.
  pub fn groups_claim(&self) -> Option<&str> {
    if !self.groups_claim.is_empty() {
      Some(&self.groups_claim)
    } else if !self.allowed_groups.is_empty()
      || !self.admin_groups.is_empty()
    {
      Some("groups")
    } else {
      None
    }
  }

  pub fn sanitize(&mut self) {
    self.client_id = empty_or_redacted(&self.client_id);
    self.client_secret = empty_or_redacted(&self.client_secret);
  }
}

/// The client secret is redacted.
impl std::fmt::Debug for OidcConfig {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("OidcConfig")
      .field("enabled", &self.enabled)
      .field("provider", &self.provider)
      .field("redirect_host", &self.redirect_host)
      .field("client_id", &self.client_id)
      .field("client_secret", &empty_or_redacted(&self.client_secret))
      .field("use_full_email", &self.use_full_email)
      .field("additional_audiences", &self.additional_audiences)
      .field("auto_redirect", &self.auto_redirect)
      .field("additional_scopes", &self.additional_scopes)
      .field("groups_claim", &self.groups_claim)
      .field("allowed_groups", &self.allowed_groups)
      .field("admin_groups", &self.admin_groups)
      .finish()
  }
}

/// Configuration for a named Oauth2 provider,
/// like Github or Google.
#[typeshare]
#[derive(Clone, Default, PartialEq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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

impl NamedOauthConfig {
  pub fn enabled(&self) -> bool {
    self.enabled && !self.client_id.is_empty()
  }

  pub fn sanitize(&mut self) {
    self.client_id = empty_or_redacted(&self.client_id);
    self.client_secret = empty_or_redacted(&self.client_secret);
  }
}

/// The client secret is redacted.
impl std::fmt::Debug for NamedOauthConfig {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("NamedOauthConfig")
      .field("enabled", &self.enabled)
      .field("client_id", &self.client_id)
      .field("client_secret", &empty_or_redacted(&self.client_secret))
      .finish()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn github_provider(id: &str) -> ExternalLoginProvider {
    ExternalLoginProvider {
      id: id.to_string(),
      name: "Github".to_string(),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Github(NamedOauthConfig {
        enabled: true,
        client_id: "client-id".into(),
        client_secret: "super-secret".into(),
      }),
    }
  }

  #[test]
  fn test_debug_redacts_client_secret() {
    let provider = github_provider("github");
    let debug = format!("{provider:?}");
    assert!(debug.contains("client-id"));
    assert!(!debug.contains("super-secret"));
    let oidc = OidcConfig {
      client_secret: "super-secret".into(),
      ..Default::default()
    };
    assert!(!format!("{oidc:?}").contains("super-secret"));
  }

  #[test]
  fn test_slug_falls_back_to_the_id() {
    let mut provider = github_provider("a1B2");
    assert_eq!(provider.slug(), "a1B2");
    assert_eq!(provider.callback_path(), "/external/a1B2/callback");
    provider.slug = "company-github".into();
    assert_eq!(provider.slug(), "company-github");
    assert_eq!(
      provider.callback_path(),
      "/external/company-github/callback"
    );
    // The reserved paths go with the id, never with a slug
    provider.slug = "github".into();
    assert_eq!(provider.callback_path(), "/external/github/callback");
    let mut provider = github_provider("github");
    assert!(provider.uses_reserved_id());
    assert_eq!(provider.callback_path(), "/github/callback");
    provider.slug = "gh".into();
    assert!(!provider.uses_reserved_id());
    assert_eq!(provider.callback_path(), "/external/gh/callback");
  }

  #[test]
  fn test_slugify_and_validate_slug() {
    assert_eq!(slugify("Company SSO"), "company-sso");
    assert_eq!(slugify("  Okta -- Prod!! "), "okta-prod");
    assert_eq!(slugify("Ünïcode Name"), "n-code-name");
    assert_eq!(slugify("🚀"), "");
    assert_eq!(slugify(&"a".repeat(100)).len(), MAX_SLUG_LENGTH);
    assert_eq!(
      slugify(&format!("{}-b", "a".repeat(63))),
      "a".repeat(63)
    );
    for slug in ["okta", "company-sso", "a1", "x"] {
      assert!(validate_slug(slug).is_ok(), "{slug}");
    }
    for slug in [
      "",
      "Okta",
      "company sso",
      "-okta",
      "okta-",
      "a--b",
      "a_b",
      "ä",
      &"a".repeat(65),
    ] {
      assert!(validate_slug(slug).is_err(), "{slug}");
    }
  }

  #[test]
  fn test_callback_path_reserved_id_keeps_original_path() {
    assert_eq!(
      github_provider("github").callback_path(),
      "/github/callback"
    );
    // Reserved id of another kind is not special
    assert_eq!(
      github_provider("oidc").callback_path(),
      "/external/oidc/callback"
    );
    assert_eq!(
      github_provider("a1B2").callback_path(),
      "/external/a1B2/callback"
    );
  }

  #[test]
  fn test_redact_secret_keeps_client_id() {
    let mut provider = github_provider("github");
    provider.config.redact_secret();
    assert_eq!(provider.config.client_secret(), REDACTED);
    let ExternalLoginProviderConfig::Github(config) =
      &provider.config
    else {
      unreachable!()
    };
    assert_eq!(config.client_id, "client-id");
  }

  #[test]
  fn test_provider_config_wire_format() {
    let provider = github_provider("github");
    let value = serde_json::to_value(&provider).unwrap();
    assert_eq!(value["config"]["kind"], "Github");
    assert_eq!(value["config"]["params"]["client_id"], "client-id");
    let roundtrip: ExternalLoginProvider =
      serde_json::from_value(value).unwrap();
    assert_eq!(roundtrip, provider);
  }

  #[test]
  fn test_trusted_issuer_defaults_and_wire_format() {
    let issuer: TrustedIssuer =
      serde_json::from_value(serde_json::json!({
        "id": "github",
        "name": "Github Actions",
        "issuer": "https://token.actions.githubusercontent.com",
        "rules": [{ "name": "Deploy" }],
      }))
      .unwrap();
    // Nothing is accepted unless explicitly enabled
    assert!(!issuer.enabled);
    assert!(!issuer.rules[0].enabled);
    assert!(!issuer.rules[0].admin);
    assert!(issuer.audiences.is_empty());
    assert_eq!(issuer.keys, TrustedIssuerKeys::Discovery {});

    let keys = TrustedIssuerKeys::JwksUri(
      "https://example.com/jwks".to_string(),
    );
    assert_eq!(
      serde_json::to_value(&keys).unwrap(),
      serde_json::json!({
        "source": "JwksUri",
        "params": "https://example.com/jwks",
      })
    );
    assert_eq!(
      serde_json::to_value(TrustedIssuerKeys::Discovery {}).unwrap(),
      serde_json::json!({ "source": "Discovery", "params": {} })
    );
  }

  #[test]
  fn test_slug_empty_by_default() {
    // Providers stored before slugs existed keep their id in the urls
    let provider: ExternalLoginProvider =
      serde_json::from_value(serde_json::json!({
        "id": "a1B2",
        "name": "Github",
        "config": { "kind": "Github", "params": {} },
      }))
      .unwrap();
    assert!(provider.slug.is_empty());
    assert_eq!(provider.slug(), "a1B2");
  }

  #[test]
  fn test_token_exchange_disabled_by_default() {
    // Providers stored before token exchange existed
    let provider: ExternalLoginProvider =
      serde_json::from_value(serde_json::json!({
        "id": "github",
        "name": "Github",
        "config": { "kind": "Github", "params": {} },
      }))
      .unwrap();
    assert!(!provider.token_exchange.enabled);
    assert!(provider.token_exchange.audiences.is_empty());
    assert_eq!(provider.token_exchange.max_token_age_secs, 0);
  }

  #[test]
  fn test_empty_or_redacted() {
    assert_eq!(empty_or_redacted(""), "");
    let redacted = empty_or_redacted("super-secret");
    assert!(!redacted.is_empty());
    assert!(!redacted.contains("super-secret"));
  }

  #[test]
  fn test_oidc_config_defaults_from_empty_json() {
    let config: OidcConfig = serde_json::from_str("{}").unwrap();
    assert!(!config.enabled);
    assert!(config.provider.is_empty());
    assert!(config.redirect_host.is_empty());
    assert!(config.client_id.is_empty());
    assert!(config.client_secret.is_empty());
    assert!(!config.use_full_email);
    assert!(config.additional_audiences.is_empty());
    assert!(!config.auto_redirect);
    assert!(!config.enabled());
  }

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
  fn test_oidc_config_groups_disabled_by_default() {
    // Backwards compatibility: old configs without any group options
    let config: OidcConfig = serde_json::from_str("{}").unwrap();
    assert!(config.additional_scopes.is_empty());
    assert!(config.groups_claim.is_empty());
    assert!(config.allowed_groups.is_empty());
    assert!(config.admin_groups.is_empty());
    assert_eq!(config.groups_claim(), None);
  }

  #[test]
  fn test_oidc_config_groups_claim_explicit() {
    let config = OidcConfig {
      groups_claim: "realm_access.roles".into(),
      allowed_groups: vec!["users".into()],
      ..Default::default()
    };
    assert_eq!(config.groups_claim(), Some("realm_access.roles"));
  }

  #[test]
  fn test_oidc_config_groups_claim_falls_back_when_groups_used() {
    let config = OidcConfig {
      allowed_groups: vec!["users".into()],
      ..Default::default()
    };
    assert_eq!(config.groups_claim(), Some("groups"));
    let config = OidcConfig {
      admin_groups: vec!["admins".into()],
      ..Default::default()
    };
    assert_eq!(config.groups_claim(), Some("groups"));
  }

  #[test]
  fn test_oidc_config_id_and_secret_aliases() {
    let json = r#"{"enabled":true,"provider":"https://idp.example.com","id":"aliased-id","secret":"aliased-secret"}"#;
    let config: OidcConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.client_id, "aliased-id");
    assert_eq!(config.client_secret, "aliased-secret");
  }

  #[test]
  fn test_oidc_config_enabled_requires_provider_and_client_id() {
    let mut config = OidcConfig {
      enabled: true,
      provider: "https://idp.example.com".into(),
      client_id: "id".into(),
      ..Default::default()
    };
    assert!(config.enabled());
    config.provider = String::new();
    assert!(!config.enabled());
    config.provider = "https://idp.example.com".into();
    config.client_id = String::new();
    assert!(!config.enabled());
    config.client_id = "id".into();
    config.enabled = false;
    assert!(!config.enabled());
  }

  #[test]
  fn test_oidc_config_sanitize_redacts_credentials() {
    let mut config = OidcConfig {
      client_id: "id".into(),
      client_secret: "secret".into(),
      ..Default::default()
    };
    config.sanitize();
    assert!(!config.client_id.contains("id"));
    assert!(!config.client_secret.contains("secret"));
    // Empty fields stay empty after sanitize.
    let mut config = OidcConfig::default();
    config.sanitize();
    assert!(config.client_id.is_empty());
    assert!(config.client_secret.is_empty());
  }

  #[test]
  fn test_named_oauth_config_defaults_and_aliases() {
    let config: NamedOauthConfig =
      serde_json::from_str("{}").unwrap();
    assert!(!config.enabled);
    assert!(!config.enabled());
    let json =
      r#"{"enabled":true,"id":"gh-id","secret":"gh-secret"}"#;
    let config: NamedOauthConfig =
      serde_json::from_str(json).unwrap();
    assert_eq!(config.client_id, "gh-id");
    assert_eq!(config.client_secret, "gh-secret");
    assert!(config.enabled());
  }

  #[test]
  fn test_named_oauth_config_serde_field_names_stable() {
    let config = NamedOauthConfig {
      enabled: true,
      client_id: "id".into(),
      client_secret: "secret".into(),
    };
    let value = serde_json::to_value(&config).unwrap();
    assert_eq!(
      value,
      serde_json::json!({
        "enabled": true,
        "client_id": "id",
        "client_secret": "secret",
      })
    );
  }
}
