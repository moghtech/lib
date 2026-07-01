use std::{
  collections::HashMap,
  sync::{Arc, OnceLock},
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow};
use arc_swap::ArcSwapOption;
use mogh_auth_client::config::OidcConfig;
use openidconnect::{
  AccessTokenHash, AdditionalClaims, AuthorizationCode, Client,
  ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
  EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenFields,
  IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
  PkceCodeVerifier, RedirectUrl, Scope, StandardErrorResponse,
  StandardTokenResponse, TokenResponse as _,
  core::*,
  reqwest::{self, Url},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error};

pub use openidconnect::SubjectIdentifier;

/// Some OIDC providers use 'username' additional claim
/// rather than the standard 'preferred_username'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameAdditionalClaims {
  pub username: Option<String>,
  /// Additional non-standard claims (eg `groups`), captured for syncing.
  #[serde(flatten)]
  pub other: HashMap<String, serde_json::Value>,
}

impl AdditionalClaims for UsernameAdditionalClaims {}

/// Group names from a flattened claim, either an array of strings
/// or a single string.
fn extract_groups(
  claims: &UsernameAdditionalClaims,
  claim: &str,
) -> Vec<String> {
  match claims.other.get(claim) {
    Some(serde_json::Value::Array(arr)) => arr
      .iter()
      .filter_map(|v| v.as_str().map(ToString::to_string))
      .collect(),
    Some(serde_json::Value::String(s)) => vec![s.clone()],
    _ => Vec::new(),
  }
}

/// Admin signal from a flattened claim, or `None` if absent. Strings
/// (`"true"`, `"1"`) and non-zero numbers are treated as truthy.
fn extract_admin(
  claims: &UsernameAdditionalClaims,
  claim: &str,
) -> Option<bool> {
  match claims.other.get(claim)? {
    serde_json::Value::Bool(b) => Some(*b),
    serde_json::Value::String(s) => {
      Some(s.eq_ignore_ascii_case("true") || s == "1")
    }
    serde_json::Value::Number(n) => {
      Some(n.as_i64().map(|i| i != 0).unwrap_or(false))
    }
    _ => None,
  }
}

/// Admin when the claim is truthy or the user is in `admin_group`.
/// `None` when neither is configured, so admin is left untouched.
fn resolve_admin(
  admin_claim_signal: Option<bool>,
  groups: &[String],
  admin_claim: &str,
  admin_group: &str,
) -> Option<bool> {
  let want_claim = !admin_claim.is_empty();
  let want_group = !admin_group.is_empty();
  if !want_claim && !want_group {
    return None;
  }
  let from_claim = admin_claim_signal.unwrap_or(false);
  let from_group =
    want_group && groups.iter().any(|group| group == admin_group);
  Some(from_claim || from_group)
}

pub type TokenResponse = StandardTokenResponse<
  IdTokenFields<
    UsernameAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
  >,
  CoreTokenType,
>;

#[derive(Serialize, Deserialize)]
pub struct SessionOidcLogin {
  pub csrf_token: String,
  pub pkce_verifier: openidconnect::PkceCodeVerifier,
  pub nonce: openidconnect::Nonce,
  pub redirect: Option<String>,
}

//

#[derive(Serialize, Deserialize)]
pub struct SessionOidcLink {
  pub user_id: String,
  pub csrf_token: String,
  pub pkce_verifier: openidconnect::PkceCodeVerifier,
  pub nonce: openidconnect::Nonce,
}

fn reqwest(app_user_agent: &str) -> &'static reqwest::Client {
  static REQWEST: OnceLock<reqwest::Client> = OnceLock::new();
  REQWEST.get_or_init(|| {
    reqwest::Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .user_agent(app_user_agent)
      .build()
      .expect("Invalid OIDC reqwest client")
  })
}

pub type InnerOidcProvider = Client<
  UsernameAdditionalClaims,
  CoreAuthDisplay,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJsonWebKey,
  CoreAuthPrompt,
  StandardErrorResponse<CoreErrorResponseType>,
  TokenResponse,
  CoreTokenIntrospectionResponse,
  CoreRevocableToken,
  CoreRevocationErrorResponse,
  EndpointSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointMaybeSet,
  EndpointMaybeSet,
>;

/// Cache discovery data for 1min
const PROVIDER_VALID_FOR_MS: u128 = 60_000;

fn oidc_provider() -> &'static ArcSwapOption<OidcProvider> {
  static OIDC_CLIENT: OnceLock<ArcSwapOption<OidcProvider>> =
    OnceLock::new();
  OIDC_CLIENT.get_or_init(Default::default)
}

pub async fn load_oidc_provider(
  app_user_agent: &'static str,
  host: &str,
  path: &str,
  config: &OidcConfig,
) -> Option<Arc<OidcProvider>> {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .ok()?
    .as_millis();

  if let Some(curr) = oidc_provider().load().as_ref()
    && curr.valid_until > now
  {
    return Some(curr.clone());
  }

  let client = match OidcProvider::new(
    app_user_agent,
    host,
    path,
    config,
    now + PROVIDER_VALID_FOR_MS,
  )
  .await
  {
    Ok(client) => Arc::new(client),
    Err(e) => {
      error!("Failed to initialize OIDC client | {e:#}");
      return None;
    }
  };

  oidc_provider().store(Some(client.clone()));

  Some(client)
}

pub struct OidcProvider {
  app_user_agent: &'static str,
  client: InnerOidcProvider,
  valid_until: u128,
  use_full_email: bool,
  additional_scopes: Vec<String>,
}

impl OidcProvider {
  /// Initialize a new OIDC provider using the configured provider's
  /// discovery endpoint.
  pub async fn new(
    app_user_agent: &'static str,
    host: &str,
    path: &str,
    config: &OidcConfig,
    valid_until: u128,
  ) -> anyhow::Result<OidcProvider> {
    if !config.enabled() {
      return Err(anyhow!(
        "OIDC provider is disabled or not configured."
      ));
    }

    // Use OpenID Connect Discovery to fetch the provider metadata.
    let provider_metadata = CoreProviderMetadata::discover_async(
      IssuerUrl::new(config.provider.clone())?,
      reqwest(app_user_agent),
    )
    .await
    .context(
      "Failed to get OIDC /.well-known/openid-configuration",
    )?;

    let client = InnerOidcProvider::from_provider_metadata(
      provider_metadata,
      ClientId::new(config.client_id.to_string()),
      // The secret may be empty / ommitted if auth provider supports PKCE
      if config.client_secret.is_empty() {
        None
      } else {
        Some(ClientSecret::new(config.client_secret.to_string()))
      },
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new(format!(
      "{host}{path}/oidc/callback",
    ))?);

    Ok(OidcProvider {
      client,
      valid_until,
      app_user_agent,
      use_full_email: config.use_full_email,
      additional_scopes: config.additional_scopes.clone(),
    })
  }

  pub fn authorize_url(
    &self,
    pkce_challenge: PkceCodeChallenge,
  ) -> (Url, CsrfToken, Nonce) {
    let mut request = self
      .client
      .authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
      )
      .set_pkce_challenge(pkce_challenge)
      .add_scope(Scope::new("openid".to_string()))
      .add_scope(Scope::new("profile".to_string()))
      .add_scope(Scope::new("email".to_string()));
    // eg `groups`, if the provider requires it for that claim.
    for scope in &self.additional_scopes {
      request = request.add_scope(Scope::new(scope.clone()));
    }
    request.url()
  }

  /// Applied security validations and extracts the
  /// oidc user id.
  pub async fn validate_extract_subject_and_token(
    &self,
    config: &OidcConfig,
    (client, server): (CsrfToken, String),
    code: String,
    pkce_verifier: PkceCodeVerifier,
    nonce: &Nonce,
  ) -> anyhow::Result<(SubjectIdentifier, TokenResponse)> {
    // Validate CSRF tokens match
    if client.secret() != &server {
      return Err(anyhow!("CSRF token invalid"));
    }

    let reqwest_client = reqwest(self.app_user_agent);
    let token_response = self
      .client
      .exchange_code(AuthorizationCode::new(code))
      .context("Failed to get Oauth token at exchange code")?
      .set_pkce_verifier(pkce_verifier)
      .request_async(reqwest_client)
      .await
      .context("Failed to get Oauth token")?;

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response
      .id_token()
      .context("OIDC Server did not return an ID token")?;

    // Some providers attach additional audiences, they must be added here
    // so token verification succeeds.
    let verifier = self.client.id_token_verifier();
    let additional_audiences = &config.additional_audiences;
    let verifier = if additional_audiences.is_empty() {
      verifier
    } else {
      verifier.set_other_audience_verifier_fn(|aud| {
        additional_audiences.contains(aud)
      })
    };

    let claims = id_token
      .claims(&verifier, nonce)
      .context("Failed to verify token claims. This issue may be temporary (60 seconds max).")?;

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) =
      claims.access_token_hash()
    {
      let actual_access_token_hash = AccessTokenHash::from_token(
        &token_response.access_token().clone(),
        id_token.signing_alg()?,
        id_token.signing_key(&verifier)?,
      )?;
      if actual_access_token_hash != *expected_access_token_hash {
        return Err(anyhow!("Invalid access token"));
      }
    }

    Ok((claims.subject().clone(), token_response))
  }

  pub async fn get_username(
    &self,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
    nonce: &Nonce,
  ) -> String {
    if self.use_full_email {
      return self
        .get_username_prioritize_email(subject, token, nonce)
        .await;
    }

    let id_claims = token.id_token().and_then(|token| {
      token
        .claims(&self.client.id_token_verifier(), nonce)
        .inspect(|claims| debug!("OIDC ID TOKEN CLAIMS: {claims:?}"))
        .ok()
    });

    // Priority 1: preferred_username from id_token.
    if let Some(username) = id_claims.as_ref().and_then(|claims| {
      claims.preferred_username()?.to_string().into()
    }) {
      return username;
    }

    // Get networked user info
    let user_info = async {
      self
        .client
        .user_info(
          token.access_token().clone(),
          Some(subject.clone()),
        )
        .ok()?
        .request_async::<UsernameAdditionalClaims, _, CoreGenderClaim>(
          reqwest(self.app_user_agent),
        )
        .await
        .inspect(|user_info| debug!("OIDC USER INFO: {user_info:?}"))
        .ok()
    }
    .await;

    // Priority 2: preferred_username from user_info
    if let Some(username) = user_info.as_ref().and_then(|user_info| {
      user_info.preferred_username()?.to_string().into()
    }) {
      return username;
    }

    // Priority 3: username additional claim from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.additional_claims().username.clone()
      })
      .or_else(|| {
        user_info.as_ref()?.additional_claims().username.clone()
      })
    {
      return username;
    }

    // Priority 4: name from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.name()?.get(None)?.to_string().into()
      })
      .or_else(|| {
        user_info.as_ref()?.name()?.get(None)?.to_string().into()
      })
    {
      return username;
    }

    // Priority 5: username part of email from id claims, then user info
    if let Some(email) = id_claims
      .as_ref()
      .and_then(|id_claims| id_claims.email()?.to_string().into())
      .or_else(|| user_info.as_ref()?.email()?.to_string().into())
    {
      let username = email
        .split_once('@')
        .map(|(username, _)| username)
        .unwrap_or(email.as_str())
        .to_string();
      return username;
    }

    // Priority 6 (fallback): use the subject if no others available
    subject.to_string()
  }

  /// Used with 'use_full_email' option
  pub async fn get_username_prioritize_email(
    &self,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
    nonce: &Nonce,
  ) -> String {
    let id_claims = token.id_token().and_then(|token| {
      token
        .claims(&self.client.id_token_verifier(), nonce)
        .inspect(|claims| debug!("OIDC ID TOKEN CLAIMS: {claims:?}"))
        .ok()
    });

    // Priority 1: email from id_token.
    if let Some(email) = id_claims
      .as_ref()
      .and_then(|claims| claims.email()?.to_string().into())
    {
      return email;
    }

    // Get networked user info
    let user_info = async {
      self
        .client
        .user_info(
          token.access_token().clone(),
          Some(subject.clone()),
        )
        .ok()?
        .request_async::<UsernameAdditionalClaims, _, CoreGenderClaim>(
          reqwest(self.app_user_agent),
        )
        .await
        .inspect(|user_info| debug!("OIDC USER INFO: {user_info:?}"))
        .ok()
    }
    .await;

    // Priority 2: email from user_info
    if let Some(username) = user_info
      .as_ref()
      .and_then(|user_info| user_info.email()?.to_string().into())
    {
      return username;
    }

    // Priority 3: preferred_username from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.preferred_username()?.to_string().into()
      })
      .or_else(|| {
        user_info.as_ref()?.preferred_username()?.to_string().into()
      })
    {
      return username;
    }

    // Priority 4: username additional claim from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.additional_claims().username.clone()
      })
      .or_else(|| {
        user_info.as_ref()?.additional_claims().username.clone()
      })
    {
      return username;
    }

    // Priority 5: name from id claims, then user info
    if let Some(username) = id_claims
      .as_ref()
      .and_then(|id_claims| {
        id_claims.name()?.get(None)?.to_string().into()
      })
      .or_else(|| {
        user_info.as_ref()?.name()?.get(None)?.to_string().into()
      })
    {
      return username;
    }

    // Priority 6 (fallback): use the subject if no others available
    subject.to_string()
  }

  /// Reads the configured group memberships and admin signal from the
  /// claims, preferring the id token and falling back to userinfo only
  /// for what is missing. `is_admin` is `None` when neither
  /// `admin_claim` nor `admin_group` is configured.
  pub async fn get_groups_and_admin(
    &self,
    config: &OidcConfig,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
    nonce: &Nonce,
  ) -> (Vec<String>, Option<bool>) {
    let want_groups = !config.groups_claim.is_empty();
    let want_admin_claim = !config.admin_claim.is_empty();
    let want_admin =
      want_admin_claim || !config.admin_group.is_empty();
    if !want_groups && !want_admin {
      return (Vec::new(), None);
    }

    let id_claims = token.id_token().and_then(|token| {
      token.claims(&self.client.id_token_verifier(), nonce).ok()
    });
    let id_extra =
      id_claims.as_ref().map(|claims| claims.additional_claims());

    let mut groups = if want_groups {
      id_extra
        .map(|extra| extract_groups(extra, &config.groups_claim))
        .unwrap_or_default()
    } else {
      Vec::new()
    };
    let mut admin_claim_signal = id_extra
      .and_then(|extra| extract_admin(extra, &config.admin_claim));

    // Some providers omit these from the id token.
    let need_userinfo = (want_groups && groups.is_empty())
      || (want_admin_claim && admin_claim_signal.is_none());
    if need_userinfo {
      let user_info = async {
        self
          .client
          .user_info(token.access_token().clone(), Some(subject.clone()))
          .ok()?
          .request_async::<UsernameAdditionalClaims, _, CoreGenderClaim>(
            reqwest(self.app_user_agent),
          )
          .await
          .inspect(|user_info| debug!("OIDC USER INFO: {user_info:?}"))
          .ok()
      }
      .await;

      if let Some(info) = user_info.as_ref() {
        let extra = info.additional_claims();
        if want_groups && groups.is_empty() {
          groups = extract_groups(extra, &config.groups_claim);
        }
        if want_admin_claim && admin_claim_signal.is_none() {
          admin_claim_signal =
            extract_admin(extra, &config.admin_claim);
        }
      }
    }

    let admin = resolve_admin(
      admin_claim_signal,
      &groups,
      &config.admin_claim,
      &config.admin_group,
    );

    (groups, admin)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  fn claims(value: serde_json::Value) -> UsernameAdditionalClaims {
    let other = match value {
      serde_json::Value::Object(map) => map.into_iter().collect(),
      _ => HashMap::new(),
    };
    UsernameAdditionalClaims {
      username: None,
      other,
    }
  }

  #[test]
  fn extract_groups_from_array() {
    let c = claims(json!({ "groups": ["admins", "devs"] }));
    assert_eq!(
      extract_groups(&c, "groups"),
      vec!["admins".to_string(), "devs".to_string()]
    );
  }

  #[test]
  fn extract_groups_from_single_string() {
    let c = claims(json!({ "groups": "admins" }));
    assert_eq!(
      extract_groups(&c, "groups"),
      vec!["admins".to_string()]
    );
  }

  #[test]
  fn extract_groups_missing_claim_is_empty() {
    let c = claims(json!({ "roles": ["admins"] }));
    assert!(extract_groups(&c, "groups").is_empty());
  }

  #[test]
  fn extract_groups_ignores_non_string_entries() {
    let c = claims(json!({ "groups": ["admins", 1, true] }));
    assert_eq!(
      extract_groups(&c, "groups"),
      vec!["admins".to_string()]
    );
  }

  #[test]
  fn extract_admin_bool() {
    assert_eq!(
      extract_admin(&claims(json!({ "admin": true })), "admin"),
      Some(true)
    );
    assert_eq!(
      extract_admin(&claims(json!({ "admin": false })), "admin"),
      Some(false)
    );
  }

  #[test]
  fn extract_admin_string_and_number() {
    assert_eq!(
      extract_admin(&claims(json!({ "admin": "true" })), "admin"),
      Some(true)
    );
    assert_eq!(
      extract_admin(&claims(json!({ "admin": "TRUE" })), "admin"),
      Some(true)
    );
    assert_eq!(
      extract_admin(&claims(json!({ "admin": "false" })), "admin"),
      Some(false)
    );
    assert_eq!(
      extract_admin(&claims(json!({ "admin": 1 })), "admin"),
      Some(true)
    );
    assert_eq!(
      extract_admin(&claims(json!({ "admin": 0 })), "admin"),
      Some(false)
    );
  }

  #[test]
  fn extract_admin_missing_claim_is_none() {
    assert_eq!(
      extract_admin(&claims(json!({ "other": true })), "admin"),
      None
    );
  }

  #[test]
  fn resolve_admin_none_when_nothing_configured() {
    assert_eq!(resolve_admin(None, &["a".to_string()], "", ""), None);
  }

  #[test]
  fn resolve_admin_by_claim_only() {
    assert_eq!(
      resolve_admin(Some(true), &[], "admin", ""),
      Some(true)
    );
    assert_eq!(
      resolve_admin(Some(false), &[], "admin", ""),
      Some(false)
    );
    // Configured but claim absent everywhere -> Some(false).
    assert_eq!(resolve_admin(None, &[], "admin", ""), Some(false));
  }

  #[test]
  fn resolve_admin_by_group_only() {
    let groups =
      vec!["devs".to_string(), "komodo-admins".to_string()];
    assert_eq!(
      resolve_admin(None, &groups, "", "komodo-admins"),
      Some(true)
    );
    assert_eq!(
      resolve_admin(None, &groups, "", "other-group"),
      Some(false)
    );
  }

  #[test]
  fn resolve_admin_claim_or_group() {
    let groups = vec!["komodo-admins".to_string()];
    // Group matches even when claim is false.
    assert_eq!(
      resolve_admin(Some(false), &groups, "admin", "komodo-admins"),
      Some(true)
    );
    // Claim true even when group does not match.
    assert_eq!(
      resolve_admin(Some(true), &[], "admin", "komodo-admins"),
      Some(true)
    );
    // Neither matches.
    assert_eq!(
      resolve_admin(Some(false), &[], "admin", "komodo-admins"),
      Some(false)
    );
  }
}
