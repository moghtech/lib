use std::{
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
  StandardTokenResponse, TokenResponse as _, UserInfoClaims,
  core::*,
  reqwest::{self, Url},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tracing::{debug, error};

pub use openidconnect::SubjectIdentifier;

/// Some OIDC providers use 'username' additional claim
/// rather than the standard 'preferred_username'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameAdditionalClaims {
  pub username: Option<String>,
}

impl AdditionalClaims for UsernameAdditionalClaims {}

/// Additional OIDC claims captured for verified ID token and userinfo data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OidcAdditionalClaims {
  /// Some providers use 'username' rather than 'preferred_username'.
  pub username: Option<String>,
  /// Provider-specific claims, excluding standard OIDC claims.
  #[serde(flatten)]
  pub custom_claims: Map<String, Value>,
}

impl AdditionalClaims for OidcAdditionalClaims {}

/// Verified OIDC claims from the ID token and, when available, userinfo.
///
/// `id_token_claims` contains the claims from the validated ID token.
/// `userinfo_claims` contains claims returned by the userinfo endpoint only
/// when that response was available and verified for the same subject.
/// `claims` is a merged view where userinfo values override ID token values.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct OidcClaims {
  /// The validated OIDC subject from the ID token.
  pub subject: String,
  /// Convenience standard claims. Userinfo values take precedence when
  /// available; otherwise the ID token value is used.
  pub email: Option<String>,
  pub preferred_username: Option<String>,
  pub name: Option<String>,
  /// Merged ID token and userinfo claims. Userinfo values take precedence.
  pub claims: Map<String, Value>,
  /// Claims from the validated ID token.
  pub id_token_claims: Map<String, Value>,
  /// Claims from the userinfo endpoint, when available and verified for the
  /// same subject.
  pub userinfo_claims: Option<Map<String, Value>>,
}

impl OidcClaims {
  /// Read a claim from the merged claims view. Userinfo claims take
  /// precedence over ID token claims when both sources contain the key.
  pub fn claim(&self, key: &str) -> Option<&Value> {
    self.claims.get(key)
  }

  pub fn id_token_claim(&self, key: &str) -> Option<&Value> {
    self.id_token_claims.get(key)
  }

  pub fn userinfo_claim(&self, key: &str) -> Option<&Value> {
    self.userinfo_claims.as_ref()?.get(key)
  }
}

pub type TokenResponse = StandardTokenResponse<
  IdTokenFields<
    OidcAdditionalClaims,
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
  OidcAdditionalClaims,
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
    })
  }

  pub fn authorize_url(
    &self,
    pkce_challenge: PkceCodeChallenge,
  ) -> (Url, CsrfToken, Nonce) {
    self
      .client
      .authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
      )
      .set_pkce_challenge(pkce_challenge)
      .add_scope(Scope::new("openid".to_string()))
      .add_scope(Scope::new("profile".to_string()))
      .add_scope(Scope::new("email".to_string()))
      .url()
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

  /// Collect verified claims from the ID token and the userinfo endpoint.
  ///
  /// This must only be called after the normal authorization-code exchange.
  /// ID token claims are verified with the same nonce and audience handling as
  /// `validate_extract_subject_and_token`. Userinfo is optional; if the
  /// provider has no endpoint or the request fails, only ID token claims are
  /// returned.
  pub async fn get_verified_claims(
    &self,
    config: &OidcConfig,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
    nonce: &Nonce,
  ) -> anyhow::Result<OidcClaims> {
    let id_token = token
      .id_token()
      .context("OIDC Server did not return an ID token")?;

    let verifier = self.client.id_token_verifier();
    let additional_audiences = &config.additional_audiences;
    let verifier = if additional_audiences.is_empty() {
      verifier
    } else {
      verifier.set_other_audience_verifier_fn(|aud| {
        additional_audiences.contains(aud)
      })
    };

    let id_claims = id_token
      .claims(&verifier, nonce)
      .context("Failed to verify token claims")?;
    let id_token_claims = claims_to_map(id_claims)?;

    let userinfo = self.get_userinfo(subject, token).await;
    let userinfo_claims = userinfo
      .as_ref()
      .map(claims_to_map)
      .transpose()?;

    Ok(OidcClaims::new(
      id_claims.subject().to_string(),
      userinfo
        .as_ref()
        .and_then(|claims| {
          claims.email().map(|email| email.as_str().to_string())
        })
        .or_else(|| {
          id_claims.email().map(|email| email.as_str().to_string())
        }),
      userinfo
        .as_ref()
        .and_then(|claims| {
          claims
            .preferred_username()
            .map(|username| username.as_str().to_string())
        })
        .or_else(|| {
          id_claims
            .preferred_username()
            .map(|username| username.as_str().to_string())
        }),
      userinfo
        .as_ref()
        .and_then(|claims| {
          claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str().to_string())
        })
        .or_else(|| {
          id_claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str().to_string())
        }),
      id_token_claims,
      userinfo_claims,
    ))
  }

  async fn get_userinfo(
    &self,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
  ) -> Option<UserInfoClaims<OidcAdditionalClaims, CoreGenderClaim>>
  {
    self
      .client
      .user_info(token.access_token().clone(), Some(subject.clone()))
      .ok()?
      .request_async::<OidcAdditionalClaims, _, CoreGenderClaim>(
        reqwest(self.app_user_agent),
      )
      .await
      .inspect(|user_info| debug!("OIDC USER INFO: {user_info:?}"))
      .ok()
  }

  pub fn get_username_from_claims(&self, claims: &OidcClaims) -> String {
    if self.use_full_email {
      return self.get_username_from_claims_prioritize_email(claims);
    }

    // Priority 1: preferred_username from id_token.
    if let Some(username) =
      string_claim(&claims.id_token_claims, "preferred_username")
    {
      return username;
    }

    // Priority 2: preferred_username from userinfo.
    if let Some(username) = claims
      .userinfo_claims
      .as_ref()
      .and_then(|claims| string_claim(claims, "preferred_username"))
    {
      return username;
    }

    // Priority 3: username additional claim from id claims, then userinfo.
    if let Some(username) = string_claim(&claims.id_token_claims, "username")
      .or_else(|| {
        claims
          .userinfo_claims
          .as_ref()
          .and_then(|claims| string_claim(claims, "username"))
      })
    {
      return username;
    }

    // Priority 4: name from id claims, then userinfo.
    if let Some(username) = string_claim(&claims.id_token_claims, "name")
      .or_else(|| {
        claims
          .userinfo_claims
          .as_ref()
          .and_then(|claims| string_claim(claims, "name"))
      })
    {
      return username;
    }

    // Priority 5: username part of email from id claims, then userinfo.
    if let Some(email) = string_claim(&claims.id_token_claims, "email")
      .or_else(|| {
        claims
          .userinfo_claims
          .as_ref()
          .and_then(|claims| string_claim(claims, "email"))
      })
    {
      let username = email
        .split_once('@')
        .map(|(username, _)| username)
        .unwrap_or(email.as_str())
        .to_string();
      return username;
    }

    // Priority 6 (fallback): use the subject if no others available.
    claims.subject.clone()
  }

  fn get_username_from_claims_prioritize_email(
    &self,
    claims: &OidcClaims,
  ) -> String {
    // Priority 1: email from id_token.
    if let Some(email) = string_claim(&claims.id_token_claims, "email") {
      return email;
    }

    // Priority 2: email from userinfo.
    if let Some(email) = claims
      .userinfo_claims
      .as_ref()
      .and_then(|claims| string_claim(claims, "email"))
    {
      return email;
    }

    // Priority 3: preferred_username from id claims, then userinfo.
    if let Some(username) =
      string_claim(&claims.id_token_claims, "preferred_username")
        .or_else(|| {
          claims
            .userinfo_claims
            .as_ref()
            .and_then(|claims| string_claim(claims, "preferred_username"))
        })
    {
      return username;
    }

    // Priority 4: username additional claim from id claims, then userinfo.
    if let Some(username) = string_claim(&claims.id_token_claims, "username")
      .or_else(|| {
        claims
          .userinfo_claims
          .as_ref()
          .and_then(|claims| string_claim(claims, "username"))
      })
    {
      return username;
    }

    // Priority 5: name from id claims, then userinfo.
    if let Some(username) = string_claim(&claims.id_token_claims, "name")
      .or_else(|| {
        claims
          .userinfo_claims
          .as_ref()
          .and_then(|claims| string_claim(claims, "name"))
      })
    {
      return username;
    }

    // Priority 6 (fallback): use the subject if no others available.
    claims.subject.clone()
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
}

impl OidcClaims {
  fn new(
    subject: String,
    email: Option<String>,
    preferred_username: Option<String>,
    name: Option<String>,
    id_token_claims: Map<String, Value>,
    userinfo_claims: Option<Map<String, Value>>,
  ) -> Self {
    let mut claims = id_token_claims.clone();
    if let Some(userinfo_claims) = userinfo_claims.as_ref() {
      claims.extend(userinfo_claims.clone());
    }

    Self {
      subject,
      email,
      preferred_username,
      name,
      claims,
      id_token_claims,
      userinfo_claims,
    }
  }
}

fn claims_to_map<T: Serialize>(
  claims: &T,
) -> anyhow::Result<Map<String, Value>> {
  match serde_json::to_value(claims)? {
    Value::Object(map) => Ok(map),
    _ => Ok(Map::new()),
  }
}

fn string_claim(claims: &Map<String, Value>, key: &str) -> Option<String> {
  claims.get(key)?.as_str().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  #[test]
  fn merged_claim_lookup_prefers_userinfo_claims() {
    let mut id_token_claims = Map::new();
    id_token_claims
      .insert("groups".to_string(), json!(["id-token-group"]));
    id_token_claims.insert("roles".to_string(), json!(["admin"]));

    let mut userinfo_claims = Map::new();
    userinfo_claims
      .insert("groups".to_string(), json!(["userinfo-group"]));

    let claims = OidcClaims::new(
      "subject-1".to_string(),
      Some("user@example.com".to_string()),
      Some("user".to_string()),
      Some("User Example".to_string()),
      id_token_claims,
      Some(userinfo_claims),
    );

    assert_eq!(
      claims.claim("groups"),
      Some(&json!(["userinfo-group"]))
    );
    assert_eq!(claims.claim("roles"), Some(&json!(["admin"])));
    assert_eq!(
      claims.id_token_claim("groups"),
      Some(&json!(["id-token-group"]))
    );
    assert_eq!(
      claims.userinfo_claim("groups"),
      Some(&json!(["userinfo-group"]))
    );
  }
}
