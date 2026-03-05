use std::{
  sync::{Arc, OnceLock},
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow};
use arc_swap::ArcSwapOption;
use mogh_auth_client::config::OidcConfig;
use openidconnect::{
  AccessTokenHash, AuthorizationCode, Client, ClientId, ClientSecret,
  CsrfToken, EmptyAdditionalClaims, EmptyExtraTokenFields,
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

pub type TokenResponse = StandardTokenResponse<
  IdTokenFields<
    EmptyAdditionalClaims,
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
  EmptyAdditionalClaims,
  CoreAuthDisplay,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJsonWebKey,
  CoreAuthPrompt,
  StandardErrorResponse<CoreErrorResponseType>,
  CoreTokenResponse,
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

    let client = CoreClient::from_provider_metadata(
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
        .request_async::<EmptyAdditionalClaims, _, CoreGenderClaim>(
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

    // Priority 3: name from id claims, then user info
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

    // Priority 4: username part of email from id claims, then user info
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

    // Priority 5 (fallback): use the subject if no others available
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
        .request_async::<EmptyAdditionalClaims, _, CoreGenderClaim>(
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

    // Priority 5 (fallback): use the subject if no others available
    subject.to_string()
  }
}
