use std::sync::OnceLock;

use anyhow::Context;
use mogh_auth_client::config::NamedOauthConfig;
use openidconnect::{
  ClientId, ClientSecret, IssuerUrl, Nonce, RedirectUrl,
  core::CoreProviderMetadata,
  reqwest as oidc_reqwest,
};
use serde::Deserialize;
use tracing::warn;

use crate::{
  provider::named::STATE_PREFIX_LENGTH,
  rand::random_string,
};

pub fn google_provider(
  host: &str,
  path: &str,
  config: &NamedOauthConfig,
) -> Option<&'static GoogleProvider> {
  static GOOGLE_PROVIDER: OnceLock<Option<GoogleProvider>> =
    OnceLock::new();
  GOOGLE_PROVIDER
    .get_or_init(|| GoogleProvider::new(host, path, config))
    .as_ref()
}

pub struct GoogleProvider {
  client_id: String,
  client_secret: String,
  redirect_uri: String,
  scopes: String,
}

impl GoogleProvider {
  pub fn new(
    host: &str,
    path: &str,
    NamedOauthConfig {
      enabled,
      client_id,
      client_secret,
    }: &NamedOauthConfig,
  ) -> Option<GoogleProvider> {
    if !enabled {
      return None;
    }
    if host.is_empty() {
      warn!("Google oauth is enabled, but 'host' is not configured");
      return None;
    }
    if client_id.is_empty() {
      warn!(
        "Google oauth is enabled, but 'google_oauth.client_id' is not configured"
      );
      return None;
    }
    if client_secret.is_empty() {
      warn!(
        "Google oauth is enabled, but 'google_oauth.client_secret' is not configured"
      );
      return None;
    }
    let scopes = urlencoding::encode(
      &[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
      ]
      .join(" "),
    )
    .to_string();
    GoogleProvider {
      client_id: client_id.clone(),
      client_secret: client_secret.clone(),
      redirect_uri: format!("{host}{path}/google/callback"),
      scopes,
    }
    .into()
  }

  pub async fn get_state_and_login_redirect_url(
    &self,
    redirect: Option<String>,
  ) -> (String, String, String) {
    let state_prefix = random_string(STATE_PREFIX_LENGTH);
    let state = match redirect {
      Some(redirect) => state_prefix + &redirect,
      None => state_prefix,
    };
    let nonce = Nonce::new(random_string(32));
    let redirect_url = format!(
      "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&state={state}&nonce={}&client_id={}&redirect_uri={}&scope={}",
      urlencoding::encode(nonce.secret()),
      self.client_id,
      self.redirect_uri,
      self.scopes
    );
    (state, nonce.secret().clone(), redirect_url)
  }

  pub async fn get_google_user(
    &self,
    code: &str,
    nonce: &str,
  ) -> anyhow::Result<GoogleUser> {
    let http_client = oidc_reqwest::ClientBuilder::new()
      .redirect(oidc_reqwest::redirect::Policy::none())
      .build()
      .context("Failed to build HTTP client")?;

    let issuer_url =
      IssuerUrl::new("https://accounts.google.com".to_string())
        .context("Invalid Google issuer URL")?;

    let provider_metadata =
      CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .context("Failed to discover Google OpenID configuration")?;

    let client = openidconnect::core::CoreClient::from_provider_metadata(
      provider_metadata,
      ClientId::new(self.client_id.clone()),
      Some(ClientSecret::new(self.client_secret.clone())),
    )
    .set_redirect_uri(
      RedirectUrl::new(self.redirect_uri.clone())
        .context("Invalid Google redirect URI")?,
    );

    let token_response = client
      .exchange_code(openidconnect::AuthorizationCode::new(
        code.to_string(),
      ))?
      .request_async(&http_client)
      .await
      .context("Failed to exchange Google authorization code")?;

    let id_token = token_response
      .extra_fields()
      .id_token()
      .context("Google did not return an ID token")?;

    let verifier = client.id_token_verifier();
    let claims = id_token
      .claims(&verifier, &Nonce::new(nonce.to_string()))
      .context("Failed to verify Google ID token")?;

    Ok(GoogleUser {
      id: claims.subject().as_str().to_string(),
      email: claims
        .email()
        .map(|e| e.as_str().to_string())
        .unwrap_or_default(),
      picture: claims
        .picture()
        .and_then(|p| p.get(None))
        .map(|p| p.as_str().to_string())
        .unwrap_or_default(),
    })
  }
}

#[derive(Deserialize, Clone)]
pub struct GoogleUser {
  #[serde(rename = "sub")]
  pub id: String,
  pub email: String,
  #[serde(default)]
  pub picture: String,
}
