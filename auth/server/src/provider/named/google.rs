use std::sync::{Arc, OnceLock};

use anyhow::Context;
use arc_swap::ArcSwapOption;
use mogh_auth_client::config::NamedOauthConfig;
use openidconnect::{
  ClientId, ClientSecret, EndpointMaybeSet, EndpointNotSet,
  EndpointSet, IssuerUrl, Nonce, RedirectUrl,
  core::CoreProviderMetadata, reqwest as oidc_reqwest,
};
use tracing::warn;

use crate::{
  provider::named::STATE_PREFIX_LENGTH, rand::random_string,
};

fn google_provider() -> &'static ArcSwapOption<GoogleProvider> {
  static GOOGLE_PROVIDER: OnceLock<ArcSwapOption<GoogleProvider>> =
    OnceLock::new();
  GOOGLE_PROVIDER.get_or_init(Default::default)
}

pub async fn load_google_provider(
  app_user_agent: &'static str,
  host: &str,
  path: &str,
  config: &NamedOauthConfig,
) -> Option<Arc<GoogleProvider>> {
  let client: Arc<_> =
    GoogleProvider::new(app_user_agent, host, path, config)
      .await?
      .into();

  google_provider().store(Some(client.clone()));

  Some(client)
}

type GoogleOidcClient = openidconnect::core::CoreClient<
  EndpointSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointMaybeSet,
  EndpointMaybeSet,
>;

pub struct GoogleProvider {
  http_client: oidc_reqwest::Client,
  oidc_client: GoogleOidcClient,
  client_id: String,
  redirect_uri: String,
  scopes: String,
}

impl GoogleProvider {
  pub async fn new(
    app_user_agent: &'static str,
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

    let http_client = oidc_reqwest::ClientBuilder::new()
      .redirect(oidc_reqwest::redirect::Policy::none())
      .user_agent(app_user_agent)
      .build()
      .context("Failed to build Google HTTP client")
      .inspect_err(|e| warn!("{e:#}"))
      .ok()?;

    let issuer_url =
      IssuerUrl::new("https://accounts.google.com".to_string())
        .context("Failed to initialize Google issuer url")
        .inspect_err(|e| warn!("{e:#}"))
        .ok()?;

    let provider_metadata =
      CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .context("Failed to discover Google OpenID configuration")
        .inspect_err(|e| warn!("{e:#}"))
        .ok()?;

    let oidc_client =
      openidconnect::core::CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.clone()),
        Some(ClientSecret::new(client_secret.clone())),
      )
      .set_redirect_uri(
        RedirectUrl::new(format!("{host}{path}/google/callback"))
          .context("Invalid Google redirect URI")
          .inspect_err(|e| warn!("{e:#}"))
          .ok()?,
      );

    GoogleProvider {
      http_client,
      oidc_client,
      client_id: client_id.clone(),
      redirect_uri: format!("{host}{path}/google/callback"),
      scopes,
    }
    .into()
  }

  pub async fn get_state_and_login_redirect_url(
    &self,
    redirect: Option<String>,
  ) -> (String, Nonce, String) {
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
    (state, nonce, redirect_url)
  }

  pub async fn get_google_user(
    &self,
    code: String,
    nonce: String,
  ) -> anyhow::Result<GoogleUser> {
    let token_response = self
      .oidc_client
      .exchange_code(openidconnect::AuthorizationCode::new(code))?
      .request_async(&self.http_client)
      .await
      .context("Failed to exchange Google authorization code")?;

    let id_token = token_response
      .extra_fields()
      .id_token()
      .context("Google did not return an ID token")?;

    let verifier = self.oidc_client.id_token_verifier();
    let claims = id_token
      .claims(&verifier, &Nonce::new(nonce))
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

pub struct GoogleUser {
  pub id: String,
  pub email: String,
  pub picture: String,
}
