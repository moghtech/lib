use std::sync::OnceLock;

use anyhow::Context;
use jsonwebtoken::dangerous::insecure_decode;
use mogh_auth_client::config::NamedOauthConfig;
use serde::{Deserialize, de::DeserializeOwned};
use tracing::warn;

use crate::{
  provider::named::{STATE_PREFIX_LENGTH, handle_response},
  rand::random_string,
};

pub fn google_provider(
  host: &str,
  config: &NamedOauthConfig,
) -> Option<&'static GoogleProvider> {
  static GOOGLE_PROVIDER: OnceLock<Option<GoogleProvider>> =
    OnceLock::new();
  GOOGLE_PROVIDER
    .get_or_init(|| GoogleProvider::new(host, config))
    .as_ref()
}

pub struct GoogleProvider {
  http: reqwest::Client,
  client_id: String,
  client_secret: String,
  redirect_uri: String,
  scopes: String,
  user_agent: String,
}

impl GoogleProvider {
  pub fn new(
    host: &str,
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
      http: Default::default(),
      client_id: client_id.clone(),
      client_secret: client_secret.clone(),
      redirect_uri: format!("{host}/auth/google/callback"),
      user_agent: String::from("komodo"),
      scopes,
    }
    .into()
  }

  pub async fn get_state_and_login_redirect_url(
    &self,
    redirect: Option<String>,
  ) -> (String, String) {
    let state_prefix = random_string(STATE_PREFIX_LENGTH);
    let state = match redirect {
      Some(redirect) => format!("{state_prefix}{redirect}"),
      None => state_prefix,
    };
    let redirect_url = format!(
      "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&state={state}&client_id={}&redirect_uri={}&scope={}",
      self.client_id, self.redirect_uri, self.scopes
    );
    (state, redirect_url)
  }

  pub async fn get_access_token(
    &self,
    code: &str,
  ) -> anyhow::Result<AccessTokenResponse> {
    self
      .post::<_>(
        "https://oauth2.googleapis.com/token",
        &[
          ("client_id", self.client_id.as_str()),
          ("client_secret", self.client_secret.as_str()),
          ("redirect_uri", self.redirect_uri.as_str()),
          ("code", code),
          ("grant_type", "authorization_code"),
        ],
        None,
      )
      .await
      .context("failed to get google access token using code")
  }

  pub fn get_google_user(
    &self,
    id_token: &str,
  ) -> anyhow::Result<GoogleUser> {
    let res = insecure_decode::<GoogleUser>(id_token)
      .context("failed to decode google id token")?;
    Ok(res.claims)
  }

  async fn post<R: DeserializeOwned>(
    &self,
    endpoint: &str,
    body: &[(&str, &str)],
    bearer_token: Option<&str>,
  ) -> anyhow::Result<R> {
    let mut req = self
      .http
      .post(endpoint)
      .form(body)
      .header("Accept", "application/json")
      .header("User-Agent", &self.user_agent);

    if let Some(bearer_token) = bearer_token {
      req =
        req.header("Authorization", format!("Bearer {bearer_token}"));
    }

    let res = req.send().await.context("Failed to reach Google")?;

    handle_response(res).await
  }
}

#[derive(Deserialize)]
pub struct AccessTokenResponse {
  // pub access_token: String,
  pub id_token: String,
  // pub scope: String,
  // pub token_type: String,
}

#[derive(Deserialize, Clone)]
pub struct GoogleUser {
  #[serde(rename = "sub")]
  pub id: String,
  pub email: String,
  #[serde(default)]
  pub picture: String,
}
