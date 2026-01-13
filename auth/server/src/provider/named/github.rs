use std::sync::OnceLock;

use anyhow::Context;
use mogh_auth_client::config::NamedOauthConfig;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::warn;

use crate::{
  provider::named::{STATE_PREFIX_LENGTH, handle_response},
  rand::random_string,
};

pub fn github_provider(
  host: &str,
  config: &NamedOauthConfig,
) -> Option<&'static GithubProvider> {
  static GITHUB_PROVIDER: OnceLock<Option<GithubProvider>> =
    OnceLock::new();
  GITHUB_PROVIDER
    .get_or_init(|| GithubProvider::new(host, config))
    .as_ref()
}

pub struct GithubProvider {
  http: reqwest::Client,
  client_id: String,
  client_secret: String,
  redirect_uri: String,
  scopes: String,
  user_agent: String,
}

impl GithubProvider {
  pub fn new(
    host: &str,
    NamedOauthConfig {
      enabled,
      client_id,
      client_secret,
    }: &NamedOauthConfig,
  ) -> Option<GithubProvider> {
    if !enabled {
      return None;
    }
    if host.is_empty() {
      warn!("Github oauth is enabled, but 'host' is not configured");
      return None;
    }
    if client_id.is_empty() {
      warn!(
        "Github oauth is enabled, but 'github_oauth.client_id' is not configured"
      );
      return None;
    }
    if client_secret.is_empty() {
      warn!(
        "Github oauth is enabled, but 'github_oauth.client_secret' is not configured"
      );
      return None;
    }
    GithubProvider {
      http: reqwest::Client::new(),
      client_id: client_id.clone(),
      client_secret: client_secret.clone(),
      redirect_uri: format!("{host}/github/callback"),
      user_agent: Default::default(),
      scopes: Default::default(),
    }
    .into()
  }

  pub async fn get_state_and_login_redirect_url(
    &self,
    redirect: Option<String>,
  ) -> (String, String) {
    let state_prefix = random_string(STATE_PREFIX_LENGTH);
    let state = match redirect {
      Some(redirect) => state_prefix + &redirect,
      None => state_prefix,
    };
    let redirect_url = format!(
      "https://github.com/login/oauth/authorize?state={state}&client_id={}&redirect_uri={}&scope={}",
      self.client_id, self.redirect_uri, self.scopes
    );
    (state, redirect_url)
  }

  pub async fn get_access_token(
    &self,
    code: &str,
  ) -> anyhow::Result<AccessTokenResponse> {
    self
      .post::<(), _>(
        "https://github.com/login/oauth/access_token",
        &[
          ("client_id", self.client_id.as_str()),
          ("client_secret", self.client_secret.as_str()),
          ("redirect_uri", self.redirect_uri.as_str()),
          ("code", code),
        ],
        None,
        None,
      )
      .await
      .context("failed to get github access token using code")
  }

  pub async fn get_github_user(
    &self,
    token: &str,
  ) -> anyhow::Result<GithubUserResponse> {
    self
      .get("https://api.github.com/user", &[], Some(token))
      .await
      .context("failed to get github user using access token")
  }

  async fn get<R: DeserializeOwned>(
    &self,
    endpoint: &str,
    query: &[(&str, &str)],
    bearer_token: Option<&str>,
  ) -> anyhow::Result<R> {
    let mut req = self
      .http
      .get(endpoint)
      .query(query)
      .header("User-Agent", &self.user_agent);

    if let Some(bearer_token) = bearer_token {
      req =
        req.header("Authorization", format!("Bearer {bearer_token}"));
    }

    let res = req.send().await.context("failed to reach github")?;

    handle_response(res).await
  }

  async fn post<B: Serialize, R: DeserializeOwned>(
    &self,
    endpoint: &str,
    query: &[(&str, &str)],
    body: Option<&B>,
    bearer_token: Option<&str>,
  ) -> anyhow::Result<R> {
    let mut req = self
      .http
      .post(endpoint)
      .query(query)
      .header("Accept", "application/json")
      .header("User-Agent", &self.user_agent);

    if let Some(body) = body {
      req = req.json(body);
    }

    if let Some(bearer_token) = bearer_token {
      req =
        req.header("Authorization", format!("Bearer {bearer_token}"));
    }

    let res = req.send().await.context("Gailed to reach Github")?;

    handle_response(res).await
  }
}

#[derive(Deserialize)]
pub struct AccessTokenResponse {
  pub access_token: String,
  // pub scope: String,
  // pub token_type: String,
}

#[derive(Deserialize)]
pub struct GithubUserResponse {
  pub login: String,
  pub id: u128,
  pub avatar_url: String,
  // pub email: Option<String>,
}
