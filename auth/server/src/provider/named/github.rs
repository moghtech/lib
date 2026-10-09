use std::time::Duration;

use anyhow::{Context, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::config::NamedOauthConfig;
use mogh_error::AddStatusCodeError as _;
use openidconnect::{PkceCodeChallenge, PkceCodeVerifier};
use serde::{Deserialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{
  provider::{
    CONNECT_TIMEOUT, REQUEST_TIMEOUT,
    named::{STATE_LENGTH, handle_response, sanitize_text},
  },
  rand::random_string,
};

/// Where the Github login page and token endpoint live.
const WEB_URL: &str = "https://github.com";
/// Where the Github REST api lives.
const API_URL: &str = "https://api.github.com";

pub struct GithubProvider {
  http: reqwest::Client,
  client_id: String,
  /// Wiped from memory when the provider is dropped,
  /// eg. after its configuration is updated or deleted.
  client_secret: Zeroizing<String>,
  redirect_uri: String,
  scopes: String,
  user_agent: String,
  /// [WEB_URL], replaced in tests.
  web_url: String,
  /// [API_URL], replaced in tests.
  api_url: String,
}

impl GithubProvider {
  pub fn new(
    redirect_uri: String,
    NamedOauthConfig {
      enabled,
      client_id,
      client_secret,
    }: &NamedOauthConfig,
  ) -> anyhow::Result<GithubProvider> {
    if !enabled {
      return Err(anyhow!("Github login is not enabled"));
    }
    if client_id.is_empty() {
      return Err(anyhow!(
        "Github login is enabled, but 'client_id' is not configured"
      ));
    }
    if client_secret.is_empty() {
      return Err(anyhow!(
        "Github login is enabled, but 'client_secret' is not configured"
      ));
    }
    Ok(GithubProvider {
      http: http_client(REQUEST_TIMEOUT)
        .context("Failed to build Github HTTP client")?,
      client_id: client_id.clone(),
      client_secret: Zeroizing::new(client_secret.clone()),
      redirect_uri,
      // The Github API rejects requests without a User-Agent header.
      user_agent: concat!(
        env!("CARGO_PKG_NAME"),
        "/",
        env!("CARGO_PKG_VERSION")
      )
      .to_string(),
      scopes: Default::default(),
      web_url: WEB_URL.to_string(),
      api_url: API_URL.to_string(),
    })
  }

  /// Gives up on requests after `timeout`
  /// instead of [REQUEST_TIMEOUT].
  #[cfg(test)]
  fn with_request_timeout(mut self, timeout: Duration) -> Self {
    self.http = http_client(timeout).unwrap();
    self
  }

  /// Points the provider at a mock of Github.
  #[cfg(test)]
  pub(crate) fn with_base_urls(
    mut self,
    web_url: &str,
    api_url: &str,
  ) -> GithubProvider {
    self.web_url = web_url.to_string();
    self.api_url = api_url.to_string();
    self
  }

  /// Returns (state, login redirect url).
  ///
  /// The code Github redirects back with can only be redeemed with
  /// the verifier of `pkce_challenge` (PKCE, S256), which stays
  /// on the session: a code which leaks can't be redeemed
  /// from another session.
  pub fn get_state_and_login_redirect_url(
    &self,
    pkce_challenge: &PkceCodeChallenge,
  ) -> (String, String) {
    let state = random_string(STATE_LENGTH);
    let redirect_url = format!(
      "{}/login/oauth/authorize?state={}&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method={}",
      self.web_url,
      urlencoding::encode(&state),
      urlencoding::encode(&self.client_id),
      urlencoding::encode(&self.redirect_uri),
      self.scopes,
      urlencoding::encode(pkce_challenge.as_str()),
      urlencoding::encode(pkce_challenge.method().as_str()),
    );
    (state, redirect_url)
  }

  /// Redeems the callback code.
  ///
  /// Github answers a code it refuses (expired, used,
  /// or unknown) with `200 OK` and the error in the body. That is the
  /// user's failed login (`401`), and the configuration errors
  /// (wrong client secret or redirect uri) are server errors. Either
  /// carries only the error Github reports, never the request.
  pub async fn get_access_token(
    &self,
    code: &str,
    pkce_verifier: &PkceCodeVerifier,
  ) -> mogh_error::Result<AccessTokenResponse> {
    // The credentials go in the form body, never the url: the url
    // ends up in the errors of the request, and so in the logs.
    let res = self
      .http
      .post(format!("{}/login/oauth/access_token", self.web_url))
      .header("Accept", "application/json")
      .header("User-Agent", &self.user_agent)
      .form(&[
        ("client_id", self.client_id.as_str()),
        ("client_secret", self.client_secret.as_str()),
        ("redirect_uri", self.redirect_uri.as_str()),
        ("code", code),
        ("code_verifier", pkce_verifier.secret().as_str()),
      ])
      .send()
      .await
      .map_err(reqwest::Error::without_url)
      .context("Failed to reach Github")
      .context("Failed to get Github access token using code")?;
    let res = handle_response::<AccessTokenResult>(res)
      .await
      .context("Failed to get Github access token using code")?;
    match res {
      AccessTokenResult::Token(token) => Ok(token),
      AccessTokenResult::Error(e) => Err(e.into_error()),
    }
  }

  pub async fn get_github_user(
    &self,
    token: &str,
  ) -> anyhow::Result<GithubUserResponse> {
    self
      .get(&format!("{}/user", self.api_url), token)
      .await
      .context("Failed to get Github user using access token")
  }

  async fn get<R: DeserializeOwned>(
    &self,
    url: &str,
    bearer_token: &str,
  ) -> anyhow::Result<R> {
    let res = self
      .http
      .get(url)
      .header("Accept", "application/json")
      .header("User-Agent", &self.user_agent)
      .header("Authorization", format!("Bearer {bearer_token}"))
      .send()
      .await
      .map_err(reqwest::Error::without_url)
      .context("Failed to reach Github")?;
    handle_response(res).await
  }
}

/// A client which gives up on requests after `timeout`.
///
/// Redirects are not followed: the token request carries the
/// client secret in its body, which a redirect would send on.
fn http_client(
  timeout: Duration,
) -> reqwest::Result<reqwest::Client> {
  reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(timeout)
    .connect_timeout(CONNECT_TIMEOUT.min(timeout))
    .build()
}

#[derive(Deserialize)]
pub struct AccessTokenResponse {
  pub access_token: String,
  // pub scope: String,
  // pub token_type: String,
}

/// The body of Github's `200 OK` answer to a token request.
#[derive(Deserialize)]
#[serde(untagged)]
enum AccessTokenResult {
  Token(AccessTokenResponse),
  Error(OauthError),
}

/// A token request Github refused, see
/// <https://docs.github.com/en/apps/oauth-apps/maintaining-oauth-apps/troubleshooting-oauth-app-access-token-request-errors>.
#[derive(Deserialize)]
struct OauthError {
  error: String,
  #[serde(default)]
  error_description: Option<String>,
}

impl OauthError {
  fn into_error(self) -> mogh_error::Error {
    let code = sanitize_text(&self.error);
    let status = match code.as_str() {
      // The app's configuration, not the user's login.
      "incorrect_client_credentials" | "redirect_uri_mismatch" => {
        StatusCode::INTERNAL_SERVER_ERROR
      }
      // Eg. 'bad_verification_code': expired, used or made up.
      _ => StatusCode::UNAUTHORIZED,
    };
    let e = match self.error_description.as_deref().map(sanitize_text)
    {
      Some(description) if !description.is_empty() => {
        anyhow!("{description}")
          .context(format!("Github refused the login: {code}"))
      }
      _ => anyhow!("Github refused the login: {code}"),
    };
    e.status_code(status)
  }
}

#[derive(Deserialize)]
pub struct GithubUserResponse {
  pub login: String,
  pub id: u128,
  pub avatar_url: String,
  // pub email: Option<String>,
}

/// A local stand in for Github's token and user endpoints.
#[cfg(test)]
pub(crate) mod mock {
  use std::sync::{Arc, Mutex};

  use axum::{
    Router,
    http::{HeaderMap, Uri},
    routing::{get, post},
  };

  /// A request the mock received.
  #[derive(Clone, Debug)]
  pub struct Received {
    pub uri: String,
    pub headers: HeaderMap,
    pub body: String,
  }

  pub struct MockGithub {
    /// Serves both the web and the api urls.
    pub url: String,
    pub received: Arc<Mutex<Vec<Received>>>,
  }

  /// Answers token requests with `200 OK` and `token_body`,
  /// and user requests with a user.
  pub async fn spawn(token_body: &'static str) -> MockGithub {
    let received = Arc::new(Mutex::new(Vec::<Received>::new()));
    let on_token = received.clone();
    let on_user = received.clone();
    let app = Router::new()
      .route(
        "/login/oauth/access_token",
        post(move |uri: Uri, headers: HeaderMap, body: String| {
          on_token.lock().unwrap().push(Received {
            uri: uri.to_string(),
            headers,
            body,
          });
          async move {
            ([("content-type", "application/json")], token_body)
          }
        }),
      )
      .route(
        "/user",
        get(move |uri: Uri, headers: HeaderMap| {
          on_user.lock().unwrap().push(Received {
            uri: uri.to_string(),
            headers,
            body: String::new(),
          });
          async move {
            (
              [("content-type", "application/json")],
              r#"{"login":"octocat","id":42,"avatar_url":"https://avatars.example/42"}"#,
            )
          }
        }),
      );
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    MockGithub {
      url: format!("http://{address}"),
      received,
    }
  }

  /// The fields of a form body.
  pub fn form(
    body: &str,
  ) -> std::collections::HashMap<String, String> {
    reqwest::Url::parse(&format!("http://form/?{body}"))
      .unwrap()
      .query_pairs()
      .into_owned()
      .collect()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const REDIRECT_URI: &str =
    "https://example.com/auth/external/abc/callback";
  const SECRET: &str = "super-secret-client-secret-value";

  fn config(
    enabled: bool,
    client_id: &str,
    client_secret: &str,
  ) -> NamedOauthConfig {
    NamedOauthConfig {
      enabled,
      client_id: client_id.to_string(),
      client_secret: client_secret.to_string(),
    }
  }

  fn test_provider() -> GithubProvider {
    GithubProvider::new(
      REDIRECT_URI.to_string(),
      &config(true, "test-client-id", SECRET),
    )
    .unwrap()
  }

  fn challenge() -> (PkceCodeChallenge, PkceCodeVerifier) {
    PkceCodeChallenge::new_random_sha256()
  }

  #[test]
  fn test_provider_disabled_or_misconfigured_errors() {
    for config in [
      config(false, "id", "secret"),
      config(true, "", "secret"),
      config(true, "id", ""),
    ] {
      assert!(
        GithubProvider::new(REDIRECT_URI.to_string(), &config)
          .is_err()
      );
    }
  }

  #[test]
  fn test_state_and_login_redirect_url() {
    let provider = test_provider();
    let (challenge, _) = challenge();
    let (state, url) =
      provider.get_state_and_login_redirect_url(&challenge);
    assert_eq!(state.len(), STATE_LENGTH);
    assert!(state.chars().all(|c| c.is_ascii_alphanumeric()));
    assert!(
      url.starts_with("https://github.com/login/oauth/authorize?")
    );
    assert!(url.contains(&format!("state={state}")));
    assert!(url.contains("client_id=test-client-id"));
    // Redirect uri is urlencoded.
    assert!(url.contains(urlencoding::encode(REDIRECT_URI).as_ref()));
    // The code is bound to the verifier (PKCE).
    assert!(url.contains(&format!(
      "code_challenge={}&code_challenge_method=S256",
      challenge.as_str()
    )));
    // The client secret must never appear in the user-facing URL.
    assert!(!url.contains(SECRET));
  }

  #[test]
  fn test_client_id_cannot_inject_query_params() {
    let provider = GithubProvider::new(
      REDIRECT_URI.to_string(),
      &config(true, "id&redirect_uri=https://evil", "secret"),
    )
    .unwrap();
    let (_, url) =
      provider.get_state_and_login_redirect_url(&challenge().0);
    assert!(!url.contains("&redirect_uri=https://evil"));
  }

  #[test]
  fn test_states_are_unique() {
    let provider = test_provider();
    let (state_a, _) =
      provider.get_state_and_login_redirect_url(&challenge().0);
    let (state_b, _) =
      provider.get_state_and_login_redirect_url(&challenge().0);
    assert_ne!(state_a, state_b);
  }

  #[test]
  fn test_token_response_shapes() {
    let parse = |body: &str| {
      serde_json::from_str::<AccessTokenResult>(body).unwrap()
    };
    assert!(matches!(
      parse(r#"{"access_token":"gho_1","token_type":"bearer"}"#),
      AccessTokenResult::Token(_)
    ));
    assert!(matches!(
      parse(r#"{"error":"bad_verification_code"}"#),
      AccessTokenResult::Error(_)
    ));
    assert!(
      serde_json::from_str::<AccessTokenResult>(r#"{"other":1}"#)
        .is_err()
    );
  }

  /// Asserts the error of a token request carries
  /// neither the client secret nor the request url.
  fn assert_no_secret(err: &mogh_error::Error, url: &str) {
    for rendered in [
      format!("{:#}", err.error),
      format!("{:?}", err.error),
      mogh_error::serialize_error(&err.error),
    ] {
      assert!(!rendered.contains(SECRET), "{rendered}");
      assert!(!rendered.contains("client_secret="), "{rendered}");
      assert!(!rendered.contains(url), "{rendered}");
    }
  }

  /// Github answers a code it refuses with `200 OK`. The error
  /// used to be reqwest's decode error, which names the request url:
  /// with the credentials in its query, the client secret went to
  /// the unauthenticated caller and the logs.
  #[tokio::test]
  async fn test_refused_code_is_a_401_without_the_secret() {
    let github = mock::spawn(
      r#"{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired.","error_uri":"https://docs.github.com"}"#,
    )
    .await;
    let provider =
      test_provider().with_base_urls(&github.url, &github.url);
    let (_, verifier) = challenge();
    let err =
      match provider.get_access_token("garbage", &verifier).await {
        Ok(_) => panic!("expected the code to be refused"),
        Err(e) => e,
      };
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let message = format!("{:#}", err.error);
    assert!(message.contains("bad_verification_code"), "{message}");
    assert!(message.contains("incorrect or expired"), "{message}");
    assert_no_secret(&err, &github.url);

    // The credentials were sent in the body, not the url.
    let received = github.received.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].uri, "/login/oauth/access_token");
    let form = mock::form(&received[0].body);
    assert_eq!(form["client_id"], "test-client-id");
    assert_eq!(form["client_secret"], SECRET);
    assert_eq!(form["code"], "garbage");
    assert_eq!(form["redirect_uri"], REDIRECT_URI);
    assert_eq!(form["code_verifier"], verifier.secret().as_str());
    assert_eq!(
      received[0].headers["content-type"],
      "application/x-www-form-urlencoded"
    );
  }

  #[tokio::test]
  async fn test_misconfiguration_is_a_server_error_without_the_secret()
   {
    let github = mock::spawn(
      r#"{"error":"incorrect_client_credentials","error_description":"The client_id and/or client_secret passed are incorrect."}"#,
    )
    .await;
    let provider =
      test_provider().with_base_urls(&github.url, &github.url);
    let err =
      match provider.get_access_token("code", &challenge().1).await {
        Ok(_) => panic!("expected the request to be refused"),
        Err(e) => e,
      };
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
      format!("{:#}", err.error)
        .contains("incorrect_client_credentials")
    );
    assert_no_secret(&err, &github.url);
  }

  #[tokio::test]
  async fn test_unexpected_body_is_an_error_without_the_secret() {
    let github = mock::spawn("<html>not json</html>").await;
    let provider =
      test_provider().with_base_urls(&github.url, &github.url);
    let err =
      match provider.get_access_token("code", &challenge().1).await {
        Ok(_) => panic!("expected the body to be refused"),
        Err(e) => e,
      };
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_no_secret(&err, &github.url);
  }

  #[tokio::test]
  async fn test_unreachable_github_is_an_error_without_the_secret() {
    // Nothing listens there.
    let listener =
      std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let provider = test_provider().with_base_urls(&url, &url);
    let err =
      match provider.get_access_token("code", &challenge().1).await {
        Ok(_) => panic!("expected the request to fail"),
        Err(e) => e,
      };
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(format!("{:#}", err.error).contains("Failed to reach"));
    assert_no_secret(&err, &url);
  }

  /// A Github which accepts the connection but never
  /// answers fails the login, instead of leaving it hanging.
  #[tokio::test]
  async fn test_stalled_github_fails_the_login() {
    let stalled = crate::provider::stalled_server().await;
    let provider = test_provider()
      .with_base_urls(&stalled, &stalled)
      .with_request_timeout(Duration::from_millis(200));
    let (_, verifier) = challenge();
    let login = provider.get_access_token("code", &verifier);
    let err =
      match tokio::time::timeout(Duration::from_secs(10), login)
        .await
        .expect("the login must fail, not hang")
      {
        Ok(_) => panic!("a login without an answer must fail"),
        Err(e) => e,
      };
    let message = format!("{:#}", err.error);
    assert!(message.contains("timed out"), "{message}");
    assert_no_secret(&err, &stalled);
    let user = provider.get_github_user("gho_token");
    assert!(
      tokio::time::timeout(Duration::from_secs(10), user)
        .await
        .expect("the user request must fail, not hang")
        .is_err()
    );
  }

  /// Github's responses are read up to a limit as well.
  #[tokio::test]
  async fn test_oversized_responses_are_not_read() {
    for url in crate::provider::oversized_servers().await {
      let provider = test_provider().with_base_urls(&url, &url);
      let (_, verifier) = challenge();
      let err = match tokio::time::timeout(
        Duration::from_secs(10),
        provider.get_access_token("code", &verifier),
      )
      .await
      .expect("the read must stop at the limit")
      {
        Ok(_) => panic!("an oversized answer must fail"),
        Err(e) => e,
      };
      let message = format!("{:#}", err.error);
      assert!(message.contains("larger than"), "{message}");
      assert_no_secret(&err, &url);
    }
  }

  #[tokio::test]
  async fn test_token_and_user() {
    let github = mock::spawn(
      r#"{"access_token":"gho_token","token_type":"bearer","scope":""}"#,
    )
    .await;
    let provider =
      test_provider().with_base_urls(&github.url, &github.url);
    let token =
      match provider.get_access_token("code", &challenge().1).await {
        Ok(token) => token,
        Err(e) => panic!("{:#}", e.error),
      };
    assert_eq!(token.access_token, "gho_token");
    let user = provider.get_github_user("gho_token").await.unwrap();
    assert_eq!(user.login, "octocat");
    assert_eq!(user.id, 42);
    let received = github.received.lock().unwrap().clone();
    assert_eq!(received[1].uri, "/user");
    assert_eq!(
      received[1].headers["authorization"],
      "Bearer gho_token"
    );
  }
}
