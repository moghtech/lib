use anyhow::{Context, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::config::{
  NamedOauthConfig, TokenExchangeConfig,
};
use mogh_error::AddStatusCode as _;
use openidconnect::{
  ClientId, ClientSecret, EndpointMaybeSet, EndpointNotSet,
  EndpointSet, IssuerUrl, Nonce, RedirectUrl,
  core::{CoreIdTokenClaims, CoreProviderMetadata},
};

use crate::{
  provider::{
    REQUEST_TIMEOUT,
    named::STATE_LENGTH,
    oidc::{ProviderHttpClient, http_client, token_request_error},
    token_exchange::TokenVerificationKeys,
  },
  rand::random_string,
};

type GoogleOidcClient = openidconnect::core::CoreClient<
  EndpointSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointMaybeSet,
  EndpointMaybeSet,
>;

pub struct GoogleProvider {
  http_client: ProviderHttpClient,
  oidc_client: GoogleOidcClient,
  client_id: String,
  redirect_uri: String,
  scopes: String,
  /// To verify tokens presented for token exchange
  verification_keys: TokenVerificationKeys,
}

impl GoogleProvider {
  /// Initialize a new Google provider using Googles
  /// OpenID discovery endpoint, which includes the
  /// signing keys used to verify the ID token.
  pub async fn new(
    app_user_agent: &'static str,
    redirect_uri: String,
    NamedOauthConfig {
      enabled,
      client_id,
      client_secret,
    }: &NamedOauthConfig,
  ) -> anyhow::Result<GoogleProvider> {
    if !enabled {
      return Err(anyhow!("Google login is not enabled"));
    }
    if client_id.is_empty() {
      return Err(anyhow!(
        "Google login is enabled, but 'client_id' is not configured"
      ));
    }
    if client_secret.is_empty() {
      return Err(anyhow!(
        "Google login is enabled, but 'client_secret' is not configured"
      ));
    }

    let http_client = http_client(app_user_agent, REQUEST_TIMEOUT)
      .context("Failed to build Google HTTP client")?;

    let issuer_url =
      IssuerUrl::new("https://accounts.google.com".to_string())
        .context("Failed to initialize Google issuer url")?;

    let provider_metadata =
      CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .context("Failed to discover Google OpenID configuration")?;

    Self::from_metadata(
      http_client,
      redirect_uri,
      client_id,
      client_secret,
      provider_metadata,
    )
  }

  /// Initialize the provider from already discovered metadata.
  fn from_metadata(
    http_client: ProviderHttpClient,
    redirect_uri: String,
    client_id: &str,
    client_secret: &str,
    provider_metadata: CoreProviderMetadata,
  ) -> anyhow::Result<GoogleProvider> {
    let scopes = urlencoding::encode(
      &[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
      ]
      .join(" "),
    )
    .to_string();

    let verification_keys =
      TokenVerificationKeys::from_metadata(&provider_metadata);

    let oidc_client =
      openidconnect::core::CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
      )
      .set_redirect_uri(
        RedirectUrl::new(redirect_uri.clone())
          .context("Invalid Google redirect URI")?,
      );

    Ok(GoogleProvider {
      http_client,
      oidc_client,
      client_id: client_id.to_string(),
      redirect_uri,
      scopes,
      verification_keys,
    })
  }

  /// Verifies a Google ID token presented for RFC 8693 token exchange,
  /// which must be issued to the client id or one of the exchange audiences.
  pub fn verify_exchange_token(
    &self,
    exchange: &TokenExchangeConfig,
    token: &str,
  ) -> anyhow::Result<GoogleUser> {
    let mut audiences = vec![self.client_id.clone()];
    audiences.extend(exchange.audiences.iter().cloned());
    let claims = self
      .verification_keys
      .verify::<openidconnect::EmptyAdditionalClaims>(
      token,
      &audiences,
      &[],
      exchange.max_token_age_secs,
    )?;
    Ok(GoogleUser::from_claims(&claims))
  }

  /// Returns (state, nonce, login redirect url)
  pub fn get_state_and_login_redirect_url(
    &self,
  ) -> (String, Nonce, String) {
    let state = random_string(STATE_LENGTH);
    let nonce = Nonce::new(random_string(32));
    let redirect_url = format!(
      "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&state={}&nonce={}&client_id={}&redirect_uri={}&scope={}",
      urlencoding::encode(&state),
      urlencoding::encode(nonce.secret()),
      urlencoding::encode(&self.client_id),
      urlencoding::encode(&self.redirect_uri),
      self.scopes
    );
    (state, nonce, redirect_url)
  }

  /// Redeems the callback code, and verifies the ID token it gets
  /// (signature, audience, nonce). A code or an ID token Google
  /// refuses is the user's failed login (`401`), like at an OIDC
  /// provider; Google refusing the app's configuration (its client
  /// credentials) or not answering is a server error.
  pub async fn get_google_user(
    &self,
    code: String,
    nonce: String,
  ) -> mogh_error::Result<GoogleUser> {
    let token_response = self
      .oidc_client
      .exchange_code(openidconnect::AuthorizationCode::new(code))
      .context("Failed to exchange Google authorization code")?
      .request_async(&self.http_client)
      .await
      .map_err(|e| token_request_error("Google", e))?;

    let id_token = token_response
      .extra_fields()
      .id_token()
      .context("Google did not return an ID token")?;

    // The login can't be trusted, which is not a server error.
    let verifier = self.oidc_client.id_token_verifier();
    let claims = id_token
      .claims(&verifier, &Nonce::new(nonce))
      .context("Failed to verify Google ID token")
      .status_code(StatusCode::UNAUTHORIZED)?;

    Ok(GoogleUser::from_claims(claims))
  }
}

pub struct GoogleUser {
  pub id: String,
  pub email: String,
  pub picture: String,
}

impl GoogleUser {
  fn from_claims(claims: &CoreIdTokenClaims) -> GoogleUser {
    GoogleUser {
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
    }
  }
}

#[cfg(test)]
mod tests {
  use std::time::Duration;

  use openidconnect::TokenUrl;

  use super::*;
  use crate::provider::{
    stalled_server, token_exchange::test_tokens::metadata,
  };

  /// The Google of the test metadata, with its token endpoint at
  /// `token_url`.
  fn google_at(token_url: &str) -> GoogleProvider {
    GoogleProvider::from_metadata(
      http_client("test", Duration::from_secs(10)).unwrap(),
      "https://app.example.com/auth/google/callback".to_string(),
      "client-id",
      "client-secret",
      metadata().set_token_endpoint(Some(
        TokenUrl::new(format!("{token_url}/token")).unwrap(),
      )),
    )
    .unwrap()
  }

  /// A code Google refuses, and an ID token which fails verification
  /// (here its nonce), are the user's failed login: `401`, as for an
  /// OIDC provider.
  #[tokio::test]
  async fn test_refused_logins_are_the_users() {
    use crate::provider::{
      answering_server, oidc::UsernameAdditionalClaims,
      token_exchange::test_tokens::TestToken,
    };
    use axum::http::StatusCode;

    let refused = answering_server(
      StatusCode::BAD_REQUEST,
      serde_json::json!({ "error": "invalid_grant" }).to_string(),
    )
    .await;
    let Err(err) = google_at(&refused)
      .get_google_user("made-up".to_string(), "nonce".to_string())
      .await
    else {
      panic!("a refused code must fail the login");
    };
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("invalid_grant"));

    let id_token = TestToken {
      audiences: vec!["client-id".to_string()],
      nonce: Some("the-nonce".to_string()),
      ..TestToken::new(UsernameAdditionalClaims {
        username: None,
        extra: Default::default(),
      })
    }
    .mint();
    let issued = answering_server(
      StatusCode::OK,
      serde_json::json!({
        "access_token": "access-token",
        "token_type": "bearer",
        "id_token": id_token,
      })
      .to_string(),
    )
    .await;
    let google = google_at(&issued);
    let Err(err) = google
      .get_google_user(
        "code".to_string(),
        "another-nonce".to_string(),
      )
      .await
    else {
      panic!("an ID token for another login must fail it");
    };
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let Ok(user) = google
      .get_google_user("code".to_string(), "the-nonce".to_string())
      .await
    else {
      panic!("the login's own ID token logs in");
    };
    assert_eq!(user.id, "subject-123");
  }

  /// A Google which accepts the connection but never answers
  /// fails the login, instead of leaving the callback hanging.
  #[tokio::test]
  async fn test_stalled_token_endpoint_fails_the_login() {
    let stalled = stalled_server().await;
    let provider = GoogleProvider::from_metadata(
      http_client("test", Duration::from_millis(200)).unwrap(),
      "https://app.example.com/auth/google/callback".to_string(),
      "client-id",
      "client-secret",
      metadata().set_token_endpoint(Some(
        TokenUrl::new(format!("{stalled}/token")).unwrap(),
      )),
    )
    .unwrap();
    let login = provider
      .get_google_user("code".to_string(), "nonce".to_string());
    let Err(err) =
      tokio::time::timeout(Duration::from_secs(10), login)
        .await
        .expect("the login must fail, not hang")
    else {
      panic!("a login without an answer must fail");
    };
    let message = format!("{:#}", err.error);
    assert!(message.contains("timed out"), "{message}");
  }
}
