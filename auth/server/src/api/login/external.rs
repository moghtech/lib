//! Token exchange as part of the login api: [ExchangeExternalForJwt].
//! Shares the verification with the `/token` endpoint
//! ([crate::api::token]), but can continue with a second factor.

use std::{net::IpAddr, sync::Arc};

use anyhow::Context as _;
use axum::http::StatusCode;
use mogh_auth_client::{
  api::login::{ExchangeExternalForJwt, JwtOrTwoFactor},
  config::ExternalLoginProvider,
};
use mogh_error::AddStatusCode as _;
use mogh_resolver::Resolve;
use tracing::{info, instrument};

use crate::{
  AuthImpl,
  api::{
    begin_external_two_factor,
    external::load_provider_client,
    login::{
      IssueToken, LoginArgs, SecondFactorChallenge, issue_login,
    },
    provider_login,
    token::{
      VerifiedExchange, verify_exchange, with_exchange_rate_limit,
    },
  },
  middleware::check_user_cidr_whitelist,
  provider::external::BuiltProvider,
  session::Session,
};

/// `load_client` loads the client which verifies tokens of a provider.
pub async fn exchange_external_for_jwt<I, L, F>(
  auth: &I,
  session: &Session,
  ip: IpAddr,
  token: &str,
  load_client: L,
) -> mogh_error::Result<JwtOrTwoFactor>
where
  I: AuthImpl + ?Sized,
  L: Fn(ExternalLoginProvider) -> F,
  F: Future<Output = mogh_error::Result<Arc<BuiltProvider>>>,
{
  let VerifiedExchange {
    provider,
    user,
    info,
    authenticated_at,
  } = verify_exchange(auth, token, load_client, None)
    .await?
    .context(
      "No login provider accepts tokens of this issuer for token exchange",
    )
    .status_code(StatusCode::BAD_REQUEST)?;

  // Users outside their whitelist are rejected
  // before the exchange has any effect on them.
  check_user_cidr_whitelist(user.as_ref(), ip)?;

  // Sync before anything is issued, like for a login.
  auth.sync_external_user(user.id().to_string(), info).await?;

  let res = match begin_external_two_factor(
    auth,
    session,
    user.as_ref(),
    &provider,
  )
  .await?
  {
    None => {
      // A login when the provider authenticated the user, not now:
      // the token may be replayed until it expires.
      let token = issue_login(
        auth,
        user.id(),
        user.username(),
        ip,
        provider_login(&provider),
        None,
        IssueToken::AuthTime(authenticated_at),
      )
      .await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        provider_id = provider.id,
        provider = provider.name,
        "User logged in (token exchange)"
      );

      JwtOrTwoFactor::Jwt(token.into())
    }
    // The JWT is only issued once the second factor is completed
    // on the same session, which makes it a login right then.
    Some(SecondFactorChallenge::Passkey(response)) => {
      JwtOrTwoFactor::Passkey(response)
    }
    Some(SecondFactorChallenge::Totp) => JwtOrTwoFactor::Totp {},
  };

  Ok(res)
}

impl Resolve<LoginArgs> for ExchangeExternalForJwt {
  #[instrument(
    "ExchangeExternalForJwt",
    skip_all,
    fields(ip = ip.to_string())
  )]
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    let auth = auth.as_ref();
    with_exchange_rate_limit(
      exchange_external_for_jwt(
        auth,
        session,
        *ip,
        &self.token,
        |provider| async move {
          load_provider_client(auth, &provider).await
        },
      ),
      auth.general_rate_limiter(),
      ip,
    )
    .await
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Mutex;

  use mogh_auth_client::config::{
    ExternalLoginProviderConfig, OidcConfig, TokenExchangeConfig,
  };

  use super::*;
  use crate::{
    Login,
    provider::{
      external::ExternalLoginInfo,
      jwt::JwtProvider,
      oidc::{OidcProvider, UsernameAdditionalClaims},
      token_exchange::test_tokens::{
        CLIENT_ID, ISSUER, TestToken, metadata,
      },
    },
    test_support::{session, stub_auth_impl},
    user::{AuthUserImpl, BoxAuthUser},
  };

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

  #[derive(Clone, Default)]
  struct TestUser {
    external_skip_2fa: bool,
    totp: bool,
    cidr_whitelist: Vec<String>,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      "user-id"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn external_skip_2fa(&self) -> bool {
      self.external_skip_2fa
    }
    fn totp_secret(&self) -> Option<&str> {
      self.totp.then_some("totp-secret")
    }
    fn cidr_whitelist(&self) -> &[String] {
      &self.cidr_whitelist
    }
  }

  struct TestAuth {
    user: Option<TestUser>,
    synced: Arc<Mutex<Vec<ExternalLoginInfo>>>,
    logins: Arc<Mutex<Vec<Login>>>,
    jwt: JwtProvider,
  }

  impl TestAuth {
    fn with_user(user: Option<TestUser>) -> TestAuth {
      TestAuth {
        user,
        synced: Default::default(),
        logins: Default::default(),
        jwt: JwtProvider::new(b"test-jwt-secret", 60_000),
      }
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      unreachable!()
    }

    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      vec![ExternalLoginProvider {
        id: "oidc".to_string(),
        name: "OIDC".to_string(),
        registration_disabled: false,
        slug: String::new(),
        token_exchange: TokenExchangeConfig {
          enabled: true,
          ..Default::default()
        },
        config: ExternalLoginProviderConfig::Oidc(OidcConfig {
          enabled: true,
          provider: ISSUER.to_string(),
          client_id: CLIENT_ID.to_string(),
          ..Default::default()
        }),
      }]
    }

    fn find_user_with_external_login(
      &self,
      provider_id: String,
      external_id: String,
    ) -> crate::DynFuture<mogh_error::Result<Option<BoxAuthUser>>>
    {
      let user = self
        .user
        .clone()
        .filter(|_| {
          provider_id == "oidc" && external_id == "subject-123"
        })
        .map(|user| Box::new(user) as BoxAuthUser);
      Box::pin(async move { Ok(user) })
    }

    fn sync_external_user(
      &self,
      _user_id: String,
      info: ExternalLoginInfo,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.synced.lock().unwrap().push(info);
      Box::pin(async { Ok(()) })
    }

    fn record_login(
      &self,
      login: Login,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.logins.lock().unwrap().push(login);
      Box::pin(async { Ok(()) })
    }

    stub_auth_impl!(get_user, handle_request_authentication);

    fn jwt_provider(&self) -> &JwtProvider {
      &self.jwt
    }
  }

  fn token() -> String {
    TestToken::new(UsernameAdditionalClaims {
      username: None,
      extra: Default::default(),
    })
    .mint()
  }

  /// Builds the client from fixed metadata, in place of network discovery.
  async fn load_client(
    provider: ExternalLoginProvider,
  ) -> mogh_error::Result<Arc<BuiltProvider>> {
    let ExternalLoginProviderConfig::Oidc(config) = &provider.config
    else {
      unreachable!()
    };
    let client = OidcProvider::from_metadata(
      "test",
      "https://app.example.com/auth/oidc/callback".to_string(),
      config,
      metadata(),
    )?;
    Ok(Arc::new(BuiltProvider::Oidc(client)))
  }

  async fn run(
    auth: &TestAuth,
    session: &Session,
    token: &str,
  ) -> mogh_error::Result<JwtOrTwoFactor> {
    exchange_external_for_jwt(auth, session, IP, token, load_client)
      .await
  }

  #[tokio::test]
  async fn test_issues_jwt_without_second_factor() {
    for user in [
      TestUser::default(),
      // Enrolled, but skipped for external logins
      TestUser {
        external_skip_2fa: true,
        totp: true,
        ..Default::default()
      },
    ] {
      let auth = TestAuth::with_user(Some(user));
      let session = session();
      let JwtOrTwoFactor::Jwt(jwt) =
        run(&auth, &session, &token()).await.unwrap()
      else {
        panic!("expected a jwt")
      };
      assert_eq!(auth.jwt.decode_sub(&jwt.jwt).unwrap(), "user-id");
      assert_eq!(auth.synced.lock().unwrap().len(), 1);
      // Nothing is left pending on the session
      assert!(session.begin_totp_login_attempt().await.is_err());
      // The exchange is the login
      let logins = auth.logins.lock().unwrap();
      assert_eq!(logins.len(), 1);
      assert_eq!(logins[0].user_id, "user-id");
      assert!(logins[0].second_factor.is_none());
      assert!(matches!(
        &logins[0].kind,
        crate::LoginKind::Provider { provider_id, .. } if provider_id == "oidc"
      ));
    }
  }

  /// Like `/token`: the JWT counts as a login when the provider
  /// authenticated the user, not now. A provider token can be
  /// exchanged again until it expires.
  #[tokio::test]
  async fn test_jwt_is_a_login_when_the_provider_authenticated() {
    let auth = TestAuth::with_user(Some(TestUser::default()));
    let session = session();
    let now = chrono::Utc::now().timestamp() as u64;
    let token = TestToken {
      issued_ago: chrono::Duration::minutes(30),
      expires_in: chrono::Duration::hours(8),
      ..TestToken::new(UsernameAdditionalClaims {
        username: None,
        extra: Default::default(),
      })
    }
    .mint();
    let JwtOrTwoFactor::Jwt(jwt) =
      run(&auth, &session, &token).await.unwrap()
    else {
      panic!("expected a jwt")
    };
    let claims = auth.jwt.decode_claims(&jwt.jwt).unwrap();
    assert!(claims.authenticated_at().abs_diff(now - 30 * 60) <= 5);
    // Valid like any other token
    assert!(claims.iat.abs_diff(now) <= 5);
  }

  /// Where the `/token` endpoint has to reject the
  /// user, the login api continues with the second factor.
  #[tokio::test]
  async fn test_continues_with_second_factor_without_issuing_jwt() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: false,
      totp: true,
      ..Default::default()
    }));
    let session = session();
    let res = run(&auth, &session, &token()).await.unwrap();
    assert!(matches!(res, JwtOrTwoFactor::Totp {}));
    // The user to complete 'CompleteTotpLogin' for is on the session
    assert_eq!(
      session.begin_totp_login_attempt().await.unwrap(),
      "user-id"
    );
    // The session is not authenticated by the exchange alone
    assert!(session.retrieve_authenticated_user_id().await.is_err());
  }

  #[tokio::test]
  async fn test_same_rules_as_token_endpoint() {
    // Unknown user
    let auth = TestAuth::with_user(None);
    let session = session();
    let err = run(&auth, &session, &token()).await.err().unwrap();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(err.error.to_string().contains("No user is linked"));

    // Invalid tokens
    let auth = TestAuth::with_user(Some(TestUser::default()));
    for invalid in ["", "not-a-jwt", &"a".repeat(64 * 1024)] {
      let err = run(&auth, &session, invalid).await.err().unwrap();
      assert_eq!(err.status, StatusCode::BAD_REQUEST, "{invalid}");
    }
    assert!(auth.synced.lock().unwrap().is_empty());

    // Cidr whitelist, before any sync or second factor
    let auth = TestAuth::with_user(Some(TestUser {
      totp: true,
      cidr_whitelist: vec!["192.168.0.0/16".to_string()],
      ..Default::default()
    }));
    let err = run(&auth, &session, &token()).await.err().unwrap();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert!(auth.synced.lock().unwrap().is_empty());
    assert!(session.begin_totp_login_attempt().await.is_err());
  }
}
