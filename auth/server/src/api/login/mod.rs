use std::net::IpAddr;

use anyhow::Context as _;
use axum::{Router, extract::Path, routing::post};
use mogh_auth_client::{
  api::login::*, config::ExternalLoginProviderConfig,
  passkey::RequestChallengeResponse,
};
use mogh_error::Json;
use mogh_rate_limit::WithFailureRateLimit;
use mogh_request_ip::RequestIp;
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumDiscriminants, IntoStaticStr};
use tracing::{debug, info, instrument};
use typeshare::typeshare;
use uuid::Uuid;

use crate::{
  AuthImpl, BoxAuthImpl, Login, LoginKind, SecondFactor,
  api::{Variant, parse_variant_request},
  middleware::check_user_cidr_whitelist,
  provider::{
    external::list_external_providers_lossy, jwt::EncodedJwt,
  },
  session::Session,
  user::AuthUserImpl,
};

pub mod external;
pub mod local;
pub mod passkey;
pub mod totp;

pub struct LoginArgs {
  auth: BoxAuthImpl,
  session: Session,
  ip: IpAddr,
}

#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[args(LoginArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[strum_discriminants(
  name(LoginRequestMethod),
  derive(Display, IntoStaticStr)
)]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names, clippy::large_enum_variant)]
pub enum LoginRequest {
  GetLoginOptions(GetLoginOptions),
  ExchangeForJwt(ExchangeForJwt),
  ExchangeExternalForJwt(ExchangeExternalForJwt),
  SignUpLocalUser(SignUpLocalUser),
  LoginLocalUser(LoginLocalUser),
  CompletePasskeyLogin(CompletePasskeyLogin),
  CompleteTotpLogin(CompleteTotpLogin),
  CompleteTotpRecoveryLogin(CompleteTotpRecoveryLogin),
}

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/", post(handler::<I>))
    .route("/{variant}", post(variant_handler::<I>))
}

async fn variant_handler<I: AuthImpl>(
  ip: RequestIp,
  session: Session,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: LoginRequest = parse_variant_request(variant, params)?;
  handler::<I>(ip, session, Json(req)).await
}

async fn handler<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  session: Session,
  Json(request): Json<LoginRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let req_id = Uuid::new_v4();
  let method: LoginRequestMethod = (&request).into();
  crate::context::set_request_method(method.into());

  debug!(
    api = "Auth Login",
    req_id = req_id.to_string(),
    method = method.to_string(),
  );

  let args = LoginArgs {
    auth: Box::new(I::new()),
    session,
    ip,
  };

  let res = request.resolve(&args).await;

  if let Err(e) = &res {
    debug!(
      api = "Auth Login",
      req_id = req_id.to_string(),
      method = method.to_string(),
      "ERROR: {:#}",
      e.error
    );
  }

  res.map(|res| res.0)
}

/// How the token of a login is issued, see [issue_login].
pub(crate) enum IssueToken {
  /// For the app's ttl, a login now.
  Now,
  /// For `ttl_ms` (capped at the app's ttl), a login now: a
  /// workload's token.
  Ttl(u128),
  /// For the app's ttl, a login when the provider authenticated the
  /// user (unix seconds): token exchange, see
  /// [JwtProvider::encode_sub_with_auth_time][crate::provider::jwt::JwtProvider::encode_sub_with_auth_time].
  AuthTime(u64),
}

/// Issues the token of a login of the user `user_id` (`username`),
/// and records the login ([AuthImpl::record_login]) with the token's
/// own expiry. Encoded first, so the record says when the token the
/// user gets expires (without a second computation of it), and handed
/// out only once the hook accepted the login. The one way every login
/// which issues a token is recorded: a local sign up or login, a
/// second factor completed, a token exchange.
pub(crate) async fn issue_login<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: &str,
  username: &str,
  ip: IpAddr,
  kind: LoginKind,
  second_factor: Option<SecondFactor>,
  issue: IssueToken,
) -> mogh_error::Result<EncodedJwt> {
  let jwt = auth.jwt_provider();
  let token = match issue {
    IssueToken::Now => jwt.encode_sub(user_id),
    IssueToken::Ttl(ttl_ms) => {
      jwt.encode_sub_with_ttl(user_id, ttl_ms)
    }
    IssueToken::AuthTime(auth_time) => {
      jwt.encode_sub_with_auth_time(user_id, auth_time)
    }
  }?;
  auth
    .record_login(Login {
      user_id: user_id.to_string(),
      username: username.to_string(),
      ip,
      kind,
      second_factor,
      token_expires: token.exp,
    })
    .await?;
  Ok(token)
}

/// The second factor a login continues with, begun on the session
/// by [begin_second_factor].
pub(crate) enum SecondFactorChallenge {
  /// Completed with `CompletePasskeyLogin`, signing this challenge.
  Passkey(RequestChallengeResponse),
  /// Completed with `CompleteTotpLogin` (or a recovery code).
  Totp,
}

/// Begins the second factor of a login whose first factor passed, if
/// the user is enrolled in one: their passkey if they have one, else
/// TOTP. The login's first factor (`kind`, which records the login
/// once it is complete) is stored on the session with it, and the
/// session id is cycled. `None` for a user enrolled in neither.
///
/// The one place the precedence and the session state of a second
/// factor are decided, for local logins and the external ones (a
/// provider's callback, `ExchangeExternalForJwt`) alike.
pub(crate) async fn begin_second_factor<I: AuthImpl + ?Sized>(
  auth: &I,
  session: &Session,
  user: &dyn AuthUserImpl,
  kind: &LoginKind,
) -> mogh_error::Result<Option<SecondFactorChallenge>> {
  match (user.passkey(), user.totp_secret()) {
    (Some(passkey), _) => {
      let passkeys = auth.passkey_provider().context(
        "No passkey provider available, possibly invalid 'host' config.",
      )?;
      let (response, state) = passkeys
        .start_passkey_authentication(passkey)
        .context("Failed to start passkey authentication flow")?;
      session.insert_passkey_login(user.id(), &state).await?;
      session.insert_login_kind(kind).await?;
      info!(
        user_id = user.id(),
        username = user.username(),
        "Passkey 2FA flow initiated"
      );
      Ok(Some(SecondFactorChallenge::Passkey(response)))
    }
    (None, Some(_)) => {
      session.insert_totp_login_user_id(user.id()).await?;
      session.insert_login_kind(kind).await?;
      info!(
        user_id = user.id(),
        username = user.username(),
        "TOTP 2FA flow initiated"
      );
      Ok(Some(SecondFactorChallenge::Totp))
    }
    (None, None) => Ok(None),
  }
}

pub async fn get_login_options<I: AuthImpl + ?Sized>(
  auth: &I,
) -> GetLoginOptionsResponse {
  // Only lists the static providers if the stored ones fail
  // to load, so the login page stays usable.
  let providers = list_external_providers_lossy(auth)
    .await
    .into_iter()
    .map(|resolved| resolved.provider)
    .filter(|provider| provider.enabled())
    .collect::<Vec<_>>();

  let auto_redirect = providers
    .iter()
    .find(|provider| {
      matches!(
        &provider.config,
        ExternalLoginProviderConfig::Oidc(config) if config.auto_redirect
      )
    })
    .map(|provider| provider.slug().to_string());

  GetLoginOptionsResponse {
    local: auth.local_auth_enabled(),
    registration_disabled: auth.local_registration_disabled(),
    providers: providers
      .into_iter()
      .map(|provider| LoginOptionsProvider {
        kind: provider.kind(),
        registration_disabled: auth
          .external_registration_disabled(&provider),
        slug: provider.slug().to_string(),
        id: provider.id,
        name: provider.name,
      })
      .collect(),
    auto_redirect,
  }
}

impl Resolve<LoginArgs> for GetLoginOptions {
  async fn resolve(
    self,
    LoginArgs { auth, .. }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    Ok(get_login_options(auth.as_ref()).await)
  }
}

impl Resolve<LoginArgs> for ExchangeForJwt {
  #[instrument("ExchangeForJwt", skip_all, fields(ip = ip.to_string()))]
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    // Taken before the rate limit: a session without a completed
    // login (or with an expired one) holds nothing to guess, and is
    // refused without counting against the ip. Anyone can get a
    // browser to send it with a `redeem_ready=true` link: mogh_ui's
    // useAuthState redeems one on every page load, since the login
    // waits in the visitor's own session and completes in whichever
    // tab it returns to. A client over the limit loses the login all
    // the same, and logs in again.
    let login = session.retrieve_authenticated_user_id().await?;
    async {
      let user = auth.get_user(login.user_id).await?;
      check_user_cidr_whitelist(user.as_ref(), *ip)?;
      // A login when the provider's callback completed it, not now.
      auth
        .jwt_provider()
        .encode_sub_with_auth_time(user.id(), login.authenticated_at)
        .map(Into::into)
        .map_err(Into::into)
    }
    .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), ip)
    .await
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    AuthImpl,
    test_support::{session, stub_auth_impl},
  };
  use mogh_auth_client::config::{
    ExternalLoginKind, ExternalLoginProvider, NamedOauthConfig,
    OidcConfig,
  };

  /// Minimal AuthImpl for testing
  struct TestAuth {
    local: bool,
    static_providers: Vec<ExternalLoginProvider>,
    stored_providers: Option<Vec<ExternalLoginProvider>>,
    registration_disabled: bool,
    local_registration_disabled: Option<bool>,
  }

  impl TestAuth {
    fn default_test() -> Self {
      Self {
        local: true,
        static_providers: Vec::new(),
        stored_providers: Some(Vec::new()),
        registration_disabled: false,
        local_registration_disabled: None,
      }
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::default_test()
    }

    fn local_auth_enabled(&self) -> bool {
      self.local
    }

    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      self.static_providers.clone()
    }

    fn list_external_providers(
      &self,
    ) -> crate::DynFuture<
      mogh_error::Result<Vec<ExternalLoginProvider>>,
    > {
      let providers = self.stored_providers.clone();
      Box::pin(async move {
        providers.ok_or_else(|| {
          anyhow::anyhow!("database unavailable").into()
        })
      })
    }

    fn registration_disabled(&self) -> bool {
      self.registration_disabled
    }

    fn local_registration_disabled(&self) -> bool {
      self
        .local_registration_disabled
        .unwrap_or_else(|| self.registration_disabled())
    }

    stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
  }

  fn oidc(
    id: &str,
    enabled: bool,
    auto_redirect: bool,
  ) -> ExternalLoginProvider {
    ExternalLoginProvider {
      id: id.to_string(),
      name: format!("OIDC {id}"),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Oidc(OidcConfig {
        enabled,
        provider: "https://idp.example.com".into(),
        client_id: "test-id".into(),
        auto_redirect,
        ..Default::default()
      }),
    }
  }

  fn github(
    id: &str,
    registration_disabled: bool,
  ) -> ExternalLoginProvider {
    ExternalLoginProvider {
      id: id.to_string(),
      name: format!("Github {id}"),
      registration_disabled,
      slug: String::new(),
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Github(NamedOauthConfig {
        enabled: true,
        client_id: "test-id".into(),
        client_secret: "test-secret".into(),
      }),
    }
  }

  #[test]
  fn test_registration_disabled_defaults() {
    // Local and external registration fall
    // back to the global registration_disabled flag.
    let auth = TestAuth {
      registration_disabled: true,
      ..TestAuth::default_test()
    };
    assert!(auth.local_registration_disabled());
    assert!(auth.external_registration_disabled(&github("a", false)));

    let auth = TestAuth::default_test();
    assert!(!auth.local_registration_disabled());
    assert!(
      !auth.external_registration_disabled(&github("a", false))
    );
    // Provider level setting
    assert!(auth.external_registration_disabled(&github("a", true)));
  }

  #[test]
  fn test_global_disabled_local_override_enabled() {
    let auth = TestAuth {
      registration_disabled: true,
      local_registration_disabled: Some(false),
      ..TestAuth::default_test()
    };
    assert!(!auth.local_registration_disabled());
    assert!(auth.external_registration_disabled(&github("a", false)));
  }

  #[tokio::test]
  async fn test_login_options_without_providers() {
    let opts = get_login_options(&TestAuth::default_test()).await;
    assert!(opts.local);
    assert!(!opts.registration_disabled);
    assert!(opts.providers.is_empty());
    assert_eq!(opts.auto_redirect, None);
  }

  #[tokio::test]
  async fn test_login_options_lists_enabled_static_and_stored_providers()
   {
    let auth = TestAuth {
      static_providers: vec![oidc("oidc", true, false)],
      stored_providers: Some(vec![
        github("abc", true),
        oidc("disabled", false, false),
      ]),
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth).await;
    assert_eq!(
      opts.providers,
      vec![
        LoginOptionsProvider {
          id: "oidc".into(),
          name: "OIDC oidc".into(),
          kind: ExternalLoginKind::Oidc,
          registration_disabled: false,
          slug: "oidc".into(),
        },
        LoginOptionsProvider {
          id: "abc".into(),
          name: "Github abc".into(),
          kind: ExternalLoginKind::Github,
          registration_disabled: true,
          slug: "abc".into(),
        },
      ]
    );
  }

  #[tokio::test]
  async fn test_login_options_never_include_provider_config() {
    let auth = TestAuth {
      stored_providers: Some(vec![github("abc", false)]),
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth).await;
    let json = serde_json::to_string(&opts).unwrap();
    assert!(!json.contains("test-secret"));
    assert!(!json.contains("test-id"));
  }

  #[tokio::test]
  async fn test_login_options_survive_stored_provider_failure() {
    let auth = TestAuth {
      static_providers: vec![oidc("oidc", true, false)],
      stored_providers: None,
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth).await;
    assert!(opts.local);
    assert_eq!(opts.providers.len(), 1);
    assert_eq!(opts.providers[0].id, "oidc");
  }

  #[tokio::test]
  async fn test_auto_redirect_first_enabled_oidc_provider() {
    let auth = TestAuth {
      static_providers: vec![oidc("oidc", true, false)],
      stored_providers: Some(vec![
        // Disabled providers are never redirected to
        oidc("disabled", false, true),
        oidc("first", true, true),
        oidc("second", true, true),
      ]),
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth).await;
    assert_eq!(opts.auto_redirect.as_deref(), Some("first"));
  }

  /// One user, `user-1`, and a rate limiter allowing one failure
  /// per ip.
  struct RedeemAuth {
    limiter: std::sync::Arc<mogh_rate_limit::RateLimiter>,
  }

  impl RedeemAuth {
    fn args(session: Session) -> LoginArgs {
      LoginArgs {
        auth: Box::new(RedeemAuth {
          limiter: mogh_rate_limit::RateLimiter::new(
            false,
            1,
            std::time::Duration::from_secs(60),
          ),
        }),
        session,
        ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3)),
      }
    }
  }

  struct RedeemUser;

  impl crate::user::AuthUserImpl for RedeemUser {
    fn id(&self) -> &str {
      "user-1"
    }
    fn username(&self) -> &str {
      "user"
    }
  }

  impl AuthImpl for RedeemAuth {
    fn new() -> Self {
      unimplemented!("built by RedeemAuth::args")
    }

    fn get_user(
      &self,
      user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      Box::pin(async move {
        if user_id == "user-1" {
          Ok(Box::new(RedeemUser) as crate::user::BoxAuthUser)
        } else {
          // UNAUTHORIZED, as AuthImpl::get_user asks: a server
          // error is no failed attempt (mogh_rate_limit 3.0).
          Err(mogh_error::AddStatusCodeError::status_code(
            anyhow::anyhow!("User not found"),
            reqwest::StatusCode::UNAUTHORIZED,
          ))
        }
      })
    }

    stub_auth_impl!(handle_request_authentication, jwt_provider);

    fn general_rate_limiter(&self) -> &mogh_rate_limit::RateLimiter {
      &self.limiter
    }
  }

  fn unix_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_secs()
  }

  /// The JWT of an external login counts as a login from when the
  /// provider's callback completed it, not from its exchange: a
  /// login redeemed late isn't a fresh one for the reauthentication
  /// window.
  #[tokio::test]
  async fn test_exchange_for_jwt_counts_from_the_callback() {
    let completed = unix_timestamp_secs() - 90;
    let session = session();
    session
      .insert_authenticated_user("user-1", completed)
      .await
      .unwrap();
    let args = RedeemAuth::args(session);
    let jwt = ExchangeForJwt {}.resolve(&args).await.unwrap().jwt;
    let claims =
      args.auth.jwt_provider().decode_claims(&jwt).unwrap();
    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.auth_time, Some(completed));
    assert_eq!(claims.authenticated_at(), completed);
    assert!(claims.iat >= completed + 90);
    // Only once.
    let err = ExchangeForJwt {}.resolve(&args).await.unwrap_err();
    assert_eq!(err.status, reqwest::StatusCode::UNAUTHORIZED);
  }

  /// The login steps which find nothing to complete on the session
  /// (nothing pending, or expired) are refused without counting
  /// against the ip: there is nothing to guess, and anyone can get a
  /// browser to send `ExchangeForJwt` (eg. with a link to an app
  /// which redeems any `redeem_ready=true` in its url). The
  /// credential checks still count.
  #[tokio::test]
  async fn test_nothing_to_complete_is_not_counted() {
    let args = RedeemAuth::args(session());
    let credential: mogh_auth_client::passkey::PublicKeyCredential =
      serde_json::from_value(serde_json::json!({
        "id": "AQID",
        "rawId": "AQID",
        "response": {
          "authenticatorData": "AQID",
          "clientDataJSON": "AQID",
          "signature": "AQID",
          "userHandle": null,
        },
        "extensions": {},
        "type": "public-key",
      }))
      .unwrap();
    let expired = unix_timestamp_secs()
      - Session::MAX_SECOND_FACTOR_LOGIN_AGE.as_secs()
      - 60;
    for _ in 0..3 {
      // Expired logins, then nothing pending.
      args
        .session
        .insert_authenticated_user("user-1", expired)
        .await
        .unwrap();
      args
        .session
        .insert_totp_login("user-1", expired)
        .await
        .unwrap();
      for request in [
        LoginRequest::ExchangeForJwt(ExchangeForJwt {}),
        LoginRequest::ExchangeForJwt(ExchangeForJwt {}),
        LoginRequest::CompleteTotpLogin(CompleteTotpLogin {
          code: "123456".into(),
        }),
        LoginRequest::CompleteTotpLogin(CompleteTotpLogin {
          code: "123456".into(),
        }),
        LoginRequest::CompleteTotpRecoveryLogin(
          CompleteTotpRecoveryLogin {
            code: "recovery".into(),
          },
        ),
        LoginRequest::CompletePasskeyLogin(CompletePasskeyLogin {
          credential: credential.clone(),
        }),
      ] {
        let method = LoginRequestMethod::from(&request);
        let err = request.resolve(&args).await.err().unwrap();
        assert_eq!(
          err.status,
          reqwest::StatusCode::UNAUTHORIZED,
          "{method}"
        );
        let message = format!("{:#}", err.error);
        assert!(!message.contains("attempts remaining"), "{message}");
      }
    }

    // A completed login of a user who can't be found counts...
    args
      .session
      .insert_authenticated_user_id("unknown")
      .await
      .unwrap();
    let err = ExchangeForJwt {}.resolve(&args).await.unwrap_err();
    assert!(
      format!("{:#}", err.error).contains("0 attempts remaining"),
      "{:#}",
      err.error
    );
    // ...and the ip is out of attempts.
    args
      .session
      .insert_authenticated_user_id("user-1")
      .await
      .unwrap();
    let err = ExchangeForJwt {}.resolve(&args).await.unwrap_err();
    assert_eq!(err.status, reqwest::StatusCode::TOO_MANY_REQUESTS);
  }

  /// A user enrolled in a passkey and / or TOTP.
  struct EnrolledUser {
    passkey: bool,
    totp: bool,
  }

  impl crate::user::AuthUserImpl for EnrolledUser {
    fn id(&self) -> &str {
      "user-1"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn passkey(&self) -> Option<crate::passkey::Passkey> {
      self
        .passkey
        .then(|| crate::provider::passkey::test_passkey(&[1; 16]))
    }
    fn totp_secret(&self) -> Option<&str> {
      self.totp.then_some("secret")
    }
  }

  struct PasskeyAuth;

  impl AuthImpl for PasskeyAuth {
    fn new() -> Self {
      PasskeyAuth
    }
    fn passkey_provider(
      &self,
    ) -> Option<&crate::provider::passkey::PasskeyProvider> {
      static PROVIDER: std::sync::LazyLock<
        crate::provider::passkey::PasskeyProvider,
      > = std::sync::LazyLock::new(|| {
        crate::provider::passkey::PasskeyProvider::new(
          "https://example.com",
        )
        .unwrap()
      });
      Some(&PROVIDER)
    }
    stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
  }

  /// One precedence for every first factor: the passkey before TOTP,
  /// stored on the session with the first factor's kind (which records
  /// the login once complete). Nothing for a user without either.
  #[tokio::test]
  async fn test_begin_second_factor() {
    let provider = LoginKind::Provider {
      provider_id: "oidc".into(),
      provider_name: "OIDC".into(),
    };
    for kind in [LoginKind::Local, provider] {
      let begin = |passkey, totp| {
        let session = session();
        let kind = kind.clone();
        async move {
          let challenge = begin_second_factor(
            &PasskeyAuth,
            &session,
            &EnrolledUser { passkey, totp },
            &kind,
          )
          .await
          .unwrap();
          (challenge, session)
        }
      };

      let (challenge, session) = begin(false, false).await;
      assert!(challenge.is_none());
      assert!(!session.0.is_modified());

      let (challenge, session) = begin(false, true).await;
      assert!(matches!(challenge, Some(SecondFactorChallenge::Totp)));
      assert_eq!(
        session.begin_totp_login_attempt().await.unwrap(),
        "user-1"
      );
      assert_eq!(session.take_login_kind().await, kind);

      for totp in [false, true] {
        let (challenge, session) = begin(true, totp).await;
        assert!(matches!(
          challenge,
          Some(SecondFactorChallenge::Passkey(_))
        ));
        let (user_id, _, stored_kind) =
          session.retrieve_passkey_login().await.unwrap();
        assert_eq!(user_id, "user-1");
        assert_eq!(stored_kind, kind);
        assert!(session.begin_totp_login_attempt().await.is_err());
      }
    }
  }

  #[tokio::test]
  async fn test_auto_redirect_none_when_not_fully_enabled() {
    let mut provider = oidc("oidc", true, true);
    let ExternalLoginProviderConfig::Oidc(config) =
      &mut provider.config
    else {
      unreachable!()
    };
    // Enabled but missing client id
    config.client_id = String::new();
    let auth = TestAuth {
      static_providers: vec![provider],
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth).await;
    assert!(opts.providers.is_empty());
    assert_eq!(opts.auto_redirect, None);
  }
}
