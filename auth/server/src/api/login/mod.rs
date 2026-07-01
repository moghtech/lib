use std::net::IpAddr;

use axum::{Router, extract::Path, routing::post};
use mogh_auth_client::api::login::*;
use mogh_error::Json;
use mogh_rate_limit::WithFailureRateLimit;
use mogh_request_ip::RequestIp;
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use serde_json::json;
use strum::{Display, EnumDiscriminants};
use tracing::{debug, instrument};
use typeshare::typeshare;
use uuid::Uuid;

use crate::{AuthImpl, BoxAuthImpl, api::Variant, session::Session};

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
#[strum_discriminants(name(LoginRequestMethod), derive(Display))]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names, clippy::large_enum_variant)]
pub enum LoginRequest {
  GetLoginOptions(GetLoginOptions),
  ExchangeForJwt(ExchangeForJwt),
  ExchangeProviderTokenForJwt(ExchangeProviderTokenForJwt),
  SignUpLocalUser(SignUpLocalUser),
  LoginLocalUser(LoginLocalUser),
  CompletePasskeyLogin(CompletePasskeyLogin),
  CompleteTotpLogin(CompleteTotpLogin),
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
  let req: LoginRequest = serde_json::from_value(json!({
    "type": variant,
    "params": params,
  }))?;
  handler::<I>(ip, session, Json(req)).await
}

async fn handler<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  session: Session,
  Json(request): Json<LoginRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let req_id = Uuid::new_v4();
  let method: LoginRequestMethod = (&request).into();

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

pub fn get_login_options<I: AuthImpl + ?Sized>(
  auth: &I,
) -> GetLoginOptionsResponse {
  GetLoginOptionsResponse {
    local: auth.local_auth_enabled(),
    oidc: auth
      .oidc_config()
      .map(|config| config.enabled())
      .unwrap_or_default(),
    github: auth
      .github_config()
      .map(|config| config.enabled())
      .unwrap_or_default(),
    google: auth
      .google_config()
      .map(|config| config.enabled())
      .unwrap_or_default(),
    registration_disabled: auth.local_registration_disabled(),
    oidc_auto_redirect: auth
      .oidc_config()
      .map(|config| config.enabled() && config.auto_redirect)
      .unwrap_or_default(),
  }
}

impl Resolve<LoginArgs> for GetLoginOptions {
  async fn resolve(
    self,
    LoginArgs { auth, .. }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    Ok(get_login_options(auth.as_ref()))
  }
}

impl Resolve<LoginArgs> for ExchangeForJwt {
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    exchange_for_jwt(auth, session, ip).await
  }
}

impl Resolve<LoginArgs> for ExchangeProviderTokenForJwt {
  async fn resolve(
    self,
    LoginArgs { auth, ip, ..}: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    exchange_provider_token_for_jwt(auth, ip, self).await
  }
}

#[instrument("ExchangeForJwt", skip_all, fields(ip = ip.to_string()))]
async fn exchange_for_jwt(
  auth: &BoxAuthImpl,
  session: &Session,
  ip: &IpAddr,
) -> Result<ExchangeForJwtResponse, mogh_error::Error> {
  async {
    let user_id = session.retrieve_authenticated_user_id().await?;
    auth.jwt_provider().encode_sub(&user_id).map_err(Into::into)
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), ip)
  .await
}

#[instrument(
  "ExchangeProviderTokenForJwt", 
  skip_all, 
  fields(ip = ip.to_string(), subject_token_type = %request.subject_token_type)
)]
async fn exchange_provider_token_for_jwt(
  auth: &BoxAuthImpl,
  ip: &IpAddr,
  request: ExchangeProviderTokenForJwt,
) -> Result<ExchangeProviderTokenForJwtResponse, mogh_error::Error> {
  async {
    let user_id = match request.subject_token_type {
      SubjectTokenType::OidcIdToken => {
        auth
          .exchange_and_validate_oidc_token(&request.subject_token)
          .await?
      }
      SubjectTokenType::GitHubAccessToken => {
        auth
          .exchange_and_validate_github_token(&request.subject_token)
          .await?
      }
      SubjectTokenType::GoogleIdToken => {
        auth
          .exchange_and_validate_google_token(&request.subject_token)
          .await?
      }
    };

    auth.jwt_provider().encode_sub(&user_id).map_err(Into::into)
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), ip)
  .await
}

#[cfg(test)]
mod tests {
  use std::net::IpAddr;
  use std::sync::LazyLock;
  use super::*;
  use crate::AuthImpl;
  use crate::provider::jwt::JwtProvider;
  use mogh_auth_client::config::OidcConfig;

  static SHARED_JWT_PROVIDER: LazyLock<JwtProvider> =
    LazyLock::new(
      || JwtProvider::new(
        b"test-secret-login-mod", 
        60_000
      )
    );

  fn loopback() -> IpAddr {
    IpAddr::from([127, 0, 0, 1])
  }

  /// Minimal AuthImpl for testing
  struct TestAuth {
    local: bool,
    oidc: Option<OidcConfig>,
    registration_disabled: bool,
    local_registration_disabled: Option<bool>,
    oidc_registration_disabled: Option<bool>,
  }

  impl TestAuth {
    fn default_test() -> Self {
      Self {
        local: true,
        oidc: None,
        registration_disabled: false,
        local_registration_disabled: None,
        oidc_registration_disabled: None,
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

    fn oidc_config(&self) -> Option<&OidcConfig> {
      self.oidc.as_ref()
    }

    fn registration_disabled(&self) -> bool {
      self.registration_disabled
    }

    fn local_registration_disabled(&self) -> bool {
      self
        .local_registration_disabled
        .unwrap_or_else(|| self.registration_disabled())
    }

    fn oidc_registration_disabled(&self) -> bool {
      self
        .oidc_registration_disabled
        .unwrap_or_else(|| self.registration_disabled())
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn jwt_provider(&self) -> &JwtProvider {
      &SHARED_JWT_PROVIDER
    }
  }

  // ── ExchangeTestAuth — for ExchangeProviderTokenForJwt tests ─────────────────
  //
  // Token contracts (any other value → error):
  //   "oidc_ok"   → subject "oidc-subject"   (OidcIdToken)
  //   "github_ok" → subject "github-subject" (GitHubAccessToken)
  //   "google_ok" → subject "google-subject" (GoogleIdToken)

  struct ExchangeTestAuth;

  impl AuthImpl for ExchangeTestAuth {
    fn new() -> Self {
      Self
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      Box::pin(async { Err(anyhow::anyhow!("not implemented").into()) })
    }

    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn jwt_provider(&self) -> &JwtProvider {
      &SHARED_JWT_PROVIDER
    }

    fn exchange_and_validate_oidc_token(
      &self,
      token: &str,
    ) -> crate::DynFuture<mogh_error::Result<String>> {
      let token = token.to_owned();
      Box::pin(async move {
        if token == "oidc_ok" {
          Ok("oidc-subject".to_string())
        } else {
          Err(anyhow::anyhow!("invalid oidc token").into())
        }
      })
    }

    fn exchange_and_validate_github_token(
      &self,
      token: &str,
    ) -> crate::DynFuture<mogh_error::Result<String>> {
      let token = token.to_owned();
      Box::pin(async move {
        if token == "github_ok" {
          Ok("github-subject".to_string())
        } else {
          Err(anyhow::anyhow!("invalid github token").into())
        }
      })
    }

    fn exchange_and_validate_google_token(
      &self,
      token: &str,
    ) -> crate::DynFuture<mogh_error::Result<String>> {
      let token = token.to_owned();
      Box::pin(async move {
        if token == "google_ok" {
          Ok("google-subject".to_string())
        } else {
          Err(anyhow::anyhow!("invalid google token").into())
        }
      })
    }
  }

  fn exchange_auth() -> crate::BoxAuthImpl {
    Box::new(ExchangeTestAuth)
  }

  fn exchange_request(
    token_type: SubjectTokenType,
    token: &str,
  ) -> ExchangeProviderTokenForJwt {
    ExchangeProviderTokenForJwt {
      subject_token_type: token_type,
      subject_token: token.to_string(),
    }
  }

  async fn assert_exchange_subject(
    token_type: SubjectTokenType,
    token: &str,
    expected_subject: &str,
  ) {
    let response =
      exchange_provider_token_for_jwt(
        &exchange_auth(), 
        &loopback(), 
        exchange_request(token_type, token)
      )
        .await
        .expect("exchange should succeed");
    let subject = SHARED_JWT_PROVIDER
      .decode_sub(&response.jwt)
      .expect("jwt should decode");
    assert_eq!(subject, expected_subject);
  }

  async fn assert_exchange_fails(token_type: SubjectTokenType, token: &str) {
    let result =
      exchange_provider_token_for_jwt(
        &exchange_auth(),
        &loopback(),
        exchange_request(token_type, token)
      )
        .await;
    assert!(
      result.is_err(),
      "exchange should have failed for token {token:?} but succeeded"
    );
  }

  #[test]
  fn test_default_granular_methods_delegate_to_registration_disabled()
  {
    // When granular overrides are None, they should
    // fall back to the global registration_disabled flag.
    let auth = TestAuth {
      registration_disabled: true,
      ..TestAuth::default_test()
    };
    assert!(auth.local_registration_disabled());
    assert!(auth.oidc_registration_disabled());
    assert!(auth.github_registration_disabled());
    assert!(auth.google_registration_disabled());
  }

  #[test]
  fn test_global_disabled_local_override_enabled() {
    // Global registration disabled, but local override allows it
    let auth = TestAuth {
      registration_disabled: true,
      local_registration_disabled: Some(false),
      ..TestAuth::default_test()
    };
    assert!(!auth.local_registration_disabled());
    assert!(auth.oidc_registration_disabled());
  }

  #[test]
  fn test_global_enabled_local_override_disabled() {
    // Global registration enabled, but local override blocks it
    let auth = TestAuth {
      registration_disabled: false,
      local_registration_disabled: Some(true),
      ..TestAuth::default_test()
    };
    assert!(auth.local_registration_disabled());
    assert!(!auth.oidc_registration_disabled());
  }

  #[test]
  fn test_disable_local_allow_oidc() {
    // The #1087 use case: disable local signup, allow OIDC
    let auth = TestAuth {
      registration_disabled: false,
      local_registration_disabled: Some(true),
      oidc_registration_disabled: Some(false),
      ..TestAuth::default_test()
    };
    assert!(auth.local_registration_disabled());
    assert!(!auth.oidc_registration_disabled());
  }

  #[test]
  fn test_registration_disabled_reflects_local_in_login_options() {
    // registration_disabled in the response controls the Sign Up button,
    // which is local-only. It should reflect local_registration_disabled.
    let auth = TestAuth {
      registration_disabled: false,
      local_registration_disabled: Some(true),
      oidc_registration_disabled: Some(false),
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth);
    assert!(opts.registration_disabled);
  }

  #[test]
  fn test_registration_disabled_false_when_local_allowed() {
    let auth = TestAuth {
      registration_disabled: true,
      local_registration_disabled: Some(false),
      oidc_registration_disabled: Some(true),
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth);
    assert!(!opts.registration_disabled);
  }

  #[test]
  fn test_oidc_auto_redirect_defaults_false() {
    let auth = TestAuth::default_test();
    let opts = get_login_options(&auth);
    assert!(!opts.oidc_auto_redirect);
  }

  #[test]
  fn test_oidc_auto_redirect_false_when_disabled() {
    let auth = TestAuth {
      oidc: Some(OidcConfig {
        enabled: true,
        provider: "https://idp.example.com".into(),
        client_id: "test-id".into(),
        auto_redirect: false,
        ..Default::default()
      }),
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth);
    assert!(opts.oidc);
    assert!(!opts.oidc_auto_redirect);
  }

  #[test]
  fn test_oidc_auto_redirect_true_when_enabled() {
    let auth = TestAuth {
      oidc: Some(OidcConfig {
        enabled: true,
        provider: "https://idp.example.com".into(),
        client_id: "test-id".into(),
        auto_redirect: true,
        ..Default::default()
      }),
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth);
    assert!(opts.oidc);
    assert!(opts.oidc_auto_redirect);
  }

  #[test]
  fn test_oidc_auto_redirect_false_when_oidc_not_fully_enabled() {
    // auto_redirect is true but OIDC is not fully enabled (missing client_id)
    let auth = TestAuth {
      oidc: Some(OidcConfig {
        enabled: true,
        provider: "https://idp.example.com".into(),
        client_id: String::new(), // empty = not fully enabled
        auto_redirect: true,
        ..Default::default()
      }),
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth);
    assert!(!opts.oidc);
    assert!(!opts.oidc_auto_redirect);
  }

  #[test]
  fn test_oidc_auto_redirect_false_when_no_oidc_config() {
    let auth = TestAuth {
      oidc: None,
      ..TestAuth::default_test()
    };
    let opts = get_login_options(&auth);
    assert!(!opts.oidc_auto_redirect);
  }

  #[tokio::test]
  async fn test_exchange_oidc_mints_jwt_for_correct_subject() {
    assert_exchange_subject(
      SubjectTokenType::OidcIdToken, 
      "oidc_ok", 
      "oidc-subject"
    ).await;
  }

  #[tokio::test]
  async fn test_exchange_github_mints_jwt_for_correct_subject() {
    assert_exchange_subject(
      SubjectTokenType::GitHubAccessToken, 
      "github_ok", 
      "github-subject"
    ).await;
  }

  #[tokio::test]
  async fn test_exchange_google_mints_jwt_for_correct_subject() {
    assert_exchange_subject(
      SubjectTokenType::GoogleIdToken, 
      "google_ok", 
      "google-subject"
    ).await;
  }

  #[tokio::test]
  async fn test_exchange_oidc_invalid_token_returns_error() {
    assert_exchange_fails(
      SubjectTokenType::OidcIdToken, 
      "invalid"
    ).await;
  }

  #[tokio::test]
  async fn test_exchange_github_invalid_token_returns_error() {
    assert_exchange_fails(
      SubjectTokenType::GitHubAccessToken, 
      "invalid"
    ).await;
  }

  #[tokio::test]
  async fn test_exchange_google_invalid_token_returns_error() {
    assert_exchange_fails(
      SubjectTokenType::GoogleIdToken, 
      "invalid"
    ).await;
  }

  #[tokio::test]
  async fn test_exchange_empty_token_returns_error() {
    assert_exchange_fails(
      SubjectTokenType::OidcIdToken, 
      ""
    ).await;
  }

  #[tokio::test]
  async fn test_exchange_oidc_token_presented_as_github_returns_error() {
    assert_exchange_fails(
      SubjectTokenType::GitHubAccessToken, 
      "oidc_ok"
    ).await;
  }

  #[tokio::test]
  async fn test_exchange_github_token_presented_as_oidc_returns_error() {
    assert_exchange_fails(
      SubjectTokenType::OidcIdToken, 
      "github_ok"
    ).await;
  }

  #[tokio::test]
  async fn test_exchange_google_token_presented_as_github_returns_error() {
    assert_exchange_fails(
      SubjectTokenType::GitHubAccessToken, 
      "google_ok"
    ).await;
  }
}
