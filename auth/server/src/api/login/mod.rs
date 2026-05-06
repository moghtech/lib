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
<<<<<<< granular-registration-control
    registration_disabled: auth.local_registration_disabled(),
=======
    registration_disabled: auth.registration_disabled(),
    oidc_auto_redirect: auth
      .oidc_config()
      .map(|config| config.enabled() && config.auto_redirect)
      .unwrap_or_default(),
>>>>>>> main
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::AuthImpl;
  use mogh_auth_client::config::OidcConfig;

<<<<<<< granular-registration-control
  /// Minimal AuthImpl for testing
=======
  /// Minimal AuthImpl for testing get_login_options
>>>>>>> main
  struct TestAuth {
    local: bool,
    oidc: Option<OidcConfig>,
    registration_disabled: bool,
<<<<<<< granular-registration-control
    local_registration_disabled: Option<bool>,
    oidc_registration_disabled: Option<bool>,
=======
>>>>>>> main
  }

  impl TestAuth {
    fn default_test() -> Self {
      Self {
        local: true,
        oidc: None,
        registration_disabled: false,
<<<<<<< granular-registration-control
        local_registration_disabled: None,
        oidc_registration_disabled: None,
=======
>>>>>>> main
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

<<<<<<< granular-registration-control
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

=======
>>>>>>> main
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

<<<<<<< granular-registration-control
    fn jwt_provider(
      &self,
    ) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for these tests")
=======
    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for login options tests")
>>>>>>> main
    }
  }

  #[test]
<<<<<<< granular-registration-control
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
=======
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
>>>>>>> main
  }
}

impl Resolve<LoginArgs> for ExchangeForJwt {
  #[instrument("ExchangeForJwt", skip_all, fields(ip = ip.to_string()))]
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let user_id = session.retrieve_authenticated_user_id().await?;
      auth.jwt_provider().encode_sub(&user_id).map_err(Into::into)
    }
    .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), ip)
    .await
  }
}
