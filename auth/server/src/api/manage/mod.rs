use std::sync::Arc;

use axum::{Router, extract::Path, http::HeaderMap, routing::post};
use mogh_auth_client::api::{NoData, manage::*};
use mogh_error::{AddStatusCodeError as _, Json};
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumDiscriminants, IntoStaticStr};
use tracing::debug;
use typeshare::typeshare;
use uuid::Uuid;

use crate::{
  AuthImpl,
  api::{Variant, parse_variant_request},
  middleware::{
    AuthenticatedAt, UserExtractor, check_login_age,
    extract_request_jwt,
  },
  session::Session,
  user::BoxAuthUser,
};

pub mod api_key;
pub mod external;
pub mod issuer;
pub mod local;
pub mod passkey;
pub mod provider;
pub mod totp;

pub(crate) mod middleware;

use middleware::attach_user;

pub struct ManageArgs {
  /// Shared, so work which has to complete even when the request is
  /// dropped can own it in a task (a trusted issuer update).
  auth: Arc<dyn AuthImpl>,
  user: Arc<BoxAuthUser>,
  session: Session,
  /// The session token the request authenticated with: kept valid
  /// when the request changes how the user logs in
  /// ([AuthImpl::credentials_changed]).
  jwt: Option<String>,
}

impl ManageArgs {
  /// [AuthImpl::credentials_changed] for the user of the request,
  /// keeping its session.
  async fn credentials_changed(
    &self,
    change: crate::CredentialChange,
  ) -> mogh_error::Result<()> {
    self
      .auth
      .credentials_changed(
        self.user.id().to_string(),
        change,
        self.jwt.clone(),
      )
      .await
  }
}

#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[args(ManageArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[strum_discriminants(
  name(ManageRequestMethod),
  derive(Display, IntoStaticStr)
)]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names, clippy::large_enum_variant)]
pub enum ManageRequest {
  GetUserId(GetUserId),
  // Local
  UpdateUsername(UpdateUsername),
  UpdatePassword(UpdatePassword),
  // External
  BeginExternalLoginLink(BeginExternalLoginLink),
  UnlinkLocalLogin(UnlinkLocalLogin),
  UnlinkExternalLogin(UnlinkExternalLogin),
  // External login providers (admin)
  ListExternalLoginProviders(ListExternalLoginProviders),
  CreateExternalLoginProvider(CreateExternalLoginProvider),
  UpdateExternalLoginProvider(UpdateExternalLoginProvider),
  DeleteExternalLoginProvider(DeleteExternalLoginProvider),
  // Trusted issuers for workload identity (admin)
  ListTrustedIssuers(ListTrustedIssuers),
  CreateTrustedIssuer(CreateTrustedIssuer),
  UpdateTrustedIssuer(UpdateTrustedIssuer),
  DeleteTrustedIssuer(DeleteTrustedIssuer),
  // Passkey
  BeginPasskeyEnrollment(BeginPasskeyEnrollment),
  ConfirmPasskeyEnrollment(ConfirmPasskeyEnrollment),
  UnenrollPasskey(UnenrollPasskey),
  // TOTP
  BeginTotpEnrollment(BeginTotpEnrollment),
  ConfirmTotpEnrollment(ConfirmTotpEnrollment),
  UnenrollTotp(UnenrollTotp),
  // SKIP 2FA
  UpdateExternalSkip2fa(UpdateExternalSkip2fa),
  // API KEY
  CreateApiKey(CreateApiKey),
  DeleteApiKey(DeleteApiKey),
  // SIGNING KEY
  CreateSigningKey(CreateSigningKey),
  DeleteSigningKey(DeleteSigningKey),
}

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/", post(handler::<I>))
    .route("/{variant}", post(variant_handler::<I>))
    .layer(axum::middleware::from_fn(attach_user::<I>))
}

async fn variant_handler<I: AuthImpl>(
  session: Session,
  user: UserExtractor,
  authenticated_at: AuthenticatedAt,
  headers: HeaderMap,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<axum::response::Response> {
  let req: ManageRequest = parse_variant_request(variant, params)?;
  handler::<I>(session, user, authenticated_at, headers, Json(req))
    .await
}

async fn handler<I: AuthImpl>(
  session: Session,
  UserExtractor(user): UserExtractor,
  AuthenticatedAt(authenticated_at): AuthenticatedAt,
  headers: HeaderMap,
  Json(request): Json<ManageRequest>,
) -> mogh_error::Result<axum::response::Response> {
  let req_id = Uuid::new_v4();
  let method: ManageRequestMethod = (&request).into();
  crate::context::set_request_method(method.into());
  let username = user.username();
  let user_id = user.id();

  debug!(
    api = "Auth Management",
    req_id = req_id.to_string(),
    method = method.to_string(),
    user_id,
    username,
  );

  check_not_workload(user.as_ref().as_ref(), &request)?;
  // Before the window check, which `0` disables: an api key or
  // signing key is refused the account requests whatever the window.
  check_credential_kind(authenticated_at, &request)?;

  let auth = I::new();
  check_recent_login(
    auth.reauthentication_window_secs(),
    auth.jwt_provider().validation().leeway,
    authenticated_at,
    unix_timestamp_secs(),
    &request,
  )?;

  // Held until the flow completes or expires, like the session of
  // a login start: limited per user (AuthImpl::login_start_limiter).
  if begins_login_session(&request) {
    auth.login_start_limiter().take_user_start(user_id)?;
  }
  // The request authenticated with it, a jwt takes precedence over
  // other credentials.
  let jwt = extract_request_jwt(&headers).ok().flatten();

  let args = ManageArgs {
    auth: Arc::new(auth),
    user,
    session,
    jwt,
  };

  let res = request.resolve(&args).await;

  if let Err(e) = &res {
    debug!(
      api = "Auth Management",
      req_id = req_id.to_string(),
      method = method.to_string(),
      "ERROR: {:#}",
      e.error
    );
  }

  res.map(|res| res.0)
}

/// The requests which store a flow on the session, held until it
/// completes or expires.
fn begins_login_session(request: &ManageRequest) -> bool {
  matches!(
    request,
    ManageRequest::BeginExternalLoginLink(_)
      | ManageRequest::BeginPasskeyEnrollment(_)
      | ManageRequest::BeginTotpEnrollment(_)
  )
}

/// Workloads only act through the short lived tokens they get by token
/// exchange. Everything here either creates a way to log in which
/// outlives that (api keys, signing keys, passwords, 2fa, linked
/// logins) or configures who can log in, so all of it is refused,
/// including any request added in the future.
fn check_not_workload(
  user: &dyn crate::user::AuthUserImpl,
  request: &ManageRequest,
) -> mogh_error::Result<()> {
  if !user.is_workload()
    || matches!(request, ManageRequest::GetUserId(_))
  {
    return Ok(());
  }
  Err(
    anyhow::anyhow!(
      "Workload users can't use the auth management API"
    )
    .status_code(axum::http::StatusCode::FORBIDDEN),
  )
}

fn unix_timestamp_secs() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|duration| duration.as_secs())
    .unwrap_or_default()
}

/// Whether the request changes how somebody can log in, see
/// [AuthImpl::reauthentication_window_secs]. Everything does unless it
/// is listed here, including any request added in the future.
fn requires_recent_login(request: &ManageRequest) -> bool {
  !matches!(
    request,
    ManageRequest::GetUserId(_)
      | ManageRequest::ListExternalLoginProviders(_)
      | ManageRequest::ListTrustedIssuers(_)
      // Removing a credential never gives more access.
      | ManageRequest::DeleteApiKey(_)
      | ManageRequest::DeleteSigningKey(_)
  )
}

/// The requests which manage resources rather than the caller's
/// account: the login providers and trusted issuers, whose handlers
/// require an admin. A credential without a login (an api key or
/// signing key, where the app accepts them at all) may perform these
/// — automation manages them — and none of the account requests, see
/// [check_credential_kind].
fn manages_resources(request: &ManageRequest) -> bool {
  matches!(
    request,
    ManageRequest::CreateExternalLoginProvider(_)
      | ManageRequest::UpdateExternalLoginProvider(_)
      | ManageRequest::DeleteExternalLoginProvider(_)
      | ManageRequest::CreateTrustedIssuer(_)
      | ManageRequest::UpdateTrustedIssuer(_)
      | ManageRequest::DeleteTrustedIssuer(_)
  )
}

/// `authenticated_at` is when the user logged in, as for
/// [check_recent_login]
/// ([JwtClaims::authenticated_at][crate::provider::jwt::JwtClaims::authenticated_at]),
/// or `None` for credentials without a login (api keys, signing
/// keys, and tokens the app accepts which [AuthImpl::jwt_provider]
/// did not issue).
/// Only whether there is a login matters here. Those take the resource
/// requests ([manages_resources]) and the ones which need no login
/// ([requires_recent_login]), and are refused the account requests,
/// whatever [AuthImpl::reauthentication_window_secs] is (`0`
/// included): a leaked api key or signing key must not be able to
/// change the password, unenroll 2fa or mint replacement credentials.
fn check_credential_kind(
  authenticated_at: Option<u64>,
  request: &ManageRequest,
) -> mogh_error::Result<()> {
  if authenticated_at.is_some()
    || !requires_recent_login(request)
    || manages_resources(request)
  {
    return Ok(());
  }
  Err(
    anyhow::anyhow!(
      "{REAUTHENTICATION_REQUIRED}: this needs a recent login, credentials without a login (api keys, signing keys) can't be used for it"
    )
    .status_code(axum::http::StatusCode::FORBIDDEN),
  )
}

/// `authenticated_at` is when the user logged in: the `auth_time` of
/// the token, else when it was issued
/// ([JwtClaims::authenticated_at][crate::provider::jwt::JwtClaims::authenticated_at]).
/// A session needs a login within the window for the account and the
/// resource requests alike. `None` (an api key or signing key) has
/// no login to be recent, [check_credential_kind] decides what it may
/// do.
///
/// `leeway_secs` is the clock skew the token validation tolerates
/// ([JwtProvider::validation][crate::provider::jwt::JwtProvider::validation]):
/// a token another instance with a clock running ahead issued a
/// moment ago is a recent login, not one from the future.
///
/// The check an app's own api makes with
/// [require_recent_login][crate::middleware::require_recent_login],
/// for the requests of this api which need it.
fn check_recent_login(
  window_secs: u64,
  leeway_secs: u64,
  authenticated_at: Option<u64>,
  now: u64,
  request: &ManageRequest,
) -> mogh_error::Result<()> {
  if !requires_recent_login(request) {
    return Ok(());
  }
  check_login_age(window_secs, leeway_secs, authenticated_at, now)
}

impl Resolve<ManageArgs> for GetUserId {
  async fn resolve(
    self,
    ManageArgs { user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    Ok(GetUserIdResponse {
      id: user.id().to_string(),
    })
  }
}

impl Resolve<ManageArgs> for UpdateExternalSkip2fa {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;
    auth
      .update_user_external_skip_2fa(
        user.id().to_string(),
        self.external_skip_2fa,
      )
      .await?;
    Ok(NoData {})
  }
}

#[cfg(test)]
mod tests {
  use axum::http::StatusCode;
  use mogh_auth_client::config::{
    ExternalLoginProviderConfig, NamedOauthConfig,
  };

  use super::*;
  use crate::user::AuthUserImpl;

  struct TestUser {
    workload: bool,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      "id"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn is_workload(&self) -> bool {
      self.workload
    }
    // Even an admin workload can't configure logins
    fn is_admin(&self) -> bool {
      true
    }
  }

  /// One of each kind of request.
  fn requests() -> Vec<ManageRequest> {
    vec![
      ManageRequest::UpdatePassword(UpdatePassword {
        password: "password".into(),
      }),
      ManageRequest::BeginExternalLoginLink(BeginExternalLoginLink {
        slug: "github".into(),
      }),
      ManageRequest::BeginPasskeyEnrollment(
        BeginPasskeyEnrollment {},
      ),
      ManageRequest::BeginTotpEnrollment(BeginTotpEnrollment {}),
      ManageRequest::CreateApiKey(CreateApiKey {
        name: "key".into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
      }),
      ManageRequest::CreateExternalLoginProvider(
        CreateExternalLoginProvider {
          name: "Github".into(),
          registration_disabled: false,
          slug: String::new(),
          token_exchange: Default::default(),
          config: ExternalLoginProviderConfig::Github(
            NamedOauthConfig::default(),
          ),
        },
      ),
      ManageRequest::ListTrustedIssuers(ListTrustedIssuers {}),
      ManageRequest::DeleteTrustedIssuer(DeleteTrustedIssuer {
        id: "id".into(),
      }),
    ]
  }

  #[test]
  fn test_workload_users_are_refused() {
    let workload = TestUser { workload: true };
    for request in requests() {
      let method: ManageRequestMethod = (&request).into();
      let err = check_not_workload(&workload, &request).unwrap_err();
      assert_eq!(err.status, StatusCode::FORBIDDEN, "{method}");
    }
    // Harmless, and lets a workload check who it is
    assert!(
      check_not_workload(
        &workload,
        &ManageRequest::GetUserId(GetUserId {})
      )
      .is_ok()
    );
  }

  const NOW: u64 = 1_800_000_000;
  const WINDOW: u64 = 15 * 60;
  /// The default of the token validation.
  const LEEWAY: u64 = 10;

  /// Requests which can't change how anybody logs in.
  fn harmless_requests() -> Vec<ManageRequest> {
    vec![
      ManageRequest::GetUserId(GetUserId {}),
      ManageRequest::ListExternalLoginProviders(
        ListExternalLoginProviders {},
      ),
      ManageRequest::ListTrustedIssuers(ListTrustedIssuers {}),
      ManageRequest::DeleteApiKey(DeleteApiKey { key: "key".into() }),
      ManageRequest::DeleteSigningKey(DeleteSigningKey {
        public_key: "key".into(),
      }),
    ]
  }

  fn sensitive_requests() -> Vec<ManageRequest> {
    requests()
      .into_iter()
      .filter(requires_recent_login)
      .chain([
        ManageRequest::UpdateUsername(UpdateUsername {
          username: "name".into(),
        }),
        ManageRequest::UnenrollTotp(UnenrollTotp {}),
        ManageRequest::UnenrollPasskey(UnenrollPasskey {}),
        ManageRequest::UnlinkLocalLogin(UnlinkLocalLogin {}),
        ManageRequest::UpdateExternalSkip2fa(UpdateExternalSkip2fa {
          external_skip_2fa: true,
        }),
        ManageRequest::CreateSigningKey(CreateSigningKey {
          name: "key".into(),
          expires: 0,
          cidr_whitelist: Vec::new(),
          public_key: String::new(),
        }),
      ])
      .collect()
  }

  /// The handler's credential checks, in its order.
  fn check(
    window_secs: u64,
    authenticated_at: Option<u64>,
    request: &ManageRequest,
  ) -> mogh_error::Result<()> {
    check_credential_kind(authenticated_at, request)?;
    check_recent_login(
      window_secs,
      LEEWAY,
      authenticated_at,
      NOW,
      request,
    )
  }

  fn assert_reauthentication_required(
    res: mogh_error::Result<()>,
    what: &str,
  ) {
    let err = res.expect_err(what);
    assert_eq!(err.status, StatusCode::FORBIDDEN, "{what}");
    // Clients recognize the error by the start of its message.
    assert!(
      format!("{:#}", err.error)
        .starts_with(REAUTHENTICATION_REQUIRED),
      "{what}: {:#}",
      err.error
    );
  }

  #[test]
  fn test_sensitive_requests_need_a_recent_login() {
    let sensitive = sensitive_requests();
    assert!(sensitive.len() > 10);
    for request in sensitive {
      let method: ManageRequestMethod = (&request).into();
      // Just logged in, and at the end of the window.
      for age in [0, 1, WINDOW] {
        check(WINDOW, Some(NOW - age), &request)
          .unwrap_or_else(|_| panic!("{method} at {age}s"));
      }
      // Issued by an instance with its clock a little ahead, which
      // the token validation accepts.
      for ahead in [1, 5, LEEWAY] {
        check(WINDOW, Some(NOW + ahead), &request)
          .unwrap_or_else(|_| panic!("{method} {ahead}s ahead"));
      }
      // Too old, or from the future.
      for authenticated_at in [
        Some(NOW - WINDOW - 1),
        Some(0),
        Some(NOW + LEEWAY + 1),
        Some(NOW + 60),
        Some(u64::MAX),
      ] {
        assert_reauthentication_required(
          check(WINDOW, authenticated_at, &request),
          &format!("{method} at {authenticated_at:?}"),
        );
      }
    }
  }

  #[test]
  fn test_harmless_requests_work_with_any_credentials() {
    for request in harmless_requests() {
      for window in [0, WINDOW] {
        for authenticated_at in [Some(0), Some(NOW + 60), None] {
          assert!(check(window, authenticated_at, &request).is_ok());
        }
      }
    }
  }

  /// The resource requests take a credential without a login; a
  /// stale login is still refused them.
  #[test]
  fn test_resource_requests_take_api_keys() {
    let resources = sensitive_requests()
      .into_iter()
      .filter(manages_resources)
      .collect::<Vec<_>>();
    // One of each kind is listed, not every resource request.
    assert!(!resources.is_empty());
    for request in &resources {
      for window in [0, WINDOW] {
        assert!(check(window, None, request).is_ok());
      }
      assert_reauthentication_required(
        check(WINDOW, Some(0), request),
        "stale login",
      );
    }
  }

  /// An api key is refused every account request, whether the
  /// reauthentication window is enabled or not (`0`): it could
  /// otherwise set a password, unenroll 2fa or mint a replacement
  /// key, and keep the account after the key is deleted.
  #[test]
  fn test_api_keys_are_refused_account_requests_at_any_window() {
    let accounts = sensitive_requests()
      .into_iter()
      .filter(|request| !manages_resources(request))
      .collect::<Vec<_>>();
    assert!(accounts.len() > 6);
    for request in &accounts {
      let method: ManageRequestMethod = request.into();
      assert_reauthentication_required(
        check_credential_kind(None, request),
        &method.to_string(),
      );
      for window in [0, 1, WINDOW] {
        assert_reauthentication_required(
          check(window, None, request),
          &format!("{method} at window {window}"),
        );
      }
    }
    for request in harmless_requests().iter().chain(
      sensitive_requests().iter().filter(|r| manages_resources(r)),
    ) {
      assert!(check_credential_kind(None, request).is_ok());
    }
  }

  /// `0` disables the window for sessions, not the refusal of api
  /// keys ([test_api_keys_are_refused_account_requests_at_any_window]).
  #[test]
  fn test_recent_login_check_can_be_disabled() {
    for request in sensitive_requests() {
      for authenticated_at in [Some(0), Some(NOW + 60)] {
        assert!(check(0, authenticated_at, &request).is_ok());
      }
    }
  }

  /// The changes [ChangesAuth] was told about.
  static CHANGES: std::sync::Mutex<
    Vec<(String, crate::CredentialChange, Option<String>)>,
  > = std::sync::Mutex::new(Vec::new());

  /// Stores every credential change, and remembers what it is told.
  struct ChangesAuth;

  impl AuthImpl for ChangesAuth {
    fn new() -> Self {
      ChangesAuth
    }
    fn app_name(&self) -> &'static str {
      "Test"
    }
    fn local_auth_bcrypt_cost(&self) -> u32 {
      4
    }
    fn get_user(
      &self,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<BoxAuthUser>> {
      unimplemented!()
    }
    fn handle_request_authentication(
      &self,
      _: crate::RequestAuthentication,
      _: std::net::IpAddr,
      _: bool,
      _: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      unimplemented!()
    }
    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      unimplemented!()
    }
    fn update_user_password(
      &self,
      _: String,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
    fn update_user_stored_totp(
      &self,
      _: String,
      _: String,
      _: Vec<String>,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
    fn remove_user_stored_totp(
      &self,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
    fn update_user_stored_passkey(
      &self,
      _: String,
      _: Option<crate::Passkey>,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
    fn unlink_local_login(
      &self,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
    fn unlink_external_login(
      &self,
      _: String,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
    fn credentials_changed(
      &self,
      user_id: String,
      change: crate::CredentialChange,
      kept_jwt: Option<String>,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      CHANGES.lock().unwrap().push((user_id, change, kept_jwt));
      Box::pin(async { Ok(()) })
    }
  }

  /// Once a change of how the user logs in is stored, the app is told,
  /// with the session to keep. A refused change tells nothing.
  #[tokio::test]
  async fn test_credential_changes_are_reported() {
    use crate::CredentialChange;
    let args = ManageArgs {
      auth: Arc::new(ChangesAuth),
      user: Arc::new(Box::new(TestUser { workload: false })),
      session: Session(tower_sessions::Session::new(
        None,
        Arc::new(tower_sessions::MemoryStore::default()),
        None,
      )),
      jwt: Some(String::from("the-session")),
    };
    let reported = || {
      std::mem::take(&mut *CHANGES.lock().unwrap())
        .into_iter()
        .map(|(user_id, change, kept)| {
          assert_eq!(user_id, "id");
          assert_eq!(kept.as_deref(), Some("the-session"));
          change
        })
        .collect::<Vec<_>>()
    };

    // Refused: nothing changed.
    assert!(
      UpdatePassword {
        password: "short".into()
      }
      .resolve(&args)
      .await
      .is_err()
    );
    let totp = ChangesAuth.make_totp(vec![7; 20], None).unwrap();
    args
      .session
      .insert_totp_enrollment("id", &totp)
      .await
      .unwrap();
    assert!(
      ConfirmTotpEnrollment {
        code: "000000".into()
      }
      .resolve(&args)
      .await
      .is_err()
    );
    assert_eq!(reported(), []);

    UpdatePassword {
      password: "a-new-password".into(),
    }
    .resolve(&args)
    .await
    .unwrap();
    args
      .session
      .insert_totp_enrollment("id", &totp)
      .await
      .unwrap();
    ConfirmTotpEnrollment {
      code: totp.generate_current().to_string(),
    }
    .resolve(&args)
    .await
    .unwrap();
    UnenrollTotp {}.resolve(&args).await.unwrap();
    UnenrollPasskey {}.resolve(&args).await.unwrap();
    UnlinkLocalLogin {}.resolve(&args).await.unwrap();
    UnlinkExternalLogin {
      provider_id: "github".into(),
    }
    .resolve(&args)
    .await
    .unwrap();
    assert_eq!(
      reported(),
      [
        CredentialChange::Password,
        CredentialChange::TotpEnrolled,
        CredentialChange::TotpUnenrolled,
        CredentialChange::PasskeyUnenrolled,
        CredentialChange::LocalLoginUnlinked,
        CredentialChange::ExternalLoginUnlinked {
          provider_id: "github".into()
        },
      ]
    );
  }

  #[test]
  fn test_other_users_are_not_affected() {
    let user = TestUser { workload: false };
    for request in requests() {
      assert!(check_not_workload(&user, &request).is_ok());
    }
  }
}
