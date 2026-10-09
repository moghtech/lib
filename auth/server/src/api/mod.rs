use std::net::IpAddr;

use anyhow::Context as _;
use axum::{
  Router,
  extract::Request,
  middleware::Next,
  response::{Redirect, Response},
  routing::get,
};
use data_encoding::BASE64URL;
use mogh_auth_client::{
  api::login::UserIdOrTwoFactor, config::ExternalLoginProvider,
};
use mogh_error::Variant;
use serde::Deserialize;
use tracing::info;
use utoipa::ToSchema;

use mogh_request_ip::RequestIp;

use crate::{
  AuthImpl, Login, LoginKind, RequestContext, context,
  middleware::check_user_cidr_whitelist, scope_request_context,
  session::Session, user::BoxAuthUser,
};

pub mod external;
pub mod login;
pub mod manage;
pub mod token;

/// The auth api, for the app to nest at [AuthImpl::path] (`/auth` by
/// default) under a session layer (tower-sessions, eg.
/// `mogh_server::session::memory_session_layer`): the login flows keep
/// their steps in flight on the session.
///
/// Layers of the app's own around it are fine (eg. hiding the details
/// of server errors, a body limit, an audit layer): the router relies
/// on none being absent, and scopes the
/// [request_context][crate::request_context] of its requests itself.
/// A layer which reads request bodies runs before the timestamp of a
/// signed request is checked though, which counts the upload against
/// [AuthImpl::signing_key_timestamp_tolerance_ms].
pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
    .nest(
      "/login",
      login::router::<I>().layer(axum::middleware::from_fn(
        |ip, req, next| scope_context(context::LOGIN, ip, req, next),
      )),
    )
    .nest(
      "/manage",
      manage::router::<I>().layer(axum::middleware::from_fn(
        |ip, req, next| scope_context(context::MANAGE, ip, req, next),
      )),
    )
    .merge(external::router::<I>().layer(axum::middleware::from_fn(
      |ip, req: Request, next| {
        let method = external_method(req.uri().path());
        scope_context(method, ip, req, next)
      },
    )))
    .merge(token::router::<I>().layer(axum::middleware::from_fn(
      |ip, req, next| {
        scope_context(context::TOKEN_EXCHANGE, ip, req, next)
      },
    )))
}

/// Runs the request in its [RequestContext] ([request_context]), for
/// the app's hooks to read. A request whose client ip can't be told
/// runs without: the handlers refuse it.
async fn scope_context(
  method: &'static str,
  ip: Result<RequestIp, mogh_error::Error>,
  req: Request,
  next: Next,
) -> Response {
  match ip {
    Ok(RequestIp(ip)) => {
      scope_request_context(
        RequestContext::new(ip, method, None),
        next.run(req),
      )
      .await
    }
    Err(_) => next.run(req).await,
  }
}

/// The [RequestContext::method] of a route of the external login
/// router: `/external/{slug}/{login,link,callback}`, or the same
/// under a provider's reserved id (`/oidc/callback`).
fn external_method(path: &str) -> &'static str {
  match path.rsplit('/').next() {
    Some("login") => context::EXTERNAL_LOGIN,
    Some("link") => context::EXTERNAL_LINK,
    _ => context::EXTERNAL_CALLBACK,
  }
}

/// Builds the tagged request (`{ type, params }`) of the
/// `/{variant}` routes with [mogh_error::variant_request], as the
/// apps' own `/{variant}` routes do: an unknown variant or invalid
/// params is the client's fault, `422 Unprocessable Entity` like the
/// tagged route answers, and the error never repeats a param's value
/// (a password, on the login api).
fn parse_variant_request<R: serde::de::DeserializeOwned>(
  variant: String,
  params: serde_json::Value,
) -> mogh_error::Result<R> {
  mogh_error::variant_request(&variant, params)
}

#[derive(serde::Deserialize)]
pub(crate) struct RedirectQuery {
  redirect: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct StandardCallbackQuery {
  pub state: Option<String>,
  pub code: Option<String>,
  pub error: Option<String>,
}

/// The longest post-login `redirect` which is kept. The login
/// is started by unauthenticated requests, which store it on the
/// session until the callback.
pub(crate) const MAX_REDIRECT_LENGTH: usize = 2048;

/// Only allow post-login redirects back to the app itself,
/// preventing open redirects through the `redirect` query param.
/// The redirect is resolved against `host` (so absolute urls, paths
/// and relative paths all work) and must be http(s) on the same
/// hostname, any scheme or port. Anything else (other origins,
/// protocol-relative `//evil`, scheme tricks) is dropped.
fn sanitize_redirect(
  host: &str,
  redirect: &str,
) -> Option<reqwest::Url> {
  let redirect = redirect.trim();
  if redirect.is_empty() {
    return None;
  }
  let host = reqwest::Url::parse(host).ok()?;
  let host_name = host.host_str()?;
  let target = host.join(redirect).ok()?;
  if !matches!(target.scheme(), "http" | "https") {
    return None;
  }
  if !target.host_str()?.eq_ignore_ascii_case(host_name) {
    return None;
  }
  Some(target)
}

/// The `redirect` of a login as it is stored on the session until
/// the callback: sanitized ([sanitize_redirect]), and dropped if longer
/// than [MAX_REDIRECT_LENGTH]. Without one, the login ends at `host`.
fn login_redirect(
  host: &str,
  redirect: Option<String>,
) -> Option<String> {
  redirect
    .filter(|redirect| redirect.len() <= MAX_REDIRECT_LENGTH)
    .and_then(|redirect| sanitize_redirect(host, &redirect))
    .map(String::from)
    .filter(|redirect| redirect.len() <= MAX_REDIRECT_LENGTH)
}

/// The url the browser is sent to after an external login, with the
/// `extra` query for the app (`redeem_ready=true`, `totp=true`,
/// `passkey=...`). The query is placed before the redirect's fragment,
/// where the app reads it.
fn format_redirect(
  host: &str,
  redirect: Option<&str>,
  extra: &str,
) -> Redirect {
  let redirect_url = if let Some(mut redirect) =
    redirect.and_then(|redirect| sanitize_redirect(host, redirect))
  {
    if !extra.is_empty() {
      let query = match redirect.query() {
        Some(query) if !query.is_empty() => {
          format!("{query}&{extra}")
        }
        _ => extra.to_string(),
      };
      redirect.set_query(Some(&query));
    }
    redirect.to_string()
  } else {
    format!(
      "{host}{}{extra}",
      if extra.is_empty() { "" } else { "?" }
    )
  };
  Redirect::to(&redirect_url)
}

/// The app's rules for a name a user takes (a sign up's, a rename's):
/// [AuthImpl::validate_username], then
/// [AuthImpl::validate_new_username]. Logins check only the first.
pub(crate) fn check_new_username<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
) -> mogh_error::Result<()> {
  auth.validate_username(username)?;
  auth.validate_new_username(username)
}

/// The length of the suffix [unique_username] appends.
const UNIQUE_USERNAME_SUFFIX_LENGTH: usize = 6;

/// Append a random suffix to the username if it is already taken.
/// The name is shortened to make room for it, so the result
/// is at most [MAX_USERNAME_LENGTH][crate::validations::MAX_USERNAME_LENGTH].
async fn unique_username<I: AuthImpl>(
  auth: &I,
  mut username: String,
) -> mogh_error::Result<String> {
  if auth
    .find_user_with_username(username.clone())
    .await?
    .is_some()
  {
    truncate_chars(
      &mut username,
      crate::validations::MAX_USERNAME_LENGTH
        - UNIQUE_USERNAME_SUFFIX_LENGTH,
    );
    username.push('-');
    username.push_str(&crate::rand::random_string(
      UNIQUE_USERNAME_SUFFIX_LENGTH - 1,
    ));
  }
  Ok(username)
}

/// Keeps the first `max` characters.
fn truncate_chars(text: &mut String, max: usize) {
  if let Some((end, _)) = text.char_indices().nth(max) {
    text.truncate(end);
  }
}

/// Whether an external login of the user has to be completed with a
/// second factor, matching [get_user_id_or_two_factor].
pub(crate) fn external_login_requires_two_factor(
  user: &dyn crate::user::AuthUserImpl,
) -> bool {
  !user.external_skip_2fa()
    && (user.passkey().is_some() || user.totp_secret().is_some())
}

/// The kind of a login through `provider`, for its record.
pub(crate) fn provider_login(
  provider: &ExternalLoginProvider,
) -> LoginKind {
  LoginKind::Provider {
    provider_id: provider.id.clone(),
    provider_name: provider.name.clone(),
  }
}

/// Begins the second factor of an external login on the session if the
/// user requires one ([external_login_requires_two_factor]), see
/// [begin_second_factor][login::begin_second_factor]. It is completed
/// with `CompletePasskeyLogin` / `CompleteTotpLogin`, which record the
/// login as one through `provider`.
pub(crate) async fn begin_external_two_factor<
  I: AuthImpl + ?Sized,
>(
  auth: &I,
  session: &Session,
  user: &dyn crate::user::AuthUserImpl,
  provider: &ExternalLoginProvider,
) -> mogh_error::Result<Option<login::SecondFactorChallenge>> {
  if !external_login_requires_two_factor(user) {
    return Ok(None);
  }
  login::begin_second_factor(
    auth,
    session,
    user,
    &provider_login(provider),
  )
  .await
}

/// Logs in an existing user found by an external provider,
/// initiating 2FA if required. Enforces the user cidr whitelist.
///
/// Without a second factor the login is completed here, at the
/// callback, and counts as a fresh one for
/// [AuthImpl::reauthentication_window_secs] even when the provider
/// answered from its single sign-on session (see there).
async fn get_user_id_or_two_factor<I: AuthImpl>(
  auth: &I,
  session: &Session,
  user: &BoxAuthUser,
  ip: IpAddr,
  provider: &ExternalLoginProvider,
) -> mogh_error::Result<UserIdOrTwoFactor> {
  check_user_cidr_whitelist(user.as_ref(), ip)?;

  let res = match begin_external_two_factor(
    auth,
    session,
    user.as_ref(),
    provider,
  )
  .await?
  {
    // Skip / No 2FA
    None => {
      auth
        .record_login(Login::of(
          user.as_ref(),
          ip,
          provider_login(provider),
          None,
          auth.jwt_provider().default_expires_at()?,
        ))
        .await?;
      session.insert_authenticated_user_id(user.id()).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "User logged in"
      );

      UserIdOrTwoFactor::UserId(user.id().to_string())
    }
    Some(login::SecondFactorChallenge::Passkey(response)) => {
      UserIdOrTwoFactor::Passkey(response)
    }
    Some(login::SecondFactorChallenge::Totp) => {
      UserIdOrTwoFactor::Totp {}
    }
  };
  Ok(res)
}

fn user_id_or_two_factor_redirect<I: AuthImpl>(
  auth: &I,
  user_id_or_two_factor: UserIdOrTwoFactor,
  redirect: Option<&str>,
) -> mogh_error::Result<Redirect> {
  match user_id_or_two_factor {
    UserIdOrTwoFactor::UserId(_) => {
      Ok(format_redirect(auth.host(), redirect, "redeem_ready=true"))
    }
    UserIdOrTwoFactor::Totp {} => {
      Ok(format_redirect(auth.host(), redirect, "totp=true"))
    }
    UserIdOrTwoFactor::Passkey(passkey) => {
      let passkey = serde_json::to_vec(&passkey)
        .context("Failed to serialize passkey response")?;
      let passkey = BASE64URL.encode(&passkey);
      Ok(format_redirect(
        auth.host(),
        redirect,
        &format!("passkey={passkey}"),
      ))
    }
  }
}

#[cfg(test)]
mod tests {
  use anyhow::anyhow;
  use reqwest::StatusCode;
  use std::sync::{LazyLock, Mutex};

  use axum::response::IntoResponse;
  use mogh_rate_limit::RateLimiter;

  use super::*;
  use crate::{
    DynFuture, RequestAuthentication, provider::jwt::JwtProvider,
    request_context,
  };

  /// The contexts [ContextAuth]'s hooks ran in, by hook.
  static SEEN: Mutex<Vec<(&'static str, RequestContext)>> =
    Mutex::new(Vec::new());

  fn see(hook: &'static str) {
    if let Some(context) = request_context() {
      SEEN.lock().unwrap().push((hook, context));
    }
  }

  /// Every user exists, the hooks remember the context they ran in.
  struct ContextAuth;

  struct ContextUser(String);

  impl crate::user::AuthUserImpl for ContextUser {
    fn id(&self) -> &str {
      &self.0
    }
    fn username(&self) -> &str {
      "user"
    }
  }

  impl AuthImpl for ContextAuth {
    fn new() -> Self {
      ContextAuth
    }
    fn host(&self) -> &str {
      "https://example.com"
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthUser>> {
      see("get_user");
      Box::pin(async move {
        Ok(Box::new(ContextUser(user_id)) as BoxAuthUser)
      })
    }
    fn handle_request_authentication(
      &self,
      _auth: RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      req: axum::extract::Request,
    ) -> DynFuture<mogh_error::Result<axum::extract::Request>> {
      Box::pin(async { Ok(req) })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      static PROVIDER: LazyLock<JwtProvider> =
        LazyLock::new(|| JwtProvider::new(b"secret", 60_000));
      &PROVIDER
    }
    fn general_rate_limiter(&self) -> &RateLimiter {
      see("general_rate_limiter");
      static LIMITER: LazyLock<std::sync::Arc<RateLimiter>> =
        LazyLock::new(|| {
          RateLimiter::new(true, 0, Default::default())
        });
      &LIMITER
    }
    fn external_login_error_redirect(&self) -> Option<&str> {
      see("external_login_error_redirect");
      None
    }
    fn list_external_providers(
      &self,
    ) -> DynFuture<mogh_error::Result<Vec<ExternalLoginProvider>>>
    {
      see("list_external_providers");
      Box::pin(async { Ok(Vec::new()) })
    }
    fn find_user_with_username(
      &self,
      _username: String,
    ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
      see("find_user_with_username");
      Box::pin(async { Ok(None) })
    }
    fn update_user_username(
      &self,
      _user_id: String,
      _username: String,
    ) -> DynFuture<mogh_error::Result<()>> {
      see("update_user_username");
      Box::pin(async { Ok(()) })
    }
  }

  /// The hooks run in the [RequestContext] of their request: the
  /// client ip, the request by its wire name once known, and the
  /// user of an authenticated management request.
  #[tokio::test]
  async fn test_hooks_run_in_the_request_context() {
    let app = router::<ContextAuth>().layer(
      tower_sessions::SessionManagerLayer::new(
        tower_sessions::MemoryStore::default(),
      )
      .with_secure(false),
    );
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
      axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
      )
      .await
      .unwrap()
    });
    let client = reqwest::Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .unwrap();
    // The loopback peer is a trusted proxy by default.
    let ip: IpAddr = "203.0.113.9".parse().unwrap();
    let url = |path: &str| format!("http://{address}{path}");
    let jwt =
      ContextAuth.jwt_provider().encode_sub("user-1").unwrap().jwt;
    let seen = |hook: &str| {
      SEEN
        .lock()
        .unwrap()
        .iter()
        .filter(|(seen, _)| *seen == hook)
        .map(|(_, context)| context.clone())
        .collect::<Vec<_>>()
    };

    // A management request, by its variant route and the tagged one.
    for (path, body) in [
      ("/manage/UpdateUsername", r#"{"username":"new-name"}"#),
      (
        "/manage",
        r#"{"type":"UpdateUsername","params":{"username":"new-name"}}"#,
      ),
    ] {
      SEEN.lock().unwrap().clear();
      let res = client
        .post(url(path))
        .header("x-forwarded-for", ip.to_string())
        .header("authorization", format!("Bearer {jwt}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
      assert!(res.status().is_success(), "{path}: {}", res.status());
      // Authenticated first, before the body is read.
      assert_eq!(
        seen("get_user"),
        [RequestContext::new(ip, context::MANAGE, None)],
        "{path}"
      );
      let handled = RequestContext::new(
        ip,
        "UpdateUsername",
        Some("user-1".into()),
      );
      assert_eq!(
        seen("find_user_with_username"),
        std::slice::from_ref(&handled)
      );
      assert_eq!(seen("update_user_username"), [handled]);
    }

    // A login request.
    SEEN.lock().unwrap().clear();
    let res = client
      .post(url("/login/GetLoginOptions"))
      .header("x-forwarded-for", ip.to_string())
      .header("content-type", "application/json")
      .body("{}")
      .send()
      .await
      .unwrap();
    assert!(res.status().is_success(), "{}", res.status());
    assert_eq!(
      seen("list_external_providers"),
      [RequestContext::new(ip, "GetLoginOptions", None)]
    );

    // The browser routes of external logins, failing here (no such
    // provider, nothing begun on the session).
    for (path, method) in [
      ("/external/nope/login", context::EXTERNAL_LOGIN),
      ("/external/nope/link", context::EXTERNAL_LINK),
      ("/external/nope/callback", context::EXTERNAL_CALLBACK),
      ("/oidc/callback", context::EXTERNAL_CALLBACK),
    ] {
      SEEN.lock().unwrap().clear();
      client
        .get(url(path))
        .header("x-forwarded-for", ip.to_string())
        .send()
        .await
        .unwrap();
      assert_eq!(
        seen("external_login_error_redirect"),
        [RequestContext::new(ip, method, None)],
        "{path}"
      );
    }

    // Token exchange.
    SEEN.lock().unwrap().clear();
    client
      .post(url("/token"))
      .header("x-forwarded-for", ip.to_string())
      .form(
        &mogh_auth_client::api::token::TokenExchangeRequest::id_token(
          "not-a-token",
        ),
      )
      .send()
      .await
      .unwrap();
    assert_eq!(
      seen("general_rate_limiter"),
      [RequestContext::new(ip, context::TOKEN_EXCHANGE, None)]
    );

    // Outside of a request, there is none.
    assert_eq!(request_context(), None);
  }

  struct TwoFactorUser {
    external_skip_2fa: bool,
    totp: bool,
  }

  impl crate::user::AuthUserImpl for TwoFactorUser {
    fn id(&self) -> &str {
      "id"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn external_skip_2fa(&self) -> bool {
      self.external_skip_2fa
    }
    fn totp_secret(&self) -> Option<&str> {
      self.totp.then_some("secret")
    }
  }

  #[test]
  fn test_external_login_requires_two_factor() {
    for (external_skip_2fa, totp, required) in [
      (true, true, false),
      (true, false, false),
      (false, false, false),
      (false, true, true),
    ] {
      let user = TwoFactorUser {
        external_skip_2fa,
        totp,
      };
      assert_eq!(
        external_login_requires_two_factor(&user),
        required,
        "skip: {external_skip_2fa}, totp: {totp}"
      );
    }
  }

  struct TakenUsernames;

  impl AuthImpl for TakenUsernames {
    fn new() -> Self {
      TakenUsernames
    }
    fn find_user_with_username(
      &self,
      _username: String,
    ) -> crate::DynFuture<mogh_error::Result<Option<BoxAuthUser>>>
    {
      Box::pin(async {
        Ok(Some(Box::new(TwoFactorUser {
          external_skip_2fa: false,
          totp: false,
        }) as BoxAuthUser))
      })
    }
    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }
    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }
    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for these tests")
    }
  }

  /// The suffix fits: a taken name at the length limit stays valid.
  #[tokio::test]
  async fn test_unique_username_stays_within_the_limit() {
    use crate::validations::{
      MAX_USERNAME_LENGTH, validate_username,
    };
    for name in [
      "alice".to_string(),
      "a".repeat(MAX_USERNAME_LENGTH),
      "é".repeat(MAX_USERNAME_LENGTH),
    ] {
      let unique = unique_username(&TakenUsernames, name.clone())
        .await
        .unwrap();
      assert_ne!(unique, name);
      assert!(unique.chars().count() <= MAX_USERNAME_LENGTH);
      assert_eq!(
        unique.chars().count(),
        name
          .chars()
          .count()
          .min(MAX_USERNAME_LENGTH - UNIQUE_USERNAME_SUFFIX_LENGTH)
          + UNIQUE_USERNAME_SUFFIX_LENGTH
      );
      if name.is_ascii() {
        validate_username(&unique).unwrap();
      }
    }
  }

  #[test]
  fn test_parse_variant_request() {
    use mogh_auth_client::api::login::{
      LoginLocalUser, SignUpLocalUser,
    };

    #[derive(Deserialize)]
    #[serde(tag = "type", content = "params")]
    enum TestRequest {
      LoginLocalUser(LoginLocalUser),
      #[allow(unused)]
      SignUpLocalUser(SignUpLocalUser),
    }

    let req: TestRequest = parse_variant_request(
      "LoginLocalUser".into(),
      serde_json::json!({ "username": "user", "password": "pass" }),
    )
    .unwrap();
    assert!(matches!(
      req,
      TestRequest::LoginLocalUser(LoginLocalUser { username, .. })
        if username == "user"
    ));

    // The client sent these, so they aren't server errors, and the
    // errors don't repeat the values sent (passwords).
    for (variant, params) in [
      ("Unknown", serde_json::json!({})),
      ("LoginLocalUser", serde_json::json!({})),
      ("LoginLocalUser", serde_json::json!({ "username": 1 })),
      ("LoginLocalUser", serde_json::json!(null)),
      (
        "LoginLocalUser",
        serde_json::json!({ "username": "user", "password": 1234567 }),
      ),
    ] {
      let err = parse_variant_request::<TestRequest>(
        variant.into(),
        params.clone(),
      )
      .err()
      .unwrap();
      assert_eq!(
        err.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{variant} {params}"
      );
      assert!(
        !format!("{:#}", err.error).contains("1234567"),
        "{:#}",
        err.error
      );
    }
  }

  fn location(redirect: Redirect) -> String {
    redirect
      .into_response()
      .headers()
      .get("location")
      .unwrap()
      .to_str()
      .unwrap()
      .to_string()
  }

  #[test]
  fn test_format_redirect_with_redirect_no_query() {
    let redirect = format_redirect(
      "https://example.com",
      Some("https://example.com/dest"),
      "redeem_ready=true",
    );
    assert_eq!(
      location(redirect),
      "https://example.com/dest?redeem_ready=true"
    );
  }

  #[test]
  fn test_format_redirect_with_redirect_existing_query() {
    let redirect = format_redirect(
      "https://example.com",
      Some("https://example.com/dest?a=1"),
      "totp=true",
    );
    assert_eq!(
      location(redirect),
      "https://example.com/dest?a=1&totp=true"
    );
  }

  #[test]
  fn test_format_redirect_without_redirect_falls_back_to_host() {
    let redirect = format_redirect(
      "https://example.com",
      None,
      "redeem_ready=true",
    );
    assert_eq!(
      location(redirect),
      "https://example.com?redeem_ready=true"
    );
  }

  #[test]
  fn test_format_redirect_empty_redirect_falls_back_to_host() {
    let redirect =
      format_redirect("https://example.com", Some(""), "totp=true");
    assert_eq!(location(redirect), "https://example.com?totp=true");
  }

  #[test]
  fn test_format_redirect_rejects_other_origins() {
    // Open redirect attempts fall back to the host.
    for evil in [
      "https://evil.com",
      "https://evil.com/?next=https://example.com",
      "https://example.com.evil.com/dest",
      "https://example.com@evil.com",
      "//evil.com/dest",
      "/\\evil.com",
      "\\\\evil.com",
      "javascript:alert(1)",
      "data:text/html,hi",
    ] {
      let redirect = format_redirect(
        "https://example.com",
        Some(evil),
        "redeem_ready=true",
      );
      assert_eq!(
        location(redirect),
        "https://example.com?redeem_ready=true",
        "{evil}"
      );
    }
  }

  #[test]
  fn test_format_redirect_allows_same_host() {
    let cases = [
      ("https://example.com", "https://example.com/?totp=true"),
      (
        "/servers/abc?tab=1",
        "https://example.com/servers/abc?tab=1&totp=true",
      ),
      ("servers/abc", "https://example.com/servers/abc?totp=true"),
      ("?tab=1", "https://example.com/?tab=1&totp=true"),
      // Same host, other scheme / port (eg TLS at the proxy).
      (
        "http://example.com/dest",
        "http://example.com/dest?totp=true",
      ),
      (
        "https://example.com:8443/dest",
        "https://example.com:8443/dest?totp=true",
      ),
      (
        "https://EXAMPLE.com/dest",
        "https://example.com/dest?totp=true",
      ),
      // Same scheme without `//` is a relative path on the host.
      ("https:evil.com", "https://example.com/evil.com?totp=true"),
    ];
    for (redirect, expected) in cases {
      let redirect = format_redirect(
        "https://example.com",
        Some(redirect),
        "totp=true",
      );
      assert_eq!(location(redirect), expected);
    }
    // Trailing slash on host is tolerated.
    let redirect = format_redirect(
      "https://example.com/",
      Some("/dest"),
      "totp=true",
    );
    assert_eq!(
      location(redirect),
      "https://example.com/dest?totp=true"
    );
  }

  /// The query goes before the fragment, where the app reads it.
  #[test]
  fn test_format_redirect_keeps_the_fragment_last() {
    let cases = [
      (
        "https://example.com/dest#frag",
        "https://example.com/dest?totp=true#frag",
      ),
      (
        "/dest?a=1#frag",
        "https://example.com/dest?a=1&totp=true#frag",
      ),
      // A '?' in the fragment is not the query.
      ("/x#a?b=1", "https://example.com/x?totp=true#a?b=1"),
      ("/x?#frag", "https://example.com/x?totp=true#frag"),
    ];
    for (redirect, expected) in cases {
      let redirect = format_redirect(
        "https://example.com",
        Some(redirect),
        "totp=true",
      );
      assert_eq!(location(redirect), expected);
    }
    let redirect = format_redirect(
      "https://example.com",
      Some("/stacks/abc#logs"),
      "passkey=eyJhIjoiYiJ9",
    );
    let url = reqwest::Url::parse(&location(redirect)).unwrap();
    assert_eq!(url.query(), Some("passkey=eyJhIjoiYiJ9"));
    assert_eq!(url.fragment(), Some("logs"));
  }

  #[test]
  fn test_login_redirect_is_sanitized_and_bounded() {
    let host = "https://example.com";
    assert_eq!(
      login_redirect(host, Some("/notes?tab=1".into())).as_deref(),
      Some("https://example.com/notes?tab=1")
    );
    for dropped in [
      None,
      Some(String::new()),
      Some("https://evil.example/steal".into()),
      Some("//evil.example".into()),
      Some(format!("/{}", "a".repeat(MAX_REDIRECT_LENGTH))),
      Some(format!("/{}", "a".repeat(60 * 1024))),
      // Short, but longer once resolved and encoded.
      Some(format!("/{}", "\"".repeat(MAX_REDIRECT_LENGTH / 2))),
    ] {
      assert_eq!(login_redirect(host, dropped.clone()), None);
    }
  }

  #[test]
  fn test_format_redirect_empty_extra() {
    let redirect = format_redirect(
      "https://example.com",
      Some("https://example.com/dest"),
      "",
    );
    assert_eq!(location(redirect), "https://example.com/dest");
    let redirect = format_redirect("https://example.com", None, "");
    assert_eq!(location(redirect), "https://example.com");
  }
}
