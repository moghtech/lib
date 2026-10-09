use anyhow::{Context as _, anyhow};
use axum::{
  Router,
  extract::{Path, Query},
  http::{HeaderMap, StatusCode},
  response::Redirect,
  routing::get,
};
use mogh_auth_client::{
  api::login::UserIdOrTwoFactor,
  config::{
    ExternalLoginKind, ExternalLoginProvider,
    ExternalLoginProviderConfig,
  },
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError};
use mogh_rate_limit::{FailedAttempt, WithFailureRateLimit};
use mogh_request_ip::RequestIp;
use serde::Deserialize;
use std::{net::IpAddr, sync::Arc};
use tracing::{error, info, instrument, warn};

use crate::{
  AuthImpl,
  api::{
    RedirectQuery, StandardCallbackQuery, check_new_username,
    get_user_id_or_two_factor, login_redirect, unique_username,
    user_id_or_two_factor_redirect,
  },
  login_start::{embedded_refused, embedded_request},
  middleware::check_user_cidr_whitelist,
  provider::{
    external::{
      BuiltProvider, CompletedExternalLogin, SessionExternalLogin,
      load_built_provider, resolve_external_provider_by_slug,
    },
    load_cache::LoadFailedRecently,
    named::sanitize_text,
  },
  rand::random_string,
  session::{ExternalLink, Session},
  user::AuthUserImpl,
  validations::{MAX_USERNAME_LENGTH, constant_time_eq},
};
use crate::{Login, api::provider_login};

/// The urls name the provider by its slug (its id for a provider
/// without one), see `ExternalLoginProvider::slug`.
#[derive(Deserialize)]
struct ProviderPath {
  slug: String,
}

pub fn router<I: AuthImpl>() -> Router {
  let mut router = Router::new()
    .route(
      "/external/{slug}/login",
      get(
        |Path(ProviderPath { slug }), ip, session, headers, query| {
          external_login::<I>(slug, ip, session, headers, query)
        },
      ),
    )
    .route(
      "/external/{slug}/link",
      get(|Path(ProviderPath { slug }), ip, session, headers| {
        external_link::<I>(slug, ip, session, headers)
      }),
    )
    .route(
      "/external/{slug}/callback",
      get(|Path(ProviderPath { slug }), ip, session, query| {
        external_callback::<I>(slug, ip, session, query)
      }),
    );

  // Providers using the reserved id of their kind keep the original
  // paths, so existing redirect URIs registered at the provider keep working.
  for kind in [
    ExternalLoginKind::Oidc,
    ExternalLoginKind::Github,
    ExternalLoginKind::Google,
  ] {
    let id = kind.reserved_id();
    router = router
      .route(
        &format!("/{id}/login"),
        get(move |ip, session, headers, query| {
          external_login::<I>(
            id.to_string(),
            ip,
            session,
            headers,
            query,
          )
        }),
      )
      .route(
        &format!("/{id}/link"),
        get(move |ip, session, headers| {
          external_link::<I>(id.to_string(), ip, session, headers)
        }),
      )
      .route(
        &format!("/{id}/callback"),
        get(move |ip, session, query| {
          external_callback::<I>(id.to_string(), ip, session, query)
        }),
      );
  }

  router
}

/// Resolves the provider of the url's slug, ensuring it's enabled.
async fn resolve_enabled_provider<I: AuthImpl>(
  auth: &I,
  slug: &str,
) -> mogh_error::Result<ExternalLoginProvider> {
  let provider = resolve_external_provider_by_slug(auth, slug)
    .await?
    .provider;

  if !provider.enabled() {
    return Err(
      anyhow!("Login with '{}' is not enabled", provider.name)
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  Ok(provider)
}

/// Resolves the provider of the url's slug and its client,
/// ensuring it's enabled.
async fn load_enabled_provider<I: AuthImpl>(
  auth: &I,
  slug: &str,
) -> mogh_error::Result<(ExternalLoginProvider, Arc<BuiltProvider>)> {
  let provider = resolve_enabled_provider(auth, slug).await?;
  let built = load_provider_client(auth, &provider).await?;
  Ok((provider, built))
}

/// Loads the client of an already resolved provider.
pub(crate) async fn load_provider_client<I: AuthImpl + ?Sized>(
  auth: &I,
  provider: &ExternalLoginProvider,
) -> mogh_error::Result<Arc<BuiltProvider>> {
  // The app name is the user agent for provider discovery,
  // only require apps to implement it for the kinds using it.
  let app_user_agent = match provider.kind() {
    ExternalLoginKind::Oidc | ExternalLoginKind::Google => {
      auth.app_name()
    }
    ExternalLoginKind::Github => "",
  };

  // These endpoints are unauthenticated. The reason may include
  // internal addresses or configuration details, so it is only logged.
  let built = load_built_provider(
    app_user_agent,
    auth.host(),
    auth.path(),
    provider,
  )
  .await
  .map_err(|e| {
    // Logged once per attempt, not by every request while it is down.
    if !LoadFailedRecently::is(&e) {
      error!(
        provider_id = provider.id,
        provider = provider.name,
        "Failed to initialize external login provider | {e:#}"
      );
    }
    anyhow::Error::new(ProviderUnavailable(provider.name.clone()))
      .status_code(StatusCode::SERVICE_UNAVAILABLE)
  })?;

  Ok(built)
}

/// The error of a login provider which can't be loaded
/// ([load_provider_client]). The reason was logged there, once per
/// attempt, and isn't part of the error.
#[derive(Debug)]
struct ProviderUnavailable(String);

impl std::fmt::Display for ProviderUnavailable {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "Login provider '{}' is not available", self.0)
  }
}

impl std::error::Error for ProviderUnavailable {}

// Rate limiting: these routes are plain GETs, which any web page the
// user visits can send from their browser (and ip). Only the failures
// of a callback which redeems a code (the credential of these flows)
// count against the client ip. A request naming an unknown provider,
// or a flow which was never started on the session, is refused
// without counting it, so it can't lock the ip out of logging in.
//
// Starting a login or link takes one of the client's starts
// ([take_login_start]), which bound the login sessions a client can
// have created, so it can't push the logins of others out of the
// session store. A browser request which another site embedded is
// refused before it takes one.

/// Refuses a request another site embedded ([embedded_request]) with
/// `403`, before it counts or starts anything, then takes one of the
/// client's login starts
/// ([AuthImpl::login_start_limiter], `429` with `Retry-After` past
/// it).
fn take_login_start<I: AuthImpl>(
  auth: &I,
  headers: &HeaderMap,
  ip: IpAddr,
) -> mogh_error::Result<()> {
  if embedded_request(headers) {
    return Err(embedded_refused());
  }
  auth.login_start_limiter().take_client_start(ip)
}

/// Starts an external login: stores it on the session, and sends the
/// browser to the provider. The `redirect` (where the login ends) must
/// be on the app's host, and at most
/// [MAX_REDIRECT_LENGTH][crate::api::MAX_REDIRECT_LENGTH] characters,
/// otherwise the login ends at the host.
///
/// Starting a login handles no credential, so its failures are not
/// counted against the client ip. Each one takes one of the client's
/// login starts though ([AuthImpl::login_start_limiter]), and a
/// browser request another site embedded is refused before it does.
pub(crate) async fn external_login<I: AuthImpl>(
  slug: String,
  RequestIp(ip): RequestIp,
  session: Session,
  headers: HeaderMap,
  Query(RedirectQuery { redirect }): Query<RedirectQuery>,
) -> mogh_error::Result<Redirect> {
  let auth = I::new();
  let res = async {
    take_login_start(&auth, &headers, ip)?;
    begin_external_login(&auth, &slug, &session, redirect).await
  }
  .await;
  error_redirect(&auth, ExternalFlow::Login, res)
}

async fn begin_external_login<I: AuthImpl>(
  auth: &I,
  slug: &str,
  session: &Session,
  redirect: Option<String>,
) -> mogh_error::Result<Redirect> {
  let (provider, built) = load_enabled_provider(auth, slug).await?;

  let begin = built.begin_login();

  // Data inserted here will be matched on callback side for csrf protection.
  session
    .insert_external_login(&SessionExternalLogin {
      provider_id: provider.id.clone(),
      link_user_id: None,
      state: begin.state,
      nonce: begin.nonce,
      pkce_verifier: begin.pkce_verifier,
      // Stored by an unauthenticated request,
      // so only a bounded, sanitized one.
      redirect: login_redirect(auth.host(), redirect),
    })
    .await?;

  provider_redirect(&provider, &begin.url)
}

/// Starts linking an external login to the user who began the link on
/// the session ([BeginExternalLoginLink][mogh_auth_client::api::manage::BeginExternalLoginLink]).
///
/// The link begun on the session is used up by the first request,
/// whatever its outcome, and refused once it is older than 10 minutes
/// (`Session::MAX_EXTERNAL_LINK_AGE`). Until it is taken, the request
/// is not known to be a link, and a failure goes to the login page.
/// A user who was disabled (or locked) since is refused, here and
/// again when the provider's callback completes the link.
///
/// Like a login, it takes one of the client's login starts
/// ([AuthImpl::login_start_limiter]), before the link is taken.
pub(crate) async fn external_link<I: AuthImpl>(
  slug: String,
  RequestIp(ip): RequestIp,
  session: Session,
  headers: HeaderMap,
) -> mogh_error::Result<Redirect> {
  let auth = I::new();
  // Known once the link begun on the session is taken.
  let mut flow = ExternalFlow::Login;
  let res = async {
    // Before the link is taken: another site embedding the route
    // can't use it up, and a start refused here leaves it to a
    // later try.
    take_login_start(&auth, &headers, ip)?;
    // Taken before anything else can fail: a failed attempt can't
    // leave the link to be completed later (for any provider) by
    // whoever holds the session.
    let link = take_external_link(&session).await?;
    flow = ExternalFlow::Link;
    link.check_age()?;
    // Only at the provider it was begun for.
    link.check_slug(&slug)?;
    let user_id = link.user_id;

    let (provider, built) =
      load_enabled_provider(&auth, &slug).await?;

    let user = auth.get_user(user_id.clone()).await?;
    check_user_can_link(&auth, user.as_ref(), ip)?;

    let begin = built.begin_login();

    session
      .insert_external_login(&SessionExternalLogin {
        provider_id: provider.id.clone(),
        link_user_id: Some(user_id),
        state: begin.state,
        nonce: begin.nonce,
        pkce_verifier: begin.pkce_verifier,
        redirect: None,
      })
      .await?;

    info!(
      user_id = user.id(),
      username = user.username(),
      provider_id = provider.id,
      provider = provider.name,
      "External login link flow initiated"
    );

    provider_redirect(&provider, &begin.url)
  }
  .await;
  error_redirect(&auth, flow, res)
}

/// Whether `user` can link a login now, checked when the link is
/// started (`/link`) and again before the provider's callback links
/// the login (the user may have changed in between):
/// - the user is enabled: a disabled user changes nothing about how
///   they log in (like the management api they began it with),
/// - the username isn't locked,
/// - the request comes from within the user's cidr whitelist.
fn check_user_can_link<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  ip: IpAddr,
) -> mogh_error::Result<()> {
  if !user.is_enabled() {
    return Err(
      anyhow!("User is not enabled")
        .status_code(StatusCode::FORBIDDEN),
    );
  }
  auth.check_username_locked(user.username())?;
  check_user_cidr_whitelist(user, ip)?;
  Ok(())
}

/// Takes the link begun on the session, and saves the session right
/// away: the session layer doesn't save it for a response with a
/// server error, which would leave the link on the session.
async fn take_external_link(
  session: &Session,
) -> mogh_error::Result<ExternalLink> {
  let link = session.retrieve_external_link().await?;
  session.0.save().await.context("Failed to save session")?;
  Ok(link)
}

/// Takes the external login or link in flight on the session,
/// and saves the session right away, see [take_external_link].
async fn take_external_login(
  session: &Session,
) -> mogh_error::Result<SessionExternalLogin> {
  let login = session.retrieve_external_login().await?;
  session.0.save().await.context("Failed to save session")?;
  Ok(login)
}

/// Whether an external flow logs a user in, or links
/// the provider to the user who is already logged in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ExternalFlow {
  Login,
  Link,
}

/// What a redirect reports for a server error (5xx) of the external
/// flows. Its causes (provider responses, internal addresses) are for
/// the operator, not for the url bar.
const SERVER_ERROR_MESSAGE: &str =
  "Login failed, see the server logs for details";

/// External logins are browser navigations, so with
/// [AuthImpl::external_login_error_redirect] configured a failure sends
/// the user back to the app with the reason, rather than leaving them
/// on a page showing the JSON error. A failed link (once the session
/// had one begun) goes to [AuthImpl::post_link_redirect] instead.
///
/// Server errors are logged ([is_logged_here]). The redirect reports
/// them only as [SERVER_ERROR_MESSAGE]. Without the redirect the error
/// is returned as it is, with as much detail as `mogh_error` sends for
/// 5xx responses (see `mogh_error::set_server_error_detail`).
fn error_redirect<I: AuthImpl>(
  auth: &I,
  flow: ExternalFlow,
  res: mogh_error::Result<Redirect>,
) -> mogh_error::Result<Redirect> {
  let e = match res {
    Ok(redirect) => return Ok(redirect),
    Err(e) => e,
  };
  if is_logged_here(&e) {
    match flow {
      ExternalFlow::Login => {
        error!("External login failed | {:#}", e.error)
      }
      ExternalFlow::Link => {
        error!("External login link failed | {:#}", e.error)
      }
    }
  }
  let Some(login_page) = auth.external_login_error_redirect() else {
    return Err(e);
  };
  let (target, param) = match flow {
    ExternalFlow::Login => (login_page, "login_error"),
    ExternalFlow::Link => (auth.post_link_redirect(), "link_error"),
  };
  let message = if e.status.is_server_error() {
    String::from(SERVER_ERROR_MESSAGE)
  } else if let Some(attempt) =
    e.error.downcast_ref::<FailedAttempt>()
  {
    // The rate limit tops the flows' errors. Its message already has
    // the error with its causes, which `{:#}` would repeat after it.
    attempt.to_string()
  } else {
    format!("{:#}", e.error)
  };
  let splitter = if target.contains('?') { '&' } else { '?' };
  Ok(Redirect::to(&format!(
    "{target}{splitter}{param}={}",
    urlencoding::encode(&message)
  )))
}

/// Whether [error_redirect] logs `e`: the server errors, except a
/// provider which can't be loaded ([ProviderUnavailable]). That was
/// logged where it happened, once per attempt, not by every request
/// while the provider is down (starting a login isn't rate limited).
fn is_logged_here(e: &mogh_error::Error) -> bool {
  e.status.is_server_error()
    && e.error.downcast_ref::<ProviderUnavailable>().is_none()
}

/// Applies the OIDC 'redirect_host'
fn provider_redirect(
  provider: &ExternalLoginProvider,
  url: &str,
) -> mogh_error::Result<Redirect> {
  match &provider.config {
    ExternalLoginProviderConfig::Oidc(config) => {
      auth_redirect(url, &config.redirect_host)
    }
    _ => Ok(Redirect::to(url)),
  }
}

/// Applies 'oidc_redirect_host'
fn auth_redirect(
  auth_url: &str,
  redirect_host: &str,
) -> mogh_error::Result<Redirect> {
  let redirect = if !redirect_host.is_empty() {
    let (protocol, rest) = auth_url
      .split_once("://")
      .context("Invalid URL: Missing protocol (eg 'https://')")?;
    let host = rest
      .split_once(['/', '?'])
      .map(|(host, _)| host)
      .unwrap_or(rest);
    Redirect::to(
      &auth_url
        .replace(&format!("{protocol}://{host}"), redirect_host),
    )
  } else {
    Redirect::to(auth_url)
  };
  Ok(redirect)
}

#[instrument(
  "ExternalLoginCallback",
  skip_all,
  fields(ip = ip.to_string(), slug)
)]
pub(crate) async fn external_callback<I: AuthImpl>(
  slug: String,
  RequestIp(ip): RequestIp,
  session: Session,
  Query(query): Query<StandardCallbackQuery>,
) -> mogh_error::Result<Redirect> {
  let auth = I::new();
  // Known once the login which was started is taken from the session.
  let mut flow = ExternalFlow::Login;
  let res = async {
    // Taken before anything else can fail: the attempt is used up
    // whatever the outcome (a login denied at the provider included),
    // and a failed link goes back to where links are managed.
    let login = take_external_login(&session).await?;
    if login.link_user_id.is_some() {
      flow = ExternalFlow::Link;
    }

    let StandardCallbackQuery {
      state: client_state,
      code,
      error,
    } = query;
    let client_state = client_state
      .context("Callback query does not contain state")
      .status_code(StatusCode::UNAUTHORIZED)?;

    // Checked before the provider's client is loaded (which may
    // mean discovery requests) and without counting a failure: none
    // of this is a credential which could be guessed.
    let provider = resolve_enabled_provider(&auth, &slug).await?;

    // The provider the url named, by its id: the slug may have
    // changed while the login was in flight. And the state, also
    // before the provider's error is looked at: anybody can send
    // the browser here with an error, only the provider's answer to
    // this login carries the state (RFC 6749 section 4.1.2.1).
    validate_callback(&login, &provider.id, &client_state)?;

    if let Some(error) = error {
      return Err(provider_error(&provider, &error));
    }
    let code = code
      .context("Callback query does not contain code")
      .status_code(StatusCode::UNAUTHORIZED)?;

    let built = load_provider_client(&auth, &provider).await?;

    let link_user_id = login.link_user_id.clone();
    let redirect = login.redirect.clone();

    // Redeeming the code is the credential check of the flow.
    async {
      let completed = built
        .complete_login(&provider, login, client_state, code)
        .await?;

      match link_user_id {
        Some(user_id) => {
          link_callback(&auth, &provider, user_id, completed, ip)
            .await
        }
        None => {
          login_callback(
            &auth, &session, &provider, &built, completed, redirect,
            ip,
          )
          .await
        }
      }
    }
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &ip,
    )
    .await
  }
  .await;
  error_redirect(&auth, flow, res)
}

/// The error the provider answered the login with (RFC 6749 section
/// 4.1.2.1), as the user is told: a fixed message by its code, never
/// the text of the url, which the login page shows as the server's
/// reason. The code is logged for the operator, as some are
/// configuration errors (`invalid_scope`, `unauthorized_client`).
fn provider_error(
  provider: &ExternalLoginProvider,
  error: &str,
) -> mogh_error::Error {
  let error = sanitize_text(error);
  let message = if error == "access_denied" {
    info!(
      provider_id = provider.id,
      provider = provider.name,
      "Login was denied at the provider"
    );
    "Login was denied at the provider"
  } else {
    warn!(
      provider_id = provider.id,
      provider = provider.name,
      error,
      "Login provider answered the login with an error"
    );
    "Login was not completed at the provider"
  };
  anyhow!(message).status_code(StatusCode::UNAUTHORIZED)
}

/// The callback must be for the provider the login was started
/// with, otherwise the code of one provider could be redeemed
/// at another (mix-up), and carry the CSRF state stored on the session.
fn validate_callback(
  login: &SessionExternalLogin,
  provider_id: &str,
  client_state: &str,
) -> mogh_error::Result<()> {
  if login.provider_id != provider_id {
    return Err(
      anyhow!("Login was initiated with another provider")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }
  if !constant_time_eq(client_state, &login.state) {
    return Err(
      anyhow!("State mismatch").status_code(StatusCode::UNAUTHORIZED),
    );
  }
  Ok(())
}

async fn login_callback<I: AuthImpl>(
  auth: &I,
  session: &Session,
  provider: &ExternalLoginProvider,
  built: &BuiltProvider,
  completed: CompletedExternalLogin,
  redirect: Option<String>,
  ip: IpAddr,
) -> mogh_error::Result<Redirect> {
  let info = completed.info.clone();

  let user = auth
    .find_user_with_external_login(
      info.provider_id.clone(),
      info.external_id.clone(),
    )
    .await?;

  let user_id_or_two_factor = match user {
    // Log in existing user
    Some(user) => {
      // Users outside their whitelist are rejected
      // before the login has any effect on them.
      check_user_cidr_whitelist(user.as_ref(), ip)?;
      // Sync before the session is authenticated,
      // so a failed sync does not leave a logged in session.
      auth.sync_external_user(user.id().to_string(), info).await?;
      get_user_id_or_two_factor(auth, session, &user, ip, provider)
        .await?
    }
    // Sign up user
    None => {
      let no_users_exist = auth.no_users_exist().await?;

      if auth.external_registration_disabled(provider)
        && !no_users_exist
      {
        return Err(
          anyhow!("User registration is disabled")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      let username = signup_username(
        auth,
        provider,
        completed.username(built).await,
      )
      .await?;

      let user_id = auth
        .sign_up_external_user(
          username.clone(),
          info.clone(),
          no_users_exist,
        )
        .await?;

      info!(
        user_id,
        username,
        provider_id = provider.id,
        provider = provider.name,
        "New user registration (external)"
      );

      auth.sync_external_user(user_id.clone(), info).await?;

      auth
        .record_login(Login {
          user_id: user_id.clone(),
          username,
          ip,
          kind: provider_login(provider),
          second_factor: None,
          token_expires: auth.jwt_provider().default_expires_at()?,
        })
        .await?;
      session.insert_authenticated_user_id(&user_id).await?;

      UserIdOrTwoFactor::UserId(user_id)
    }
  };

  user_id_or_two_factor_redirect(
    auth,
    user_id_or_two_factor,
    redirect.as_deref(),
  )
}

/// The username a new external user is signed up with, which passes
/// [AuthImpl::validate_username] (the rule local users are held to)
/// and [AuthImpl::validate_new_username]:
/// - the provider's name for the user, if it passes,
/// - else that name reduced to the characters of the default rule
///   ([normalize_username]), if it passes,
/// - else a name made from the provider's slug and random characters.
///
/// A taken name gets a random suffix ([unique_username]), and has to
/// pass with it.
async fn signup_username<I: AuthImpl>(
  auth: &I,
  provider: &ExternalLoginProvider,
  provider_username: String,
) -> mogh_error::Result<String> {
  let normalized = normalize_username(&provider_username);
  for candidate in [provider_username, normalized] {
    if candidate.is_empty()
      || check_new_username(auth, &candidate).is_err()
    {
      continue;
    }
    let username = unique_username(auth, candidate).await?;
    if check_new_username(auth, &username).is_ok() {
      return Ok(username);
    }
  }
  let generated = format!(
    "{}-{}",
    normalize_username(provider.slug()),
    random_string(8)
  );
  let username = unique_username(auth, generated).await?;
  // The app's rules refuse even the generated name.
  if let Err(e) = check_new_username(auth, &username) {
    return Err(
      e.error
        .context(
          "No username for the new user passes 'validate_username' and 'validate_new_username'",
        )
        .status_code(StatusCode::INTERNAL_SERVER_ERROR),
    );
  }
  Ok(username)
}

/// Reduces a provider's name for a user to the characters of the
/// default username rule (`[a-zA-Z0-9._@-]`): any other becomes a
/// '-' (runs of them collapse), it doesn't start or end with '-' or
/// '.', and it is cut to [MAX_USERNAME_LENGTH] characters.
fn normalize_username(name: &str) -> String {
  let mut normalized = String::with_capacity(name.len());
  for c in name.trim().chars() {
    let c =
      if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@') {
        c
      } else {
        '-'
      };
    if c == '-'
      && (normalized.is_empty() || normalized.ends_with('-'))
    {
      continue;
    }
    normalized.push(c);
    if normalized.len() >= MAX_USERNAME_LENGTH {
      break;
    }
  }
  normalized.trim_matches(['-', '.']).to_string()
}

/// Links the login completed at the provider to the user who
/// started the link (`user_id`), checked again first
/// ([check_user_can_link]): the user may have been disabled, or
/// locked, since the link was started.
async fn link_callback<I: AuthImpl>(
  auth: &I,
  provider: &ExternalLoginProvider,
  user_id: String,
  completed: CompletedExternalLogin,
  ip: IpAddr,
) -> mogh_error::Result<Redirect> {
  let info = completed.info;

  let user = auth.get_user(user_id.clone()).await?;
  check_user_can_link(auth, user.as_ref(), ip)?;

  // Ensure there are no other existing users with this login linked.
  if let Some(existing_user) = auth
    .find_user_with_external_login(
      info.provider_id.clone(),
      info.external_id.clone(),
    )
    .await?
  {
    if existing_user.id() == user_id {
      // Link is already complete, only need to sync
      auth.sync_external_user(user_id, info).await?;
      return Ok(Redirect::to(auth.post_link_redirect()));
    } else {
      return Err(
        anyhow!("Account already linked to another user.")
          .status_code(StatusCode::CONFLICT),
      );
    }
  }

  auth
    .link_external_login(user_id.clone(), info.clone())
    .await?;

  info!(
    user_id,
    provider_id = provider.id,
    provider = provider.name,
    "External login linked"
  );

  auth.sync_external_user(user_id, info).await?;

  Ok(Redirect::to(auth.post_link_redirect()))
}

#[cfg(test)]
mod tests {
  use axum::response::IntoResponse;

  use super::*;
  use crate::{
    LoginKind,
    provider::external::ExternalLoginInfo,
    test_support::{session, stub_auth_impl},
  };

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

  fn session_login(provider_id: &str) -> SessionExternalLogin {
    SessionExternalLogin {
      provider_id: provider_id.to_string(),
      link_user_id: None,
      state: "expected-state".to_string(),
      nonce: None,
      pkce_verifier: None,
      redirect: None,
    }
  }

  struct TestUser {
    id: String,
    cidr_whitelist: Vec<String>,
    enabled: bool,
  }

  impl crate::user::AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      &self.id
    }
    fn username(&self) -> &str {
      "user"
    }
    fn cidr_whitelist(&self) -> &[String] {
      &self.cidr_whitelist
    }
    fn is_enabled(&self) -> bool {
      self.enabled
    }
  }

  /// Records what the flows ask the app to do.
  #[derive(Default)]
  struct Calls {
    /// (provider_id, external_id) -> user id
    logins: Vec<((String, String), String)>,
    synced: Vec<(String, ExternalLoginInfo)>,
    signed_up: Vec<String>,
    recorded: Vec<Login>,
  }

  #[derive(Default)]
  struct TestAuth {
    static_providers: Vec<ExternalLoginProvider>,
    registration_disabled: bool,
    no_users_exist: bool,
    sync_fails: bool,
    cidr_whitelist: Vec<String>,
    /// The users [AuthImpl::get_user] finds are disabled.
    users_disabled: bool,
    /// The username of the users is locked.
    username_locked: bool,
    error_redirect: Option<&'static str>,
    /// Refused by the app's 'validate_username', on top of the default rule.
    rejected_usernames: Vec<&'static str>,
    /// Refused by the app's 'validate_new_username'.
    refused_new_usernames: Option<fn(&str) -> bool>,
    /// Usernames other users have.
    taken_usernames: Vec<&'static str>,
    calls: Arc<std::sync::Mutex<Calls>>,
  }

  impl TestAuth {
    fn with_login(
      self,
      provider_id: &str,
      external_id: &str,
    ) -> Self {
      self.calls.lock().unwrap().logins.push((
        (provider_id.to_string(), external_id.to_string()),
        "existing-user".to_string(),
      ));
      self
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      TestAuth::default()
    }

    fn host(&self) -> &str {
      "https://example.com"
    }

    fn post_link_redirect(&self) -> &str {
      "https://example.com/profile"
    }

    fn external_login_error_redirect(&self) -> Option<&str> {
      self.error_redirect
    }

    fn registration_disabled(&self) -> bool {
      self.registration_disabled
    }

    fn validate_username(
      &self,
      username: &str,
    ) -> mogh_error::Result<()> {
      if self.rejected_usernames.contains(&username) {
        return Err(
          anyhow!("Username is reserved")
            .status_code(StatusCode::BAD_REQUEST),
        );
      }
      crate::validations::validate_username(username)
        .status_code(StatusCode::BAD_REQUEST)
    }

    fn validate_new_username(
      &self,
      username: &str,
    ) -> mogh_error::Result<()> {
      if self
        .refused_new_usernames
        .is_some_and(|refused| refused(username))
      {
        return Err(
          anyhow!("Username is reserved")
            .status_code(StatusCode::BAD_REQUEST),
        );
      }
      Ok(())
    }

    fn no_users_exist(
      &self,
    ) -> crate::DynFuture<mogh_error::Result<bool>> {
      let no_users_exist = self.no_users_exist;
      Box::pin(async move { Ok(no_users_exist) })
    }

    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      self.static_providers.clone()
    }

    fn find_user_with_username(
      &self,
      username: String,
    ) -> crate::DynFuture<
      mogh_error::Result<Option<crate::user::BoxAuthUser>>,
    > {
      let user = self
        .taken_usernames
        .contains(&username.as_str())
        .then(|| {
          Box::new(TestUser {
            id: format!("id-of-{username}"),
            cidr_whitelist: Vec::new(),
            enabled: true,
          }) as crate::user::BoxAuthUser
        });
      Box::pin(async { Ok(user) })
    }

    fn record_login(
      &self,
      login: Login,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.calls.lock().unwrap().recorded.push(login);
      Box::pin(async { Ok(()) })
    }

    fn find_user_with_external_login(
      &self,
      provider_id: String,
      external_id: String,
    ) -> crate::DynFuture<
      mogh_error::Result<Option<crate::user::BoxAuthUser>>,
    > {
      let user = self
        .calls
        .lock()
        .unwrap()
        .logins
        .iter()
        .find(|(login, _)| {
          *login == (provider_id.clone(), external_id.clone())
        })
        .map(|(_, user_id)| {
          Box::new(TestUser {
            id: user_id.clone(),
            cidr_whitelist: self.cidr_whitelist.clone(),
            enabled: true,
          }) as crate::user::BoxAuthUser
        });
      Box::pin(async move { Ok(user) })
    }

    fn sign_up_external_user(
      &self,
      username: String,
      info: ExternalLoginInfo,
      _no_users_exist: bool,
    ) -> crate::DynFuture<mogh_error::Result<String>> {
      let mut calls = self.calls.lock().unwrap();
      calls.signed_up.push(username);
      calls.logins.push((
        (info.provider_id, info.external_id),
        "new-user".into(),
      ));
      Box::pin(async { Ok("new-user".to_string()) })
    }

    fn sync_external_user(
      &self,
      user_id: String,
      info: ExternalLoginInfo,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      if self.sync_fails {
        return Box::pin(async {
          Err(anyhow!("sync failed").into())
        });
      }
      self.calls.lock().unwrap().synced.push((user_id, info));
      Box::pin(async { Ok(()) })
    }

    fn link_external_login(
      &self,
      user_id: String,
      info: ExternalLoginInfo,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self
        .calls
        .lock()
        .unwrap()
        .logins
        .push(((info.provider_id, info.external_id), user_id));
      Box::pin(async { Ok(()) })
    }

    fn get_user(
      &self,
      user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      let user = Box::new(TestUser {
        id: user_id,
        cidr_whitelist: self.cidr_whitelist.clone(),
        enabled: !self.users_disabled,
      }) as crate::user::BoxAuthUser;
      Box::pin(async { Ok(user) })
    }

    fn locked_usernames(&self) -> &'static [String] {
      static LOCKED: std::sync::LazyLock<Vec<String>> =
        std::sync::LazyLock::new(|| vec!["user".to_string()]);
      if self.username_locked { &LOCKED } else { &[] }
    }

    // The sign-up / login paths stamp the session expiry on the
    // login record through jwt_provider.
    stub_auth_impl!(handle_request_authentication, jwt_provider);
  }

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

  fn github(
    id: &str,
    enabled: bool,
    client_secret: &str,
  ) -> ExternalLoginProvider {
    ExternalLoginProvider {
      id: id.to_string(),
      name: "Github".to_string(),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Github(
        mogh_auth_client::config::NamedOauthConfig {
          enabled,
          client_id: "client-id".to_string(),
          client_secret: client_secret.to_string(),
        },
      ),
    }
  }

  async fn built(
    provider: &ExternalLoginProvider,
  ) -> Arc<BuiltProvider> {
    load_built_provider(
      "test",
      "https://example.com",
      "/auth",
      provider,
    )
    .await
    .unwrap()
  }

  fn completed(
    provider: &ExternalLoginProvider,
    external_id: &str,
    admin: Option<bool>,
  ) -> CompletedExternalLogin {
    CompletedExternalLogin::known(
      ExternalLoginInfo {
        provider_id: provider.id.clone(),
        kind: provider.kind(),
        external_id: external_id.to_string(),
        avatar_url: None,
        groups: None,
        admin,
      },
      "octocat",
    )
  }

  async fn run_login(
    auth: &TestAuth,
    session: &Session,
    provider: &ExternalLoginProvider,
    external_id: &str,
  ) -> mogh_error::Result<Redirect> {
    login_callback(
      auth,
      session,
      provider,
      built(provider).await.as_ref(),
      completed(provider, external_id, Some(true)),
      None,
      IP,
    )
    .await
  }

  #[tokio::test]
  async fn test_load_provider_unknown_and_disabled() {
    let auth = TestAuth {
      static_providers: vec![github(
        "flow-disabled",
        false,
        "secret",
      )],
      ..Default::default()
    };
    let err =
      load_enabled_provider(&auth, "unknown").await.err().unwrap();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
    let err = load_enabled_provider(&auth, "flow-disabled")
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// The login endpoints are unauthenticated, the reason
  /// a provider can't be built is only logged.
  #[tokio::test]
  async fn test_load_provider_failure_does_not_leak_details() {
    let auth = TestAuth {
      static_providers: vec![github("flow-broken", true, "")],
      ..Default::default()
    };
    let err = load_enabled_provider(&auth, "flow-broken")
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
    let message = format!("{:#}", err.error);
    assert!(message.contains("not available"), "{message}");
    assert!(!message.contains("client_secret"), "{message}");
    // Nor logged again by every request while it is down.
    assert!(!is_logged_here(&err));
  }

  #[tokio::test]
  async fn test_login_existing_user_syncs_and_authenticates() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth::default().with_login("flow-a", "42");
    let session = session();

    let redirect =
      run_login(&auth, &session, &provider, "42").await.unwrap();
    assert!(location(redirect).contains("redeem_ready=true"));

    {
      let calls = auth.calls.lock().unwrap();
      assert!(calls.signed_up.is_empty());
      assert_eq!(calls.synced.len(), 1);
      assert_eq!(calls.synced[0].0, "existing-user");
      assert_eq!(calls.synced[0].1.provider_id, "flow-a");
      assert_eq!(calls.synced[0].1.admin, Some(true));
      // The login is recorded as one through the provider
      assert_eq!(calls.recorded.len(), 1);
      assert_eq!(calls.recorded[0].user_id, "existing-user");
      assert!(calls.recorded[0].second_factor.is_none());
      assert_eq!(
        calls.recorded[0].kind,
        LoginKind::Provider {
          provider_id: "flow-a".into(),
          provider_name: provider.name.clone(),
        }
      );
    }
    assert_eq!(
      session
        .retrieve_authenticated_user_id()
        .await
        .unwrap()
        .user_id,
      "existing-user"
    );
  }

  /// External ids are only unique per provider: the same id at
  /// another provider must never log in as the existing user.
  #[tokio::test]
  async fn test_login_same_external_id_at_other_provider_is_other_user()
   {
    let provider = github("flow-b", true, "secret");
    let auth = TestAuth::default().with_login("flow-a", "42");
    let session = session();

    let _redirect =
      run_login(&auth, &session, &provider, "42").await.unwrap();

    assert_eq!(auth.calls.lock().unwrap().signed_up, ["octocat"]);
    assert_eq!(
      session
        .retrieve_authenticated_user_id()
        .await
        .unwrap()
        .user_id,
      "new-user"
    );
  }

  #[tokio::test]
  async fn test_signup_respects_registration_disabled() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth {
      registration_disabled: true,
      ..Default::default()
    };
    let session = session();
    let err = run_login(&auth, &session, &provider, "42")
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(auth.calls.lock().unwrap().signed_up.is_empty());
    assert!(auth.calls.lock().unwrap().recorded.is_empty());
    assert!(session.retrieve_authenticated_user_id().await.is_err());

    // Provider level setting
    let mut disabled = github("flow-a", true, "secret");
    disabled.registration_disabled = true;
    let auth = TestAuth::default();
    assert!(
      run_login(&auth, &session, &disabled, "42").await.is_err()
    );
    assert!(auth.calls.lock().unwrap().recorded.is_empty());

    // The first user can always sign up, which logs them in
    let auth = TestAuth {
      registration_disabled: true,
      no_users_exist: true,
      ..Default::default()
    };
    let _redirect =
      run_login(&auth, &session, &provider, "42").await.unwrap();
    let calls = auth.calls.lock().unwrap();
    assert_eq!(calls.signed_up, ["octocat"]);
    assert_eq!(calls.recorded.len(), 1);
    assert_eq!(calls.recorded[0].username, "octocat");
    assert_eq!(calls.recorded[0].ip, IP);
    assert!(calls.recorded[0].second_factor.is_none());
    assert_eq!(
      calls.recorded[0].kind,
      LoginKind::Provider {
        provider_id: "flow-a".into(),
        provider_name: provider.name.clone(),
      }
    );
  }

  #[tokio::test]
  async fn test_failed_sync_fails_login_without_session() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth {
      sync_fails: true,
      ..Default::default()
    }
    .with_login("flow-a", "42");
    let session = session();
    assert!(
      run_login(&auth, &session, &provider, "42").await.is_err()
    );
    assert!(session.retrieve_authenticated_user_id().await.is_err());
  }

  #[tokio::test]
  async fn test_cidr_whitelist_rejected_before_sync() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth {
      cidr_whitelist: vec!["192.168.0.0/16".to_string()],
      ..Default::default()
    }
    .with_login("flow-a", "42");
    let session = session();
    let err = run_login(&auth, &session, &provider, "42")
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert!(auth.calls.lock().unwrap().synced.is_empty());
    assert!(session.retrieve_authenticated_user_id().await.is_err());
  }

  #[tokio::test]
  async fn test_link_new_login_links_and_syncs() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth::default();
    let redirect = link_callback(
      &auth,
      &provider,
      "linking-user".to_string(),
      completed(&provider, "42", None),
      IP,
    )
    .await
    .unwrap();
    assert_eq!(location(redirect), "https://example.com/profile");
    let calls = auth.calls.lock().unwrap();
    assert_eq!(
      calls.logins,
      [(("flow-a".into(), "42".into()), "linking-user".into())]
    );
    assert_eq!(calls.synced.len(), 1);
    assert_eq!(calls.synced[0].0, "linking-user");
  }

  fn rejected() -> mogh_error::Result<Redirect> {
    Err(
      anyhow!("User registration is disabled & more")
        .status_code(StatusCode::UNAUTHORIZED),
    )
  }

  #[test]
  fn test_error_redirect_is_opt_in() {
    // By default the JSON error is the response, as before.
    let auth = TestAuth::default();
    let err = error_redirect(&auth, ExternalFlow::Login, rejected())
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // Successful flows are never touched.
    let auth = TestAuth {
      error_redirect: Some("https://example.com/login"),
      ..Default::default()
    };
    let ok = error_redirect(
      &auth,
      ExternalFlow::Login,
      Ok(Redirect::to("https://idp.example.com/authorize")),
    )
    .unwrap();
    assert_eq!(location(ok), "https://idp.example.com/authorize");
  }

  #[test]
  fn test_error_redirect_sends_the_reason_to_the_app() {
    let auth = TestAuth {
      error_redirect: Some("https://example.com/login"),
      ..Default::default()
    };
    let redirect =
      error_redirect(&auth, ExternalFlow::Login, rejected()).unwrap();
    assert_eq!(
      location(redirect),
      "https://example.com/login?login_error=User%20registration%20is%20disabled%20%26%20more"
    );
    // A failed link goes back to where links are managed.
    let redirect =
      error_redirect(&auth, ExternalFlow::Link, rejected()).unwrap();
    assert!(
      location(redirect)
        .starts_with("https://example.com/profile?link_error=User")
    );
    // An existing query is kept.
    let auth = TestAuth {
      error_redirect: Some("https://example.com/login?theme=dark"),
      ..Default::default()
    };
    let redirect =
      error_redirect(&auth, ExternalFlow::Login, rejected()).unwrap();
    assert!(location(redirect).starts_with(
      "https://example.com/login?theme=dark&login_error=User"
    ));
  }

  /// The flows' failures come through the rate limit, which notes
  /// the attempts left on top of the error.
  #[tokio::test]
  async fn test_error_redirect_shows_the_attempts_left_once() {
    let auth = TestAuth {
      error_redirect: Some("https://example.com/login"),
      ..Default::default()
    };
    let limiter = mogh_rate_limit::RateLimiter::new(
      false,
      3,
      std::time::Duration::from_secs(60),
    );
    let ip = IpAddr::from([10, 0, 0, 1]);
    let res = async {
      Err::<Redirect, _>(
        anyhow!("User registration is disabled")
          .context("Login rejected")
          .status_code(StatusCode::UNAUTHORIZED),
      )
    }
    .with_failure_rate_limit_using_ip(&limiter, &ip)
    .await;
    let redirect =
      error_redirect(&auth, ExternalFlow::Login, res).unwrap();
    assert_eq!(
      location(redirect),
      "https://example.com/login?login_error=Login%20rejected%3A%20User%20registration%20is%20disabled%20%7C%20You%20have%202%20attempts%20remaining"
    );
  }

  /// A redirect reports server errors only as such: their
  /// causes are for the operator, not for the url bar.
  #[test]
  fn test_error_redirect_hides_server_errors() {
    let auth = TestAuth {
      error_redirect: Some("https://example.com/login"),
      ..Default::default()
    };
    for (flow, target) in [
      (
        ExternalFlow::Login,
        "https://example.com/login?login_error=",
      ),
      (
        ExternalFlow::Link,
        "https://example.com/profile?link_error=",
      ),
    ] {
      let location = location(
        error_redirect(&auth, flow, server_error()).unwrap(),
      );
      assert!(location.starts_with(target), "{location}");
      assert!(
        location
          .ends_with(&*urlencoding::encode(SERVER_ERROR_MESSAGE)),
        "{location}"
      );
      assert!(!location.contains("10.0.0.5"), "{location}");
    }
  }

  #[tokio::test]
  async fn test_link_rejects_login_linked_to_another_user() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth::default().with_login("flow-a", "42");
    let err = link_callback(
      &auth,
      &provider,
      "linking-user".to_string(),
      completed(&provider, "42", None),
      IP,
    )
    .await
    .unwrap_err();
    // Not a server error, the login belongs to somebody else.
    assert_eq!(err.status, StatusCode::CONFLICT);
    let calls = auth.calls.lock().unwrap();
    assert_eq!(calls.logins.len(), 1);
    assert!(calls.synced.is_empty());
  }

  #[tokio::test]
  async fn test_empty_provider_username_falls_back_to_external_id() {
    let provider = github("flow-a", true, "secret");
    let completed = CompletedExternalLogin::known(
      completed(&provider, "42", None).info,
      "  ",
    );
    assert_eq!(
      completed.username(built(&provider).await.as_ref()).await,
      "42"
    );
  }

  /// The login is started by unauthenticated requests: only a
  /// bounded, sanitized redirect is stored on the session.
  #[tokio::test]
  async fn test_login_stores_only_a_sanitized_bounded_redirect() {
    let auth = TestAuth {
      static_providers: vec![github("flow-redirect", true, "secret")],
      ..Default::default()
    };
    for (redirect, stored) in [
      (
        Some("/notes?tab=1"),
        Some("https://example.com/notes?tab=1"),
      ),
      (Some("https://evil.example/steal"), None),
      (Some("//evil.example"), None),
      (None, None),
    ] {
      let session = session();
      let _redirect = begin_external_login(
        &auth,
        "flow-redirect",
        &session,
        redirect.map(String::from),
      )
      .await
      .unwrap();
      let login = session.retrieve_external_login().await.unwrap();
      assert_eq!(login.redirect.as_deref(), stored, "{redirect:?}");
    }
    let session = session();
    let long = format!("/{}", "a".repeat(60 * 1024));
    let _redirect = begin_external_login(
      &auth,
      "flow-redirect",
      &session,
      Some(long),
    )
    .await
    .unwrap();
    let login = session.retrieve_external_login().await.unwrap();
    assert_eq!(login.redirect, None);
  }

  fn session_on(
    store: &Arc<tower_sessions::MemoryStore>,
    id: Option<tower_sessions::session::Id>,
  ) -> Session {
    Session(tower_sessions::Session::new(id, store.clone(), None))
  }

  /// A failed link request uses up the link begun on the session,
  /// in the store as well, so it can't be completed later (with
  /// another provider) by whoever holds the session.
  #[tokio::test]
  async fn test_failed_link_uses_up_the_begun_link() {
    let store = Arc::new(tower_sessions::MemoryStore::default());
    let session = session_on(&store, None);
    // As BeginExternalLoginLink leaves it.
    session
      .insert_external_link_user_id("user-1", "unknown")
      .await
      .unwrap();
    session.0.save().await.unwrap();
    let id = session.id();

    let err = external_link::<TestAuth>(
      "unknown".to_string(),
      RequestIp(IP),
      session.clone(),
      HeaderMap::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::NOT_FOUND);

    assert!(session.retrieve_external_link().await.is_err());
    let stored = session_on(&store, id);
    let err = stored.retrieve_external_link().await.err().unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// A link begun longer than [Session::MAX_EXTERNAL_LINK_AGE] ago is
  /// refused, and used up as well. The failure is one of the link,
  /// it goes back to where the link was begun.
  #[tokio::test]
  async fn test_expired_link_is_refused_and_used_up() {
    let store = Arc::new(tower_sessions::MemoryStore::default());
    let session = session_on(&store, None);
    let now = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_secs();
    let expired = now - Session::MAX_EXTERNAL_LINK_AGE.as_secs() - 60;
    session
      .insert_external_link("user-1", "github", expired)
      .await
      .unwrap();
    session.0.save().await.unwrap();
    let id = session.id();

    let err = external_link::<TestAuth>(
      "github".to_string(),
      RequestIp(IP),
      session.clone(),
      HeaderMap::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("expired"));

    let stored = session_on(&store, id);
    let err = stored.retrieve_external_link().await.err().unwrap();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );

    // With the error redirect, to the page of the link.
    session
      .insert_external_link("user-1", "github", expired)
      .await
      .unwrap();
    let redirect = external_link::<LinkErrorAuth>(
      "github".to_string(),
      RequestIp(IP),
      session.clone(),
      HeaderMap::new(),
    )
    .await
    .unwrap();
    let location = location(redirect);
    assert!(
      location.starts_with("https://example.com/profile?link_error="),
      "{location}"
    );
  }

  /// An app which shows failed logins and links, for flows which
  /// fail before they need anything else.
  struct LinkErrorAuth;

  impl AuthImpl for LinkErrorAuth {
    fn new() -> Self {
      LinkErrorAuth
    }
    fn host(&self) -> &str {
      "https://example.com"
    }
    fn post_link_redirect(&self) -> &str {
      "https://example.com/profile"
    }
    fn external_login_error_redirect(&self) -> Option<&str> {
      Some("https://example.com/login")
    }
    stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
  }

  /// An app which shows failed logins on its login page, but has no
  /// linking (so no [AuthImpl::post_link_redirect], whose default
  /// panics).
  struct NoLinkingAuth;

  impl AuthImpl for NoLinkingAuth {
    fn new() -> Self {
      NoLinkingAuth
    }
    fn host(&self) -> &str {
      "https://example.com"
    }
    fn external_login_error_redirect(&self) -> Option<&str> {
      Some("https://example.com/login")
    }
    stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
  }

  /// Anyone can request the link routes. Without a link begun on the
  /// session the request is not a link, and fails to the login page
  /// rather than the (panicking) link page.
  #[tokio::test]
  async fn test_link_without_begun_link_fails_to_the_login_page() {
    for slug in ["oidc", "unknown"] {
      let redirect = external_link::<NoLinkingAuth>(
        slug.to_string(),
        RequestIp(IP),
        session(),
        HeaderMap::new(),
      )
      .await
      .unwrap();
      let location = location(redirect);
      assert!(
        location
          .starts_with("https://example.com/login?login_error="),
        "{location}"
      );
      assert!(
        location.contains("not%20been%20initiated"),
        "{location}"
      );
    }
    // The callback of a flow never started on the session.
    let redirect = external_callback::<NoLinkingAuth>(
      "oidc".to_string(),
      RequestIp(IP),
      session(),
      Query(StandardCallbackQuery {
        state: Some("state".into()),
        code: Some("code".into()),
        error: None,
      }),
    )
    .await
    .unwrap();
    assert!(
      location(redirect)
        .starts_with("https://example.com/login?login_error=")
    );
  }

  /// The requests anybody holding the cookie can send leave a
  /// session without a flow in flight unmodified: the session layer
  /// would save it, extending its expiry, and keep whatever else is
  /// pending on it (a second factor) alive.
  #[tokio::test]
  async fn test_nothing_in_flight_leaves_the_session_unmodified() {
    let store = Arc::new(tower_sessions::MemoryStore::default());
    let session = session_on(&store, None);
    session.insert_totp_login_user_id("user-1").await.unwrap();
    session.0.save().await.unwrap();
    let id = session.id();

    let session = session_on(&store, id);
    let redirect = external_callback::<NoLinkingAuth>(
      "oidc".to_string(),
      RequestIp(IP),
      session.clone(),
      Query(StandardCallbackQuery {
        state: Some("state".into()),
        code: Some("code".into()),
        error: None,
      }),
    )
    .await
    .unwrap();
    assert!(location(redirect).contains("not%20been%20initiated"));
    let redirect = external_link::<NoLinkingAuth>(
      "oidc".to_string(),
      RequestIp(IP),
      session.clone(),
      HeaderMap::new(),
    )
    .await
    .unwrap();
    assert!(location(redirect).contains("not%20been%20initiated"));
    assert!(!session.0.is_modified());
  }

  /// A link completes only for a user who can still link: enabled,
  /// not locked, and within their cidr whitelist. The user may have
  /// changed since the link was started.
  #[tokio::test]
  async fn test_link_is_refused_once_the_user_can_not_link() {
    let provider = github("flow-a", true, "secret");
    for (auth, status, reason) in [
      (
        TestAuth {
          users_disabled: true,
          ..Default::default()
        },
        StatusCode::FORBIDDEN,
        "not enabled",
      ),
      (
        TestAuth {
          username_locked: true,
          ..Default::default()
        },
        StatusCode::UNAUTHORIZED,
        "locked",
      ),
      (
        TestAuth {
          cidr_whitelist: vec!["192.168.0.0/16".to_string()],
          ..Default::default()
        },
        StatusCode::FORBIDDEN,
        "",
      ),
    ] {
      let err = link_callback(
        &auth,
        &provider,
        "linking-user".to_string(),
        completed(&provider, "42", None),
        IP,
      )
      .await
      .unwrap_err();
      assert_eq!(err.status, status, "{reason}");
      assert!(format!("{:#}", err.error).contains(reason));
      let calls = auth.calls.lock().unwrap();
      assert!(calls.logins.is_empty(), "{reason}");
      assert!(calls.synced.is_empty(), "{reason}");
    }
  }

  /// An app whose users are disabled, with a provider to link.
  struct DisabledUserAuth;

  impl AuthImpl for DisabledUserAuth {
    fn new() -> Self {
      DisabledUserAuth
    }
    fn host(&self) -> &str {
      "https://example.com"
    }
    fn post_link_redirect(&self) -> &str {
      "https://example.com/profile"
    }
    fn external_login_error_redirect(&self) -> Option<&str> {
      Some("https://example.com/login")
    }
    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      vec![github("flow-link", true, "secret")]
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      Box::pin(async {
        Ok(Box::new(TestUser {
          id: user_id,
          cidr_whitelist: Vec::new(),
          enabled: false,
        }) as crate::user::BoxAuthUser)
      })
    }
    stub_auth_impl!(handle_request_authentication, jwt_provider);
  }

  /// A user disabled after beginning a link can't start it: nothing
  /// is left on the session for the provider's callback to complete.
  #[tokio::test]
  async fn test_link_start_is_refused_for_a_disabled_user() {
    let session = session();
    session
      .insert_external_link_user_id("user-1", "flow-link")
      .await
      .unwrap();
    let redirect = external_link::<DisabledUserAuth>(
      "flow-link".to_string(),
      RequestIp(IP),
      session.clone(),
      HeaderMap::new(),
    )
    .await
    .unwrap();
    assert_eq!(
      location(redirect),
      "https://example.com/profile?link_error=User%20is%20not%20enabled"
    );
    assert!(session.retrieve_external_login().await.is_err());
  }

  fn server_error() -> mogh_error::Result<Redirect> {
    Err(
      anyhow!("connection refused to 10.0.0.5:5432")
        .context("Failed to get Oauth token")
        .status_code(StatusCode::BAD_GATEWAY),
    )
  }

  /// Server errors are logged by [error_redirect], but not a provider
  /// which can't be loaded: [load_provider_client] logged it once.
  #[tokio::test]
  async fn test_error_redirect_logs_server_errors() {
    assert!(is_logged_here(&server_error().unwrap_err()));
    assert!(!is_logged_here(&rejected().unwrap_err()));
    let unavailable = || {
      anyhow::Error::new(ProviderUnavailable("flow-a".into()))
        .status_code(StatusCode::SERVICE_UNAVAILABLE)
    };
    assert!(!is_logged_here(&unavailable()));
    // Also under the note of the rate limit (callbacks).
    let limiter = mogh_rate_limit::RateLimiter::new(
      false,
      3,
      std::time::Duration::from_secs(60),
    );
    let err = async { Err::<Redirect, _>(unavailable()) }
      .with_failure_rate_limit_using_ip(
        &limiter,
        &IpAddr::from([10, 0, 0, 2]),
      )
      .await
      .unwrap_err();
    assert!(!is_logged_here(&err));
  }

  /// Without the redirect the JSON error is left to `mogh_error`,
  /// which sends the full trace by default.
  #[test]
  fn test_server_errors_keep_their_detail_without_the_redirect() {
    let auth = TestAuth::default();
    for flow in [ExternalFlow::Login, ExternalFlow::Link] {
      let err =
        error_redirect(&auth, flow, server_error()).unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_GATEWAY);
      let body = mogh_error::serialize_error(&err.error);
      assert!(body.contains("Failed to get Oauth token"), "{body}");
      assert!(body.contains("10.0.0.5"), "{body}");
      assert!(!body.contains(SERVER_ERROR_MESSAGE), "{body}");
    }
  }

  async fn signup_username_of(
    auth: &TestAuth,
    provider_username: &str,
  ) -> String {
    signup_username(
      auth,
      &github("flow-names", true, "secret"),
      provider_username.to_string(),
    )
    .await
    .unwrap()
  }

  /// External sign ups are held to the app's username rule.
  #[tokio::test]
  async fn test_signup_username_passes_validate_username() {
    let auth = TestAuth {
      rejected_usernames: vec!["admin"],
      ..Default::default()
    };
    for (provider_username, username) in [
      ("octocat", "octocat"),
      ("john.doe@example.com", "john.doe@example.com"),
      ("John Smith", "John-Smith"),
      ("  José  Müller ", "Jos-M-ller"),
      ("john.doe+tag@example.com", "john.doe-tag@example.com"),
      // A name the rule allows is kept as it is.
      ("-.alice.-", "-.alice.-"),
      ("- alice -", "alice"),
    ] {
      assert_eq!(
        signup_username_of(&auth, provider_username).await,
        username
      );
    }
    let long = signup_username_of(&auth, &"a".repeat(150)).await;
    assert_eq!(long, "a".repeat(MAX_USERNAME_LENGTH));

    // Nothing usable is left, or the app refuses it:
    // a name made from the provider's slug.
    for provider_username in ["日本語", "admin", "!!!"] {
      let username =
        signup_username_of(&auth, provider_username).await;
      assert!(username.starts_with("flow-names-"), "{username}");
      assert_eq!(username.len(), "flow-names-".len() + 8);
      crate::validations::validate_username(&username).unwrap();
    }
  }

  /// External sign ups are held to the app's rule for new usernames
  /// too, the names with a random suffix included: a refused name
  /// moves on to the next one, and to a generated name. A refused
  /// generated name fails the sign up.
  #[tokio::test]
  async fn test_signup_username_passes_validate_new_username() {
    let auth = TestAuth {
      // Reserved, and the suffixed form of a taken name.
      refused_new_usernames: Some(|name| {
        name == "System" || name.starts_with("octocat-")
      }),
      taken_usernames: vec!["octocat"],
      ..Default::default()
    };
    for provider_username in ["System", "octocat"] {
      let username =
        signup_username_of(&auth, provider_username).await;
      assert!(
        username.starts_with("flow-names-"),
        "{provider_username}: {username}"
      );
    }
    assert_eq!(signup_username_of(&auth, "Systems").await, "Systems");

    let auth = TestAuth {
      refused_new_usernames: Some(|_| true),
      ..Default::default()
    };
    let err = signup_username(
      &auth,
      &github("flow-names", true, "secret"),
      "anybody".to_string(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
      format!("{:#}", err.error).contains("validate_new_username"),
      "{:#}",
      err.error
    );
  }

  #[tokio::test]
  async fn test_signup_uses_the_valid_username() {
    let provider = github("flow-a", true, "secret");
    let auth = TestAuth::default();
    let completed = CompletedExternalLogin::known(
      completed(&provider, "42", None).info,
      "Mona Lisa Octocat",
    );
    let _redirect = login_callback(
      &auth,
      &session(),
      &provider,
      built(&provider).await.as_ref(),
      completed,
      None,
      IP,
    )
    .await
    .unwrap();
    assert_eq!(
      auth.calls.lock().unwrap().signed_up,
      ["Mona-Lisa-Octocat"]
    );
  }

  /// Axum panics on conflicting or malformed routes when the
  /// router is built, which covers the reserved id paths
  /// living next to `/external/{provider_id}`.
  /// One provider, and 2 login starts per client, for the tests of
  /// the start limit.
  struct StartLimitAuth;

  impl AuthImpl for StartLimitAuth {
    fn new() -> Self {
      StartLimitAuth
    }
    fn host(&self) -> &str {
      "https://example.com"
    }
    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      vec![github("start-limit", true, "secret")]
    }
    fn login_start_limiter(
      &self,
    ) -> &crate::login_start::LoginStartLimiter {
      static LIMITER: std::sync::LazyLock<
        crate::login_start::LoginStartLimiter,
      > = std::sync::LazyLock::new(|| {
        crate::login_start::LoginStartLimiter::new(
          2,
          1,
          std::time::Duration::from_secs(60),
        )
      });
      &LIMITER
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      let user = Box::new(TestUser {
        id: user_id,
        cidr_whitelist: Vec::new(),
        enabled: true,
      }) as crate::user::BoxAuthUser;
      Box::pin(async { Ok(user) })
    }
    stub_auth_impl!(handle_request_authentication, jwt_provider);
  }

  async fn start_login(
    ip: IpAddr,
    session: Session,
    headers: HeaderMap,
  ) -> mogh_error::Result<Redirect> {
    external_login::<StartLimitAuth>(
      "start-limit".to_string(),
      RequestIp(ip),
      session,
      headers,
      Query(RedirectQuery { redirect: None }),
    )
    .await
  }

  /// Each start takes one of the client's: past them a start is
  /// refused (`429`, `Retry-After`) and stores nothing on the
  /// session. A request another site embedded (eg. as an image) is
  /// refused before it takes one. Other clients have their own.
  #[tokio::test]
  async fn test_login_starts_are_limited_per_client() {
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 7, 1));
    let mut embedded = HeaderMap::new();
    for (name, value) in [
      ("sec-fetch-site", "cross-site"),
      ("sec-fetch-mode", "no-cors"),
      ("sec-fetch-dest", "image"),
    ] {
      embedded.insert(name, value.parse().unwrap());
    }
    for _ in 0..5 {
      let session = session();
      let err = start_login(ip, session.clone(), embedded.clone())
        .await
        .unwrap_err();
      assert_eq!(err.status, StatusCode::FORBIDDEN);
      assert!(session.retrieve_external_login().await.is_err());
    }
    for _ in 0..2 {
      let session = session();
      let redirect =
        start_login(ip, session.clone(), HeaderMap::new())
          .await
          .unwrap();
      assert!(location(redirect).starts_with("https://github.com/"));
      assert!(session.retrieve_external_login().await.is_ok());
    }
    let refused = session();
    let err = start_login(ip, refused.clone(), HeaderMap::new())
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
      err
        .headers
        .as_ref()
        .is_some_and(|headers| headers.contains_key("retry-after"))
    );
    assert!(
      err.error.to_string().starts_with("Too many logins started")
    );
    assert!(refused.retrieve_external_login().await.is_err());
    // Not a server error, so not logged by every refused request.
    assert!(!is_logged_here(&err));

    let other = IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 7, 2));
    let _started = start_login(other, session(), HeaderMap::new())
      .await
      .unwrap();
  }

  /// A link start takes one of the client's starts as well. Refused,
  /// it leaves the link begun on the session for a later try.
  #[tokio::test]
  async fn test_a_refused_link_start_keeps_the_link() {
    let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 7, 7, 3));
    for _ in 0..2 {
      let _started =
        start_login(ip, session(), HeaderMap::new()).await.unwrap();
    }
    let session = session();
    session
      .insert_external_link_user_id("user-1", "start-limit")
      .await
      .unwrap();
    let err = external_link::<StartLimitAuth>(
      "start-limit".to_string(),
      RequestIp(ip),
      session.clone(),
      HeaderMap::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(session.retrieve_external_link().await.is_ok());
  }

  /// Anybody can send a browser to the callback with an `error`:
  /// only one carrying the state of the login the session started is
  /// the provider's answer, others are a state mismatch. The answer is
  /// reported with a fixed message by its code, never its text, which
  /// the login page would show as the server's reason.
  #[tokio::test]
  async fn test_callback_error_is_checked_against_the_state() {
    let callback = |state: Option<&str>, error: &str| {
      let query = StandardCallbackQuery {
        state: state.map(String::from),
        code: None,
        error: Some(error.to_string()),
      };
      async move {
        let session = session();
        session
          .insert_external_login(&session_login("start-limit"))
          .await
          .unwrap();
        external_callback::<StartLimitAuth>(
          "start-limit".to_string(),
          RequestIp(IP),
          session,
          Query(query),
        )
        .await
        .unwrap_err()
      }
    };
    let made_up = "Your account is locked, call +1-555-0100";
    for state in [Some("forged"), Some("")] {
      let err = callback(state, made_up).await;
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
      assert_eq!(format!("{:#}", err.error), "State mismatch");
    }
    let err = callback(None, made_up).await;
    assert!(format!("{:#}", err.error).contains("contain state"));

    let err = callback(Some("expected-state"), "access_denied").await;
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
      format!("{:#}", err.error),
      "Login was denied at the provider"
    );
    for error in [made_up, "invalid_scope"] {
      let err = callback(Some("expected-state"), error).await;
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
      assert_eq!(
        format!("{:#}", err.error),
        "Login was not completed at the provider"
      );
    }
  }

  #[test]
  fn test_router_builds_without_route_conflicts() {
    let _ = router::<TestAuth>();
    let _ = crate::api::router::<TestAuth>();
  }

  #[test]
  fn test_validate_callback_accepts_matching_provider_and_state() {
    assert!(
      validate_callback(
        &session_login("abc"),
        "abc",
        "expected-state"
      )
      .is_ok()
    );
  }

  #[test]
  fn test_validate_callback_rejects_other_provider() {
    let err = validate_callback(
      &session_login("abc"),
      "other",
      "expected-state",
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_validate_callback_rejects_state_mismatch() {
    let err =
      validate_callback(&session_login("abc"), "abc", "forged-state")
        .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_auth_redirect_no_redirect_host() {
    let redirect =
      auth_redirect("https://idp.internal/authorize?a=1", "")
        .unwrap();
    assert_eq!(
      location(redirect),
      "https://idp.internal/authorize?a=1"
    );
  }

  #[test]
  fn test_auth_redirect_replaces_host() {
    let redirect = auth_redirect(
      "https://idp.internal/authorize?a=1",
      "https://idp.external",
    )
    .unwrap();
    assert_eq!(
      location(redirect),
      "https://idp.external/authorize?a=1"
    );
  }

  #[test]
  fn test_auth_redirect_host_without_path() {
    let redirect =
      auth_redirect("https://idp.internal", "https://idp.external")
        .unwrap();
    assert_eq!(location(redirect), "https://idp.external");
  }

  #[test]
  fn test_auth_redirect_missing_protocol_errors() {
    assert!(
      auth_redirect("idp.internal/authorize", "https://external")
        .is_err()
    );
  }
}
