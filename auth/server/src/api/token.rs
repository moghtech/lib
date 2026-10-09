//! The OAuth 2.0 token endpoint, implementing
//! [RFC 8693 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693):
//! a token issued by an external login provider is
//! exchanged for an app token, without any user interaction.
//!
//! - Only providers which opt in with `token_exchange.enabled` take part.
//! - Only tokens signed by the provider are accepted (ID tokens / JWTs),
//!   and they must be issued to an accepted audience.
//! - The user must already exist, the endpoint never signs anyone up.
//! - Users who need a second factor for external logins are rejected,
//!   there is nobody to ask for it.
//! - The app token of a user counts as a login at the time the
//!   provider authenticated the user (the token's `auth_time`, else its
//!   `iat`), not at the exchange: a provider token can be exchanged
//!   again until it expires, so an old one is no recent login for
//!   [AuthImpl::reauthentication_window_secs].
//!
//! Errors are OAuth errors (RFC 6749 section 5.2). A malformed request
//! is `invalid_request`, and a token which is rejected for any reason
//! (signature, audience, expiry, no matching rule, the login rules) is
//! `invalid_grant`, as for the assertion grants of RFC 7521 / 7523 and
//! common token services. This deliberately deviates from RFC 8693
//! section 2.2.2, which would report a rejected `subject_token` as
//! `invalid_request` too: clients can tell a request to fix apart from
//! a token to replace.
//!
//! Except when another login provider / trusted issuer of the same
//! issuer couldn't be loaded: a token the others rejected for its
//! signature, audience, expiry or a provider's `allowed_groups` is
//! then `503 temporarily_unavailable`, since the one which couldn't be
//! asked might have accepted it. A token one of them verified whose
//! user is unknown, or which matches no rule, stays `invalid_grant`,
//! as does a user one of them accepted who fails the login rules.
//! Login providers and trusted issuers are ranked together, the
//! furthest any of them got is reported. Such a `503` still counts
//! against the rate limit when another rejected the token: the
//! caller picks the issuer, and a forged token aimed at one with a
//! candidate down would otherwise never count.
//!
//! Apps serving the exchange on another surface (a Vault compatible
//! `auth/jwt/login`) use [exchange_token] and [token_exchange_error].
//!
//! The endpoint takes a form, which any web page can make its
//! visitors' browsers post without asking (a CORS "simple" request).
//! Such a request is refused before anything counts against the
//! visitor's ip ([check_not_cross_site]): failing exchanges on purpose,
//! a page could otherwise get everybody behind that ip refused by
//! [AuthImpl::token_exchange_rate_limiter], which is the general rate
//! limiter of their logins and api requests by default.

use std::{net::IpAddr, sync::Arc};

use axum::{
  Form, Json, Router,
  extract::rejection::FormRejection,
  http::{HeaderMap, HeaderValue, StatusCode, header},
  response::{IntoResponse, Response},
  routing::post,
};
use mogh_auth_client::{
  api::token::{
    GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_JWT, TokenExchangeError,
    TokenExchangeRequest, TokenExchangeResponse,
  },
  config::{
    ExternalLoginProvider, ExternalLoginProviderConfig,
    TrustedIssuer, WorkloadRule,
  },
};
use mogh_error::AddStatusCodeError as _;
use mogh_rate_limit::{
  FailedAttempt, RateLimiter, WithFailureRateLimit as _,
};
use mogh_request_ip::RequestIp;
use tracing::{debug, error, info, instrument};

use crate::{
  AuthImpl, LoginKind,
  api::{
    external::load_provider_client,
    external_login_requires_two_factor,
    login::{IssueToken, issue_login},
  },
  middleware::{
    check_user_cidr_whitelist, is_cross_site_browser_request,
  },
  provider::{
    external::{
      BuiltProvider, ExternalLoginInfo, list_external_providers,
      validate_provider_id,
    },
    load_cache::LoadFailedRecently,
    token_exchange::{
      MAX_SUBJECT_TOKEN_LENGTH, TokenVerificationKeys,
      authenticated_at, issuers_match, unverified_issuer,
    },
    workload::{
      Claims, WorkloadIdentity, hold_off_removal,
      list_trusted_issuers, load_verification_keys,
      lock_workload_user, lookup_claim, match_rule,
    },
  },
  user::BoxAuthUser,
};

/// The issuer of Google ID tokens. Google documents that tokens may
/// also carry the scheme-less `accounts.google.com`, which can't
/// verify: the token parser requires `iss` to be a url. Those are
/// left to "no login provider accepts tokens of this issuer" rather
/// than routed to a provider which always rejects them.
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

pub fn router<I: AuthImpl>() -> Router {
  Router::new().route("/token", post(token::<I>))
}

/// What the exchange should accept, beyond a valid token.
#[derive(Debug, Clone, Default)]
pub struct TokenExchangeOptions {
  /// Only log in through the login provider or workload rule with
  /// this id or name (Vault's `role`): a workload token is matched
  /// against that rule alone, rather than the first matching rule
  /// of its issuer, and a user token only by that provider. A role
  /// nothing accepting the token's issuer has is refused up front
  /// ([RoleNotFound]), before the exchange has any effect.
  pub role: Option<String>,
}

/// What [exchange_token] logged a token in as.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExchangedToken {
  /// The issued app token, as the endpoint answers.
  pub response: TokenExchangeResponse,
  /// The id of the user the token belongs to.
  pub user_id: String,
  /// What the token logged in through.
  pub login: ExchangedLogin,
}

/// What a token was exchanged through.
#[derive(Debug, Clone)]
pub enum ExchangedLogin {
  /// A user's token, verified by a login provider.
  Provider {
    provider_id: String,
    provider_name: String,
  },
  /// A workload's token, verified by a trusted issuer and matched
  /// to one of its rules.
  Workload {
    issuer_id: String,
    issuer_name: String,
    rule_id: String,
    rule_name: String,
  },
}

/// The `role` of [TokenExchangeOptions] names no login provider
/// and no workload rule accepting tokens of the token's issuer.
/// Reported as `invalid_grant`; apps can tell it apart with
/// `error.downcast_ref::<RoleNotFound>()`.
#[derive(Debug)]
pub struct RoleNotFound {
  pub role: String,
}

impl std::fmt::Display for RoleNotFound {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "No login provider or workload rule '{}' accepts tokens of this issuer",
      self.role
    )
  }
}

impl std::error::Error for RoleNotFound {}

/// An error with the OAuth error code to report it as (RFC 6749 section 5.2).
#[derive(Debug)]
struct OauthError {
  code: &'static str,
  description: String,
}

impl std::fmt::Display for OauthError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.description)
  }
}

impl std::error::Error for OauthError {}

fn oauth_error(
  code: &'static str,
  description: impl Into<String>,
) -> mogh_error::Error {
  anyhow::Error::new(OauthError {
    code,
    description: description.into(),
  })
  .status_code(StatusCode::BAD_REQUEST)
}

fn invalid_request(
  description: impl Into<String>,
) -> mogh_error::Error {
  oauth_error("invalid_request", description)
}

fn invalid_grant(
  description: impl Into<String>,
) -> mogh_error::Error {
  oauth_error("invalid_grant", description)
}

/// Converts any error into the OAuth error format.
fn error_response(e: mogh_error::Error) -> Response {
  let (status, error) = token_exchange_error(&e);
  no_store((status, Json(error)).into_response())
}

/// The status and OAuth error (RFC 6749 section 5.2) a failed
/// [exchange_token] is answered with, as the endpoint answers it.
/// Everything but the token's own rejection (`invalid_*`, the rate
/// limit, an unavailable provider) is logged here and reported as
/// a bare `server_error`: the reasons may include internal details.
/// The descriptions of failures counted against the rate limit note
/// the attempts left (`... | You have 2 attempts remaining`).
pub fn token_exchange_error(
  e: &mogh_error::Error,
) -> (StatusCode, TokenExchangeError) {
  let (status, error) =
    if let Some(oauth) = e.error.downcast_ref::<OauthError>() {
      (
        StatusCode::BAD_REQUEST,
        TokenExchangeError {
          error: oauth.code.to_string(),
          error_description: Some(oauth_description(e, oauth)),
        },
      )
    } else if [
      StatusCode::TOO_MANY_REQUESTS,
      // A provider / issuer which can't be reached. The reason
      // was logged where it happened, and isn't part of the error.
      StatusCode::SERVICE_UNAVAILABLE,
    ]
    .contains(&e.status)
    {
      (
        e.status,
        TokenExchangeError {
          error: "temporarily_unavailable".to_string(),
          error_description: Some(e.error.to_string()),
        },
      )
    } else if e.status.is_client_error() {
      // Rejections by the login rules, eg. the group or ip restrictions.
      (
        StatusCode::BAD_REQUEST,
        TokenExchangeError {
          error: "invalid_grant".to_string(),
          error_description: Some(e.error.to_string()),
        },
      )
    } else {
      // May include internal details, which this
      // unauthenticated endpoint must not hand out.
      error!("Token exchange failed | {:#}", e.error);
      (
        StatusCode::INTERNAL_SERVER_ERROR,
        TokenExchangeError {
          error: "server_error".to_string(),
          error_description: None,
        },
      )
    };
  (status, error)
}

/// The description of the OAuth error `e` was found to be. A failed
/// exchange counts against the rate limit, which notes how many
/// attempts are left, as it does on the other errors' descriptions.
fn oauth_description(
  e: &mogh_error::Error,
  oauth: &OauthError,
) -> String {
  match e.error.downcast_ref::<FailedAttempt>() {
    Some(attempt) => attempt.annotate(&oauth.description),
    None => oauth.description.clone(),
  }
}

/// Token responses must not be cached (RFC 6749 section 5.1).
fn no_store(mut response: Response) -> Response {
  let headers = response.headers_mut();
  headers.insert(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-store"),
  );
  headers
    .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
  response
}

async fn token<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  headers: HeaderMap,
  form: Result<Form<TokenExchangeRequest>, FormRejection>,
) -> Response {
  let auth = I::new();
  let res = async {
    // Before anything is counted, see the module doc.
    check_not_cross_site(&auth, &headers)?;
    let Form(request) = form.map_err(|e| {
      invalid_request(format!("Invalid token request | {e}"))
    })?;
    exchange_token(&auth, ip, request, Default::default()).await
  }
  .await;
  match res {
    Ok(exchanged) => {
      no_store(Json(exchanged.response).into_response())
    }
    Err(e) => error_response(e),
  }
}

/// Refuses a request a web browser sent from a page of another site
/// ([is_cross_site_browser_request]) with `invalid_request`, before
/// anything about it is counted.
///
/// A form post is a CORS "simple" request: any page can have its
/// visitors' browsers send one, from their ip. Failing token
/// exchanges on purpose, a page could get everybody behind that ip
/// refused by the rate limiter
/// ([AuthImpl::token_exchange_rate_limiter]), which is the one of
/// their logins and api requests by default. RFC 8693 clients (CLIs,
/// CI jobs, other servers) send neither header the check looks at.
///
/// The `/token` endpoint calls it first. Apps serving the exchange on
/// another surface which takes bodies a browser can post across sites
/// (a form, or a body of any content type) call it before
/// [exchange_token], or [is_cross_site_browser_request] to answer in
/// that surface's own error format.
///
/// ⚠️ An `Origin` without `Sec-Fetch-Site` is compared with
/// [AuthImpl::host], whose default panics: an app serving token
/// exchange implements it.
pub fn check_not_cross_site<I: AuthImpl + ?Sized>(
  auth: &I,
  headers: &HeaderMap,
) -> mogh_error::Result<()> {
  if is_cross_site_browser_request(auth, headers) {
    debug!(
      "Refused a token request a browser sent from another site"
    );
    return Err(invalid_request(
      "A web browser sent this request from another site. Token exchange is refused to web pages of other sites.",
    ));
  }
  Ok(())
}

/// The RFC 8693 exchange of the `/token` endpoint as a function,
/// for apps serving it on another surface, eg. a Vault compatible
/// `auth/jwt/login`. Exactly what the endpoint does, the failure
/// rate limit by client `ip` included
/// ([AuthImpl::token_exchange_rate_limiter]: the surface is
/// unauthenticated wherever it is served): the token is verified
/// by the login providers and trusted issuers, the user's login
/// rules apply, and the app is told about the login through its
/// hooks. Errors map with [token_exchange_error].
///
/// The endpoint refuses requests browsers send from other sites
/// before calling this, see [check_not_cross_site].
pub async fn exchange_token<I: AuthImpl>(
  auth: &I,
  ip: IpAddr,
  request: TokenExchangeRequest,
  options: TokenExchangeOptions,
) -> mogh_error::Result<ExchangedToken> {
  with_exchange_rate_limit(
    exchange(
      auth,
      ip,
      request,
      |provider| async move {
        load_provider_client(auth, &provider).await
      },
      load_issuer_keys,
      options.role.as_deref(),
    ),
    auth.token_exchange_rate_limiter(),
    &ip,
  )
  .await
}

/// Checks the request parameters, returning the token type to issue.
fn validate_request(
  request: &TokenExchangeRequest,
) -> mogh_error::Result<&'static str> {
  if request.grant_type != GRANT_TYPE_TOKEN_EXCHANGE {
    return Err(oauth_error(
      "unsupported_grant_type",
      format!("Only '{GRANT_TYPE_TOKEN_EXCHANGE}' is supported"),
    ));
  }
  if ![TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_JWT]
    .contains(&request.subject_token_type.as_str())
  {
    return Err(invalid_request(format!(
      "'subject_token_type' must be '{TOKEN_TYPE_ID_TOKEN}' or '{TOKEN_TYPE_JWT}'. Only tokens signed by the provider can be exchanged."
    )));
  }
  if request.actor_token.is_some()
    || request.actor_token_type.is_some()
  {
    return Err(invalid_request(
      "'actor_token' (delegation) is not supported",
    ));
  }
  if request.subject_token.is_empty() {
    return Err(invalid_request("'subject_token' is empty"));
  }
  if request.subject_token.len() > MAX_SUBJECT_TOKEN_LENGTH {
    return Err(invalid_request("'subject_token' is too large"));
  }
  match request.requested_token_type.as_deref() {
    None | Some(TOKEN_TYPE_ACCESS_TOKEN) => {
      Ok(TOKEN_TYPE_ACCESS_TOKEN)
    }
    Some(TOKEN_TYPE_JWT) => Ok(TOKEN_TYPE_JWT),
    Some(_) => Err(invalid_request(format!(
      "'requested_token_type' must be '{TOKEN_TYPE_ACCESS_TOKEN}' or '{TOKEN_TYPE_JWT}'"
    ))),
  }
}

/// Whether `role` names the provider / rule: by id, slug or name.
fn is_role(role: Option<&str>, names: &[&str]) -> bool {
  role.is_none_or(|role| names.contains(&role))
}

/// The providers which may verify a token claiming to be from `issuer`:
/// enabled, opted in to token exchange, of that issuer, and the
/// `role` if one is named.
///
/// The issuer is not verified at this point, it only selects who
/// verifies the token. Trusted issuers which aren't login providers
/// (workload identity) would be further candidates here.
fn exchange_candidates(
  providers: impl IntoIterator<Item = ExternalLoginProvider>,
  issuer: &str,
  role: Option<&str>,
) -> Vec<ExternalLoginProvider> {
  providers
    .into_iter()
    .filter(|provider| {
      provider.enabled()
        && provider.token_exchange.enabled
        && is_role(
          role,
          &[&provider.id, provider.slug(), &provider.name],
        )
    })
    .filter(|provider| match &provider.config {
      ExternalLoginProviderConfig::Oidc(config) => {
        issuers_match(&config.provider, issuer)
      }
      ExternalLoginProviderConfig::Google(_) => {
        issuers_match(GOOGLE_ISSUER, issuer)
      }
      ExternalLoginProviderConfig::Github(_) => false,
    })
    .collect()
}

/// The RFC 8693 exchange of the `/token` endpoint. The token is either
/// of a user of an external login provider, or of a workload of a
/// trusted issuer.
///
/// `load_client` loads the client which verifies tokens of a provider,
/// `load_keys` the keys which verify tokens of a trusted issuer.
/// `role` restricts both, see [TokenExchangeOptions].
#[instrument("TokenExchange", skip_all, fields(ip = ip.to_string()))]
async fn exchange<I, L, F, K, G>(
  auth: &I,
  ip: IpAddr,
  request: TokenExchangeRequest,
  load_client: L,
  load_keys: K,
  role: Option<&str>,
) -> mogh_error::Result<ExchangedToken>
where
  I: AuthImpl + ?Sized,
  L: Fn(ExternalLoginProvider) -> F,
  F: Future<Output = mogh_error::Result<Arc<BuiltProvider>>>,
  K: Fn(TrustedIssuer) -> G,
  G: Future<Output = mogh_error::Result<Arc<TokenVerificationKeys>>>,
{
  let issued_token_type = validate_request(&request)?;
  let token = request.subject_token.as_str();

  let user =
    match verify_user_token(auth, token, load_client, role).await {
      Ok(Some(verified)) => {
        return complete_exchange(
          auth,
          ip,
          verified,
          issued_token_type,
        )
        .await;
      }
      Ok(None) => None,
      Err(not_accepted) => Some(not_accepted),
    };

  let workload =
    match verify_workload(auth, token, load_keys, role).await {
      Ok(Some(verified)) => {
        return complete_workload(
          auth,
          ip,
          verified,
          issued_token_type,
        )
        .await;
      }
      Ok(None) => None,
      Err(not_accepted) => Some(not_accepted),
    };

  // Login providers and trusted issuers can share an issuer: the
  // furthest any of them got, with the order each path uses.
  if let Some(not_accepted) = NotAccepted::furthest(user, workload) {
    return Err(not_accepted.into_error());
  }
  Err(match role {
      // Nothing of that name takes the token's issuer, told
      // apart from a rejected token for Vault's "role not found".
      Some(role) => anyhow::Error::new(RoleNotFound {
        role: role.to_string(),
      })
      .context(OauthError {
        code: "invalid_grant",
        description: format!(
          "No login provider or workload rule '{role}' accepts tokens of this issuer"
        ),
      })
      .status_code(StatusCode::BAD_REQUEST),
    None => invalid_grant(
      "No login provider or trusted issuer accepts tokens of this issuer",
    ),
  })
}

/// How far the candidates of one path, the login providers or the
/// trusted issuers of the token's issuer, got with a token none of
/// them accepted. The furthest is reported, within a path and across
/// both, see [NotAccepted::furthest].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reach {
  /// Every candidate which could be asked rejected the token: its
  /// signature, audience, expiry, or a provider's `allowed_groups`.
  Rejected,
  /// A candidate couldn't be asked (it couldn't be loaded, or the
  /// app's storage failed): it might have accepted what the others
  /// rejected, so the client should try again later.
  Unavailable,
  /// A candidate verified the token, and refused it for what it
  /// says: no user is linked to it, or it matches no rule. That is
  /// the token's, whatever the others would have said.
  Refused,
}

/// A token none of the candidates of a path accepted.
pub(crate) struct NotAccepted {
  reach: Reach,
  error: mogh_error::Error,
  /// Whether a candidate rejected the token as the client's
  /// (a client error), see [NotAccepted::into_error].
  rejected: bool,
}

impl NotAccepted {
  fn rejected(error: mogh_error::Error) -> NotAccepted {
    NotAccepted {
      reach: Reach::Rejected,
      rejected: error.status.is_client_error(),
      error,
    }
  }

  fn unavailable(error: mogh_error::Error) -> NotAccepted {
    NotAccepted {
      reach: Reach::Unavailable,
      error,
      rejected: false,
    }
  }

  /// The furthest of what the login providers (`user`) and the
  /// trusted issuers (`workload`) got to, the login providers' when
  /// they got as far.
  fn furthest(
    user: Option<NotAccepted>,
    workload: Option<NotAccepted>,
  ) -> Option<NotAccepted> {
    let (user, workload) = match (user, workload) {
      (Some(user), Some(workload)) => (user, workload),
      (user, workload) => return user.or(workload),
    };
    let rejected = user.rejected || workload.rejected;
    let mut furthest = if workload.reach > user.reach {
      workload
    } else {
      user
    };
    furthest.rejected = rejected;
    Some(furthest)
  }

  /// The error answered. A candidate which couldn't be asked while
  /// another rejected the token is a `503` (the client should retry,
  /// that one might accept it), which still counts as the failed
  /// attempt it may be: the caller picks the issuer of the token, and
  /// a forged token aimed at an issuer with a candidate down would
  /// otherwise never count. See [CountedServerError].
  fn into_error(self) -> mogh_error::Error {
    if self.reach == Reach::Unavailable
      && self.rejected
      && self.error.status.is_server_error()
    {
      let status = self.error.status;
      let mut error = anyhow::Error::new(CountedServerError {
        status,
        error: self.error.error,
      })
      .status_code(status);
      error.headers = self.error.headers;
      return error;
    }
    self.error
  }
}

/// A server error which counts against the failure rate limit all
/// the same, see [NotAccepted::into_error]. The rate limiter only
/// counts client errors, so [with_exchange_rate_limit] passes it as a
/// `400` and gives it back its status afterwards.
///
/// Transparent, like `mogh_error::NotAnAttempt`: it displays as the
/// error it carries, whose causes are its own.
#[derive(Debug)]
struct CountedServerError {
  status: StatusCode,
  error: anyhow::Error,
}

impl std::fmt::Display for CountedServerError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::fmt::Display::fmt(&self.error, f)
  }
}

impl std::error::Error for CountedServerError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    self.error.source()
  }
}

/// Runs an exchange under the failure rate limit of `limiter`, which
/// also counts the [CountedServerError]s (answered with their own
/// status).
pub(crate) async fn with_exchange_rate_limit<T>(
  exchange: impl Future<Output = mogh_error::Result<T>>,
  limiter: &RateLimiter,
  ip: &IpAddr,
) -> mogh_error::Result<T> {
  let status_of = |e: &mogh_error::Error| {
    e.error
      .downcast_ref::<CountedServerError>()
      .map(|counted| counted.status)
  };
  async {
    exchange.await.map_err(|mut e| {
      if status_of(&e).is_some() {
        e.status = StatusCode::BAD_REQUEST;
      }
      e
    })
  }
  .with_failure_rate_limit_using_ip(limiter, ip)
  .await
  .map_err(|mut e| {
    if let Some(status) = status_of(&e) {
      e.status = status;
    }
    e
  })
}

/// A verified token, and the user it belongs to.
pub(crate) struct VerifiedExchange {
  pub provider: ExternalLoginProvider,
  pub user: BoxAuthUser,
  pub info: ExternalLoginInfo,
  /// When the provider authenticated the user (unix seconds), which
  /// the issued app token counts as the login time, see
  /// [JwtProvider::encode_sub_with_auth_time][crate::provider::jwt::JwtProvider::encode_sub_with_auth_time].
  pub authenticated_at: u64,
}

/// The part shared by the `/token` endpoint and the login api: finds
/// the provider which accepts the token and has its user linked.
///
/// The login rules for the user (cidr whitelist, second
/// factor, sync) are still up to the caller.
///
/// `None` if no login provider (named `role`, if one is) takes
/// tokens of the issuer.
///
/// Errors count as failed attempts under [with_exchange_rate_limit].
pub(crate) async fn verify_exchange<I, L, F>(
  auth: &I,
  token: &str,
  load_client: L,
  role: Option<&str>,
) -> mogh_error::Result<Option<VerifiedExchange>>
where
  I: AuthImpl + ?Sized,
  // Takes the provider by value, a future borrowing its
  // argument can't be named in these bounds.
  L: Fn(ExternalLoginProvider) -> F,
  F: Future<Output = mogh_error::Result<Arc<BuiltProvider>>>,
{
  verify_user_token(auth, token, load_client, role)
    .await
    .map_err(NotAccepted::into_error)
}

/// [verify_exchange], telling how far the providers got with a
/// token none of them accepted.
async fn verify_user_token<I, L, F>(
  auth: &I,
  token: &str,
  load_client: L,
  role: Option<&str>,
) -> Result<Option<VerifiedExchange>, NotAccepted>
where
  I: AuthImpl + ?Sized,
  L: Fn(ExternalLoginProvider) -> F,
  F: Future<Output = mogh_error::Result<Arc<BuiltProvider>>>,
{
  if token.is_empty() {
    return Err(NotAccepted::rejected(invalid_request(
      "The token is empty",
    )));
  }
  if token.len() > MAX_SUBJECT_TOKEN_LENGTH {
    return Err(NotAccepted::rejected(invalid_request(
      "The token is too large",
    )));
  }

  let issuer = unverified_issuer(token).ok_or_else(|| {
    NotAccepted::rejected(invalid_grant(
      "The token is not a JWT with an issuer",
    ))
  })?;

  let candidates = exchange_candidates(
    list_external_providers(auth)
      .await
      .map_err(NotAccepted::unavailable)?
      .into_iter()
      .map(|resolved| resolved.provider),
    &issuer,
    role,
  );

  if candidates.is_empty() {
    return Ok(None);
  }

  // Providers can share an issuer (several clients at the same
  // provider). The first which accepts the token and has the
  // user linked decides. A provider rejecting the token, or not
  // knowing the user, leaves it to the next one.
  let mut unavailable = None;
  let mut rejected = None;
  let mut unknown_user = None;
  for provider in candidates {
    let client = match load_client(provider.clone()).await {
      Ok(client) => client,
      // Already logged
      Err(e) => {
        unavailable.get_or_insert(e);
        continue;
      }
    };
    let info = match client.verify_exchange_token(&provider, token) {
      Ok(info) => info,
      Err(e) => {
        rejected = Some(e);
        continue;
      }
    };
    let Some(user) = auth
      .find_user_with_external_login(
        info.provider_id.clone(),
        info.external_id.clone(),
      )
      .await
      .map_err(NotAccepted::unavailable)?
    else {
      unknown_user.get_or_insert(invalid_grant(format!(
        "No user is linked to this identity. Log in with '{}' once before exchanging tokens.",
        provider.name
      )));
      continue;
    };
    return Ok(Some(VerifiedExchange {
      provider,
      user,
      info,
      // The token is verified at this point. Every verified token
      // has an `iat`, one without counts as a login long ago.
      authenticated_at: authenticated_at(token).unwrap_or_default(),
    }));
  }

  // Report the furthest any provider got. A provider which couldn't
  // be asked might have accepted the token another one rejected
  // (eg. for another audience, or its 'allowed_groups'): a temporary
  // failure, not the token's.
  let was_rejected = rejected
    .as_ref()
    .is_some_and(|e| e.status.is_client_error());
  let reached = |reach, error| NotAccepted {
    reach,
    error,
    rejected: was_rejected,
  };
  Err(match (unknown_user, unavailable, rejected) {
    (Some(e), _, _) => reached(Reach::Refused, e),
    (None, Some(e), _) => reached(Reach::Unavailable, e),
    // Only describes the token the caller presented
    (None, None, Some(e)) if e.status.is_client_error() => reached(
      Reach::Rejected,
      invalid_grant(format!("{:#}", e.error)),
    ),
    (None, None, Some(e)) => reached(Reach::Rejected, e),
    (None, None, None) => {
      NotAccepted::rejected(invalid_grant("Token was rejected"))
    }
  })
}

/// Loads the keys of a trusted issuer. The reason a load fails may
/// include internal addresses, so it is only logged.
async fn load_issuer_keys(
  issuer: TrustedIssuer,
) -> mogh_error::Result<Arc<TokenVerificationKeys>> {
  load_verification_keys(&issuer).await.map_err(|e| {
    // Logged once per attempt, not by every request while it is down.
    if !LoadFailedRecently::is(&e) {
      error!(
        issuer_id = issuer.id,
        issuer = issuer.name,
        "Failed to load keys of trusted issuer | {e:#}"
      );
    }
    anyhow::anyhow!(
      "Trusted issuer '{}' is not available",
      issuer.name
    )
    .status_code(StatusCode::SERVICE_UNAVAILABLE)
  })
}

/// A verified workload token, and the rule it matched.
struct VerifiedWorkload {
  issuer: TrustedIssuer,
  rule: WorkloadRule,
  claims: Claims,
}

/// Finds the trusted issuer which accepts the token, and the rule
/// the token matches: the first matching one, or with a `role` the
/// rule of that id / name. `None` if no trusted issuer has that
/// issuer (and, with a role, a rule of that name).
async fn verify_workload<I, K, G>(
  auth: &I,
  token: &str,
  load_keys: K,
  role: Option<&str>,
) -> Result<Option<VerifiedWorkload>, NotAccepted>
where
  I: AuthImpl + ?Sized,
  K: Fn(TrustedIssuer) -> G,
  G: Future<Output = mogh_error::Result<Arc<TokenVerificationKeys>>>,
{
  let issuer = unverified_issuer(token).ok_or_else(|| {
    NotAccepted::rejected(invalid_grant(
      "The token is not a JWT with an issuer",
    ))
  })?;

  // Issuers aren't always unique. Kubernetes clusters share a default
  // issuer and only differ by their keys, so each candidate gets to
  // verify the token with its own.
  let candidates = list_trusted_issuers(auth)
    .await
    .map_err(NotAccepted::unavailable)?
    .into_iter()
    .map(|resolved| resolved.issuer)
    .filter(|trusted| {
      trusted.enabled
        && issuers_match(&trusted.issuer, &issuer)
        && trusted
          .rules
          .iter()
          .any(|rule| is_role(role, &[&rule.id, &rule.name]))
    })
    .collect::<Vec<_>>();

  if candidates.is_empty() {
    return Ok(None);
  }

  let mut unavailable = None;
  let mut rejected = None;
  let mut unmatched = None;
  for trusted in candidates {
    let keys = match load_keys(trusted.clone()).await {
      Ok(keys) => keys,
      // Already logged
      Err(e) => {
        unavailable.get_or_insert(e);
        continue;
      }
    };
    let claims = match keys.verify_payload(
      token,
      &trusted.audiences,
      trusted.max_token_age_secs,
    ) {
      Ok(claims) => claims,
      Err(e) => {
        // Only describes the token the caller presented
        rejected = Some(invalid_grant(format!("{e:#}")));
        continue;
      }
    };
    // With a role, only the rule(s) of that name are evaluated,
    // like Vault evaluates the named role.
    let rules = match role {
      Some(_) => trusted
        .rules
        .iter()
        .filter(|rule| is_role(role, &[&rule.id, &rule.name]))
        .cloned()
        .collect::<Vec<_>>(),
      None => trusted.rules.clone(),
    };
    let Some(rule) = match_rule(&rules, &claims).cloned() else {
      unmatched.get_or_insert(invalid_grant(match role {
        Some(role) => format!(
          "The token is valid, but does not match rule '{role}' of '{}'",
          trusted.name
        ),
        None => format!(
          "The token is valid, but matches no rule of '{}'",
          trusted.name
        ),
      }));
      continue;
    };
    // Verified and matched: as far as a token gets.
    check_rule_id(&trusted, &rule).map_err(|error| NotAccepted {
      reach: Reach::Refused,
      error,
      rejected: rejected.is_some(),
    })?;
    return Ok(Some(VerifiedWorkload {
      issuer: trusted,
      rule,
      claims,
    }));
  }

  // Report the furthest any issuer got: one which verified the
  // token, else one which couldn't be asked. Its keys might have
  // verified a token the others rejected (eg. the other cluster of
  // a shared issuer, which has other keys), so that's a temporary
  // failure (503), not the token's.
  let was_rejected = rejected.is_some();
  let reached = |reach, error| NotAccepted {
    reach,
    error,
    rejected: was_rejected,
  };
  Err(match (unmatched, unavailable, rejected) {
    (Some(e), _, _) => reached(Reach::Refused, e),
    (None, Some(e), _) => reached(Reach::Unavailable, e),
    (None, None, Some(e)) => reached(Reach::Rejected, e),
    (None, None, None) => {
      NotAccepted::rejected(invalid_grant("Token was rejected"))
    }
  })
}

/// The rule id identifies the user of the rule. Ids of stored issuers
/// are generated, but static issuers come from the app configuration,
/// where a missing or repeated id would make rules share one user,
/// and with it each others groups.
fn check_rule_id(
  issuer: &TrustedIssuer,
  rule: &WorkloadRule,
) -> mogh_error::Result<()> {
  let unique = issuer
    .rules
    .iter()
    .filter(|other| other.id == rule.id)
    .count()
    == 1;
  if unique && validate_provider_id(&rule.id).is_ok() {
    return Ok(());
  }
  error!(
    issuer_id = issuer.id,
    issuer = issuer.name,
    rule = rule.name,
    rule_id = rule.id,
    "Rules of a trusted issuer need a unique id (a-z A-Z 0-9 - _)"
  );
  Err(
    anyhow::anyhow!(
      "Trusted issuer '{}' is misconfigured",
      issuer.name
    )
    .into(),
  )
}

/// Claim values end up in the logs, and are as long as the issuer likes.
fn truncate_for_log(value: &str) -> String {
  const MAX: usize = 200;
  match value.char_indices().nth(MAX) {
    Some((index, _)) => format!("{}...", &value[..index]),
    None => value.to_string(),
  }
}

/// The issuer and rule of `verified` as they are now, once the
/// exchange holds the lock of the rule ([lock_workload_user]).
///
/// An update or deletion of the issuer holds its lock while the app
/// stores it and syncs the users of its rules
/// ([AuthImpl::sync_workload_users]). An exchange which read the rule
/// before, and waited for it, would otherwise give the user the
/// access the rule had before the sync (or create the user of a rule
/// which was removed), and issue a token the update meant to refuse.
async fn current_rule<I: AuthImpl + ?Sized>(
  auth: &I,
  verified: &VerifiedWorkload,
) -> mogh_error::Result<(TrustedIssuer, WorkloadRule)> {
  let VerifiedWorkload {
    issuer: read,
    rule,
    claims,
  } = verified;
  let Some(issuer) = list_trusted_issuers(auth)
    .await?
    .into_iter()
    .map(|resolved| resolved.issuer)
    .find(|issuer| issuer.id == read.id && issuer.enabled)
  else {
    return Err(invalid_grant(format!(
      "Trusted issuer '{}' no longer accepts tokens",
      read.name
    )));
  };
  // The token was verified with what the issuer was.
  if issuer.issuer != read.issuer
    || issuer.keys != read.keys
    || issuer.audiences != read.audiences
    || issuer.max_token_age_secs != read.max_token_age_secs
  {
    return Err(
      anyhow::anyhow!(
        "Trusted issuer '{}' changed during the exchange, try again",
        issuer.name
      )
      .status_code(StatusCode::SERVICE_UNAVAILABLE),
    );
  }
  let Some(current) = issuer
    .rules
    .iter()
    .find(|current| current.id == rule.id)
    .and_then(|current| {
      match_rule(std::slice::from_ref(current), claims)
    })
    .cloned()
  else {
    return Err(invalid_grant(format!(
      "The token no longer matches rule '{}' of '{}'",
      rule.name, issuer.name
    )));
  };
  check_rule_id(&issuer, &current)?;
  Ok((issuer, current))
}

/// Gets the user of the matched rule from the app,
/// applies the login rules and issues a short lived app token.
async fn complete_workload<I: AuthImpl + ?Sized>(
  auth: &I,
  ip: IpAddr,
  verified: VerifiedWorkload,
  issued_token_type: &str,
) -> mogh_error::Result<ExchangedToken> {
  // Not while sync_all_workload_users has the app remove the users
  // of the issuers and rules which are gone: a user created after
  // it listed the live ones would be taken for one of those.
  let removal = hold_off_removal().await;
  // The first exchanges of a rule (a CI matrix starting) would
  // otherwise all race to create its user, and an update of the
  // issuer with them.
  let user_lock =
    lock_workload_user(&verified.issuer.id, &verified.rule.id).await;
  let (issuer, rule) = current_rule(auth, &verified).await?;
  let claims = verified.claims;

  // What identifies the workload, for the audit log below.
  let subject = truncate_for_log(
    claims
      .get("sub")
      .and_then(|sub| sub.as_str())
      .unwrap_or_default(),
  );
  let matched = rule
    .claims
    .iter()
    .filter_map(|condition| {
      let value = lookup_claim(&claims, &condition.claim)?;
      Some(format!(
        "{}={}",
        condition.claim,
        truncate_for_log(&value.to_string())
      ))
    })
    .collect::<Vec<_>>()
    .join(" ");

  let user_id = auth
    .get_or_create_workload_user(WorkloadIdentity {
      issuer_id: issuer.id.clone(),
      rule_id: rule.id.clone(),
      rule_name: rule.name.clone(),
      groups: rule.groups.clone(),
      admin: rule.admin,
      claims,
    })
    .await?;
  drop(user_lock);
  drop(removal);
  let user = auth.get_user(user_id).await?;

  // Without the flag the management API wouldn't
  // stop the workload from creating credentials.
  if !user.is_workload() {
    return Err(
      anyhow::anyhow!(
        "The user returned by 'AuthImpl::get_or_create_workload_user' must report 'AuthUserImpl::is_workload'"
      )
      .into(),
    );
  }

  // Disabled with its rule or issuer (AuthImpl::sync_workload_users),
  // which may have happened after the rule was read here on another
  // instance of the app. Its tokens are refused as well.
  if !user.is_enabled() {
    return Err(invalid_grant(format!(
      "The user of rule '{}' is disabled",
      rule.name
    )));
  }

  // Being an admin has to be a decision made on the rule.
  if user.is_admin() && !rule.admin {
    return Err(invalid_grant(format!(
      "The user of rule '{}' is an admin, which the rule doesn't allow",
      rule.name
    )));
  }

  check_user_cidr_whitelist(user.as_ref(), ip)?;

  if external_login_requires_two_factor(user.as_ref()) {
    return Err(invalid_grant(
      "The user of the workload requires a second factor, which a workload can't provide",
    ));
  }

  let login = ExchangedLogin::Workload {
    issuer_id: issuer.id.clone(),
    issuer_name: issuer.name.clone(),
    rule_id: rule.id.clone(),
    rule_name: rule.name.clone(),
  };
  let default_ttl_ms = auth.jwt_provider().ttl_ms();
  let ttl_ms = match u128::from(rule.token_ttl_secs) * 1000 {
    0 => default_ttl_ms,
    ttl_ms => ttl_ms.min(default_ttl_ms),
  };
  let jwt = issue_login(
    auth,
    user.id(),
    user.username(),
    ip,
    LoginKind::from(login.clone()),
    None,
    IssueToken::Ttl(ttl_ms),
  )
  .await?;

  info!(
    user_id = user.id(),
    username = user.username(),
    issuer_id = issuer.id,
    issuer = issuer.name,
    rule_id = rule.id,
    rule = rule.name,
    subject,
    matched,
    "Workload logged in (token exchange)"
  );

  Ok(ExchangedToken {
    response: TokenExchangeResponse {
      access_token: jwt.jwt,
      issued_token_type: issued_token_type.to_string(),
      token_type: "Bearer".to_string(),
      expires_in: u64::try_from(ttl_ms / 1000).unwrap_or(u64::MAX),
    },
    user_id: user.id().to_string(),
    login,
  })
}

/// Applies the login rules to the user the verified
/// identity belongs to, and issues the app token.
async fn complete_exchange<I: AuthImpl + ?Sized>(
  auth: &I,
  ip: IpAddr,
  VerifiedExchange {
    provider,
    user,
    info,
    authenticated_at,
  }: VerifiedExchange,
  issued_token_type: &str,
) -> mogh_error::Result<ExchangedToken> {
  // Users outside their whitelist are rejected
  // before the exchange has any effect on them.
  check_user_cidr_whitelist(user.as_ref(), ip)?;

  // There is nobody to ask for it here, and no way to continue.
  if external_login_requires_two_factor(user.as_ref()) {
    return Err(invalid_grant(
      "The user requires a second factor for external logins, which this endpoint can't provide. Use 'ExchangeExternalForJwt' of the login api instead.",
    ));
  }

  // Sync before the token is issued, like for a login.
  auth.sync_external_user(user.id().to_string(), info).await?;

  let login = ExchangedLogin::Provider {
    provider_id: provider.id.clone(),
    provider_name: provider.name.clone(),
  };
  // A login when the provider authenticated the user, not now: the
  // token may be replayed until it expires.
  let jwt = issue_login(
    auth,
    user.id(),
    user.username(),
    ip,
    LoginKind::from(login.clone()),
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

  Ok(ExchangedToken {
    response: TokenExchangeResponse {
      access_token: jwt.jwt,
      issued_token_type: issued_token_type.to_string(),
      token_type: "Bearer".to_string(),
      expires_in: u64::try_from(auth.jwt_provider().ttl_ms() / 1000)
        .unwrap_or(u64::MAX),
    },
    user_id: user.id().to_string(),
    login,
  })
}

#[cfg(test)]
mod tests {
  use std::{
    sync::{
      Mutex,
      atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
  };

  use anyhow::anyhow;

  use mogh_auth_client::config::{
    NamedOauthConfig, OidcConfig, TokenExchangeConfig,
    TrustedIssuerKeys, WorkloadClaim,
  };
  use mogh_rate_limit::RateLimiter;

  use super::*;
  use crate::Login;
  use crate::test_support::stub_auth_impl;
  use crate::{
    passkey::Passkey,
    provider::{
      jwt::JwtProvider,
      oidc::{OidcProvider, UsernameAdditionalClaims},
      token_exchange::test_tokens::{
        CLIENT_ID, ISSUER, Signer, TestToken, jwks_json, metadata,
        other_jwks_json,
      },
      workload::{LiveIssuer, WorkloadAccess},
    },
    user::AuthUserImpl,
  };

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
  const JWT_TTL_MS: u128 = 60 * 60 * 1000;

  #[derive(Clone, Default)]
  struct TestUser {
    external_skip_2fa: bool,
    totp: bool,
    cidr_whitelist: Vec<String>,
    workload: bool,
    admin: bool,
    disabled: bool,
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
    fn passkey(&self) -> Option<Passkey> {
      None
    }
    fn totp_secret(&self) -> Option<&str> {
      self.totp.then_some("totp-secret")
    }
    fn cidr_whitelist(&self) -> &[String] {
      &self.cidr_whitelist
    }
    fn is_workload(&self) -> bool {
      self.workload
    }
    fn is_admin(&self) -> bool {
      self.admin
    }
    fn is_enabled(&self) -> bool {
      !self.disabled
    }
  }

  struct TestAuth {
    providers: Vec<ExternalLoginProvider>,
    issuers: Vec<TrustedIssuer>,
    /// The issuers stored by the app, which a test can change.
    stored_issuers: Arc<Mutex<Vec<TrustedIssuer>>>,
    /// Calls listing the stored issuers.
    stored_issuer_lists: Arc<AtomicUsize>,
    /// The user the app returns for workloads
    workload_user: TestUser,
    workloads: Arc<Mutex<Vec<WorkloadIdentity>>>,
    /// How long getting the workload user takes.
    workload_user_delay: Duration,
    /// Calls getting the workload user right now, and at most.
    workload_user_calls: Arc<AtomicUsize>,
    max_workload_user_calls: Arc<AtomicUsize>,
    /// The user linked to ("oidc", "subject-123"), if any
    user: Option<TestUser>,
    sync_fails: bool,
    synced: Arc<Mutex<Vec<ExternalLoginInfo>>>,
    logins: Arc<Mutex<Vec<Login>>>,
    jwt: JwtProvider,
    /// Disabled, unless a test enables it.
    rate_limiter: Arc<RateLimiter>,
    /// An issuer an admin stores while the app removes the users of
    /// the issuers which are gone, and a token its first exchange
    /// sends meanwhile.
    exchange_while_removing: Option<(TrustedIssuer, String)>,
    /// That exchange, once it began.
    exchanged_while_removing: Arc<Mutex<Option<ExchangeTask>>>,
  }

  type ExchangeTask = tokio::task::JoinHandle<
    mogh_error::Result<TokenExchangeResponse>,
  >;

  impl TestAuth {
    fn with_user(user: Option<TestUser>) -> TestAuth {
      TestAuth {
        providers: vec![oidc_provider("oidc", true)],
        issuers: Vec::new(),
        stored_issuers: Default::default(),
        stored_issuer_lists: Default::default(),
        workload_user: TestUser {
          workload: true,
          ..Default::default()
        },
        workloads: Default::default(),
        workload_user_delay: Duration::ZERO,
        workload_user_calls: Default::default(),
        max_workload_user_calls: Default::default(),
        user,
        sync_fails: false,
        synced: Default::default(),
        logins: Default::default(),
        jwt: JwtProvider::new(b"test-jwt-secret", JWT_TTL_MS),
        rate_limiter: RateLimiter::new(true, 0, Default::default()),
        exchange_while_removing: None,
        exchanged_while_removing: Default::default(),
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
      self.providers.clone()
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
      if self.sync_fails {
        return Box::pin(async {
          Err(anyhow!("sync failed").into())
        });
      }
      self.synced.lock().unwrap().push(info);
      Box::pin(async { Ok(()) })
    }

    fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
      self.issuers.clone()
    }

    fn list_trusted_issuers(
      &self,
    ) -> crate::DynFuture<mogh_error::Result<Vec<TrustedIssuer>>>
    {
      self.stored_issuer_lists.fetch_add(1, Ordering::SeqCst);
      let stored = self.stored_issuers.lock().unwrap().clone();
      Box::pin(async move { Ok(stored) })
    }

    fn record_login(
      &self,
      login: Login,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.logins.lock().unwrap().push(login);
      Box::pin(async { Ok(()) })
    }

    fn get_or_create_workload_user(
      &self,
      identity: WorkloadIdentity,
    ) -> crate::DynFuture<mogh_error::Result<String>> {
      self.workloads.lock().unwrap().push(identity);
      let delay = self.workload_user_delay;
      let calls = self.workload_user_calls.clone();
      let max_calls = self.max_workload_user_calls.clone();
      Box::pin(async move {
        let now = calls.fetch_add(1, Ordering::SeqCst) + 1;
        max_calls.fetch_max(now, Ordering::SeqCst);
        if !delay.is_zero() {
          tokio::time::sleep(delay).await;
        }
        calls.fetch_sub(1, Ordering::SeqCst);
        Ok("workload-user".to_string())
      })
    }

    fn sync_workload_users(
      &self,
      _issuer_id: String,
      _rules: Vec<WorkloadAccess>,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }

    /// The users are the `workloads`: the ones of no live issuer and
    /// rule are removed, once the exchange of
    /// `exchange_while_removing` had every chance to get its user.
    fn remove_workload_users_except(
      &self,
      live: Vec<LiveIssuer>,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      if let Some((issuer, token)) =
        self.exchange_while_removing.clone()
      {
        self.stored_issuers.lock().unwrap().push(issuer);
        let mut exchanging = TestAuth::with_user(None);
        exchanging.providers = Vec::new();
        exchanging.issuers = self.issuers.clone();
        exchanging.stored_issuers = self.stored_issuers.clone();
        exchanging.workloads = self.workloads.clone();
        *self.exchanged_while_removing.lock().unwrap() = Some(
          tokio::spawn(async move { run(&exchanging, token).await }),
        );
      }
      let exchange = self.exchanged_while_removing.clone();
      let workloads = self.workloads.clone();
      Box::pin(async move {
        for _ in 0..1000 {
          let done = exchange
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|exchange| exchange.is_finished());
          if done {
            break;
          }
          tokio::task::yield_now().await;
        }
        workloads.lock().unwrap().retain(|identity| {
          live.iter().any(|live| {
            live.issuer_id == identity.issuer_id
              && live.rule_ids.contains(&identity.rule_id)
          })
        });
        Ok(())
      })
    }

    fn get_user(
      &self,
      user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<BoxAuthUser>> {
      let user = (user_id == "workload-user")
        .then(|| Box::new(self.workload_user.clone()) as BoxAuthUser);
      Box::pin(async move {
        user.ok_or_else(|| anyhow!("no user").into())
      })
    }

    stub_auth_impl!(handle_request_authentication);

    fn jwt_provider(&self) -> &JwtProvider {
      &self.jwt
    }

    fn general_rate_limiter(&self) -> &RateLimiter {
      &self.rate_limiter
    }
  }

  fn oidc_config() -> OidcConfig {
    OidcConfig {
      enabled: true,
      provider: ISSUER.to_string(),
      client_id: CLIENT_ID.to_string(),
      ..Default::default()
    }
  }

  fn oidc_provider(
    id: &str,
    exchange: bool,
  ) -> ExternalLoginProvider {
    ExternalLoginProvider {
      id: id.to_string(),
      name: "OIDC".to_string(),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: TokenExchangeConfig {
        enabled: exchange,
        ..Default::default()
      },
      config: ExternalLoginProviderConfig::Oidc(oidc_config()),
    }
  }

  fn named_provider(id: &str, github: bool) -> ExternalLoginProvider {
    let config = NamedOauthConfig {
      enabled: true,
      client_id: "client-id".to_string(),
      client_secret: "secret".to_string(),
    };
    ExternalLoginProvider {
      id: id.to_string(),
      name: id.to_string(),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: TokenExchangeConfig {
        enabled: true,
        ..Default::default()
      },
      config: if github {
        ExternalLoginProviderConfig::Github(config)
      } else {
        ExternalLoginProviderConfig::Google(config)
      },
    }
  }

  fn token() -> TestToken<UsernameAdditionalClaims> {
    TestToken::new(UsernameAdditionalClaims {
      username: None,
      extra: Default::default(),
    })
  }

  /// A token of the login provider's user (audience CLIENT_ID).
  fn token_for_user() -> TestToken<UsernameAdditionalClaims> {
    token()
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
    token: String,
  ) -> mogh_error::Result<TokenExchangeResponse> {
    run_as(auth, token, None)
      .await
      .map(|exchanged| exchanged.response)
  }

  async fn run_as(
    auth: &TestAuth,
    token: String,
    role: Option<&str>,
  ) -> mogh_error::Result<ExchangedToken> {
    exchange(
      auth,
      IP,
      TokenExchangeRequest::id_token(token),
      load_client,
      load_issuer_keys,
      role,
    )
    .await
  }

  // =====================
  // = WORKLOAD IDENTITY =
  // =====================

  const WORKLOAD_AUDIENCE: &str = "https://app.example.com";

  /// A Github Actions like token of the test issuer.
  fn workload_token(
    repository_id: u64,
    git_ref: &str,
  ) -> TestToken<UsernameAdditionalClaims> {
    TestToken {
      subject: format!("repo:org/app:ref:{git_ref}"),
      audiences: vec![WORKLOAD_AUDIENCE.to_string()],
      ..TestToken::new(UsernameAdditionalClaims {
        username: None,
        extra: [
          (
            "repository_id".to_string(),
            serde_json::json!(repository_id),
          ),
          ("ref".to_string(), serde_json::json!(git_ref)),
        ]
        .into(),
      })
    }
  }

  fn deploy_rule() -> WorkloadRule {
    WorkloadRule {
      id: "deploy".to_string(),
      name: "Deploy".to_string(),
      enabled: true,
      claims: vec![
        WorkloadClaim {
          claim: "repository_id".to_string(),
          pattern: "12345".to_string(),
        },
        WorkloadClaim {
          claim: "ref".to_string(),
          pattern: "refs/heads/release/*".to_string(),
        },
      ],
      groups: vec!["deployers".to_string()],
      admin: false,
      token_ttl_secs: 900,
    }
  }

  /// Static keys, so nothing is fetched.
  fn trusted_issuer(rules: Vec<WorkloadRule>) -> TrustedIssuer {
    TrustedIssuer {
      id: "ci".to_string(),
      name: "CI".to_string(),
      enabled: true,
      issuer: ISSUER.to_string(),
      keys: TrustedIssuerKeys::Static(jwks_json()),
      audiences: vec![WORKLOAD_AUDIENCE.to_string()],
      max_token_age_secs: 0,
      rules,
    }
  }

  fn workload_auth(rules: Vec<WorkloadRule>) -> TestAuth {
    let mut auth = TestAuth::with_user(None);
    auth.providers = Vec::new();
    auth.issuers = vec![trusted_issuer(rules)];
    auth
  }

  /// The first exchange of an issuer stored while
  /// `sync_all_workload_users` has the app remove the users of the
  /// issuers which are gone (after it listed the live ones) waits for
  /// the app to be done: its user is created after the removal, not
  /// taken for the user of an issuer which is gone. The users of the
  /// issuers which are gone go.
  #[tokio::test]
  async fn test_exchange_waits_for_the_removal_of_gone_users() {
    use crate::provider::workload::sync_all_workload_users;

    let mut auth = workload_auth(Vec::new());
    auth.issuers = Vec::new();
    *auth.stored_issuers.lock().unwrap() = vec![TrustedIssuer {
      id: "removal-live".to_string(),
      issuer: "https://other-ci.example.com".to_string(),
      ..trusted_issuer(vec![deploy_rule()])
    }];
    *auth.workloads.lock().unwrap() =
      ["removal-live", "removal-gone"]
        .into_iter()
        .map(|issuer_id| WorkloadIdentity {
          issuer_id: issuer_id.to_string(),
          rule_id: "deploy".to_string(),
          rule_name: "Deploy".to_string(),
          groups: Vec::new(),
          admin: false,
          claims: Default::default(),
        })
        .collect();
    auth.exchange_while_removing = Some((
      TrustedIssuer {
        id: "removal-new".to_string(),
        ..trusted_issuer(vec![deploy_rule()])
      },
      workload_token(12345, "refs/heads/release/1").mint(),
    ));

    tokio::time::timeout(
      Duration::from_secs(10),
      sync_all_workload_users(&auth),
    )
    .await
    .expect("the sync finishes")
    .unwrap();
    let exchange = auth
      .exchanged_while_removing
      .lock()
      .unwrap()
      .take()
      .expect("the exchange began");
    tokio::time::timeout(Duration::from_secs(10), exchange)
      .await
      .expect("the exchange finishes")
      .unwrap()
      .unwrap();
    let users = auth
      .workloads
      .lock()
      .unwrap()
      .iter()
      .map(|identity| identity.issuer_id.clone())
      .collect::<Vec<_>>();
    assert_eq!(users, ["removal-live", "removal-new"]);
  }

  #[tokio::test]
  async fn test_workload_gets_short_lived_token_for_rule_user() {
    let auth = workload_auth(vec![deploy_rule()]);
    let token =
      workload_token(12345, "refs/heads/release/1.2").mint();
    let response = run(&auth, token).await.unwrap();

    assert_eq!(
      auth.jwt.decode_sub(&response.access_token).unwrap(),
      "user-id"
    );
    // The rule's lifetime, not the (longer) app default
    assert_eq!(response.expires_in, 900);

    // The app is asked for the user of the rule, with its definition
    let workloads = auth.workloads.lock().unwrap();
    assert_eq!(workloads.len(), 1);
    assert_eq!(workloads[0].issuer_id, "ci");
    assert_eq!(workloads[0].rule_id, "deploy");
    assert_eq!(workloads[0].groups, ["deployers"]);
    assert!(!workloads[0].admin);
    assert_eq!(workloads[0].claims["repository_id"], 12345);
    // Login provider hooks are not involved
    assert!(auth.synced.lock().unwrap().is_empty());
    // The exchange is the rule user's login
    let logins = auth.logins.lock().unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].user_id, "user-id");
    assert_eq!(
      logins[0].kind,
      LoginKind::Workload {
        issuer_id: "ci".into(),
        issuer_name: "CI".into(),
        rule_id: "deploy".into(),
        rule_name: "Deploy".into(),
      }
    );
    // Stamped with the expiry of the token it issued.
    assert_eq!(
      logins[0].token_expires,
      auth.jwt.decode_claims(&response.access_token).unwrap().exp
    );
    // The rule's 900s ttl.
    let now = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_secs();
    let expires = logins[0].token_expires;
    assert!(
      (now + 895..=now + 905).contains(&expires),
      "expires {expires} should be about {now} + 900"
    );
  }

  #[tokio::test]
  async fn test_workload_token_ttl_is_capped_at_app_default() {
    let now = || {
      std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
    };
    let mut rule = deploy_rule();
    rule.token_ttl_secs = 365 * 24 * 60 * 60;
    let auth = workload_auth(vec![rule]);
    let token = workload_token(12345, "refs/heads/release/1").mint();
    assert_eq!(run(&auth, token).await.unwrap().expires_in, 3600);
    // The login record's stamp is capped the same way.
    let expires = auth.logins.lock().unwrap()[0].token_expires;
    assert!((now() + 3595..=now() + 3605).contains(&expires));

    let mut rule = deploy_rule();
    rule.token_ttl_secs = 0;
    let auth = workload_auth(vec![rule]);
    let token = workload_token(12345, "refs/heads/release/1").mint();
    assert_eq!(run(&auth, token).await.unwrap().expires_in, 3600);
    let expires = auth.logins.lock().unwrap()[0].token_expires;
    assert!((now() + 3595..=now() + 3605).contains(&expires));
  }

  #[tokio::test]
  async fn test_workload_token_must_match_a_rule() {
    let auth = workload_auth(vec![deploy_rule()]);
    for token in [
      // Another repository, and another branch
      workload_token(99999, "refs/heads/release/1"),
      workload_token(12345, "refs/heads/main"),
    ] {
      let err = run(&auth, token.mint()).await.unwrap_err();
      assert_eq!(code(&err), "invalid_grant");
      assert!(err.error.to_string().contains("matches no rule"));
    }
    assert!(auth.workloads.lock().unwrap().is_empty());

    // No rules, a disabled rule, or a disabled issuer accept nothing
    let mut disabled_rule = deploy_rule();
    disabled_rule.enabled = false;
    let mut disabled_issuer = workload_auth(vec![deploy_rule()]);
    disabled_issuer.issuers[0].enabled = false;
    for auth in [
      workload_auth(Vec::new()),
      workload_auth(vec![disabled_rule]),
      disabled_issuer,
    ] {
      let token =
        workload_token(12345, "refs/heads/release/1").mint();
      assert!(run(&auth, token).await.is_err());
      assert!(auth.workloads.lock().unwrap().is_empty());
    }
  }

  #[tokio::test]
  async fn test_workload_token_is_verified_like_any_other() {
    let auth = workload_auth(vec![deploy_rule()]);
    let valid = || workload_token(12345, "refs/heads/release/1");
    for token in [
      // The platform default audience, shared with other services
      TestToken {
        audiences: vec!["https://github.com/org".to_string()],
        ..valid()
      },
      TestToken {
        signer: Signer::Other,
        ..valid()
      },
      TestToken {
        expires_in: chrono::Duration::minutes(-1),
        ..valid()
      },
    ] {
      let err = run(&auth, token.mint()).await.unwrap_err();
      assert_eq!(code(&err), "invalid_grant");
    }
    assert!(auth.workloads.lock().unwrap().is_empty());

    // No accepted audience configured accepts nothing
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.issuers[0].audiences = Vec::new();
    assert!(run(&auth, valid().mint()).await.is_err());
  }

  /// Issuers aren't unique (Kubernetes clusters share a default),
  /// the one whose keys verify the token decides.
  #[tokio::test]
  async fn test_workload_issuers_sharing_an_issuer_url() {
    let mut other_cluster = trusted_issuer(vec![deploy_rule()]);
    other_cluster.id = "other-cluster".to_string();
    // Publishes other keys
    other_cluster.keys = TrustedIssuerKeys::Static(other_jwks_json());
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.issuers.insert(0, other_cluster);

    let token = workload_token(12345, "refs/heads/release/1").mint();
    assert!(run(&auth, token).await.is_ok());
    assert_eq!(auth.workloads.lock().unwrap()[0].issuer_id, "ci");
  }

  /// A CI matrix starting: every job's first exchange asks the app
  /// for the user of the rule, which doesn't exist yet. They are asked
  /// one after another, so the app doesn't race to create it.
  #[tokio::test]
  async fn test_workload_user_is_got_one_exchange_at_a_time() {
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.issuers[0].id = "concurrent-ci".to_string();
    auth.workload_user_delay = Duration::from_millis(20);
    let auth = Arc::new(auth);
    let exchanges = (0..8)
      .map(|_| {
        let auth = auth.clone();
        let token =
          workload_token(12345, "refs/heads/release/1").mint();
        tokio::spawn(async move { run(&auth, token).await })
      })
      .collect::<Vec<_>>();
    for exchange in exchanges {
      exchange.await.unwrap().unwrap();
    }
    assert_eq!(auth.workloads.lock().unwrap().len(), 8);
    assert_eq!(
      auth.max_workload_user_calls.load(Ordering::SeqCst),
      1
    );
  }

  /// Issuers sharing an issuer url, and the one which could have
  /// verified the token is down: the caller is told to retry (503),
  /// not that its token is bad because the other one rejected it.
  #[tokio::test]
  async fn test_workload_unavailable_issuer_wins_over_a_rejection() {
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();
    let mut other_cluster = trusted_issuer(vec![deploy_rule()]);
    other_cluster.id = "shared-other-cluster".to_string();
    other_cluster.keys = TrustedIssuerKeys::Static(other_jwks_json());
    let mut down = trusted_issuer(vec![deploy_rule()]);
    down.id = "shared-down-cluster".to_string();
    down.name = "Down".to_string();
    down.keys = TrustedIssuerKeys::Static("broken".into());

    for issuers in [
      vec![other_cluster.clone(), down.clone()],
      vec![down.clone(), other_cluster.clone()],
    ] {
      let mut auth = workload_auth(Vec::new());
      auth.issuers = issuers;
      let err = run(&auth, token()).await.unwrap_err();
      assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
      let (status, body) = token_exchange_error(&err);
      assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
      assert_eq!(body.error, "temporarily_unavailable");
    }

    // One which verified the token (and matched no rule) still
    // says so: that is the token's, whatever the others would say.
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.issuers[0].id = "shared-working-cluster".to_string();
    auth.issuers.push(down);
    let err = run(
      &auth,
      workload_token(99999, "refs/heads/release/1").mint(),
    )
    .await
    .unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(err.error.to_string().contains("matches no rule"));
  }

  /// The same for login providers sharing an issuer.
  #[tokio::test]
  async fn test_unavailable_provider_wins_over_a_rejection() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    // Another client at the same issuer, which rejects the token
    // (issued to the 'oidc' client) for its audience.
    let mut other_client = oidc_provider("other", true);
    let ExternalLoginProviderConfig::Oidc(config) =
      &mut other_client.config
    else {
      unreachable!()
    };
    config.client_id = "other-client-id".to_string();
    auth.providers = vec![other_client, oidc_provider("oidc", true)];

    let err = exchange(
      &auth,
      IP,
      TokenExchangeRequest::id_token(token().mint()),
      |provider: ExternalLoginProvider| async move {
        if provider.id == "oidc" {
          return Err(
            anyhow!("Login provider 'OIDC' is not available")
              .status_code(StatusCode::SERVICE_UNAVAILABLE),
          );
        }
        load_client(provider).await
      },
      load_issuer_keys,
      None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.error, "temporarily_unavailable");
    assert!(auth.synced.lock().unwrap().is_empty());
  }

  /// A provider which verifies the token but refuses the user for its
  /// 'allowed_groups' counts as a rejection too: the one which is
  /// down might allow other groups.
  #[tokio::test]
  async fn test_unavailable_provider_wins_over_allowed_groups() {
    let auth = |providers| {
      let mut auth = TestAuth::with_user(Some(TestUser {
        external_skip_2fa: true,
        ..Default::default()
      }));
      auth.providers = providers;
      auth
    };
    // Verifies the token (issued to its client), which carries no
    // groups, so the user is refused.
    let mut gated = oidc_provider("gated", true);
    let ExternalLoginProviderConfig::Oidc(config) = &mut gated.config
    else {
      unreachable!()
    };
    config.allowed_groups = vec!["admins".to_string()];
    let run = |auth: TestAuth| async move {
      exchange(
        &auth,
        IP,
        TokenExchangeRequest::id_token(token().mint()),
        |provider: ExternalLoginProvider| async move {
          if provider.id == "down" {
            return Err(
              anyhow!("Login provider 'OIDC' is not available")
                .status_code(StatusCode::SERVICE_UNAVAILABLE),
            );
          }
          load_client(provider).await
        },
        load_issuer_keys,
        None,
      )
      .await
      .unwrap_err()
    };

    // Alone, that is the token's
    let err = run(auth(vec![gated.clone()])).await;
    assert_eq!(code(&err), "invalid_grant");
    assert!(err.error.to_string().contains("groups"));

    for providers in [
      vec![gated.clone(), oidc_provider("down", true)],
      vec![oidc_provider("down", true), gated.clone()],
    ] {
      let err = run(auth(providers)).await;
      assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
      let (status, body) = token_exchange_error(&err);
      assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
      assert_eq!(body.error, "temporarily_unavailable");
    }
  }

  /// A provider token can be exchanged again until it expires. The app
  /// token counts as a login when the provider authenticated the user,
  /// so an old one is no recent login for the reauthentication window.
  #[tokio::test]
  async fn test_exchange_login_time_is_the_providers() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    let now = chrono::Utc::now().timestamp() as u64;
    let auth = &auth;
    let authenticated_at =
      |token: TestToken<UsernameAdditionalClaims>| async move {
        let response = run(auth, token.mint()).await.unwrap();
        auth
          .jwt
          .decode_claims(&response.access_token)
          .unwrap()
          .authenticated_at()
      };

    // Issued (and so authenticated) half an hour ago
    let at = authenticated_at(TestToken {
      issued_ago: chrono::Duration::minutes(30),
      expires_in: chrono::Duration::hours(8),
      ..token()
    })
    .await;
    assert!(at.abs_diff(now - 30 * 60) <= 5, "{at}");

    // Issued just now, for a login hours ago (eg. refreshed)
    let at = authenticated_at(TestToken {
      issued_ago: chrono::Duration::zero(),
      auth_time_ago: Some(chrono::Duration::hours(3)),
      ..token()
    })
    .await;
    assert!(at.abs_diff(now - 3 * 60 * 60) <= 5, "{at}");

    // Freshly issued: a recent login
    let at = authenticated_at(TestToken {
      issued_ago: chrono::Duration::zero(),
      ..token()
    })
    .await;
    assert!(at.abs_diff(now) <= 5, "{at}");
  }

  /// Static issuers come from the app configuration. Rules without
  /// (or sharing) an id would share a user, and each others groups.
  /// A static issuer whose rule matches the audience alone would
  /// accept the token of anybody who can ask the platform for one: it
  /// is skipped (the management api refuses to store it), and accepts
  /// no token.
  #[tokio::test]
  async fn test_static_rule_matching_the_audience_alone_accepts_nothing()
   {
    let everybody = WorkloadRule {
      id: "everybody".to_string(),
      name: "Everybody".to_string(),
      claims: vec![WorkloadClaim {
        claim: "aud".to_string(),
        pattern: WORKLOAD_AUDIENCE.to_string(),
      }],
      admin: true,
      ..deploy_rule()
    };
    let auth = workload_auth(vec![everybody]);
    let err = run(&auth, workload_token(1, "refs/heads/main").mint())
      .await
      .unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(err.error.to_string().contains("No login provider"));
    assert!(auth.workloads.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_workload_rules_need_unique_ids() {
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();
    let mut admin_rule = deploy_rule();
    admin_rule.name = "Admin".to_string();
    admin_rule.admin = true;
    admin_rule.claims[0].pattern = "99999".to_string();

    for id in ["", "deploy", "not valid"] {
      let mut rules = vec![deploy_rule(), admin_rule.clone()];
      rules[0].id = id.to_string();
      rules[1].id = id.to_string();
      let auth = workload_auth(rules);
      let err = run(&auth, token()).await.unwrap_err();
      assert_eq!(
        err.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{id}"
      );
      assert!(auth.workloads.lock().unwrap().is_empty());
    }
  }

  #[test]
  fn test_truncate_for_log() {
    assert_eq!(truncate_for_log("short"), "short");
    let long = "ü".repeat(500);
    let truncated = truncate_for_log(&long);
    assert_eq!(truncated.chars().count(), 203);
    assert!(truncated.ends_with("..."));
  }

  /// An issuer which can't be reached is a temporary
  /// condition for the caller, not a server error.
  #[tokio::test]
  async fn test_workload_unavailable_issuer() {
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.issuers[0].id = "unavailable-issuer".to_string();
    auth.issuers[0].keys = TrustedIssuerKeys::Static("broken".into());
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();

    // The attempt, and a request during the retry delay
    for _ in 0..2 {
      let err = run(&auth, token()).await.unwrap_err();
      assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
      // Without the reason
      let message = format!("{:#}", err.error);
      assert_eq!(message, "Trusted issuer 'CI' is not available");

      let (status, _, body) = error_body(err).await;
      assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
      assert!(body.contains("temporarily_unavailable"));
    }
    assert!(auth.workloads.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_workload_user_must_be_flagged_as_workload() {
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.workload_user.workload = false;
    let token = workload_token(12345, "refs/heads/release/1").mint();
    let err = run(&auth, token).await.unwrap_err();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
  }

  /// Its rule or issuer was disabled (AuthImpl::sync_workload_users),
  /// eg. on another instance after this one read the rule.
  #[tokio::test]
  async fn test_workload_user_must_be_enabled() {
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.workload_user.disabled = true;
    let token = workload_token(12345, "refs/heads/release/1").mint();
    let err = run(&auth, token).await.unwrap_err();
    assert_eq!(token_exchange_error(&err).1.error, "invalid_grant");
    assert!(auth.logins.lock().unwrap().is_empty());
  }

  /// An update of the issuer which the app stores and syncs while an
  /// exchange which read the rule before waits for the rule's lock:
  /// the exchange goes by the rule as it is after the update. It never
  /// gives the user the access the rule had before, nor creates the
  /// user of a rule which is gone, after the update synced the users.
  #[tokio::test]
  async fn test_workload_exchange_gets_the_rule_as_updated_meanwhile()
  {
    type Change = fn(&mut Vec<TrustedIssuer>);
    let cases: [(&str, Change, Option<&str>); 7] = [
      ("rule disabled", |i| i[0].rules[0].enabled = false, None),
      ("issuer disabled", |i| i[0].enabled = false, None),
      ("rule removed", |i| i[0].rules.clear(), None),
      ("issuer deleted", |i| i.clear(), None),
      (
        "claims narrowed",
        |i| {
          i[0].rules[0].claims[1].pattern = "refs/heads/main".into()
        },
        None,
      ),
      (
        // Verified with the old keys / audiences
        "audience changed",
        |i| i[0].audiences = vec!["https://other.example.com".into()],
        Some("temporarily_unavailable"),
      ),
      (
        "demoted",
        |i| {
          i[0].rules[0].admin = false;
          i[0].rules[0].groups = vec!["readers".to_string()];
        },
        Some("ok"),
      ),
    ];
    for (n, (case, change, outcome)) in cases.into_iter().enumerate()
    {
      let issuer_id = format!("ci-updated-{n}");
      let mut auth = TestAuth::with_user(None);
      auth.providers = Vec::new();
      *auth.stored_issuers.lock().unwrap() = vec![TrustedIssuer {
        id: issuer_id.clone(),
        ..trusted_issuer(vec![WorkloadRule {
          admin: true,
          ..deploy_rule()
        }])
      }];
      let auth = Arc::new(auth);

      // The update holds the issuer while the app stores and syncs.
      let update =
        crate::provider::workload::lock_trusted_issuer(&issuer_id)
          .await;
      let exchange = tokio::spawn({
        let auth = auth.clone();
        let token =
          workload_token(12345, "refs/heads/release/1").mint();
        async move { run(&auth, token).await }
      });
      // The exchange read the issuer and matched the rule, and waits.
      tokio::time::timeout(Duration::from_secs(5), async {
        while auth.stored_issuer_lists.load(Ordering::SeqCst) == 0 {
          tokio::task::yield_now().await;
        }
      })
      .await
      .expect(case);
      change(&mut auth.stored_issuers.lock().unwrap());
      drop(update);

      let res = exchange.await.unwrap();
      let workloads = auth.workloads.lock().unwrap().clone();
      match outcome {
        Some("ok") => {
          res.expect(case);
          assert_eq!(workloads.len(), 1, "{case}");
          assert!(!workloads[0].admin, "{case}");
          assert_eq!(workloads[0].groups, ["readers"], "{case}");
        }
        outcome => {
          let err = res.expect_err(case);
          assert_eq!(
            token_exchange_error(&err).1.error,
            outcome.unwrap_or("invalid_grant"),
            "{case}"
          );
          assert!(workloads.is_empty(), "{case}");
        }
      }
    }
  }

  #[tokio::test]
  async fn test_workload_admin_has_to_be_allowed_by_the_rule() {
    // Made an admin some other way
    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.workload_user.admin = true;
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();
    let err = run(&auth, token()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");

    let mut rule = deploy_rule();
    rule.admin = true;
    let mut auth = workload_auth(vec![rule]);
    auth.workload_user.admin = true;
    assert!(run(&auth, token()).await.is_ok());
    assert!(auth.workloads.lock().unwrap()[0].admin);
  }

  #[tokio::test]
  async fn test_workload_user_login_rules() {
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();

    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.workload_user.cidr_whitelist =
      vec!["192.168.0.0/16".to_string()];
    let err = run(&auth, token()).await.unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);

    let mut auth = workload_auth(vec![deploy_rule()]);
    auth.workload_user.totp = true;
    let err = run(&auth, token()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
  }

  /// A login provider and a trusted issuer are independent: tokens of
  /// an issuer only known as a trusted issuer never reach user logins.
  #[tokio::test]
  async fn test_user_and_workload_paths_are_separate() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    auth.issuers = vec![trusted_issuer(vec![deploy_rule()])];

    // A user token (audience of the login provider) logs in the user
    let response = run(&auth, token().mint()).await.unwrap();
    assert_eq!(response.expires_in, 3600);
    assert!(auth.workloads.lock().unwrap().is_empty());

    // A workload token is rejected by the login provider
    // (audience), and accepted by the trusted issuer.
    let workload =
      workload_token(12345, "refs/heads/release/1").mint();
    let response = run(&auth, workload).await.unwrap();
    assert_eq!(response.expires_in, 900);
    assert_eq!(auth.workloads.lock().unwrap().len(), 1);
  }

  fn code(e: &mogh_error::Error) -> &'static str {
    e.error
      .downcast_ref::<OauthError>()
      .map(|e| e.code)
      .unwrap_or("")
  }

  #[tokio::test]
  async fn test_exchange_issues_app_token_for_linked_user() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    let response = run(&auth, token().mint()).await.unwrap();

    assert_eq!(response.token_type, "Bearer");
    assert_eq!(response.issued_token_type, TOKEN_TYPE_ACCESS_TOKEN);
    assert_eq!(response.expires_in, 3600);
    // The app token belongs to the linked user
    assert_eq!(
      auth.jwt.decode_sub(&response.access_token).unwrap(),
      "user-id"
    );
    let synced = auth.synced.lock().unwrap();
    assert_eq!(synced.len(), 1);
    assert_eq!(synced[0].provider_id, "oidc");
    assert_eq!(synced[0].external_id, "subject-123");
    // The exchange is a login through the provider
    let logins = auth.logins.lock().unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].user_id, "user-id");
    assert!(logins[0].second_factor.is_none());
    assert!(matches!(
      &logins[0].kind,
      LoginKind::Provider { provider_id, .. } if provider_id == "oidc"
    ));
  }

  #[tokio::test]
  async fn test_exchange_never_signs_up_users() {
    let auth = TestAuth::with_user(None);
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(auth.synced.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_exchange_rejects_invalid_token() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    let other_app = TestToken {
      audiences: vec!["another-app".to_string()],
      ..token()
    };
    let err = run(&auth, other_app.mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");

    let err = run(&auth, "not-a-jwt".to_string()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
  }

  #[tokio::test]
  async fn test_exchange_requires_provider_opt_in() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    auth.providers = vec![oidc_provider("oidc", false)];
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
  }

  #[tokio::test]
  async fn test_exchange_unknown_issuer() {
    let auth = TestAuth::with_user(Some(TestUser::default()));
    let foreign = TestToken {
      issuer: "https://evil.example.com".to_string(),
      ..token()
    };
    let err = run(&auth, foreign.mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
  }

  /// Token exchange must not be a way around a second factor.
  #[tokio::test]
  async fn test_exchange_rejects_users_requiring_two_factor() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: false,
      totp: true,
      ..Default::default()
    }));
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(auth.synced.lock().unwrap().is_empty());

    // Enrolled, but skipped for external logins
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      totp: true,
      ..Default::default()
    }));
    assert!(run(&auth, token().mint()).await.is_ok());

    // Not enrolled
    let auth = TestAuth::with_user(Some(TestUser::default()));
    assert!(run(&auth, token().mint()).await.is_ok());
  }

  #[tokio::test]
  async fn test_exchange_enforces_cidr_whitelist_before_sync() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      cidr_whitelist: vec!["192.168.0.0/16".to_string()],
      ..Default::default()
    }));
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    assert!(auth.synced.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_exchange_fails_if_sync_fails() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    auth.sync_fails = true;
    assert!(run(&auth, token().mint()).await.is_err());
  }

  #[tokio::test]
  async fn test_exchange_second_provider_of_same_issuer_accepts() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    // The first provider is another client at the same issuer
    let mut other_client = oidc_provider("other", true);
    let ExternalLoginProviderConfig::Oidc(config) =
      &mut other_client.config
    else {
      unreachable!()
    };
    config.client_id = "other-client-id".to_string();
    auth.providers = vec![other_client, oidc_provider("oidc", true)];

    let response = run(&auth, token().mint()).await.unwrap();
    assert!(!response.access_token.is_empty());
    assert_eq!(auth.synced.lock().unwrap()[0].provider_id, "oidc");
  }

  /// Accepting the token isn't enough to decide, the
  /// next provider may be the one the user is linked to.
  #[tokio::test]
  async fn test_exchange_falls_through_to_provider_with_the_user() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    // Another client at the same issuer, which also
    // accepts tokens issued to the 'oidc' provider.
    let mut other_client = oidc_provider("other", true);
    other_client.token_exchange.audiences =
      vec![CLIENT_ID.to_string()];
    let ExternalLoginProviderConfig::Oidc(config) =
      &mut other_client.config
    else {
      unreachable!()
    };
    config.client_id = "other-client-id".to_string();
    auth.providers =
      vec![other_client.clone(), oidc_provider("oidc", true)];

    // 'other' accepts the token, but only 'oidc' has the user linked
    let response = run(&auth, token().mint()).await.unwrap();
    assert_eq!(
      auth.jwt.decode_sub(&response.access_token).unwrap(),
      "user-id"
    );
    assert_eq!(auth.synced.lock().unwrap()[0].provider_id, "oidc");

    // Nobody has the user: reported as such, not as a rejected token
    auth.providers = vec![other_client];
    let err = run(&auth, token().mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(err.error.to_string().contains("No user is linked"));
  }

  #[tokio::test]
  async fn test_exchange_enforces_max_token_age() {
    let mut auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    auth.providers[0].token_exchange.max_token_age_secs = 300;

    let old_token = TestToken {
      issued_ago: chrono::Duration::minutes(30),
      expires_in: chrono::Duration::hours(8),
      ..token()
    };
    let err = run(&auth, old_token.mint()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(err.error.to_string().contains("seconds ago"));

    assert!(run(&auth, token().mint()).await.is_ok());
  }

  #[test]
  fn test_validate_request() {
    let valid = TokenExchangeRequest::id_token("a.b.c");
    assert_eq!(
      validate_request(&valid).unwrap(),
      TOKEN_TYPE_ACCESS_TOKEN
    );

    let jwt = TokenExchangeRequest {
      subject_token_type: TOKEN_TYPE_JWT.to_string(),
      requested_token_type: Some(TOKEN_TYPE_JWT.to_string()),
      ..valid.clone()
    };
    assert_eq!(validate_request(&jwt).unwrap(), TOKEN_TYPE_JWT);

    let wrong_grant = TokenExchangeRequest {
      grant_type: "authorization_code".to_string(),
      ..valid.clone()
    };
    assert_eq!(
      code(&validate_request(&wrong_grant).unwrap_err()),
      "unsupported_grant_type"
    );

    for invalid in [
      // Opaque access tokens have no verifiable audience
      TokenExchangeRequest {
        subject_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
        ..valid.clone()
      },
      TokenExchangeRequest {
        actor_token: Some("a.b.c".to_string()),
        ..valid.clone()
      },
      TokenExchangeRequest {
        requested_token_type: Some(
          "urn:ietf:params:oauth:token-type:refresh_token"
            .to_string(),
        ),
        ..valid.clone()
      },
      TokenExchangeRequest {
        subject_token: String::new(),
        ..valid.clone()
      },
      TokenExchangeRequest {
        subject_token: "a".repeat(MAX_SUBJECT_TOKEN_LENGTH + 1),
        ..valid.clone()
      },
    ] {
      let err = validate_request(&invalid).unwrap_err();
      assert_eq!(code(&err), "invalid_request", "{invalid:?}");
    }
  }

  #[test]
  fn test_exchange_candidates() {
    let mut disabled = oidc_provider("disabled", true);
    let ExternalLoginProviderConfig::Oidc(config) =
      &mut disabled.config
    else {
      unreachable!()
    };
    config.enabled = false;

    let providers = vec![
      oidc_provider("no-exchange", false),
      disabled,
      oidc_provider("oidc", true),
      named_provider("github", true),
      named_provider("google", false),
    ];

    let ids = |issuer: &str| {
      exchange_candidates(providers.clone(), issuer, None)
        .into_iter()
        .map(|provider| provider.id)
        .collect::<Vec<_>>()
    };
    // Trailing slash tolerant
    assert_eq!(ids(&format!("{ISSUER}/")), ["oidc"]);
    assert_eq!(ids("https://accounts.google.com"), ["google"]);
    // Can't verify (`iss` must be a url), so not routed to Google.
    assert!(ids("accounts.google.com").is_empty());
    // Github never takes part
    assert!(ids("https://github.com").is_empty());
    assert!(ids("https://evil.example.com").is_empty());
    assert!(ids("").is_empty());

    // A role names a provider by id or name, nothing else qualifies
    let named = |issuer: &str, role: &str| {
      exchange_candidates(providers.clone(), issuer, Some(role))
        .into_iter()
        .map(|provider| provider.id)
        .collect::<Vec<_>>()
    };
    assert_eq!(named(ISSUER, "oidc"), ["oidc"]);
    assert_eq!(named(ISSUER, "OIDC"), ["oidc"]);
    assert!(named(ISSUER, "github").is_empty());
    assert!(named("https://accounts.google.com", "oidc").is_empty());
  }

  // ========
  // = ROLE =
  // ========

  /// The broad rule comes first: without a role it takes every
  /// release token, with the role the narrower rule named is the
  /// one evaluated and logged in as.
  fn broad_then_narrow() -> Vec<WorkloadRule> {
    let mut broad = deploy_rule();
    broad.id = "release".to_string();
    broad.name = "Release".to_string();
    broad.claims.truncate(1);
    broad.groups = vec!["releasers".to_string()];
    vec![broad, deploy_rule()]
  }

  #[tokio::test]
  async fn test_role_selects_the_named_rule() {
    let auth = workload_auth(broad_then_narrow());
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();

    let first = run_as(&auth, token(), None).await.unwrap();
    assert!(matches!(
      &first.login,
      ExchangedLogin::Workload { rule_id, .. } if rule_id == "release"
    ));
    assert_eq!(first.user_id, "user-id");

    // By name, and by id
    for role in ["Deploy", "deploy"] {
      let named = run_as(&auth, token(), Some(role)).await.unwrap();
      let ExchangedLogin::Workload {
        issuer_id,
        issuer_name,
        rule_id,
        rule_name,
      } = &named.login
      else {
        panic!("a workload login")
      };
      assert_eq!(
        (issuer_id.as_str(), issuer_name.as_str()),
        ("ci", "CI")
      );
      assert_eq!(
        (rule_id.as_str(), rule_name.as_str()),
        ("deploy", "Deploy")
      );
      assert_eq!(named.response.expires_in, 900);
    }
    let workloads = auth.workloads.lock().unwrap();
    assert_eq!(workloads.len(), 3);
    assert_eq!(workloads[0].groups, ["releasers"]);
    assert_eq!(workloads[1].groups, ["deployers"]);
  }

  #[tokio::test]
  async fn test_role_refuses_before_any_effect() {
    let auth = workload_auth(broad_then_narrow());

    // The named rule exists but the token doesn't match it: no
    // falling back to the rule which would.
    let token = workload_token(12345, "refs/heads/main").mint();
    let err = run_as(&auth, token, Some("Deploy")).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(
      err
        .error
        .to_string()
        .contains("does not match rule 'Deploy'")
    );
    assert!(err.error.downcast_ref::<RoleNotFound>().is_none());

    // No rule (and no provider) of that name takes the issuer:
    // Vault's "role not found", told apart for the app.
    let token = workload_token(12345, "refs/heads/release/1").mint();
    let err = run_as(&auth, token, Some("nope")).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    let not_found = err.error.downcast_ref::<RoleNotFound>().unwrap();
    assert_eq!(not_found.role, "nope");
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.error, "invalid_grant");
    assert!(body.error_description.unwrap().contains("'nope'"));

    // Neither refusal reached the app
    assert!(auth.workloads.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn test_role_names_a_login_provider() {
    let auth = TestAuth::with_user(Some(TestUser {
      external_skip_2fa: true,
      ..Default::default()
    }));
    let exchanged =
      run_as(&auth, token().mint(), Some("OIDC")).await.unwrap();
    assert!(matches!(
      &exchanged.login,
      ExchangedLogin::Provider { provider_id, provider_name }
        if provider_id == "oidc" && provider_name == "OIDC"
    ));
    assert_eq!(exchanged.user_id, "user-id");

    let err = run_as(&auth, token().mint(), Some("other"))
      .await
      .unwrap_err();
    assert!(err.error.downcast_ref::<RoleNotFound>().is_some());
    // Only the successful exchange synced the user
    assert_eq!(auth.synced.lock().unwrap().len(), 1);
  }

  /// A login provider and a trusted issuer of one issuer: whichever
  /// got further with a token neither accepted is reported, in the
  /// order each path uses (verified but refused, over unavailable,
  /// over rejected), not the login provider's whatever it says.
  #[tokio::test]
  async fn test_furthest_refusal_across_providers_and_issuers() {
    // The provider (client CLIENT_ID) rejects workload tokens for
    // their audience.
    let shared = |id: &str, keys: TrustedIssuerKeys| {
      let mut auth = TestAuth::with_user(None);
      let mut issuer = trusted_issuer(vec![deploy_rule()]);
      issuer.id = id.to_string();
      issuer.keys = keys;
      auth.issuers = vec![issuer];
      auth
    };

    // The issuer can't be asked: it might accept the token, so the
    // client is told to try again.
    let auth = shared(
      "shared-down",
      TrustedIssuerKeys::Static("broken".into()),
    );
    let token =
      || workload_token(12345, "refs/heads/release/1").mint();
    let err = run(&auth, token()).await.unwrap_err();
    assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.error, "temporarily_unavailable");

    // The issuer verified the token, which matches no rule: that is
    // what the token is told, not the provider's audience.
    let auth =
      shared("shared-up", TrustedIssuerKeys::Static(jwks_json()));
    let err =
      run(&auth, workload_token(99999, "refs/heads/x").mint())
        .await
        .unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
    assert!(err.error.to_string().contains("matches no rule"));

    // The provider verified a token whose user isn't linked, which
    // the issuer rejects (audience) or can't be asked about.
    for keys in [
      TrustedIssuerKeys::Static(jwks_json()),
      TrustedIssuerKeys::Static("broken".into()),
    ] {
      let auth = shared("shared-user-token", keys);
      let err =
        run(&auth, token_for_user().mint()).await.unwrap_err();
      assert_eq!(code(&err), "invalid_grant");
      assert!(err.error.to_string().contains("No user is linked"));
    }

    // Both reject it: the provider's (first) rejection.
    let auth = shared(
      "shared-reject",
      TrustedIssuerKeys::Static(other_jwks_json()),
    );
    let err = run(&auth, token()).await.unwrap_err();
    assert_eq!(code(&err), "invalid_grant");
  }

  /// The exchange endpoint's, rate limit included, of a workload
  /// token at `ip`.
  async fn exchange_workload_at(
    auth: &TestAuth,
    ip: IpAddr,
  ) -> mogh_error::Result<ExchangedToken> {
    let token = workload_token(12345, "refs/heads/release/1").mint();
    exchange_token(
      auth,
      ip,
      TokenExchangeRequest::id_token(token),
      Default::default(),
    )
    .await
  }

  /// A token one candidate rejected while another couldn't be asked
  /// is a `503`, which still counts against the rate limit: the
  /// caller picks the issuer, and a forged token aimed at one with a
  /// candidate down would otherwise never count. Without a rejection,
  /// an unavailable issuer counts nothing.
  #[tokio::test]
  async fn test_unavailable_masking_a_rejection_counts() {
    let mut other_cluster = trusted_issuer(vec![deploy_rule()]);
    other_cluster.id = "counted-other-cluster".to_string();
    other_cluster.keys = TrustedIssuerKeys::Static(other_jwks_json());
    let mut down = trusted_issuer(vec![deploy_rule()]);
    down.id = "counted-down-cluster".to_string();
    down.name = "Down".to_string();
    down.keys = TrustedIssuerKeys::Static("broken".into());
    let mut auth = workload_auth(Vec::new());
    auth.issuers = vec![other_cluster, down.clone()];
    auth.rate_limiter =
      RateLimiter::new(false, 2, std::time::Duration::from_secs(60));
    let ip: IpAddr = "10.0.0.2".parse().unwrap();
    for remaining in [1, 0] {
      let err = exchange_workload_at(&auth, ip).await.unwrap_err();
      assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
      let (status, body) = token_exchange_error(&err);
      assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
      assert_eq!(body.error, "temporarily_unavailable");
      assert_eq!(
        body.error_description.unwrap(),
        format!(
          "Trusted issuer 'Down' is not available | You have {remaining} attempts remaining"
        )
      );
    }
    let err = exchange_workload_at(&auth, ip).await.unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);

    // Only the issuer which is down: nothing rejected the token.
    auth.issuers = vec![down];
    let ip: IpAddr = "10.0.0.3".parse().unwrap();
    for _ in 0..5 {
      let err = exchange_workload_at(&auth, ip).await.unwrap_err();
      assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
      let message = format!("{:#}", err.error);
      assert!(!message.contains("attempts"), "{message}");
    }
  }

  /// [exchange_token] is [exchange] behind the app's failure rate
  /// limit, which must keep the errors' types: the OAuth codes of
  /// the endpoint and the [RoleNotFound] apps tell apart.
  #[tokio::test]
  async fn test_exchange_token_errors_keep_their_type() {
    let mut auth = TestAuth::with_user(None);
    auth.rate_limiter =
      RateLimiter::new(false, 3, std::time::Duration::from_secs(60));
    let exchange_token = |request, role: Option<&str>| {
      exchange_token(
        &auth,
        IP,
        request,
        TokenExchangeOptions {
          role: role.map(String::from),
        },
      )
    };

    let mut request = TokenExchangeRequest::id_token(token().mint());
    request.grant_type = String::from("client_credentials");
    let err = exchange_token(request, None).await.unwrap_err();
    assert_eq!(code(&err), "unsupported_grant_type");
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
      body,
      TokenExchangeError {
        error: String::from("unsupported_grant_type"),
        // The caller is still told how many attempts are left.
        error_description: Some(format!(
          "Only '{GRANT_TYPE_TOKEN_EXCHANGE}' is supported | You have 2 attempts remaining"
        )),
      }
    );

    let err =
      exchange_token(TokenExchangeRequest::id_token(""), None)
        .await
        .unwrap_err();
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
      body,
      TokenExchangeError {
        error: String::from("invalid_request"),
        error_description: Some(String::from(
          "'subject_token' is empty | You have 1 attempts remaining"
        )),
      }
    );

    let err = exchange_token(
      TokenExchangeRequest::id_token(token().mint()),
      Some("nope"),
    )
    .await
    .unwrap_err();
    let not_found = err.error.downcast_ref::<RoleNotFound>().unwrap();
    assert_eq!(not_found.role, "nope");
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
      body,
      TokenExchangeError {
        error: String::from("invalid_grant"),
        error_description: Some(String::from(
          "No login provider or workload rule 'nope' accepts tokens of this issuer | You have 0 attempts remaining"
        )),
      }
    );

    // Out of attempts
    let err = exchange_token(
      TokenExchangeRequest::id_token(token().mint()),
      None,
    )
    .await
    .unwrap_err();
    let (status, body) = token_exchange_error(&err);
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body.error, "temporarily_unavailable");
  }

  async fn error_body(
    e: mogh_error::Error,
  ) -> (StatusCode, String, String) {
    let response = error_response(e);
    let status = response.status();
    let cache = response.headers()[header::CACHE_CONTROL]
      .to_str()
      .unwrap()
      .to_string();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
      .await
      .unwrap();
    (status, cache, String::from_utf8(body.to_vec()).unwrap())
  }

  #[tokio::test]
  async fn test_error_response_format() {
    let (status, cache, body) =
      error_body(invalid_grant("Token was rejected")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(cache, "no-store");
    assert_eq!(
      serde_json::from_str::<TokenExchangeError>(&body).unwrap(),
      TokenExchangeError {
        error: "invalid_grant".to_string(),
        error_description: Some("Token was rejected".to_string()),
      }
    );

    // Login rule rejections
    let (status, _, body) = error_body(
      anyhow!("User is not a member of any allowed group")
        .status_code(StatusCode::UNAUTHORIZED),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("invalid_grant"));
    assert!(body.contains("allowed group"));

    // Rate limited
    let (status, _, body) = error_body(
      anyhow!("Too many attempts")
        .status_code(StatusCode::TOO_MANY_REQUESTS),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("temporarily_unavailable"));

    // A provider or issuer which can't be reached
    let (status, _, body) = error_body(
      anyhow!("Trusted issuer 'CI' is not available")
        .status_code(StatusCode::SERVICE_UNAVAILABLE),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("temporarily_unavailable"));
    assert!(body.contains("not available"));
  }

  #[tokio::test]
  async fn test_error_response_hides_internal_errors() {
    let (status, _, body) = error_body(
      anyhow!("connection refused: http://10.0.0.5:9000/db").into(),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, r#"{"error":"server_error"}"#);
  }

  // =====================
  // = OVER REAL HTTP    =
  // =====================

  /// No providers configured, which is
  /// enough to exercise the http layer.
  struct HttpTestAuth;

  impl AuthImpl for HttpTestAuth {
    fn new() -> Self {
      HttpTestAuth
    }

    fn host(&self) -> &str {
      "https://app.example.com"
    }

    fn extra_hosts(&self) -> &[String] {
      static EXTRA: std::sync::LazyLock<Vec<String>> =
        std::sync::LazyLock::new(|| {
          vec![String::from("http://10.0.0.5:9120")]
        });
      &EXTRA
    }

    stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
  }

  /// [HttpTestAuth], counting failures: one per ip.
  struct LimitedHttpAuth;

  impl AuthImpl for LimitedHttpAuth {
    fn new() -> Self {
      LimitedHttpAuth
    }
    fn host(&self) -> &str {
      HttpTestAuth.host()
    }
    stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
    fn general_rate_limiter(&self) -> &RateLimiter {
      static LIMITER: std::sync::LazyLock<Arc<RateLimiter>> =
        std::sync::LazyLock::new(|| {
          RateLimiter::new(false, 1, Duration::from_secs(60))
        });
      &LIMITER
    }
  }

  /// Serves the token endpoint on a free local port.
  async fn serve() -> String {
    serve_with::<HttpTestAuth>().await
  }

  async fn serve_with<I: AuthImpl>() -> String {
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address =
      format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
      axum::serve(
        listener,
        router::<I>()
          .into_make_service_with_connect_info::<std::net::SocketAddr>(),
      )
      .await
      .unwrap();
    });
    address
  }

  /// Fetch metadata decides, else the `Origin` of the post must be
  /// the app's host or one of its extra hosts.
  #[test]
  fn test_check_not_cross_site() {
    let check = |headers: &[(&'static str, &'static str)]| {
      let mut map = HeaderMap::new();
      for (name, value) in headers {
        map.insert(*name, HeaderValue::from_static(value));
      }
      check_not_cross_site(&HttpTestAuth, &map)
    };
    // RFC 8693 clients, and the app's own pages.
    for headers in [
      &[][..],
      &[("sec-fetch-site", "same-origin")],
      &[("sec-fetch-site", "none")],
      &[("origin", "https://app.example.com")],
      &[("origin", "https://app.example.com:443")],
      &[("origin", "http://10.0.0.5:9120")],
      // Fetch metadata can't be set by a page: it decides.
      &[
        ("sec-fetch-site", "same-origin"),
        ("origin", "https://reached.another.way"),
      ],
    ] {
      assert!(check(headers).is_ok(), "{headers:?}");
    }
    // Pages of other sites, sandboxed pages, other ports / schemes.
    for headers in [
      &[("sec-fetch-site", "cross-site")][..],
      &[("sec-fetch-site", "same-site")],
      &[
        ("sec-fetch-site", "cross-site"),
        ("origin", "https://app.example.com"),
      ],
      &[("origin", "https://evil.example")],
      &[("origin", "null")],
      &[("origin", "http://app.example.com")],
      &[("origin", "https://app.example.com:8443")],
      &[("origin", "https://app.example.com.evil.example")],
    ] {
      let err = check(headers).unwrap_err();
      assert_eq!(code(&err), "invalid_request", "{headers:?}");
      let (status, _) = token_exchange_error(&err);
      assert_eq!(status, StatusCode::BAD_REQUEST);
    }
  }

  /// Any page can make its visitors' browsers post the form. Those
  /// requests are refused before they count against the ip, so they
  /// can't get it refused by the (general) rate limiter. The same
  /// exchange from another client counts.
  #[tokio::test]
  async fn test_http_cross_site_requests_are_not_counted() {
    let address = serve_with::<LimitedHttpAuth>().await;
    let token = token().mint();
    let form = [
      ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
      ("subject_token", token.as_str()),
      ("subject_token_type", TOKEN_TYPE_ID_TOKEN),
    ];
    let post =
      |headers: &'static [(&'static str, &'static str)]| {
        let mut request =
          reqwest::Client::new().post(format!("{address}/token"));
        for (name, value) in headers {
          request = request.header(*name, *value);
        }
        let request = request.form(&form);
        async move {
          let response = request.send().await.unwrap();
          let status = response.status();
          let error: TokenExchangeError =
            response.json().await.unwrap();
          (status, error)
        }
      };
    for _ in 0..3 {
      for headers in [
        &[
          ("sec-fetch-site", "cross-site"),
          ("sec-fetch-mode", "no-cors"),
        ][..],
        &[("origin", "https://evil.example")],
      ] {
        let (status, error) = post(headers).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error.error, "invalid_request");
        assert!(
          !error
            .error_description
            .unwrap_or_default()
            .contains("attempts remaining")
        );
      }
    }
    // The ip has its whole budget: the first failure of a client
    // exchanging the same token counts...
    let (status, error) = post(&[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.error, "invalid_grant");
    assert!(
      error
        .error_description
        .unwrap_or_default()
        .contains("0 attempts remaining")
    );
    // ...and uses it up.
    let (status, error) = post(&[]).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(error.error, "temporarily_unavailable");
  }

  async fn post_form(
    address: &str,
    form: &[(&str, &str)],
  ) -> (StatusCode, TokenExchangeError, String) {
    let response = reqwest::Client::new()
      .post(format!("{address}/token"))
      .form(form)
      .send()
      .await
      .unwrap();
    let status = response.status();
    let cache = response.headers()["cache-control"]
      .to_str()
      .unwrap()
      .to_string();
    (status, response.json().await.unwrap(), cache)
  }

  #[tokio::test]
  async fn test_http_unaccepted_token_gets_oauth_error() {
    let address = serve().await;
    // A well formed request, as sent by
    // `mogh_auth_client::request::token_exchange`,
    // for a token nobody accepts.
    let token = token().mint();
    let (status, error, cache) = post_form(
      &address,
      &[
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("subject_token", token.as_str()),
        ("subject_token_type", TOKEN_TYPE_ID_TOKEN),
      ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.error, "invalid_grant");
    assert!(error.error_description.is_some());
    assert_eq!(cache, "no-store");
  }

  #[tokio::test]
  async fn test_http_malformed_requests() {
    let address = serve().await;

    // Required parameters missing
    let (status, error, cache) = post_form(
      &address,
      &[("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.error, "invalid_request");
    assert_eq!(cache, "no-store");

    let (status, error, _) = post_form(
      &address,
      &[
        ("grant_type", "client_credentials"),
        ("subject_token", "a.b.c"),
        ("subject_token_type", TOKEN_TYPE_ID_TOKEN),
      ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error.error, "unsupported_grant_type");

    // `resource`, `audience` and `scope` may repeat and are ignored
    let (_, error, _) = post_form(
      &address,
      &[
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        ("subject_token", "a.b.c"),
        ("subject_token_type", TOKEN_TYPE_ID_TOKEN),
        ("resource", "https://a.example.com"),
        ("resource", "https://b.example.com"),
        ("scope", "read write"),
      ],
    )
    .await;
    assert_eq!(error.error, "invalid_grant");

    // The RFC requires a form, not json
    let response = reqwest::Client::new()
      .post(format!("{address}/token"))
      .json(&TokenExchangeRequest::id_token("a.b.c"))
      .send()
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error: TokenExchangeError = response.json().await.unwrap();
    assert_eq!(error.error, "invalid_request");

    // Only POST
    let response =
      reqwest::get(format!("{address}/token")).await.unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
  }
}
