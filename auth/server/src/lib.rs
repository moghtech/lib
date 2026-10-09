use std::{
  net::IpAddr,
  sync::{Arc, LazyLock},
  time::Duration,
};

use anyhow::{Context as _, anyhow};
use axum::{extract::Request, http::StatusCode};
use mogh_auth_client::{
  api::manage::CreateApiKey,
  config::{ExternalLoginProvider, TrustedIssuer},
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_rate_limit::RateLimiter;
use serde::{Deserialize, Serialize};

pub mod api;
pub mod api_key;
pub mod context;
pub mod login_start;
pub mod middleware;
pub mod passkey;
pub mod provider;
pub mod rand;
pub mod user;
pub mod validations;

mod bcrypt_pool;
mod session;
#[cfg(test)]
mod test_support;

use crate::{
  api_key::BoxAuthApiKey,
  passkey::Passkey,
  provider::{
    external::ExternalLoginInfo,
    jwt::JwtProvider,
    passkey::PasskeyProvider,
    workload::{WorkloadAccess, WorkloadIdentity},
  },
  user::BoxAuthUser,
  validations::{
    validate_api_key_name, validate_cidr_whitelist,
    validate_password, validate_username,
  },
};

/// Client ip extraction. The `RequestIp` extractor believes
/// forwarding headers only from the [TrustedProxies][request_ip::TrustedProxies]
/// attached to the request by `mogh_server::serve_app`
/// (`ServerConfig::trusted_proxies`), else private ranges.
/// Apps not using `mogh_server` should add
/// `TrustedProxies::layer()` to their router.
pub mod request_ip {
  pub use mogh_request_ip::*;
}

pub use bcrypt_pool::hash_password;
pub use context::{
  RequestContext, request_context, scope_request_context,
};

pub(crate) type BoxAuthImpl = Box<dyn AuthImpl>;
pub type DynFuture<O> =
  std::pin::Pin<Box<dyn Future<Output = O> + Send>>;

#[derive(Clone)]
pub enum RequestAuthentication {
  /// Jwt's coming through the AUTHORIZATION header.
  /// DANGER ⚠️ the jwt must still be validated as belonging to a particular client.
  Jwt(String),
  /// The api key and secret from X-API-KEY and X-API-SECRET.
  /// DANGER ⚠️ the secret needs bcrypt compare with matching
  /// api key's hashed secret to be validated as belonging to a particular client.
  ApiKey { key: String, secret: String },
  /// The X-API-PUBLIC-KEY of a request signed with a signing key,
  /// whose X-API-SIGNATURE verified with it.
  /// DANGER ⚠️ the public key must still be validated as belonging to a particular client.
  PublicKey(String),
}

/// The signature of a request signed with a signing key, which
/// verified and whose signer authenticated: what
/// [AuthImpl::accept_signed_request] is called with. Every field is
/// the header of the request as it was sent (each has one accepted
/// form), and the signature covers all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedSignature {
  /// `X-API-PUBLIC-KEY`: the public key of the signing key.
  pub public_key: String,
  /// `X-API-HOST`: the host of this server the request is signed
  /// for.
  pub host: String,
  /// `X-API-TIMESTAMP`: when the request was signed, unix
  /// milliseconds.
  pub timestamp: i64,
  /// `X-API-NONCE`: new for every request, which makes every
  /// signature unique.
  pub nonce: String,
  /// `X-API-SIGNATURE`.
  pub signature: String,
}

/// A login the auth server completed, see [AuthImpl::record_login].
/// Built by the server ([Login::of]); apps read it. Fields may be
/// added.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Login {
  /// The user who logged in.
  pub user_id: String,
  /// Their username at the time (for a user just signed up through
  /// a provider, the one the server made unique).
  pub username: String,
  /// The client ip the login came from (the request's, forwarding
  /// headers honored from the trusted proxies only).
  pub ip: IpAddr,
  /// How the user was authenticated.
  pub kind: LoginKind,
  /// The second factor the login was completed with, for a user
  /// enrolled in one. Never for a workload, nor for a `POST /token`
  /// exchange (which refuses such users); an `ExchangeExternalForJwt`
  /// can be completed with one.
  pub second_factor: Option<SecondFactor>,
  /// When the token the login issued expires, in unix seconds:
  /// the `exp` of the session jwt or exchanged token, computed
  /// with the encode's own arithmetic
  /// ([JwtProvider::expires_at](provider::jwt::JwtProvider::expires_at)).
  /// An app surfacing logins can show how long each granted
  /// credential lives without knowing the flows' ttl rules (a
  /// workload rule's `token_ttl_secs` capped at the app ttl,
  /// everything else the app ttl).
  ///
  /// ⚠️ An external login completed at the provider's callback
  /// without a second factor is recorded at the callback, while its
  /// session jwt is only encoded when the app redeems it
  /// (`ExchangeForJwt`): up to 2 minutes later
  /// (`Session::MAX_COMPLETED_LOGIN_AGE`), or never when it isn't
  /// redeemed. Its `token_expires` is the callback time plus the ttl,
  /// and the jwt, if any, expires up to 2 minutes after it.
  pub token_expires: u64,
}

impl Login {
  /// The login of `user`, issuing a token that expires at
  /// `token_expires` (unix seconds, see the field).
  pub fn of(
    user: &dyn crate::user::AuthUserImpl,
    ip: IpAddr,
    kind: LoginKind,
    second_factor: Option<SecondFactor>,
    token_expires: u64,
  ) -> Login {
    Login {
      user_id: user.id().to_string(),
      username: user.username().to_string(),
      ip,
      kind,
      second_factor,
      token_expires,
    }
  }
}

/// How a login authenticated the user.
///
/// Matched exhaustively on purpose, like
/// [ExchangedLogin](api::token::ExchangedLogin): a new kind of login
/// is meant to be a compile error for an app recording them, not a
/// silently unrecorded login. Its serde form is kept on the session
/// between the two factors of a login, so it stays backwards
/// compatible (a value the server can't read counts as a local
/// login).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginKind {
  /// Username and password (`LoginLocalUser`).
  Local,
  /// Through a login provider: the user logged in at the provider
  /// and came back to its callback (`/external/{slug}/callback`),
  /// or a token of the provider was exchanged (`POST /token`,
  /// `ExchangeExternalForJwt`).
  Provider {
    provider_id: String,
    provider_name: String,
  },
  /// A workload's token exchanged (`POST /token`): verified by a
  /// trusted issuer and matched to one of its rules, whose user
  /// logged in.
  Workload {
    issuer_id: String,
    issuer_name: String,
    rule_id: String,
    rule_name: String,
  },
}

impl From<api::token::ExchangedLogin> for LoginKind {
  fn from(login: api::token::ExchangedLogin) -> LoginKind {
    match login {
      api::token::ExchangedLogin::Provider {
        provider_id,
        provider_name,
      } => LoginKind::Provider {
        provider_id,
        provider_name,
      },
      api::token::ExchangedLogin::Workload {
        issuer_id,
        issuer_name,
        rule_id,
        rule_name,
      } => LoginKind::Workload {
        issuer_id,
        issuer_name,
        rule_id,
        rule_name,
      },
    }
  }
}

/// A change of how a user logs in, made through the auth management
/// api, see [AuthImpl::credentials_changed].
///
/// Matched exhaustively on purpose, like [LoginKind]: a new kind of
/// change is meant to be a compile error for an app which treats
/// them differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialChange {
  /// `UpdatePassword`: a password set or changed.
  Password,
  /// `ConfirmTotpEnrollment`: TOTP enrolled, or enrolled again (a new
  /// secret and new recovery codes). An error handling it is logged,
  /// not returned: the response carries the recovery codes.
  TotpEnrolled,
  /// `UnenrollTotp`.
  TotpUnenrolled,
  /// `ConfirmPasskeyEnrollment`: a passkey enrolled, or replaced.
  PasskeyEnrolled,
  /// `UnenrollPasskey`.
  PasskeyUnenrolled,
  /// `UnlinkLocalLogin`: the password removed.
  LocalLoginUnlinked,
  /// `UnlinkExternalLogin`: the link to the login provider removed.
  ExternalLoginUnlinked { provider_id: String },
}

/// The second factor a login was completed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondFactor {
  Passkey,
  Totp,
  /// A TOTP recovery code.
  TotpRecovery,
}

/// This trait is implemented at the app level
/// to support custom schemas, storage providers, and business logic.
pub trait AuthImpl: Send + Sync + 'static {
  /// Construct the auth implementation for extraction.
  /// Only use this at the top level of a client request.
  fn new() -> Self
  where
    Self: Sized;

  /// Provide a static app name. Used for passkeys, as the TOTP issuer,
  /// and as the user agent for OIDC / Google provider discovery.
  fn app_name(&self) -> &'static str {
    panic!(
      "Must implement 'AuthImpl::app_name' in order for passkey / totp 2fa and OIDC / Google login to work."
    )
  }

  /// Provide the app 'host' config: the origin the app is reached at,
  /// eg. `https://example.com`, without the path the auth router is
  /// nested at ([Self::path]).
  ///
  /// It is also the host requests signed with a signing key are
  /// made for ([Self::signing_keys_enabled]): `example.com` here, or
  /// `example.com:8443` for `https://example.com:8443`
  /// ([middleware::check_signed_request_hosts] at startup tells
  /// whether one can be read from it).
  ///
  /// ⚠️ The default panics. External logins (their callback url and
  /// the redirect after them), signing keys and token exchange need
  /// it: an app using any of them implements it. The `/token`
  /// endpoint compares the `Origin` of a browser request without
  /// fetch metadata with it
  /// ([middleware::is_cross_site_browser_request]), so without it
  /// such a request panics its handler instead of being refused.
  fn host(&self) -> &str {
    panic!(
      "Must implement 'AuthImpl::host' in order for external logins, signing keys, token exchange and other features to work."
    )
  }

  /// More origins the app is reached at, in the form of [Self::host]
  /// (eg. `http://10.0.0.5:9120`, an address inside the network).
  /// None by default.
  ///
  /// Allows more hosts for requests signed with a signing key
  /// ([Self::signing_keys_enabled]): a signature is made for the
  /// host the client sends the request to, and is only accepted when
  /// that is [Self::host] or one of these. So every address clients
  /// sign requests for has to be here.
  ///
  /// The host is all that tells this server from another to a signed
  /// request: list origins which are this server's alone. Never the
  /// address of another server (a request signed for it would be
  /// accepted here too), and mind names several deployments share
  /// (one service name in two networks).
  ///
  /// The hosts are not secret: a request signed for another host is
  /// told so, which tells whoever asks whether a host is one of
  /// these.
  fn extra_hosts(&self) -> &[String] {
    &[]
  }

  /// This should be the path to where the auth server is nested on 'host'.
  /// Default is "/auth".
  fn path(&self) -> &str {
    "/auth"
  }

  /// Disable new user registration (all providers).
  fn registration_disabled(&self) -> bool {
    false
  }

  /// Disable new user registration for local (username/password) signups only.
  /// Defaults to [Self::registration_disabled].
  fn local_registration_disabled(&self) -> bool {
    self.registration_disabled()
  }

  /// Disable new user registration with the given external login provider.
  /// Defaults to [Self::registration_disabled], or the providers own
  /// `registration_disabled` setting.
  fn external_registration_disabled(
    &self,
    provider: &ExternalLoginProvider,
  ) -> bool {
    self.registration_disabled() || provider.registration_disabled
  }

  /// Validate the CIDR whitelist entries of an api key or signing
  /// key, once [validations::normalize_cidr_whitelist] trimmed them
  /// and dropped the empty and repeated ones. The whitelists an app
  /// normalizes with it itself (a user's) are validated with this
  /// too.
  fn validate_cidr_whitelist(
    &self,
    cidr_whitelist: &[String],
  ) -> mogh_error::Result<()> {
    validate_cidr_whitelist(cidr_whitelist)
      .status_code(StatusCode::BAD_REQUEST)
  }

  /// Provide usernames to lock credential updates for,
  /// such as demo users.
  fn locked_usernames(&self) -> &'static [String] {
    &[]
  }

  /// If the locked usernames includes '__ALL__',
  /// this will always error.
  fn check_username_locked(
    &self,
    username: &str,
  ) -> mogh_error::Result<()> {
    if self
      .locked_usernames()
      .iter()
      .any(|locked| locked == username || locked == "__ALL__")
    {
      Err(
        anyhow!("Login credentials are locked for this user")
          .status_code(StatusCode::UNAUTHORIZED),
      )
    } else {
      Ok(())
    }
  }

  /// Whether no user exists yet. While none does, a sign up (local,
  /// or through a login provider) is let through even when
  /// registration is disabled, so the first user can always sign up.
  /// If not implemented, this always evaluates to false and does not
  /// change any behavior.
  ///
  /// ⚠️ It is a pre-check, made before the user is stored: sign ups
  /// sent at the same time all see no user, and are all let through
  /// as the first user. The app has to decide "first user" again,
  /// atomically, when it stores the user (in the insert's
  /// transaction, or under a lock), and refuse a sign up which turns
  /// out not to be the first while the matching registration is
  /// disabled, see [Self::sign_up_local_user] and
  /// [Self::sign_up_external_user].
  fn no_users_exist(&self) -> DynFuture<mogh_error::Result<bool>> {
    Box::pin(async { Ok(false) })
  }

  /// Get's the user using the user id, returning UNAUTHORIZED if none exists.
  fn get_user(
    &self,
    user_id: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthUser>>;

  /// Handle incoming request authentication in middleware.
  /// Can attach a client struct as request extension here.
  ///
  /// `ip` is the client request ip, which must be checked against
  /// the api key's [AuthApiKeyImpl::cidr_whitelist][api_key::AuthApiKeyImpl::cidr_whitelist]
  /// and the user's [AuthUserImpl::cidr_whitelist][user::AuthUserImpl::cidr_whitelist].
  /// [Self::get_user_id_from_request_authentication] handles the api key
  /// whitelist, and [middleware::get_user_from_request_authentication]
  /// additionally handles the user whitelist. See also
  /// [middleware::check_api_key_cidr_whitelist] and
  /// [middleware::check_user_cidr_whitelist] for custom implementations.
  ///
  /// An error refuses the request and counts as a failed attempt
  /// against [Self::general_rate_limiter], unless it is marked with
  /// [uncounted][mogh_error::Error::uncounted] (server errors, 5xx, are
  /// never counted). Mark the refusals which are not guesses: a
  /// session the app ended (eg. after a log out everywhere), the
  /// token of a workload user which is out of sync with its rule. The
  /// credentials are authentic then, and every tab or device of the
  /// user still sending them (often behind one ip) would otherwise
  /// lock that ip out. An authentic token which only expired is
  /// refused uncounted already ([middleware::get_jwt_user_id]).
  ///
  /// [middleware::authenticate_request] attaches
  /// [middleware::AuthenticatedAt] to the request this returns (when
  /// the user logged in, for a session token), which the app's
  /// handlers take to require a recent login for some of its
  /// requests ([middleware::require_recent_login]).
  fn handle_request_authentication(
    &self,
    auth: RequestAuthentication,
    ip: IpAddr,
    require_user_enabled: bool,
    req: Request,
  ) -> DynFuture<mogh_error::Result<Request>>;

  /// Authenticates the request credentials and returns the user id.
  ///
  /// - [RequestAuthentication::Jwt]: validated with
  ///   [middleware::get_jwt_user_id].
  /// - [RequestAuthentication::ApiKey]: secret verified and mapped
  ///   with [Self::get_api_key].
  /// - [RequestAuthentication::PublicKey]: mapped with
  ///   [Self::get_signing_key].
  ///
  /// For api keys and signing keys, the request `ip` is checked
  /// against the key's
  /// [AuthApiKeyImpl::cidr_whitelist][api_key::AuthApiKeyImpl::cidr_whitelist].
  ///
  /// DANGER ⚠️ The user's own
  /// [AuthUserImpl::cidr_whitelist][user::AuthUserImpl::cidr_whitelist]
  /// is not checked here, as the user is not loaded.
  /// Use [middleware::get_user_from_request_authentication] or
  /// [middleware::check_user_cidr_whitelist] after loading the user.
  ///
  /// The auth management api authenticates its requests with this,
  /// and counts an error as a failed attempt against
  /// [Self::general_rate_limiter]: an app overriding it marks the
  /// refusals which are not guesses (an ended session, an out of
  /// sync workload user) with
  /// [uncounted][mogh_error::Error::uncounted], as for
  /// [Self::handle_request_authentication].
  ///
  /// The default is [middleware::get_jwt_user_id] for a jwt and
  /// [middleware::get_key_user_id] for the keys: an override which
  /// checks more of one kind (eg. the sessions the app ended, for a
  /// jwt) calls the other's helper.
  fn get_user_id_from_request_authentication(
    &self,
    auth: RequestAuthentication,
    ip: IpAddr,
  ) -> DynFuture<mogh_error::Result<String>> {
    match auth {
      RequestAuthentication::Jwt(jwt) => {
        let user_id = middleware::get_jwt_user_id(self, &jwt);
        Box::pin(async move { user_id })
      }
      auth => middleware::get_key_user_id(self, auth, ip),
    }
  }

  // =========
  // = STATE =
  // =========

  /// Get the jwt provider, which issues and verifies the app tokens.
  ///
  /// ⚠️ Build it from a random secret of at least
  /// [MIN_SECRET_BYTES][provider::jwt::MIN_SECRET_BYTES] (32) bytes,
  /// shared by all instances of the app, see [JwtProvider::try_new].
  /// Anyone who knows or guesses the secret can issue tokens for any
  /// user. With an empty secret no token is issued or accepted.
  ///
  /// Build it with [JwtProvider::try_new] at startup, and fail to
  /// start on its error: built lazily on the first request which
  /// needs it, a refused secret only shows up once the app serves,
  /// and [JwtProvider::new] only warns about a short one.
  fn jwt_provider(&self) -> &JwtProvider;

  /// Get the webauthn passkey provider
  fn passkey_provider(&self) -> Option<&PasskeyProvider> {
    None
  }

  /// The rate limiter for failed authentication by client ip.
  ///
  /// ⚠️ **The default is a DISABLED limiter: nothing is rate limited
  /// by ip unless the app implements this**, eg. with
  /// `RateLimiter::new(false, 10, Duration::from_secs(60))` kept in a
  /// static. A warning is logged once when the default is used. Only
  /// failed TOTP and recovery codes are capped per user all the same
  /// ([MAX_SECOND_FACTOR_FAILURES][api::login::totp::MAX_SECOND_FACTOR_FAILURES]).
  ///
  /// It counts the failures of:
  /// - credentials presented to [middleware::authenticate_request] and
  ///   the auth management API: invalid tokens, api keys and secrets
  ///   (each wrong secret of an existing key costs a bcrypt), and the
  ///   signatures of requests signed with a signing key (each costs
  ///   reading the body and verifying a signature);
  /// - the second factor of logins (TOTP codes, recovery codes,
  ///   passkeys), and local logins unless
  ///   [Self::local_login_rate_limiter] is implemented;
  /// - external logins, and token exchanges (`POST /token`,
  ///   `ExchangeExternalForJwt`).
  ///
  /// Requests without any credentials are not counted, nor are
  /// refusals which are not guesses: an authentic token which only
  /// expired, an `Authorization` header of another scheme than
  /// `Bearer`, server errors, and what the app marks
  /// [uncounted][mogh_error::Error::uncounted] (see
  /// [Self::handle_request_authentication]). Clients are
  /// counted by ip, IPv6 clients per /64 by default (see
  /// `RateLimiter::builder`). The login steps checking a secret which
  /// can be guessed (passwords, TOTP and recovery codes, passkeys)
  /// count strictly, a burst of concurrent attempts can't go past the
  /// limit either. Request authentication counts best effort:
  /// concurrent requests from one client are all checked before their
  /// failures count.
  ///
  /// Note that hosted CI runners share their ips between many
  /// customers, so with workload identity a strict limit lets one
  /// failing job (or somebody else on the same runners) get your other
  /// jobs limited. Keep it generous if workloads come from shared ips.
  fn general_rate_limiter(&self) -> &RateLimiter {
    static DISABLED_RATE_LIMITER: LazyLock<Arc<RateLimiter>> =
      LazyLock::new(|| {
        tracing::warn!(
          "AuthImpl::general_rate_limiter is not implemented: failed authentication (passwords, api keys, tokens) is not rate limited by client ip, 2fa codes are only capped per user"
        );
        RateLimiter::new(true, 0, Default::default())
      });
    &DISABLED_RATE_LIMITER
  }

  /// The rate limiter for failed token exchanges at `POST /token`
  /// (RFC 8693, workload identity included) and
  /// [exchange_token][api::token::exchange_token]. Defaults to
  /// [Self::general_rate_limiter], so a client failing exchanges
  /// uses up the same budget as its logins and api requests.
  ///
  /// Give it a limiter of its own (eg. the same settings in another
  /// static) to keep the two apart: hosted CI runners share their
  /// ips, and with the shared budget a job failing exchanges
  /// repeatedly gets the users and jobs behind that ip refused
  /// their logins and api requests as well.
  ///
  /// A request a web browser sent from a page of another site is
  /// refused before anything counts
  /// ([check_not_cross_site][api::token::check_not_cross_site]):
  /// any site could otherwise use up the budget of its visitors' ip.
  fn token_exchange_rate_limiter(&self) -> &RateLimiter {
    self.general_rate_limiter()
  }

  /// Requests of the auth management API which change how a user (or
  /// anyone, for the admin requests) can log in are only accepted with
  /// a token of a login at most this many seconds ago: passwords,
  /// usernames, 2fa, linked logins, new api keys and signing keys,
  /// login providers, trusted issuers. A token which leaked is then not enough to take
  /// over the account for good. `0` disables the check for sessions.
  /// Default: 15 minutes.
  ///
  /// - Older tokens get `403 Forbidden`, with a message starting with
  ///   [REAUTHENTICATION_REQUIRED][mogh_auth_client::api::manage::REAUTHENTICATION_REQUIRED].
  ///   The user has to log in again, which includes their second factor.
  /// - Api keys and signing keys have no login to be recent: they get
  ///   the same `403` for these requests whatever the window, `0`
  ///   included. Except the requests which manage resources rather
  ///   than the caller's account (login providers, trusted issuers,
  ///   whose handlers require an admin), which an admin's key may
  ///   make.
  /// - The time is the `iat` of a token of [Self::jwt_provider], with
  ///   the clock skew its validation tolerates. A token issued by token
  ///   exchange (`/token`, `ExchangeExternalForJwt` without a second
  ///   factor) carries when the provider authenticated the user instead:
  ///   the provider token's `auth_time`, else its `iat`. A provider token
  ///   can be exchanged again until it expires, so an old one must not
  ///   count as a fresh login. Exchange a freshly issued provider token
  ///   (or complete a second factor) for these requests.
  ///   A fresh token is not a fresh login though: identity providers
  ///   with single sign-on sessions issue new tokens silently, which
  ///   keep the original `auth_time`. ⚠️ Only when they carry it: a
  ///   token without `auth_time` (which OIDC only requires when it is
  ///   requested, eg. with `max_age`) counts from its `iat`, so a
  ///   silently issued or refreshed one counts as a fresh login. To get a recent login
  ///   through token exchange, the client must make the provider
  ///   authenticate the user again (eg. OIDC `prompt=login` or
  ///   `max_age=0` on the authorization request).
  /// - Other tokens which [Self::get_user_id_from_request_authentication]
  ///   accepts have no known login and count as api keys: they are
  ///   refused the account requests whatever the window, and may make
  ///   only the resource requests.
  /// - The app's own api can hold its requests which mint or widen
  ///   lasting access (users with admin rights, keys for other users,
  ///   a wider cidr whitelist) to the same window, for sessions:
  ///   [middleware::require_recent_login] with the request's
  ///   [middleware::AuthenticatedAt]. Api keys and signing keys pass
  ///   it, they are the automation credentials.
  /// - ⚠️ A browser login through an external provider (OIDC,
  ///   Google, GitHub: `/external/{slug}/login`) counts as a fresh
  ///   login at its callback, also when the provider answered from
  ///   its single sign-on session without asking the user for
  ///   anything. The server sends no `prompt=login` / `max_age` and
  ///   reads no `auth_time` of the ID token there: the login is when
  ///   the callback completed it. So for a provider user who logs in
  ///   without a second factor in the app (the default
  ///   [external_skip_2fa][user::AuthUserImpl::external_skip_2fa], or
  ///   none enrolled), the window is only as strong as the provider's
  ///   session: whoever can make their browser log in again (script
  ///   on the app's origin, a browser left unlocked) gets a recent
  ///   login without their credentials, and with it the requests the
  ///   window guards. A second factor in the app
  ///   (`external_skip_2fa` off, with one enrolled) is asked at every
  ///   such login, and closes it; so does a provider configured to
  ///   authenticate the user at every login (a short or no SSO
  ///   session for the app's client). Token exchange is different:
  ///   it counts from the provider token's `auth_time`, see above.
  fn reauthentication_window_secs(&self) -> u64 {
    15 * 60
  }

  /// Where the browser is sent when an external login fails, usually
  /// the login page of the app: `https://example.com/login`.
  ///
  /// External logins are browser navigations, not api calls. With the
  /// default (`None`) a failure (registration disabled, not in an allowed
  /// group, denied at the provider, ...) answers with the JSON error,
  /// which leaves the user on a blank page showing it. With this set
  /// they are redirected here instead, with the reason in the
  /// `login_error` query parameter for the login page to show (the
  /// `mogh_ui` login does). Failed links go to [Self::post_link_redirect]
  /// with `link_error`.
  ///
  /// Server errors are logged and only reported as such.
  fn external_login_error_redirect(&self) -> Option<&str> {
    None
  }

  /// Where to default redirect after linking an external login method.
  fn post_link_redirect(&self) -> &str {
    panic!(
      "Must implement 'AuthImpl::post_link_redirect' in order for linking to work. This is usually the application profile or settings page."
    )
  }

  /// Limits how many external logins (and links) each client ip can
  /// start, and how many login sessions each user can begin through
  /// the management api (`BeginExternalLoginLink`,
  /// `BeginPasskeyEnrollment`, `BeginTotpEnrollment`), see
  /// [login_start]. Starting a login needs no credentials and holds a
  /// login session until the provider's callback, so without it a
  /// flood of starts pushes the logins of other users (at the
  /// provider, or waiting for their second factor) out of a bounded
  /// session store.
  ///
  /// On by default: [LoginStartLimiter::default][login_start::LoginStartLimiter::default],
  /// 30 starts per client and 10 sessions per user at once, refilled
  /// over a minute. Keep one in a static to change them, eg.
  /// `LoginStartLimiter::new(limit, 10, window)`, or
  /// `LoginStartLimiter::disabled()`. Keep the client limit well below
  /// what the session store holds.
  fn login_start_limiter(&self) -> &login_start::LoginStartLimiter {
    static DEFAULT: LazyLock<login_start::LoginStartLimiter> =
      LazyLock::new(Default::default);
    &DEFAULT
  }

  /// A user logged in: they are authenticated, the hooks the login
  /// needed have run (`sign_up_local_user` / `sign_up_external_user`,
  /// `sync_external_user`, `get_or_create_workload_user`), and their
  /// session or token is issued right after. For the app's own audit
  /// trail; the server logs every login itself, so the default does
  /// nothing.
  ///
  /// Called once per login, at the step which grants it: a local
  /// sign up or login when the password is verified, or once its
  /// second factor is complete; an external sign up or login at the
  /// provider's callback (redeeming the jwt on the same session
  /// afterwards is not another login), or once its second factor is
  /// complete; a token exchange, a user's (`POST /token` or
  /// `ExchangeExternalForJwt`, the latter possibly after a second
  /// factor) or a workload's, when the token is issued. A callback
  /// login's jwt is issued when the app redeems it, up to 2 minutes
  /// after the record, or never when it isn't redeemed (see
  /// [Login::token_expires]).
  ///
  /// An error fails the login. By then a one-time credential may
  /// have been consumed (the TOTP step, a recovery code), so an app
  /// whose recording can fail should log and continue rather than
  /// refuse; and the rare failure after the hook (the session
  /// store, encoding the token) leaves a recorded login the user
  /// did not get.
  fn record_login(
    &self,
    _login: Login,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async { Ok(()) })
  }

  /// A user changed how they log in through the auth management api
  /// ([CredentialChange] says how), and the change is stored. Called
  /// once `UpdatePassword`, `ConfirmTotpEnrollment`, `UnenrollTotp`,
  /// `ConfirmPasskeyEnrollment`, `UnenrollPasskey`, `UnlinkLocalLogin`
  /// or `UnlinkExternalLogin` succeeded. Not by the logins, which
  /// store credentials too (a passkey login stores the passkey's new
  /// signature counter, [Self::update_user_passkey_counter]).
  ///
  /// This is where an app ends the user's other sessions. A user who
  /// changes the password, or enrolls a second factor, because a token
  /// of theirs leaked expects that token to stop working, not to keep
  /// using the app until it expires. `kept_jwt` is the session token
  /// of the request which made the change, which should stay valid:
  /// the user isn't logged out of the page showing their new recovery
  /// codes. These requests need a recent login, so there is one (api
  /// keys are refused them). Eg. store a cutoff time with the user,
  /// and refuse the tokens issued before it (their `iat`) in
  /// [Self::get_user_id_from_request_authentication], except the kept
  /// one (stored as a hash). Refuse them
  /// [uncounted][mogh_error::Error::uncounted]: they are no guesses.
  /// Tokens carry whole seconds, so a cutoff is a choice about the
  /// second of the change: the change's second keeps the tokens issued
  /// in it (a login right after the change works, one right before it
  /// survives too), the next second ends them (a login right after
  /// the change is refused until that second). Each token is unique
  /// (a random `jti`), so the kept one keeps no other login of its
  /// second.
  ///
  /// The default does nothing, sessions end when their tokens
  /// expire. An error fails the request, after the change was stored
  /// (the client sees it, and can make the change again). Except for
  /// `ConfirmTotpEnrollment`: its response carries the new recovery
  /// codes, shown only this once, and failing it would leave the user
  /// enrolled without them. Its error is logged (the user's other
  /// sessions may then still be valid), and the codes are returned.
  fn credentials_changed(
    &self,
    _user_id: String,
    _change: CredentialChange,
    _kept_jwt: Option<String>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async { Ok(()) })
  }

  // ==============
  // = LOCAL AUTH =
  // ==============

  /// Whether local auth is enabled.
  fn local_auth_enabled(&self) -> bool {
    true
  }

  /// Set the password hash bcrypt cost.
  fn local_auth_bcrypt_cost(&self) -> u32 {
    10
  }

  /// Local login method can have it's own rate limiter
  /// for 1 to 1 user feedback on remaining attempts.
  /// By default uses the general rate limiter, which is
  /// ⚠️ disabled unless the app implements
  /// [Self::general_rate_limiter]: then passwords can be guessed
  /// without limit.
  fn local_login_rate_limiter(&self) -> &RateLimiter {
    self.general_rate_limiter()
  }

  /// Validate usernames: of new users and renames, and of every
  /// local login (a name this refuses is answered `400`, whoever has
  /// it). For a rule which only new names follow, see
  /// [Self::validate_new_username].
  fn validate_username(
    &self,
    username: &str,
  ) -> mogh_error::Result<()> {
    validate_username(username).status_code(StatusCode::BAD_REQUEST)
  }

  /// Validate a username a user takes, after [Self::validate_username]:
  /// the name of a local sign up, the names an external sign up tries
  /// (those with a random suffix included), and the new name of
  /// `UpdateUsername`. Not at login: a user whose name this refuses
  /// (eg. one reserved after they took it) keeps logging in with it.
  /// The default accepts every name.
  ///
  /// For names the app keeps for itself (eg. Komodo's `System`,
  /// `Procedure` and `Action`, which its own operations act as), or a
  /// stricter rule for new names only. Refuse with `400` (eg.
  /// `Username is reserved`): a local sign up or rename gets the
  /// error, an external sign up moves on to its next name, and to a
  /// generated one (a refused generated name fails it, `500`). Apps
  /// which name users themselves (an admin creating a user) call it
  /// there too.
  fn validate_new_username(
    &self,
    _username: &str,
  ) -> mogh_error::Result<()> {
    Ok(())
  }

  /// Validate passwords.
  fn validate_password(
    &self,
    password: &str,
  ) -> mogh_error::Result<()> {
    validate_password(password).status_code(StatusCode::BAD_REQUEST)
  }

  /// Returns created user id, or error.
  /// The username and password have already been validated.
  ///
  /// `no_users_exist` is what [Self::no_users_exist] said before:
  /// `true` let the sign up through even if
  /// [Self::local_registration_disabled]. Sign ups sent at the same
  /// time can all get `true`, so decide whether this is the first user
  /// again as the user is stored, atomically (the same transaction, or
  /// a lock). One which isn't the first while local registration is
  /// disabled must be refused (eg. `403 User registration is
  /// disabled`), not created: nobody could register it. Never give a
  /// user the first user's privileges (eg. admin) on `no_users_exist`
  /// alone.
  fn sign_up_local_user(
    &self,
    _username: String,
    _hashed_password: String,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::sign_up_local_user' in order for local login to work."
        )
        .into(),
      )
    })
  }

  /// Finds user using the username, returning UNAUTHORIZED if none exists.
  fn find_user_with_username(
    &self,
    _username: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_user_with_username' in order for local login to work."
        )
        .into(),
      )
    })
  }

  fn update_user_username(
    &self,
    _user_id: String,
    _username: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::update_user_username'.")
          .into(),
      )
    })
  }

  fn update_user_password(
    &self,
    _user_id: String,
    _hashed_password: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::update_user_password'.")
          .into(),
      )
    })
  }

  // ==================
  // = EXTERNAL LOGIN =
  // ==================

  /// The external login providers from static app
  /// configuration (file / env). These are read only in the API,
  /// and take precedence over stored providers with the same id.
  ///
  /// A provider using the reserved id of its kind (`oidc`, `github`, `google`,
  /// see [ExternalLoginKind::reserved_id][mogh_auth_client::config::ExternalLoginKind::reserved_id])
  /// keeps the original callback path, eg. `/oidc/callback`, so
  /// redirect URIs already registered at the provider keep working.
  fn static_external_providers(&self) -> Vec<ExternalLoginProvider> {
    Vec::new()
  }

  /// List the external login providers stored by the app (eg. in the database).
  /// These are managed over the API by admins ([AuthUserImpl::is_admin][crate::user::AuthUserImpl::is_admin]).
  ///
  /// The provider configurations include the client secret,
  /// which should be encrypted at rest.
  ///
  /// Note. This is called by the unauthenticated `GetLoginOptions`,
  /// and [Self::get_external_provider] on every external login,
  /// so apps should serve them from a cache rather than hit the
  /// database every time. `mogh_cache::LoadCache` is made for this:
  /// concurrent misses share one load, writes invalidate it, and the
  /// value (client secrets included) is dropped at expiry.
  fn list_external_providers(
    &self,
  ) -> DynFuture<mogh_error::Result<Vec<ExternalLoginProvider>>> {
    Box::pin(async { Ok(Vec::new()) })
  }

  /// Get a stored external login provider by id.
  /// Defaults to searching [Self::list_external_providers].
  fn get_external_provider(
    &self,
    id: String,
  ) -> DynFuture<mogh_error::Result<Option<ExternalLoginProvider>>>
  {
    let providers = self.list_external_providers();
    Box::pin(async move {
      let provider = providers
        .await?
        .into_iter()
        .find(|provider| provider.id == id);
      Ok(provider)
    })
  }

  /// Store a new external login provider.
  /// The id is generated by the auth server, and must be stored as is.
  fn create_external_provider(
    &self,
    _provider: ExternalLoginProvider,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::create_external_provider'."
        )
        .into(),
      )
    })
  }

  /// Replace the stored external login provider with the same id.
  fn update_external_provider(
    &self,
    _provider: ExternalLoginProvider,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_external_provider'."
        )
        .into(),
      )
    })
  }

  /// Delete the stored external login provider.
  ///
  /// This should also remove the links to the provider from all users.
  /// Users who only have this login can then no longer log in.
  fn delete_external_provider(
    &self,
    _id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::delete_external_provider'."
        )
        .into(),
      )
    })
  }

  /// Find the user linked to the external user id **at this provider**.
  ///
  /// ⚠️ External user ids are only unique per provider. The lookup must
  /// match both `provider_id` and `external_id`, otherwise another
  /// provider can issue the same id and log in as the user.
  fn find_user_with_external_login(
    &self,
    _provider_id: String,
    _external_id: String,
  ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_user_with_external_login'."
        )
        .into(),
      )
    })
  }

  /// Returns created user id, or error.
  ///
  /// The user should be stored with `info.provider_id` and
  /// `info.external_id` so it can be found by
  /// [AuthImpl::find_user_with_external_login].
  /// `info.groups` / `info.admin` are available to create the
  /// user with the correct access, or to reject the signup.
  /// [AuthImpl::sync_external_user] is also called directly after signup.
  ///
  /// `no_users_exist` is what [Self::no_users_exist] said before:
  /// `true` let the sign up through even if
  /// [Self::external_registration_disabled] for the provider. As for
  /// [Self::sign_up_local_user], decide whether this is the first user
  /// again as the user is stored, atomically, and refuse one which
  /// isn't the first while registration is disabled for the
  /// provider.
  fn sign_up_external_user(
    &self,
    _username: String,
    _info: ExternalLoginInfo,
    _no_users_exist: bool,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::sign_up_external_user'.")
          .into(),
      )
    })
  }

  /// Called on every successful external authentication of a user:
  /// login, directly after signup, directly after linking,
  /// and token exchange (`POST /token`, RFC 8693).
  /// Use this to sync the users groups (`info.groups`) and
  /// admin status (`info.admin`) from the provider.
  /// Both are `None` when no information is available,
  /// in which case the user should be left as is.
  ///
  /// Runs before the session is authenticated,
  /// returning an error fails the login.
  ///
  /// Note. Changes at the provider only apply on the users next external login.
  fn sync_external_user(
    &self,
    _user_id: String,
    _info: ExternalLoginInfo,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async { Ok(()) })
  }

  /// Link `info.provider_id` / `info.external_id` to the existing user.
  fn link_external_login(
    &self,
    _user_id: String,
    _info: ExternalLoginInfo,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::link_external_login'.")
          .into(),
      )
    })
  }

  /// Remove the users link to the provider.
  fn unlink_external_login(
    &self,
    _user_id: String,
    _provider_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::unlink_external_login'.")
          .into(),
      )
    })
  }

  // =====================
  // = WORKLOAD IDENTITY =
  // =====================

  /// The token issuers trusted for workload identity from static app
  /// configuration (file / env). These are read only in the API,
  /// and take precedence over stored issuers with the same id.
  ///
  /// A change to them applies to new exchanges once the app returns
  /// it: the rules match tokens as configured, and a rule's groups /
  /// admin reach its user at its next exchange. Tokens already issued
  /// keep what the user had until then, and nothing disables or
  /// removes the users of rules which were disabled or removed. Call
  /// [sync_all_workload_users][provider::workload::sync_all_workload_users]
  /// when the app starts, which applies the configured rules to their
  /// users with [Self::sync_workload_users], and removes the users of
  /// issuers which are no longer configured with
  /// [Self::remove_workload_users_except].
  fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
    Vec::new()
  }

  /// List the trusted issuers stored by the app (eg. in the database).
  /// These are managed over the API by admins ([AuthUserImpl::is_admin][crate::user::AuthUserImpl::is_admin]).
  ///
  /// Note. This is called on every token exchange (`POST /token`),
  /// which is unauthenticated, so apps should serve
  /// them from a cache rather than hit the database every time.
  /// `mogh_cache::LoadCache` is made for this: concurrent misses share
  /// one load, writes invalidate it, and the value is dropped at
  /// expiry.
  fn list_trusted_issuers(
    &self,
  ) -> DynFuture<mogh_error::Result<Vec<TrustedIssuer>>> {
    Box::pin(async { Ok(Vec::new()) })
  }

  /// Store a new trusted issuer. The ids of the issuer and its
  /// rules are generated by the auth server, and must be stored as is.
  /// They are new, so its rules have no users yet.
  fn create_trusted_issuer(
    &self,
    _issuer: TrustedIssuer,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::create_trusted_issuer'.")
          .into(),
      )
    })
  }

  /// Replace the stored trusted issuer with the same id.
  ///
  /// Once it is stored, the server calls [Self::sync_workload_users]
  /// with its rules, which applies them to their users (and removes
  /// the users of the rules which were removed). Exchanges of the
  /// issuer's rules wait for both, within one instance of the app.
  /// Both run in a task of the server's own, which the request awaits:
  /// a request dropped in between (the admin's client gone) still
  /// completes the sync. The task runs in the request's
  /// [request_context], an app's own task-locals don't reach it.
  ///
  /// ⚠️ Narrowed `claims` of a rule only stop new exchanges, see
  /// [Self::sync_workload_users].
  fn update_trusted_issuer(
    &self,
    _issuer: TrustedIssuer,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::update_trusted_issuer'.")
          .into(),
      )
    })
  }

  /// Bring the users of the rules of the trusted issuer `issuer_id`
  /// ([Self::get_or_create_workload_user]) in line with the rules,
  /// right away rather than at their next exchange. Tokens carry the
  /// user id only, so this is what reaches the tokens already issued.
  ///
  /// `rules` has every rule of the issuer
  /// ([WorkloadAccess::of_issuer][provider::workload::WorkloadAccess::of_issuer]):
  /// - Remove the users of the issuer's rules which aren't in `rules`
  ///   (users of `issuer_id` with another rule id). Their tokens stop
  ///   working.
  /// - Apply each rule's `groups`, `admin` and `enabled` to its user,
  ///   if it has one. `enabled` is `false` while the rule or the
  ///   issuer is disabled: the tokens of the user are then refused on
  ///   their next request by the app's disabled user check
  ///   (`require_user_enabled` of [Self::handle_request_authentication]),
  ///   and it gets no new ones. Enabled again, the same user works
  ///   again.
  /// - Don't create users for rules which have none, their first
  ///   exchange does.
  ///
  /// ⚠️ `enabled` is the state of the rule, not a switch of the user:
  /// `true` re-enables a user which was disabled any other way (eg. by
  /// an admin), on every sync. The rule is the user's only way in, so
  /// disabling it does the same. Apps which keep a per user switch for
  /// workload users must either drop it (refuse it for them), or store
  /// the rule's `enabled` apart from it and report
  /// [AuthUserImpl::is_enabled][crate::user::AuthUserImpl::is_enabled]
  /// as both.
  ///
  /// ⚠️ Narrowing a rule's `claims` changes nothing here: app tokens
  /// carry no claims, so the ones issued to workloads the rule no
  /// longer matches keep acting as its user until they expire. To cut
  /// them off, disable or remove the rule (a new rule has a new user).
  ///
  /// Called after [Self::update_trusted_issuer] stored an update, and
  /// by [sync_all_workload_users][provider::workload::sync_all_workload_users]
  /// (eg. for the static issuers when the app starts). Exchanges of
  /// the issuer's rules wait for it within one instance of the app. An
  /// error fails the update after the issuer was stored (and audited,
  /// with a warning that its users weren't synced): saving it again
  /// syncs again.
  fn sync_workload_users(
    &self,
    _issuer_id: String,
    _rules: Vec<WorkloadAccess>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::sync_workload_users'.")
          .into(),
      )
    })
  }

  /// Remove the users of workload rules
  /// ([Self::get_or_create_workload_user]) which are gone: the users
  /// of trusted issuers whose id isn't in `live`, and the users of the
  /// issuers in `live` whose rule id isn't among its `rule_ids`. Their
  /// tokens then stop working.
  ///
  /// Called at the end of
  /// [sync_all_workload_users][provider::workload::sync_all_workload_users]
  /// with every trusted issuer as it is then, static and stored: this
  /// is how the users of an issuer removed from the app's configuration
  /// (or a static issuer skipped for its configuration) go away. The
  /// default removes nothing: implement it to prune them.
  ///
  /// While it runs, token exchanges wait before they get or create a
  /// workload user, and `live` is listed once they do: every user the
  /// app finds is one of `live`, or of an issuer or rule which is
  /// gone, never the user of an issuer or rule created after the
  /// listing (its first exchange creates it once this returned). That
  /// holds within one instance of the app: an app which creates
  /// workload users itself (outside the exchange), or runs several
  /// instances, should check its stored issuers again in the
  /// statement which removes the users (eg. `NOT EXISTS` against them
  /// in the `DELETE`), so the user of an issuer stored meanwhile
  /// stays. Exchanging a token from it would wait for it.
  fn remove_workload_users_except(
    &self,
    _live: Vec<provider::workload::LiveIssuer>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async { Ok(()) })
  }

  /// Delete the stored trusted issuer.
  /// This should also remove the users of its rules, whose tokens
  /// then stop working. Exchanges of its rules wait for it, within one
  /// instance of the app.
  fn delete_trusted_issuer(
    &self,
    _id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::delete_trusted_issuer'.")
          .into(),
      )
    })
  }

  /// Returns the id of the user a workload acts as, creating it if it
  /// doesn't exist yet. Called on every workload token exchange, after
  /// the token is verified and matched a rule.
  ///
  /// - There is one user per (`identity.issuer_id`, `identity.rule_id`).
  ///   Store both with the user to find it again.
  /// - `identity.groups` and `identity.admin` must be applied every time,
  ///   they are the full definition of what the user can do.
  ///   [Self::sync_workload_users] applies them as well when the rule
  ///   changes.
  /// - Create the user enabled ([AuthUserImpl::is_enabled][crate::user::AuthUserImpl::is_enabled]),
  ///   and never disable it here. This is only called for enabled rules
  ///   of enabled issuers, whose users [Self::sync_workload_users]
  ///   leaves enabled: it sets `enabled` along with the rule. The
  ///   exchange of a disabled user is refused.
  /// - The user must report [AuthUserImpl::is_workload][crate::user::AuthUserImpl::is_workload],
  ///   otherwise the exchange is refused. It stops the workload from
  ///   creating credentials which outlive its rule.
  /// - Never apply signup logic like making the first user an admin.
  /// - ⚠️ It is called concurrently for the same identity, eg. by a CI
  ///   matrix starting many jobs at once, and must be safe under it:
  ///   every call has to return the same user, and none may fail
  ///   because another created it first. Keep a unique key on
  ///   (`issuer_id`, `rule_id`) and create with an upsert, or an insert
  ///   which ignores the conflict (`ON CONFLICT DO NOTHING`), followed
  ///   by reading the user. A find, then insert creates duplicate users
  ///   without the key, and fails the exchange with it. Usernames made
  ///   for the user must not collide either (derive them from the rule
  ///   id, or retry). The calls of one rule are serialized within one
  ///   instance of the app, not across several.
  /// - Within one instance of the app, the calls wait for updates and
  ///   deletions of the issuer, and get the rule as it is once they
  ///   are done: an exchange which read the rule before never applies
  ///   the old groups / admin after the update was synced, nor creates
  ///   the user of a removed rule. They also wait while
  ///   [Self::remove_workload_users_except] runs, which therefore never
  ///   finds a user created after it was told the live issuers.
  ///   ⚠️ Apps running several instances
  ///   only get this if every instance sees the change right away
  ///   ([Self::list_trusted_issuers] caches), and should otherwise
  ///   apply the rule as it is stored when the user is written (eg.
  ///   read it in the same transaction).
  fn get_or_create_workload_user(
    &self,
    _identity: WorkloadIdentity,
  ) -> DynFuture<mogh_error::Result<String>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::get_or_create_workload_user'."
        )
        .into(),
      )
    })
  }

  /// Remove the users password, disabling local login.
  fn unlink_local_login(
    &self,
    _user_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::unlink_local_login'.")
          .into(),
      )
    })
  }

  // ===============
  // = PASSKEY 2FA =
  // ===============

  /// If Some(Passkey) is passed, it should be stored,
  /// overriding any passkey which was on the User
  /// (`ConfirmPasskeyEnrollment`).
  ///
  /// If None is passed, the user passkey should be removed,
  /// unenrolling the user from passkey 2fa (`UnenrollPasskey`).
  ///
  /// Only the management api calls it, followed by
  /// [Self::credentials_changed]. A passkey login stores the counter
  /// of the passkey with [Self::update_user_passkey_counter].
  fn update_user_stored_passkey(
    &self,
    _user_id: String,
    _passkey: Option<Passkey>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_user_stored_passkey'."
        )
        .into(),
      )
    })
  }

  /// Stores the passkey of the user after a login with it: the same
  /// passkey, with the signature counter (and backup state) the
  /// authenticator reported, which the next login checks. No change
  /// of how the user logs in, so no reason to end sessions (see
  /// [Self::credentials_changed]).
  ///
  /// Defaults to [Self::update_user_stored_passkey].
  fn update_user_passkey_counter(
    &self,
    user_id: String,
    passkey: Passkey,
  ) -> DynFuture<mogh_error::Result<()>> {
    self.update_user_stored_passkey(user_id, Some(passkey))
  }

  // ============
  // = TOTP 2FA =
  // ============

  fn update_user_stored_totp(
    &self,
    _user_id: String,
    _encoded_secret: String,
    _hashed_recovery_codes: Vec<String>,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_user_stored_totp'."
        )
        .into(),
      )
    })
  }

  fn remove_user_stored_totp(
    &self,
    _user_id: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::remove_user_stored_totp'."
        )
        .into(),
      )
    })
  }

  /// Returns whether the TOTP `step` is fresh for this user (not
  /// previously accepted), marking it as consumed if so. Ensures each
  /// TOTP code is only accepted once (RFC 6238 §5.2).
  ///
  /// The default implementation tracks accepted steps in process
  /// memory, which is best-effort protection scoped to a single
  /// instance. Implement with app-level storage to enforce this
  /// across multiple instances and restarts.
  fn consume_totp_step(
    &self,
    user_id: String,
    step: u64,
  ) -> DynFuture<mogh_error::Result<bool>> {
    Box::pin(async move {
      Ok(api::login::totp::consume_totp_step_in_process(
        &user_id, step,
      ))
    })
  }

  /// Remove a used TOTP recovery code for the user, identified by its
  /// bcrypt hash exactly as returned from
  /// [AuthUserImpl][user::AuthUserImpl]::hashed_totp_recovery_codes,
  /// so the code cannot be used again.
  ///
  /// ⚠️ Make the removal atomic and conditional in storage: remove
  /// the code only if it is still there, in one operation (eg. an
  /// update filtered on the code being present, or a transaction),
  /// and return an error, eg. `401 Unauthorized`, when it was not
  /// there anymore. The login is then refused. The server serializes
  /// the recovery code logins of a user within one process only, so
  /// with a read-modify-write (load the codes, write back the rest)
  /// two instances of a replicated app can both accept the same code,
  /// and a removal can write back a code another just removed.
  ///
  /// Must be implemented for
  /// [CompleteTotpRecoveryLogin][mogh_auth_client::api::login::CompleteTotpRecoveryLogin]
  /// to be usable.
  fn remove_totp_recovery_code(
    &self,
    _user_id: String,
    _hashed_code: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::remove_totp_recovery_code'."
        )
        .into(),
      )
    })
  }

  fn make_totp(
    &self,
    secret_bytes: Vec<u8>,
    account_name: Option<String>,
  ) -> anyhow::Result<totp_rs::Totp> {
    totp_rs::Builder::new()
      .with_issuer(Some(String::from(self.app_name())))
      .with_account_name(account_name.unwrap_or_default())
      .with_algorithm(totp_rs::Algorithm::SHA1)
      .with_digits(6)
      .with_skew(1)
      .with_step_duration(30)
      .with_secret(secret_bytes)
      .build()
      .context("Failed to construct TOTP")
  }

  // ============
  // = SKIP 2FA =
  // ============
  fn update_user_external_skip_2fa(
    &self,
    _user_id: String,
    _external_skip_2fa: bool,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::update_user_external_skip_2fa'."
        )
        .into(),
      )
    })
  }

  // ============
  // = API KEYS =
  // ============
  /// Validate the name of an api key or signing key.
  fn validate_api_key_name(
    &self,
    api_key_name: &str,
  ) -> mogh_error::Result<()> {
    validate_api_key_name(api_key_name)
      .status_code(StatusCode::BAD_REQUEST)
  }

  /// Set custom API key length. Default is 40.
  fn api_key_secret_length(&self) -> usize {
    40
  }

  /// Set the api secret hash bcrypt cost.
  fn api_secret_bcrypt_cost(&self) -> u32 {
    self.local_auth_bcrypt_cost()
  }

  fn create_api_key(
    &self,
    _user_id: String,
    _body: CreateApiKey,
    _key: String,
    _hashed_secret: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::create_api_key'.").into(),
      )
    })
  }

  /// Find the api key `key` (a request's X-API-KEY) in storage, `None`
  /// when no key has it. Find expired keys too: the server refuses
  /// them to requests ([Self::get_api_key]), and their owner deletes
  /// them ([Self::get_api_key_owner_id]).
  ///
  /// This is the storage of api keys the defaults of
  /// [Self::get_api_key] and [Self::get_api_key_owner_id] use: the
  /// server does what a request's key needs checked with it, the
  /// same for every app.
  fn find_api_key(
    &self,
    _key: String,
  ) -> DynFuture<mogh_error::Result<Option<api_key::StoredApiKey>>>
  {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_api_key' (or override 'AuthImpl::get_api_key' and 'AuthImpl::get_api_key_owner_id')."
        )
        .into(),
      )
    })
  }

  /// Get the api key ([AuthApiKeyImpl][api_key::AuthApiKeyImpl]) a
  /// request's X-API-KEY and X-API-SECRET authenticate, returning
  /// `401 Invalid client credentials` otherwise.
  ///
  /// The default finds the key with [Self::find_api_key] and
  /// authenticates it with [middleware::verify_api_key]: the secret
  /// is verified against the stored bcrypt hash, then an expired key
  /// is refused. A key which doesn't exist is refused right away,
  /// without a bcrypt: key ids are random, listed by UIs and logged at
  /// creation, so the timing telling that a key doesn't exist hides
  /// nothing, and a made up key costs a lookup, not a hash. bcrypt
  /// takes tens of milliseconds, for every request naming a real key:
  /// it runs on the blocking thread pool, at most one per available
  /// core at a time, on a budget of its own, so a flood of guesses at
  /// a key's secret stalls neither the async runtime nor password
  /// logins.
  ///
  /// Override it for checks of the app's own (eg. a key which can be
  /// disabled): find the key, authenticate it with
  /// [middleware::verify_api_key], then refuse what the app refuses
  /// with the same `401`. ⚠️ An override which doesn't use
  /// [middleware::verify_api_key] has to verify the secret and refuse
  /// expired keys itself: the server checks them nowhere else.
  ///
  /// The returned [cidr_whitelist][api_key::AuthApiKeyImpl::cidr_whitelist]
  /// is enforced by [Self::get_user_id_from_request_authentication].
  fn get_api_key(
    &self,
    key: String,
    secret: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
    let stored = self.find_api_key(key);
    Box::pin(async move {
      middleware::verify_stored_api_key(stored.await?, secret)
        .await
        .map(Into::into)
    })
  }

  /// Get the user id which owns the api key, without secret
  /// verification. Used to check ownership before deletion, so it
  /// finds keys [Self::get_api_key] refuses (expired ones):
  /// `404 Not Found` when there is none.
  ///
  /// The default finds the key with [Self::find_api_key].
  fn get_api_key_owner_id(
    &self,
    key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    let stored = self.find_api_key(key);
    Box::pin(async move {
      stored
        .await?
        .map(|stored| stored.user_id)
        .context("No api key found")
        .status_code(StatusCode::NOT_FOUND)
    })
  }

  fn delete_api_key(
    &self,
    _key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::delete_api_key'.").into(),
      )
    })
  }

  // ================
  // = SIGNING KEYS =
  // ================
  /// Whether requests signed with a signing key are accepted (see
  /// [mogh_auth_client::signature]). Off by default: signed requests
  /// are then refused, before their body is read, and so is
  /// `CreateSigningKey` (`400`, the signing key storage hooks are
  /// never reached). `DeleteSigningKey` still removes the keys stored
  /// while they were on.
  ///
  /// A request is signed for the host of the server, and accepted
  /// when that is [Self::host] (which must be implemented to enable
  /// this: every signed request asks for it) or one of
  /// [Self::extra_hosts]. Check them when the app starts, with
  /// [middleware::check_signed_request_hosts]. The server verifies
  /// the signature with the public key of the signing key alone, it
  /// holds no key of its own for this.
  fn signing_keys_enabled(&self) -> bool {
    false
  }

  /// How far the `X-API-TIMESTAMP` of a signed request may be from
  /// the server time, in milliseconds. Default: 1 second.
  ///
  /// It is checked when the request headers arrive, before the body is
  /// read, so the time the body takes to upload doesn't count (behind
  /// a proxy which buffers request bodies the headers arrive with the
  /// body, and it does).
  ///
  /// The signature covers the host, method, path and query,
  /// timestamp, nonce and body of the request, so this bounds how
  /// long a captured request can be replayed for (the exact same
  /// request to the same server, it can't be changed): its headers
  /// have to arrive before the server time is past its timestamp
  /// plus the tolerance, which for a client whose clock runs ahead is
  /// up to twice the tolerance after it was first accepted, and its
  /// body within [Self::signed_request_body_timeout] of them. It is
  /// at the same time how much clock difference (plus the latency of
  /// the headers) clients can have before their requests are refused.
  /// Raise it for clients without synchronized clocks, always use TLS
  /// either way.
  ///
  /// The server doesn't remember the requests it has seen. An app
  /// which wants to refuse a replay can, in
  /// [Self::accept_signed_request].
  fn signing_key_timestamp_tolerance_ms(&self) -> u64 {
    1_000
  }

  /// Called once for every request signed with a signing key, when
  /// its signature verified and its signer authenticated, right
  /// before the request is handled: by
  /// [middleware::authenticate_request] (after
  /// [Self::handle_request_authentication]) and by the auth
  /// management api alike. An error refuses the request, and counts
  /// against [Self::general_rate_limiter]. The default accepts.
  ///
  /// This is where an app refuses a replay (here, not in
  /// [Self::handle_request_authentication], which the auth management
  /// api doesn't call: a check in both would refuse every request
  /// the second time it sees its signature). The `X-API-NONCE` makes
  /// every signature unique, and a signature has one accepted form,
  /// so one seen before is a replay.
  ///
  /// The body of a request has to arrive by its timestamp plus
  /// [Self::signing_key_timestamp_tolerance_ms] plus
  /// [Self::signed_request_body_timeout], and the request gets here
  /// a moment after that at the latest. So remember each signature
  /// ([AcceptedSignature::signature]) until some margin past that
  /// time, and refuse (`401`) one which was seen before, or which
  /// only gets here after the margin: it could be the copy of one
  /// forgotten already. The margin covers the moment it takes to
  /// authenticate the signer, and how far the clocks of the app's
  /// instances and of the store differ. Check and remember in one
  /// step (two copies arriving together), in a store all instances
  /// of the app share.
  fn accept_signed_request(
    &self,
    _accepted: AcceptedSignature,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async { Ok(()) })
  }

  /// How long the body of a request signed with a signing key may
  /// take to arrive once its headers have. Default: 30 seconds, which
  /// carries the default 2 MB ([Self::signed_request_body_limit]) over
  /// a link of ~70 KB/s. A body which takes longer is refused with
  /// `408 Request Timeout`.
  ///
  /// The `X-API-TIMESTAMP` is checked when the headers arrive
  /// ([Self::signing_key_timestamp_tolerance_ms]) and the body is read
  /// after, so this is what keeps a request from being accepted long
  /// after it was signed: its headers sent in time, its body held
  /// back. Raise it along with the limit for larger bodies, and mind
  /// that it adds to how long an app has to remember the signatures
  /// it has seen.
  fn signed_request_body_timeout(&self) -> Duration {
    Duration::from_secs(30)
  }

  /// The largest body, in bytes, a request signed with a signing key
  /// may carry. Default: 2 MB (axum's default body limit).
  ///
  /// The signature covers the body, so it is read into memory before
  /// the request is authenticated
  /// ([middleware::read_signed_request_body]), also when the signature
  /// then turns out to be invalid: anybody can send a current
  /// X-API-TIMESTAMP. It is read up to this and, like axum's body
  /// extractors, up to the `axum::extract::DefaultBodyLimit` of the
  /// router applied outside of the middleware (axum's 2 MB default
  /// when there is none), whichever is smaller. A larger signed body
  /// is refused with `413 Payload Too Large`.
  ///
  /// So raising (or disabling) the router's limit, eg. for an upload
  /// route, doesn't let unauthenticated signed requests buffer more.
  /// To accept signed bodies over 2 MB, raise both this and the
  /// router's `DefaultBodyLimit` (a layer outside of the middleware):
  /// raising only this still refuses them at axum's 2 MB default.
  /// Other requests aren't affected: their body isn't read before they
  /// are authenticated.
  fn signed_request_body_limit(&self) -> usize {
    2 * 1024 * 1024
  }

  /// Store a new signing key of the user: a key pair whose private
  /// key signs the requests, recognized by its public key (base64
  /// spki der, as requests are matched with). `body` has the name,
  /// expiry and cidr whitelist, as for an api key.
  ///
  /// ⚠️ Public keys are not secret, and one given to `CreateSigningKey`
  /// is chosen by the caller. Store them unique across all users (eg.
  /// a unique index), and fail if the key exists: the server refuses
  /// a public key [Self::get_signing_key_owner_id] finds with
  /// `409 Conflict` first, but that can race another request. A key
  /// stored twice lets requests signed by one owner authenticate as
  /// the other, and [Self::get_signing_key], [Self::get_signing_key_owner_id]
  /// and [Self::delete_signing_key] must each match exactly one key.
  fn create_signing_key(
    &self,
    _user_id: String,
    _body: CreateApiKey,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::create_signing_key'.")
          .into(),
      )
    })
  }

  /// Find the signing key with `public_key` (a request's
  /// X-API-PUBLIC-KEY, base64 spki der, the form it is stored in) in
  /// storage, `None` when no key has it. Find expired keys too: the
  /// server refuses them to requests ([Self::get_signing_key]), and
  /// their owner deletes them.
  ///
  /// This is the storage of signing keys the default of
  /// [Self::get_signing_key] uses.
  fn find_signing_key(
    &self,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<Option<api_key::StoredSigningKey>>>
  {
    Box::pin(async {
      Err(
        anyhow!(
          "Must implement 'AuthImpl::find_signing_key' (or override 'AuthImpl::get_signing_key')."
        )
        .into(),
      )
    })
  }

  /// Get the signing key ([AuthApiKeyImpl][api_key::AuthApiKeyImpl],
  /// as for an api key) of a request whose signature verified with
  /// its public key, returning `401 Invalid client credentials` if
  /// there is none, or it expired.
  ///
  /// The default finds the key with [Self::find_signing_key] and
  /// authenticates it with [middleware::verify_signing_key]. ⚠️ An
  /// override which doesn't use it has to refuse expired keys itself:
  /// the server checks them nowhere else.
  ///
  /// The returned [cidr_whitelist][api_key::AuthApiKeyImpl::cidr_whitelist]
  /// is enforced by [Self::get_user_id_from_request_authentication].
  fn get_signing_key(
    &self,
    public_key: String,
  ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
    let stored = self.find_signing_key(public_key);
    Box::pin(async move {
      middleware::verify_signing_key(stored.await?).map(Into::into)
    })
  }

  /// Get the user id which owns the signing key, without it having to
  /// be usable: find expired keys too, they must stay deletable.
  /// `404 Not Found` when no key has the public key, which is what
  /// `CreateSigningKey` checks for before storing one (any other error
  /// fails the create). Used to check ownership before deletion, and
  /// that a public key isn't stored already.
  ///
  /// The default finds the key with [Self::find_signing_key]. ⚠️ An
  /// override must not go through [Self::get_signing_key], which
  /// refuses expired keys (`401`): those could never be deleted, and a
  /// client takes the 401 for its own session ending.
  fn get_signing_key_owner_id(
    &self,
    public_key: String,
  ) -> DynFuture<mogh_error::Result<String>> {
    let stored = self.find_signing_key(public_key);
    Box::pin(async move {
      stored
        .await?
        .map(|stored| stored.user_id)
        .context("No signing key found")
        .status_code(StatusCode::NOT_FOUND)
    })
  }

  fn delete_signing_key(
    &self,
    _public_key: String,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async {
      Err(
        anyhow!("Must implement 'AuthImpl::delete_signing_key'.")
          .into(),
      )
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use crate::api_key::AuthApiKey;

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3));

  struct TestAuth {
    jwt_provider: JwtProvider,
    /// Simulates the stored bcrypt hash for any api key.
    /// None simulates an unknown api key.
    hashed_secret: Option<String>,
    /// Simulates the stored cidr whitelist for any api key.
    cidr_whitelist: Vec<String>,
  }

  impl TestAuth {
    fn with_hashed_secret(hashed_secret: Option<String>) -> Self {
      Self {
        jwt_provider: JwtProvider::new(b"secret", 60_000),
        hashed_secret,
        cidr_whitelist: Vec::new(),
      }
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::with_hashed_secret(None)
    }
    fn get_user(
      &self,
      _user_id: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async { Err(anyhow!("unimplemented").into()) })
    }
    fn handle_request_authentication(
      &self,
      _auth: RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      Box::pin(async { Ok(req) })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      &self.jwt_provider
    }
    // Low cost to keep the unknown-key dummy hash fast.
    fn api_secret_bcrypt_cost(&self) -> u32 {
      4
    }
    /// The intended implementation shape: one lookup for the key,
    /// then verify the secret with the helper, off the async runtime.
    fn get_api_key(
      &self,
      key: String,
      secret: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
      let hashed_secret = self.hashed_secret.clone();
      let cidr_whitelist = self.cidr_whitelist.clone();
      Box::pin(async move {
        middleware::verify_api_key_secret_async(
          &TestAuth::new(),
          secret,
          hashed_secret,
        )
        .await?;
        Ok(
          AuthApiKey {
            user_id: format!("user-of-{key}"),
            cidr_whitelist,
          }
          .into(),
        )
      })
    }
    fn get_signing_key(
      &self,
      public_key: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
      let cidr_whitelist = self.cidr_whitelist.clone();
      Box::pin(async move {
        Ok(
          AuthApiKey {
            user_id: format!("user-of-{public_key}"),
            cidr_whitelist,
          }
          .into(),
        )
      })
    }
  }

  #[tokio::test]
  async fn test_get_user_id_from_jwt() {
    let auth = TestAuth::new();
    let jwt = auth.jwt_provider().encode_sub("user-1").unwrap().jwt;
    let user_id = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::Jwt(jwt),
        IP,
      )
      .await
      .unwrap();
    assert_eq!(user_id, "user-1");
  }

  #[tokio::test]
  async fn test_get_user_id_from_jwt_rejects_forged() {
    let auth = TestAuth::new();
    let forged = JwtProvider::new(b"other", 60_000)
      .encode_sub("user-1")
      .unwrap()
      .jwt;
    let err = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::Jwt(forged),
        IP,
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_get_user_id_from_api_key_verifies_secret() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let auth = TestAuth::with_hashed_secret(Some(hashed));
    let user_id = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::ApiKey {
          key: "K_abc_K".into(),
          secret: "S_def_S".into(),
        },
        IP,
      )
      .await
      .unwrap();
    assert_eq!(user_id, "user-of-K_abc_K");

    let err = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::ApiKey {
          key: "K_abc_K".into(),
          secret: "S_wrong_S".into(),
        },
        IP,
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_get_user_id_from_api_key_enforces_cidr_whitelist() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let mut auth = TestAuth::with_hashed_secret(Some(hashed));
    auth.cidr_whitelist = vec!["10.0.0.0/8".into()];
    let api_key = || RequestAuthentication::ApiKey {
      key: "K_abc_K".into(),
      secret: "S_def_S".into(),
    };

    // In whitelist
    let user_id = auth
      .get_user_id_from_request_authentication(api_key(), IP)
      .await
      .unwrap();
    assert_eq!(user_id, "user-of-K_abc_K");

    // Not in whitelist
    let err = auth
      .get_user_id_from_request_authentication(
        api_key(),
        "8.8.8.8".parse().unwrap(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);

    // Wrong secret is still UNAUTHORIZED, checked before whitelist
    let err = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::ApiKey {
          key: "K_abc_K".into(),
          secret: "S_wrong_S".into(),
        },
        "8.8.8.8".parse().unwrap(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_get_user_id_from_signing_key_enforces_cidr_whitelist()
  {
    let mut auth = TestAuth::new();
    auth.cidr_whitelist = vec!["10.1.2.3".into()];
    let public_key =
      || RequestAuthentication::PublicKey("PUBKEY".into());

    let user_id = auth
      .get_user_id_from_request_authentication(public_key(), IP)
      .await
      .unwrap();
    assert_eq!(user_id, "user-of-PUBKEY");

    let err = auth
      .get_user_id_from_request_authentication(
        public_key(),
        "10.1.2.4".parse().unwrap(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
  }

  /// An app which checks more of a jwt (it ended every session)
  /// and leaves the keys to [middleware::get_key_user_id].
  struct EndedSessionsAuth(TestAuth);

  impl AuthImpl for EndedSessionsAuth {
    fn new() -> Self {
      EndedSessionsAuth(TestAuth::new())
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthUser>> {
      self.0.get_user(user_id)
    }
    fn handle_request_authentication(
      &self,
      auth: RequestAuthentication,
      ip: IpAddr,
      require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      self.0.handle_request_authentication(
        auth,
        ip,
        require_user_enabled,
        req,
      )
    }
    fn jwt_provider(&self) -> &JwtProvider {
      self.0.jwt_provider()
    }
    fn get_api_key(
      &self,
      key: String,
      secret: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
      self.0.get_api_key(key, secret)
    }
    fn get_signing_key(
      &self,
      public_key: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthApiKey>> {
      self.0.get_signing_key(public_key)
    }
    fn get_user_id_from_request_authentication(
      &self,
      auth: RequestAuthentication,
      ip: IpAddr,
    ) -> DynFuture<mogh_error::Result<String>> {
      match auth {
        RequestAuthentication::Jwt(_) => Box::pin(async {
          Err(
            anyhow!("The session has ended")
              .status_code(StatusCode::UNAUTHORIZED)
              .uncounted(),
          )
        }),
        auth => middleware::get_key_user_id(self, auth, ip),
      }
    }
  }

  /// The keys of an override are authenticated as the default does
  /// it: the secret verified, the key's whitelist enforced.
  #[tokio::test]
  async fn test_an_override_leaves_the_keys_to_get_key_user_id() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let mut inner = TestAuth::with_hashed_secret(Some(hashed));
    inner.cidr_whitelist = vec!["10.0.0.0/8".into()];
    let auth = EndedSessionsAuth(inner);
    let outside: IpAddr = "8.8.8.8".parse().unwrap();
    let api_key = |secret: &str| RequestAuthentication::ApiKey {
      key: "K_abc_K".into(),
      secret: secret.into(),
    };
    let public_key =
      || RequestAuthentication::PublicKey("PUBKEY".into());

    // The override's own jwt branch.
    let jwt = auth.jwt_provider().encode_sub("user-1").unwrap().jwt;
    let err = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::Jwt(jwt.clone()),
        IP,
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(err.is_uncounted());

    // The keys, as the default authenticates them.
    for (req_auth, user_id) in [
      (api_key("S_def_S"), "user-of-K_abc_K"),
      (public_key(), "user-of-PUBKEY"),
    ] {
      assert_eq!(
        auth
          .get_user_id_from_request_authentication(
            req_auth.clone(),
            IP
          )
          .await
          .unwrap(),
        user_id
      );
      let err = auth
        .get_user_id_from_request_authentication(req_auth, outside)
        .await
        .unwrap_err();
      assert_eq!(err.status, StatusCode::FORBIDDEN);
    }
    let err = auth
      .get_user_id_from_request_authentication(
        api_key("S_wrong_S"),
        IP,
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(!err.is_uncounted());

    // A jwt is the caller's branch: taking it here would skip the
    // session check.
    let err = middleware::get_key_user_id(
      &auth,
      RequestAuthentication::Jwt(jwt),
      IP,
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
  }

  /// Stores keys, and authenticates them with the defaults of
  /// [AuthImpl::get_api_key] / [AuthImpl::get_signing_key] /
  /// [AuthImpl::get_api_key_owner_id].
  struct StoredKeysAuth {
    jwt_provider: JwtProvider,
    api_keys: Vec<(String, api_key::StoredApiKey)>,
    signing_keys: Vec<(String, api_key::StoredSigningKey)>,
  }

  impl AuthImpl for StoredKeysAuth {
    fn new() -> Self {
      unimplemented!()
    }
    fn get_user(
      &self,
      _user_id: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async { Err(anyhow!("unimplemented").into()) })
    }
    fn handle_request_authentication(
      &self,
      _auth: RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      Box::pin(async { Ok(req) })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      &self.jwt_provider
    }
    fn api_secret_bcrypt_cost(&self) -> u32 {
      4
    }
    fn find_api_key(
      &self,
      key: String,
    ) -> DynFuture<mogh_error::Result<Option<api_key::StoredApiKey>>>
    {
      let found = if key == "K_broken_K" {
        Err(anyhow!("database is down").into())
      } else {
        Ok(
          self
            .api_keys
            .iter()
            .find(|(stored, _)| *stored == key)
            .map(|(_, stored)| stored.clone()),
        )
      };
      Box::pin(async move { found })
    }
    fn find_signing_key(
      &self,
      public_key: String,
    ) -> DynFuture<
      mogh_error::Result<Option<api_key::StoredSigningKey>>,
    > {
      let found = self
        .signing_keys
        .iter()
        .find(|(stored, _)| *stored == public_key)
        .map(|(_, stored)| stored.clone());
      Box::pin(async move { Ok(found) })
    }
  }

  fn now_ms() -> u64 {
    std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_millis() as u64
  }

  fn stored_keys_auth() -> StoredKeysAuth {
    let hashed_secret = bcrypt::hash("S_def_S", 4).unwrap();
    let api_key =
      |user_id: &str, expires: u64| api_key::StoredApiKey {
        user_id: user_id.to_string(),
        hashed_secret: hashed_secret.clone(),
        expires,
        cidr_whitelist: vec![String::from("10.0.0.0/8")],
      };
    let signing_key =
      |user_id: &str, expires: u64| api_key::StoredSigningKey {
        user_id: user_id.to_string(),
        expires,
        cidr_whitelist: vec![String::from("10.0.0.0/8")],
      };
    let later = now_ms() + 60_000;
    let earlier = now_ms() - 1;
    StoredKeysAuth {
      jwt_provider: JwtProvider::new(b"secret", 60_000),
      api_keys: vec![
        (String::from("K_never_K"), api_key("never", 0)),
        (String::from("K_later_K"), api_key("later", later)),
        (String::from("K_expired_K"), api_key("expired", earlier)),
      ],
      signing_keys: vec![
        (String::from("never"), signing_key("never", 0)),
        (String::from("later"), signing_key("later", later)),
        (String::from("expired"), signing_key("expired", earlier)),
      ],
    }
  }

  /// The default [AuthImpl::get_api_key]: the secret is verified with
  /// the stored hash, an expired key is refused even with the right
  /// secret, every refusal is the same 401, and a storage error is
  /// passed on.
  #[tokio::test]
  async fn test_default_get_api_key() {
    let auth = stored_keys_auth();
    let get = |key: &str, secret: &str| {
      auth.get_user_id_from_request_authentication(
        RequestAuthentication::ApiKey {
          key: key.into(),
          secret: secret.into(),
        },
        IP,
      )
    };
    for key in ["K_never_K", "K_later_K"] {
      let user_id = get(key, "S_def_S").await.unwrap();
      assert_eq!(format!("K_{user_id}_K"), key);
    }
    for (key, secret) in [
      ("K_never_K", "S_wrong_S"),
      ("K_expired_K", "S_def_S"),
      ("K_unknown_K", "S_def_S"),
    ] {
      let err = get(key, secret).await.unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{key}");
      assert_eq!(
        format!("{:#}", err.error),
        "Invalid client credentials",
        "{key}"
      );
    }
    let err = get("K_broken_K", "S_def_S").await.unwrap_err();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    // The key's whitelist is the one stored.
    let err = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::ApiKey {
          key: "K_never_K".into(),
          secret: "S_def_S".into(),
        },
        "8.8.8.8".parse().unwrap(),
      )
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
  }

  /// The owner of a key is found for an expired key too (it can be
  /// deleted), 404 for an unknown one.
  #[tokio::test]
  async fn test_default_get_api_key_owner_id() {
    let auth = stored_keys_auth();
    for key in ["K_never_K", "K_expired_K"] {
      let owner =
        auth.get_api_key_owner_id(key.into()).await.unwrap();
      assert_eq!(format!("K_{owner}_K"), key);
    }
    let err = auth
      .get_api_key_owner_id("K_unknown_K".into())
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
  }

  /// The default [AuthImpl::get_signing_key_owner_id] finds the owner
  /// of an expired key too (it can be deleted), 404 for an unknown
  /// one: never the 401 of [AuthImpl::get_signing_key].
  #[tokio::test]
  async fn test_default_get_signing_key_owner_id() {
    let auth = stored_keys_auth();
    for public_key in ["never", "expired"] {
      let owner = auth
        .get_signing_key_owner_id(public_key.into())
        .await
        .unwrap();
      assert_eq!(owner, public_key);
    }
    let err = auth
      .get_signing_key_owner_id("unknown".into())
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
  }

  /// The default [AuthImpl::get_signing_key]: an unknown or expired
  /// key is refused with 401.
  #[tokio::test]
  async fn test_default_get_signing_key() {
    let auth = stored_keys_auth();
    let get = |public_key: &str| {
      auth.get_user_id_from_request_authentication(
        RequestAuthentication::PublicKey(public_key.into()),
        IP,
      )
    };
    for public_key in ["never", "later"] {
      assert_eq!(get(public_key).await.unwrap(), public_key);
    }
    for public_key in ["expired", "unknown"] {
      let err = get(public_key).await.unwrap_err();
      assert_eq!(
        err.status,
        StatusCode::UNAUTHORIZED,
        "{public_key}"
      );
      assert_eq!(
        format!("{:#}", err.error),
        "Invalid client credentials"
      );
    }
  }

  #[tokio::test]
  async fn test_get_user_id_from_api_key_empty_whitelist_allows_all()
  {
    let auth = TestAuth::new();
    let user_id = auth
      .get_user_id_from_request_authentication(
        RequestAuthentication::PublicKey("PUBKEY".into()),
        "8.8.8.8".parse().unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(user_id, "user-of-PUBKEY");
  }
}
