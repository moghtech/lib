use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use axum::extract::FromRequestParts;
use mogh_error::{AddStatusCode, AddStatusCodeError as _};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use tower_sessions::{Expiry, cookie::time::OffsetDateTime};
use tracing::warn;
use webauthn_rs::prelude::{
  PasskeyAuthentication, PasskeyRegistration,
};

use crate::{LoginKind, provider::external::SessionExternalLogin};

#[derive(Clone)]
pub struct Session(pub tower_sessions::Session);

impl<S: Send + Sync> FromRequestParts<S> for Session {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    let session = parts
      .extensions
      .get::<tower_sessions::Session>()
      .cloned()
      .context("Request context missing Session extension")?;
    Ok(Session(session))
  }
}

impl Session {
  // =========
  // = LOGIN =
  // =========

  // Stored with when the login completed. The key is not the one of
  // the earlier format (the user id alone), which then reads as not
  // initiated.
  const AUTHENTICATED_USER: &str = "authenticated-user-at";

  /// How long an external login which completed at the provider's
  /// callback (without a second factor) can be exchanged for a JWT
  /// (`ExchangeForJwt`) for. The app redeems it as soon as the
  /// callback's redirect lands, an older one is refused and the
  /// user logs in again.
  ///
  /// Whoever holds the cookie can keep the session alive (starting
  /// another login saves it), so the completed login is not tied to
  /// the session's expiry: this bounds how long it outlives an
  /// unlink of the external login, or the provider being disabled.
  /// The JWT it is exchanged for counts as a login from the
  /// callback, not the exchange (see
  /// [CompletedLogin::authenticated_at]). An external login which
  /// continues with a second factor is not stored here: the second
  /// factor completes it, within
  /// [Self::MAX_SECOND_FACTOR_LOGIN_AGE], and its JWT counts from
  /// then.
  pub const MAX_COMPLETED_LOGIN_AGE: Duration =
    Duration::from_secs(2 * 60);

  pub fn id(&self) -> Option<tower_sessions::session::Id> {
    self.0.id()
  }

  /// Gives the session a new id, keeping its data, and deletes
  /// the record under the old one. Done on privilege elevation
  /// (a first factor passed) to prevent session fixation: a
  /// session id planted in the browser beforehand (eg a cookie set
  /// by a sibling subdomain) is worthless once the user logs in.
  async fn cycle_id(&self) -> mogh_error::Result<()> {
    self
      .0
      .cycle_id()
      .await
      .context("Failed to cycle session id")
      .map_err(Into::into)
  }

  /// Keeps the session for at least `max_age` from now: the step
  /// stored on it then has its whole `max_age` to complete. The
  /// session layer expires a session after its idle time otherwise
  /// (mogh_server's default is 3 minutes, Cicada's 1), counted from
  /// the last request which changed the session, and the steps of a
  /// login wait for the user (at the provider, for an authenticator
  /// app) without one.
  ///
  /// A session which lives longer already (a longer idle expiry) is
  /// left as it is. A pinned one stops being extended by its requests,
  /// so it ends `max_age` after its last step began: each step pins it
  /// again.
  fn keep_for(&self, max_age: Duration) {
    let until = OffsetDateTime::now_utc().saturating_add(
      tower_sessions::cookie::time::Duration::try_from(max_age)
        .unwrap_or(tower_sessions::cookie::time::Duration::MAX),
    );
    if self.0.expiry_date() < until {
      self.0.set_expiry(Some(Expiry::AtDateTime(until)));
    }
  }

  /// Takes the value under `key` off the session. Unlike
  /// [tower_sessions::Session::remove], a session without one is
  /// left unmodified: the session layer saves (which extends its
  /// expiry) every modified session, and a request with nothing in
  /// flight, which anyone holding the cookie can send, must not keep
  /// the session alive.
  async fn take<T: DeserializeOwned>(
    &self,
    key: &str,
  ) -> anyhow::Result<Option<T>> {
    let present = self
      .0
      .get_value(key)
      .await
      .context("Failed to load session")?
      .is_some();
    if !present {
      return Ok(None);
    }
    self
      .0
      .remove(key)
      .await
      .context("Internal session type error")
  }

  /// Stores the external login of the user, completed now at the
  /// provider's callback, to be exchanged for a JWT
  /// ([Self::retrieve_authenticated_user_id]). Cycles the session id
  /// first, like the first factor of a login which continues with a
  /// second factor.
  ///
  /// Now is the login's time, its token's `auth_time`: a recent login
  /// for [AuthImpl::reauthentication_window_secs][crate::AuthImpl::reauthentication_window_secs]
  /// whether or not the provider asked the user for anything (it may
  /// have answered from its single sign-on session, see there).
  pub async fn insert_authenticated_user_id(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<()> {
    self
      .insert_authenticated_user(user_id, unix_timestamp_secs())
      .await
  }

  /// [Self::insert_authenticated_user_id] completed at
  /// `authenticated_at` (unix seconds).
  pub(crate) async fn insert_authenticated_user(
    &self,
    user_id: &str,
    authenticated_at: u64,
  ) -> mogh_error::Result<()> {
    self.cycle_id().await?;
    self
      .0
      .insert(Self::AUTHENTICATED_USER, (user_id, authenticated_at))
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Takes the login completed on the session, it can only be
  /// exchanged for a JWT once. One older than
  /// [Self::MAX_COMPLETED_LOGIN_AGE] is refused (and taken all the
  /// same). Without one, the session is left unmodified (see
  /// [Self::take]).
  pub async fn retrieve_authenticated_user_id(
    &self,
  ) -> mogh_error::Result<CompletedLogin> {
    let (user_id, authenticated_at) = self
      .take::<(String, u64)>(Self::AUTHENTICATED_USER)
      .await?
      .context("Authentication steps must be completed before JWT can be retrieved")
      .status_code(StatusCode::UNAUTHORIZED)?;
    check_completed_login_age(
      authenticated_at,
      unix_timestamp_secs(),
    )?;
    Ok(CompletedLogin {
      user_id,
      authenticated_at,
    })
  }

  // Stored with when it began. The key is not the one of the earlier
  // format (the login alone), which then reads as not initiated.
  const EXTERNAL_LOGIN: &str = "external-login-begun";

  /// How long an external login or link in flight (redirected to the
  /// provider) can be completed at the provider's callback for. The
  /// user signs in at the provider in between (a password, maybe a
  /// second factor there): the session is kept for this long
  /// ([Self::keep_for]), and an older login is refused.
  pub const MAX_EXTERNAL_LOGIN_AGE: Duration =
    Duration::from_secs(10 * 60);

  /// Store the in flight external login or link.
  /// Only one can be in flight per session, starting
  /// another replaces the previous one.
  pub async fn insert_external_login(
    &self,
    login: &SessionExternalLogin,
  ) -> mogh_error::Result<()> {
    self
      .insert_external_login_begun_at(login, unix_timestamp_secs())
      .await
  }

  /// [Self::insert_external_login] begun at `begun_at` (unix
  /// seconds).
  pub(crate) async fn insert_external_login_begun_at(
    &self,
    login: &SessionExternalLogin,
    begun_at: u64,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::EXTERNAL_LOGIN, (login, begun_at))
      .await
      .context("Failed to serialize session data")?;
    self.keep_for(Self::MAX_EXTERNAL_LOGIN_AGE);
    Ok(())
  }

  /// Takes the in flight external login or link,
  /// it can only be completed once. One older than
  /// [Self::MAX_EXTERNAL_LOGIN_AGE] is refused (and taken all the
  /// same). Without one, the session is left unmodified (see
  /// [Self::take]): a callback anybody holding the cookie can send
  /// doesn't keep the session alive.
  pub async fn retrieve_external_login(
    &self,
  ) -> mogh_error::Result<SessionExternalLogin> {
    let (login, begun_at) = self
      .take::<(SessionExternalLogin, u64)>(Self::EXTERNAL_LOGIN)
      .await?
      .context(
        "External login has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)?;
    check_external_login_age(begun_at, unix_timestamp_secs())?;
    Ok(login)
  }

  // =============
  // = 2FA LOGIN =
  // =============

  /// How long the second factor (passkey, TOTP or recovery code) of
  /// a login can be completed for, from when its first factor (the
  /// password, or an external login) passed. An older one is refused,
  /// and the login starts over.
  ///
  /// The pending second factor is not tied to its first factor
  /// otherwise: this bounds how long it outlives a change of the
  /// password, or the unlink of the external login, it came from,
  /// however the session is kept alive.
  pub const MAX_SECOND_FACTOR_LOGIN_AGE: Duration =
    Duration::from_secs(10 * 60);

  // Stored with when the first factor passed. The key is not the
  // one of the earlier format (without it), which then reads as not
  // initiated.
  const PASSKEY_LOGIN: &str = "passkey-login-begun";

  /// Begins the passkey second factor of the user, whose first
  /// factor has passed. Cycles the session id first, so the
  /// pending login is only reachable with the cookie issued to the
  /// client which passed the first factor.
  pub async fn insert_passkey_login(
    &self,
    user_id: &str,
    state: &PasskeyAuthentication,
  ) -> mogh_error::Result<()> {
    self
      .insert_passkey_login_begun_at(
        user_id,
        state,
        unix_timestamp_secs(),
      )
      .await
  }

  /// [Self::insert_passkey_login] begun at `begun_at` (unix seconds).
  pub(crate) async fn insert_passkey_login_begun_at(
    &self,
    user_id: &str,
    state: &PasskeyAuthentication,
    begun_at: u64,
  ) -> mogh_error::Result<()> {
    self.cycle_id().await?;
    self
      .0
      .insert(Self::PASSKEY_LOGIN, (user_id, state, begun_at))
      .await
      .context("Failed to serialize session data")?;
    self.keep_for(Self::MAX_SECOND_FACTOR_LOGIN_AGE);
    Ok(())
  }

  /// Takes the passkey login in progress, and with it the kind of
  /// its first factor: the caller records the login on success,
  /// and a refused passkey ends the attempt (the login starts over).
  /// One older than [Self::MAX_SECOND_FACTOR_LOGIN_AGE] is refused
  /// (and taken all the same).
  pub async fn retrieve_passkey_login(
    &self,
  ) -> mogh_error::Result<(String, PasskeyAuthentication, LoginKind)>
  {
    let (user_id, state, begun_at) = self
      .take::<(String, PasskeyAuthentication, u64)>(
        Self::PASSKEY_LOGIN,
      )
      .await?
      .context(
        "Passkey login has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)?;
    let kind = self.take_login_kind().await;
    check_second_factor_login_age(begun_at, unix_timestamp_secs())?;
    Ok((user_id, state, kind))
  }

  const LOGIN_KIND: &str = "login-kind";

  /// Remembers how the first factor of a login was passed, for the
  /// record of the login once its second factor is complete
  /// ([crate::AuthImpl::record_login]). Every path which begins a
  /// second factor ([Self::insert_passkey_login],
  /// [Self::insert_totp_login_user_id]) sets it right after, and a
  /// finished or abandoned second factor clears it, so a stale
  /// value never labels the next login.
  pub async fn insert_login_kind(
    &self,
    kind: &LoginKind,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::LOGIN_KIND, kind)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Takes the login kind of the second factor in progress. A
  /// session without one (its first factor passed before the kind
  /// was remembered), or with one the server can't read (written
  /// by another version), counts as a local login: the kind is
  /// audit metadata, never a reason to refuse a completed login.
  pub async fn take_login_kind(&self) -> LoginKind {
    match self.0.remove::<LoginKind>(Self::LOGIN_KIND).await {
      Ok(Some(kind)) => kind,
      Ok(None) => LoginKind::Local,
      Err(e) => {
        warn!(
          "Unreadable login kind on the session, dropped | {e:?}"
        );
        let _ = self.0.remove_value(Self::LOGIN_KIND).await;
        LoginKind::Local
      }
    }
  }

  // Stored with when the first factor passed, see PASSKEY_LOGIN.
  const TOTP_LOGIN: &str = "totp-login-begun";
  const TOTP_LOGIN_ATTEMPTS: &str = "totp-login-attempts";

  /// How many codes (TOTP or recovery) can be tried for one
  /// first factor login, before it has to be started again.
  ///
  /// This spares the user from entering the password again after
  /// a mistyped code, it is not what bounds guessing: the count
  /// rides on the session record, which concurrent requests each
  /// load and write back whole, and a new first factor starts it
  /// over. The failed codes of a user are bounded by
  /// [MAX_SECOND_FACTOR_FAILURES][crate::api::login::totp::MAX_SECOND_FACTOR_FAILURES]
  /// whatever the session or client.
  pub const MAX_TOTP_LOGIN_ATTEMPTS: u32 = 5;

  /// Begins the TOTP second factor of the user, whose first factor
  /// has passed. Cycles the session id first, so the pending login
  /// is only reachable with the cookie issued to the client which
  /// passed the first factor.
  pub async fn insert_totp_login_user_id(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<()> {
    self.insert_totp_login(user_id, unix_timestamp_secs()).await
  }

  /// [Self::insert_totp_login_user_id] begun at `begun_at`
  /// (unix seconds).
  pub(crate) async fn insert_totp_login(
    &self,
    user_id: &str,
    begun_at: u64,
  ) -> mogh_error::Result<()> {
    self.cycle_id().await?;
    self
      .0
      .insert(Self::TOTP_LOGIN_ATTEMPTS, 0u32)
      .await
      .context("Failed to serialize session data")?;
    self
      .0
      .insert(Self::TOTP_LOGIN, (user_id, begun_at))
      .await
      .context("Failed to serialize session data")?;
    self.keep_for(Self::MAX_SECOND_FACTOR_LOGIN_AGE);
    Ok(())
  }

  /// Returns the user id which began totp login, and counts an attempt
  /// at the second factor. The login stays on the session, so a
  /// mistyped code can be tried again without logging in from the
  /// start, up to [Self::MAX_TOTP_LOGIN_ATTEMPTS] times, for up to
  /// [Self::MAX_SECOND_FACTOR_LOGIN_AGE]. Past either, the login is
  /// removed and refused. Finish it with [Self::complete_totp_login]
  /// once the code is accepted.
  pub async fn begin_totp_login_attempt(
    &self,
  ) -> mogh_error::Result<String> {
    let (user_id, begun_at) = self
      .0
      .get::<(String, u64)>(Self::TOTP_LOGIN)
      .await
      .context("Internal session type error")?
      .context("TOTP login has not been initiated for this session")
      .status_code(StatusCode::UNAUTHORIZED)?;
    if let Err(e) =
      check_second_factor_login_age(begun_at, unix_timestamp_secs())
    {
      self.complete_totp_login().await?;
      return Err(e);
    }
    let attempts = self
      .0
      .get::<u32>(Self::TOTP_LOGIN_ATTEMPTS)
      .await
      .context("Internal session type error")?
      .unwrap_or_default();
    if attempts >= Self::MAX_TOTP_LOGIN_ATTEMPTS {
      self.complete_totp_login().await?;
      return Err(
        anyhow::anyhow!("Too many invalid codes. Log in again.")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }
    self
      .0
      .insert(Self::TOTP_LOGIN_ATTEMPTS, attempts + 1)
      .await
      .context("Failed to serialize session data")?;
    Ok(user_id)
  }

  /// Removes the totp login from the session, it can only be
  /// completed once. Returns the kind of its first factor, for the
  /// record of the login (whoever gives up on it drops it).
  pub async fn complete_totp_login(
    &self,
  ) -> mogh_error::Result<LoginKind> {
    self
      .0
      .remove_value(Self::TOTP_LOGIN)
      .await
      .context("Internal session type error")?;
    self
      .0
      .remove_value(Self::TOTP_LOGIN_ATTEMPTS)
      .await
      .context("Internal session type error")?;
    Ok(self.take_login_kind().await)
  }

  // ==================
  // = 2FA ENROLLMENT =
  // ==================

  // The enrollment state is stored with the id of the user who
  // began it: the manage api authenticates the user by the
  // Authorization header, not the session cookie, so a client could
  // otherwise begin an enrollment as one user and confirm it as
  // another (a locked one, say) on the same cookie jar. The keys
  // are not those of the earlier format (the state alone), which
  // then reads as not initiated.

  /// How long the session is kept for an enrollment begun on it to be
  /// confirmed ([Self::keep_for]): scanning the QR code, maybe
  /// installing an authenticator app first. Confirming also needs a
  /// recent login ([AuthImpl::reauthentication_window_secs][crate::AuthImpl::reauthentication_window_secs]).
  pub const MAX_ENROLLMENT_AGE: Duration =
    Duration::from_secs(10 * 60);

  const PASSKEY_ENROLLMENT: &str = "passkey-enrollment-of-user";

  /// Stores the passkey registration `user_id` began, replacing
  /// any other in flight on the session.
  pub async fn insert_passkey_enrollment(
    &self,
    user_id: &str,
    state: &PasskeyRegistration,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::PASSKEY_ENROLLMENT, (user_id, state))
      .await
      .context(
        "Session: Failed to insert passkey enrollment state",
      )?;
    self.keep_for(Self::MAX_ENROLLMENT_AGE);
    Ok(())
  }

  /// Takes the passkey registration in flight, which only
  /// `user_id` can complete. It is taken either way, so a refused
  /// one has to be started again.
  pub async fn retrieve_passkey_enrollment(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<PasskeyRegistration> {
    let (began_by, state) = self
      .0
      .remove::<(String, PasskeyRegistration)>(
        Self::PASSKEY_ENROLLMENT,
      )
      .await
      .context("Internal session type error")?
      .context(
        "Passkey enrollment has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)?;
    check_enrollment_user("Passkey", &began_by, user_id)?;
    Ok(state)
  }

  const TOTP_ENROLLMENT: &str = "totp-enrollment-of-user";

  /// Stores the TOTP (with its secret) `user_id` began enrolling,
  /// replacing any other in flight on the session.
  pub async fn insert_totp_enrollment(
    &self,
    user_id: &str,
    totp: &totp_rs::Totp,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::TOTP_ENROLLMENT, (user_id, totp))
      .await
      .context("Failed to serialize session data")?;
    self.keep_for(Self::MAX_ENROLLMENT_AGE);
    Ok(())
  }

  /// Takes the TOTP enrollment in flight, which only `user_id`
  /// can complete. It is taken either way, so a refused one has to
  /// be started again.
  pub async fn retrieve_totp_enrollment(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<totp_rs::Totp> {
    let (began_by, totp) = self
      .0
      .remove::<(String, totp_rs::Totp)>(Self::TOTP_ENROLLMENT)
      .await
      .context("Internal session type error")?
      .context(
        "TOTP enrollment has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)?;
    check_enrollment_user("TOTP", &began_by, user_id)?;
    Ok(totp)
  }

  // ========
  // = LINK =
  // ========

  // Stored with the provider it was begun for, and when. The key is
  // not the one of the earlier formats (the user id alone, then with
  // when it was begun), which then read as not initiated.
  const EXTERNAL_LINK: &str = "external-link-to-provider";

  /// How long a link begun with
  /// [BeginExternalLoginLink][mogh_auth_client::api::manage::BeginExternalLoginLink]
  /// can be started (`/external/{slug}/link`) for. The request comes
  /// right after it from the same page, an older link is refused
  /// rather than left for whoever holds the session later.
  pub const MAX_EXTERNAL_LINK_AGE: Duration =
    Duration::from_secs(10 * 60);

  /// Stores the user id which began external login linking, the
  /// slug of the provider it is for, and when, replacing any other
  /// link begun on the session.
  ///
  /// Cycles the session id first, like the first factor of a login:
  /// the link is only reachable with the cookie issued in the
  /// response, not with a session id planted in the browser
  /// beforehand (whoever holds the session starts the link, and the
  /// login they complete at the provider is linked to the user).
  pub async fn insert_external_link_user_id(
    &self,
    user_id: &str,
    slug: &str,
  ) -> mogh_error::Result<()> {
    self
      .insert_external_link(user_id, slug, unix_timestamp_secs())
      .await
  }

  /// [Self::insert_external_link_user_id] begun at `begun_at`
  /// (unix seconds).
  pub(crate) async fn insert_external_link(
    &self,
    user_id: &str,
    slug: &str,
    begun_at: u64,
  ) -> mogh_error::Result<()> {
    self.cycle_id().await?;
    self
      .0
      .insert(Self::EXTERNAL_LINK, (user_id, slug, begun_at))
      .await
      .context("Failed to serialize session data")?;
    self.keep_for(Self::MAX_EXTERNAL_LINK_AGE);
    Ok(())
  }

  /// Takes the link begun on the session, it can only be started
  /// once. Check [ExternalLink::check_age] and
  /// [ExternalLink::check_slug] before using it: the link is taken
  /// either way, so an expired one, or one started at another
  /// provider, has to be begun again. Without one, the session is
  /// left unmodified (see [Self::take]).
  pub async fn retrieve_external_link(
    &self,
  ) -> mogh_error::Result<ExternalLink> {
    let (user_id, slug, begun_at) = self
      .take::<(String, String, u64)>(Self::EXTERNAL_LINK)
      .await?
      .context(
        "External link has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)?;
    Ok(ExternalLink {
      user_id,
      slug,
      begun_at,
    })
  }
}

/// A login completed on the session, see
/// [Session::retrieve_authenticated_user_id].
#[derive(Debug, PartialEq)]
pub struct CompletedLogin {
  /// The user who logged in.
  pub user_id: String,
  /// When the login completed (the provider's callback), unix
  /// seconds. The JWT it is exchanged for counts as a login from
  /// then ([JwtClaims::authenticated_at][crate::provider::jwt::JwtClaims::authenticated_at]),
  /// not from the exchange.
  pub authenticated_at: u64,
}

/// A link begun on the session, see [Session::retrieve_external_link].
pub struct ExternalLink {
  /// The user who began the link.
  pub user_id: String,
  /// The slug of the provider the link was begun for
  /// ([BeginExternalLoginLink::slug][mogh_auth_client::api::manage::BeginExternalLoginLink::slug]).
  pub slug: String,
  /// When the link was begun, unix seconds.
  pub begun_at: u64,
}

impl ExternalLink {
  /// Refuses the link once it is older than
  /// [Session::MAX_EXTERNAL_LINK_AGE].
  pub fn check_age(&self) -> mogh_error::Result<()> {
    check_external_link_age(self.begun_at, unix_timestamp_secs())
  }

  /// Refuses the link at another provider than the one it was begun
  /// for: `/link` is a plain GET, any page the user visits can make
  /// the browser send it, for any provider. Started at the provider
  /// of that page's choosing, the link would join the account to
  /// whatever login the browser has there (the page's own, say).
  pub fn check_slug(&self, slug: &str) -> mogh_error::Result<()> {
    if self.slug == slug {
      return Ok(());
    }
    Err(
      anyhow::anyhow!(
        "External link was begun for another login provider, begin linking again"
      )
      .status_code(StatusCode::UNAUTHORIZED),
    )
  }
}

/// Refuses a link `begun_at` more than [Session::MAX_EXTERNAL_LINK_AGE]
/// before `now` (unix seconds). One begun in the future (the clock of
/// the instance which began it runs ahead) is as good as new.
fn check_external_link_age(
  begun_at: u64,
  now: u64,
) -> mogh_error::Result<()> {
  if is_within(begun_at, now, Session::MAX_EXTERNAL_LINK_AGE) {
    return Ok(());
  }
  Err(
    anyhow::anyhow!("External link has expired, begin linking again")
      .status_code(StatusCode::UNAUTHORIZED),
  )
}

/// Refuses the callback of an external login `begun_at` more than
/// [Session::MAX_EXTERNAL_LOGIN_AGE] before `now` (unix seconds). One
/// begun in the future (the clock of the instance which began it runs
/// ahead) is as good as new.
fn check_external_login_age(
  begun_at: u64,
  now: u64,
) -> mogh_error::Result<()> {
  if is_within(begun_at, now, Session::MAX_EXTERNAL_LOGIN_AGE) {
    return Ok(());
  }
  Err(
    anyhow::anyhow!("External login has expired. Log in again.")
      .status_code(StatusCode::UNAUTHORIZED),
  )
}

/// Refuses the second factor of a login whose first factor passed
/// `begun_at`, more than [Session::MAX_SECOND_FACTOR_LOGIN_AGE] before
/// `now` (unix seconds). One begun in the future (the clock of the
/// instance which began it runs ahead) is as good as new.
fn check_second_factor_login_age(
  begun_at: u64,
  now: u64,
) -> mogh_error::Result<()> {
  check_login_age(begun_at, now, Session::MAX_SECOND_FACTOR_LOGIN_AGE)
}

/// Refuses the exchange of a login which completed
/// `authenticated_at`, more than [Session::MAX_COMPLETED_LOGIN_AGE]
/// before `now` (unix seconds). One completed in the future (the
/// clock of the instance which completed it runs ahead) is as good
/// as new.
fn check_completed_login_age(
  authenticated_at: u64,
  now: u64,
) -> mogh_error::Result<()> {
  check_login_age(
    authenticated_at,
    now,
    Session::MAX_COMPLETED_LOGIN_AGE,
  )
}

/// The refusal of a login step more than `max_age` after the
/// login `begun_at`. The message is the one clients recognize to
/// start the login over.
fn check_login_age(
  begun_at: u64,
  now: u64,
  max_age: Duration,
) -> mogh_error::Result<()> {
  if is_within(begun_at, now, max_age) {
    return Ok(());
  }
  Err(
    anyhow::anyhow!("Login has expired. Log in again.")
      .status_code(StatusCode::UNAUTHORIZED),
  )
}

/// Whether `begun_at` is at most `max_age` before `now`
/// (unix seconds), or after it.
fn is_within(begun_at: u64, now: u64, max_age: Duration) -> bool {
  now.saturating_sub(begun_at) <= max_age.as_secs()
}

fn unix_timestamp_secs() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs())
    .unwrap_or_default()
}

/// Refuses to complete an enrollment `began_by` another user than
/// the `user_id` confirming it.
fn check_enrollment_user(
  kind: &str,
  began_by: &str,
  user_id: &str,
) -> mogh_error::Result<()> {
  if began_by == user_id {
    return Ok(());
  }
  warn!(
    began_by,
    user_id,
    "Refused {kind} enrollment confirmed by another user than the one who began it"
  );
  Err(
    anyhow::anyhow!(
      "{kind} enrollment was not initiated by this user"
    )
    .status_code(StatusCode::UNAUTHORIZED),
  )
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use tower_sessions::{MemoryStore, SessionStore as _};

  use super::*;
  use crate::provider::passkey::{PasskeyProvider, test_passkey};

  fn session() -> Session {
    Session(tower_sessions::Session::new(
      None,
      Arc::new(tower_sessions::MemoryStore::default()),
      None,
    ))
  }

  /// A session saved to `store`, as a client which has
  /// its cookie holds it, and the id of the cookie.
  async fn saved_session(
    store: &Arc<MemoryStore>,
  ) -> (Session, tower_sessions::session::Id) {
    let session = Session(tower_sessions::Session::new(
      None,
      store.clone(),
      None,
    ));
    session.0.insert("marker", 1u32).await.unwrap();
    session.0.save().await.unwrap();
    let id = session.id().unwrap();
    (session, id)
  }

  /// Passing the first factor gives the session a new id, so a
  /// session id planted in the browser beforehand can't be used to
  /// send the second factor codes (session fixation).
  #[tokio::test]
  async fn test_first_factor_cycles_the_session_id() {
    let store = Arc::new(MemoryStore::default());
    let (session, planted) = saved_session(&store).await;
    session.insert_totp_login_user_id("user-1").await.unwrap();
    session.0.save().await.unwrap();
    let cycled = session.id().unwrap();
    assert_ne!(cycled, planted);
    // Nothing is left under the planted id...
    assert!(store.load(&planted).await.unwrap().is_none());
    let planted = Session(tower_sessions::Session::new(
      Some(planted),
      store.clone(),
      None,
    ));
    assert!(planted.begin_totp_login_attempt().await.is_err());
    // ...the login continues under the new one, with the data
    // the session had before.
    let session = Session(tower_sessions::Session::new(
      Some(cycled),
      store.clone(),
      None,
    ));
    assert_eq!(
      session.begin_totp_login_attempt().await.unwrap(),
      "user-1"
    );
    assert_eq!(
      session.0.get::<u32>("marker").await.unwrap(),
      Some(1)
    );

    // The passkey second factor as well
    let (session, planted) = saved_session(&store).await;
    let state = passkey_authentication();
    session
      .insert_passkey_login("user-1", &state)
      .await
      .unwrap();
    session.0.save().await.unwrap();
    assert_ne!(session.id().unwrap(), planted);
    assert!(store.load(&planted).await.unwrap().is_none());

    // And the external login ready to be exchanged for a jwt
    let (session, planted) = saved_session(&store).await;
    session
      .insert_authenticated_user_id("user-1")
      .await
      .unwrap();
    session.0.save().await.unwrap();
    assert_ne!(session.id().unwrap(), planted);
    assert!(store.load(&planted).await.unwrap().is_none());
  }

  /// Beginning a link (BeginExternalLoginLink) gives the session a
  /// new id as well: whoever holds a session id planted in the
  /// browser beforehand can't start the link, and link the login
  /// they complete at the provider to the user.
  #[tokio::test]
  async fn test_begin_link_cycles_the_session_id() {
    let store = Arc::new(MemoryStore::default());
    let (session, planted) = saved_session(&store).await;
    session
      .insert_external_link_user_id("user-1", "github")
      .await
      .unwrap();
    session.0.save().await.unwrap();
    let cycled = session.id().unwrap();
    assert_ne!(cycled, planted);
    // Nothing is left under the planted id...
    assert!(store.load(&planted).await.unwrap().is_none());
    let planted = Session(tower_sessions::Session::new(
      Some(planted),
      store.clone(),
      None,
    ));
    let err = planted.retrieve_external_link().await.err().unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // ...the link continues under the new one, with the data the
    // session had before.
    let session = Session(tower_sessions::Session::new(
      Some(cycled),
      store.clone(),
      None,
    ));
    assert_eq!(
      session.retrieve_external_link().await.unwrap().user_id,
      "user-1"
    );
    assert_eq!(
      session.0.get::<u32>("marker").await.unwrap(),
      Some(1)
    );
  }

  /// The steps anybody holding the cookie can request, with nothing
  /// in flight on the session, leave it unmodified: the session
  /// layer would save it and extend its expiry otherwise, keeping a
  /// pending second factor on it alive.
  #[tokio::test]
  async fn test_nothing_in_flight_leaves_the_session_unmodified() {
    let store = Arc::new(MemoryStore::default());
    let (session, _) = saved_session(&store).await;
    session.insert_totp_login_user_id("user-1").await.unwrap();
    session.0.save().await.unwrap();
    let id = session.id().unwrap();
    // As the next request loads it.
    let session =
      Session(tower_sessions::Session::new(Some(id), store, None));
    assert!(session.retrieve_external_login().await.is_err());
    assert!(session.retrieve_external_link().await.is_err());
    assert!(session.retrieve_authenticated_user_id().await.is_err());
    assert!(session.retrieve_passkey_login().await.is_err());
    assert!(!session.0.is_modified());
    // The pending second factor is still there.
    assert_eq!(
      session.begin_totp_login_attempt().await.unwrap(),
      "user-1"
    );
  }

  /// A second factor is refused once its first factor passed longer
  /// than [Session::MAX_SECOND_FACTOR_LOGIN_AGE] ago, and removed
  /// with the kind of its first factor: the login starts over.
  #[tokio::test]
  async fn test_second_factor_login_expires() {
    let max_age = Session::MAX_SECOND_FACTOR_LOGIN_AGE.as_secs();
    let expired = unix_timestamp_secs() - max_age - 60;
    let provider = LoginKind::Provider {
      provider_id: "oidc".into(),
      provider_name: "OIDC".into(),
    };

    let session = session();
    session.insert_totp_login("user-1", expired).await.unwrap();
    session.insert_login_kind(&provider).await.unwrap();
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("expired"));
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );
    assert_eq!(session.take_login_kind().await, LoginKind::Local);
    assert!(
      session
        .0
        .get_value(Session::TOTP_LOGIN_ATTEMPTS)
        .await
        .unwrap()
        .is_none()
    );
    // A recent one is fine.
    let recent = unix_timestamp_secs() - max_age + 60;
    session.insert_totp_login("user-1", recent).await.unwrap();
    assert_eq!(
      session.begin_totp_login_attempt().await.unwrap(),
      "user-1"
    );

    let session = self::session();
    let state = passkey_authentication();
    session
      .insert_passkey_login_begun_at("user-1", &state, expired)
      .await
      .unwrap();
    session.insert_login_kind(&provider).await.unwrap();
    let err = session.retrieve_passkey_login().await.err().unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("expired"));
    let err = session.retrieve_passkey_login().await.err().unwrap();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );
    assert_eq!(session.take_login_kind().await, LoginKind::Local);
    session
      .insert_passkey_login_begun_at("user-1", &state, recent)
      .await
      .unwrap();
    session.insert_login_kind(&provider).await.unwrap();
    let (user_id, _, kind) =
      session.retrieve_passkey_login().await.unwrap();
    assert_eq!(user_id, "user-1");
    assert_eq!(kind, provider);
  }

  /// A login completed at the provider's callback is exchanged for a
  /// JWT once, with when it completed. One completed longer than
  /// [Session::MAX_COMPLETED_LOGIN_AGE] ago is refused, and removed:
  /// however the session was kept alive, the user logs in again.
  #[tokio::test]
  async fn test_completed_login_expires() {
    let session = session();
    let before = unix_timestamp_secs();
    session
      .insert_authenticated_user_id("user-1")
      .await
      .unwrap();
    let login =
      session.retrieve_authenticated_user_id().await.unwrap();
    assert_eq!(login.user_id, "user-1");
    assert!(
      (before..=unix_timestamp_secs())
        .contains(&login.authenticated_at)
    );
    // Taken, it can only be exchanged once.
    let err =
      session.retrieve_authenticated_user_id().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let max_age = Session::MAX_COMPLETED_LOGIN_AGE.as_secs();
    let expired = unix_timestamp_secs() - max_age - 30;
    session
      .insert_authenticated_user("user-1", expired)
      .await
      .unwrap();
    let err =
      session.retrieve_authenticated_user_id().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("Login has expired"));
    // Removed all the same.
    let err =
      session.retrieve_authenticated_user_id().await.unwrap_err();
    assert!(format!("{:#}", err.error).contains("must be completed"));

    // A recent one keeps the time it completed.
    let recent = unix_timestamp_secs() - max_age + 30;
    session
      .insert_authenticated_user("user-1", recent)
      .await
      .unwrap();
    assert_eq!(
      session.retrieve_authenticated_user_id().await.unwrap(),
      CompletedLogin {
        user_id: "user-1".into(),
        authenticated_at: recent,
      }
    );
  }

  #[test]
  fn test_check_completed_login_age() {
    let max_age = Session::MAX_COMPLETED_LOGIN_AGE.as_secs();
    // Short: the app redeems it right after the callback.
    assert!(
      max_age <= Session::MAX_SECOND_FACTOR_LOGIN_AGE.as_secs()
    );
    let now = 1_000_000;
    for completed in [now, now - max_age, now + 30, u64::MAX] {
      check_completed_login_age(completed, now).unwrap();
    }
    for completed in [now - max_age - 1, 0] {
      let err =
        check_completed_login_age(completed, now).unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }

  /// A completed login stored by an earlier version (the user id
  /// alone, without when it completed) reads as not initiated,
  /// rather than being exchanged as a fresh login.
  #[tokio::test]
  async fn test_completed_login_of_earlier_format_is_not_initiated() {
    let session = session();
    session
      .0
      .insert("authenticated-user-id", "user-1")
      .await
      .unwrap();
    let err =
      session.retrieve_authenticated_user_id().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("must be completed"));
  }

  #[test]
  fn test_check_second_factor_login_age() {
    let max_age = Session::MAX_SECOND_FACTOR_LOGIN_AGE.as_secs();
    let now = 1_000_000;
    for begun_at in [now, now - max_age, now + 30, u64::MAX] {
      check_second_factor_login_age(begun_at, now).unwrap();
    }
    for begun_at in [now - max_age - 1, 0] {
      let err =
        check_second_factor_login_age(begun_at, now).unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }

  /// A pending second factor stored by an earlier version (without
  /// when it began) reads as not initiated, rather than a server
  /// error: the user logs in again.
  #[tokio::test]
  async fn test_second_factor_login_of_earlier_format_is_not_initiated()
   {
    let session = session();
    session.0.insert("totp-login", "user-1").await.unwrap();
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let state = passkey_authentication();
    session
      .0
      .insert("passkey-login", ("user-1", &state))
      .await
      .unwrap();
    let err = session.retrieve_passkey_login().await.err().unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// A passkey authentication state, for a made up passkey
  /// (never verified).
  fn passkey_authentication() -> PasskeyAuthentication {
    PasskeyProvider::new("https://example.com")
      .unwrap()
      .start_passkey_authentication(test_passkey(&[1; 16]))
      .unwrap()
      .1
  }

  /// A passkey registration state, for a made up user.
  fn passkey_registration() -> PasskeyRegistration {
    PasskeyProvider::new("https://example.com")
      .unwrap()
      .start_passkey_registration("user")
      .unwrap()
      .1
  }

  fn test_totp() -> totp_rs::Totp {
    totp_rs::Builder::new()
      .with_secret(vec![7; 20])
      .with_account_name("user-1")
      .build()
      .unwrap()
  }

  /// An enrollment is confirmed by the user who began it only: the
  /// manage api authenticates by the Authorization header, and a
  /// client could send another user's with the same cookie.
  #[tokio::test]
  async fn test_enrollment_is_bound_to_the_user() {
    let session = session();
    let totp = test_totp();

    session
      .insert_totp_enrollment("user-1", &totp)
      .await
      .unwrap();
    let err = session
      .retrieve_totp_enrollment("user-2")
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("not initiated by"));
    // Taken by the refusal, the enrollment has to be started again.
    let err = session
      .retrieve_totp_enrollment("user-1")
      .await
      .unwrap_err();
    assert!(
      format!("{:#}", err.error).contains("has not been initiated")
    );
    session
      .insert_totp_enrollment("user-1", &totp)
      .await
      .unwrap();
    let retrieved =
      session.retrieve_totp_enrollment("user-1").await.unwrap();
    assert_eq!(retrieved, totp);

    let provider =
      PasskeyProvider::new("https://example.com").unwrap();
    let (_, state) =
      provider.start_passkey_registration("user").unwrap();
    session
      .insert_passkey_enrollment("user-1", &state)
      .await
      .unwrap();
    let err = session
      .retrieve_passkey_enrollment("user-2")
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(
      session.retrieve_passkey_enrollment("user-1").await.is_err()
    );
    session
      .insert_passkey_enrollment("user-1", &state)
      .await
      .unwrap();
    session.retrieve_passkey_enrollment("user-1").await.unwrap();
  }

  /// An enrollment stored by an earlier version (the state alone)
  /// reads as not initiated, rather than a server error.
  #[tokio::test]
  async fn test_enrollment_of_earlier_format_is_not_initiated() {
    let session = session();
    let totp = test_totp();
    session.0.insert("totp-enrollment", &totp).await.unwrap();
    let err = session
      .retrieve_totp_enrollment("user-1")
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// The kind of a first factor rides on the session until the
  /// second factor ends: taken with it, once, and a local login
  /// without one.
  #[tokio::test]
  async fn test_login_kind_travels_with_the_second_factor() {
    let session = session();
    assert_eq!(session.take_login_kind().await, LoginKind::Local);
    let provider = LoginKind::Provider {
      provider_id: "oidc".into(),
      provider_name: "OIDC".into(),
    };
    session.insert_totp_login_user_id("user-1").await.unwrap();
    session.insert_login_kind(&provider).await.unwrap();
    assert_eq!(
      session.complete_totp_login().await.unwrap(),
      provider
    );
    // Gone with the completion
    assert_eq!(session.take_login_kind().await, LoginKind::Local);
    assert!(session.begin_totp_login_attempt().await.is_err());
    // A value the server can't read is dropped, not refused
    session.0.insert(Session::LOGIN_KIND, 42u32).await.unwrap();
    assert_eq!(session.take_login_kind().await, LoginKind::Local);
    assert_eq!(session.take_login_kind().await, LoginKind::Local);
  }

  #[tokio::test]
  async fn test_totp_login_requires_first_factor() {
    let session = session();
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn test_totp_login_can_be_retried_up_to_the_limit() {
    let session = session();
    session.insert_totp_login_user_id("user-1").await.unwrap();
    // A mistyped code doesn't end the login.
    for _ in 0..Session::MAX_TOTP_LOGIN_ATTEMPTS {
      assert_eq!(
        session.begin_totp_login_attempt().await.unwrap(),
        "user-1"
      );
    }
    // Out of attempts, and the login is gone.
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("Too many"));
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );
  }

  #[tokio::test]
  async fn test_totp_login_attempts_reset_by_new_first_factor() {
    let session = session();
    session.insert_totp_login_user_id("user-1").await.unwrap();
    for _ in 0..Session::MAX_TOTP_LOGIN_ATTEMPTS {
      session.begin_totp_login_attempt().await.unwrap();
    }
    session.insert_totp_login_user_id("user-1").await.unwrap();
    assert_eq!(
      session.begin_totp_login_attempt().await.unwrap(),
      "user-1"
    );
  }

  #[tokio::test]
  async fn test_external_link_expires() {
    let session = session();
    session
      .insert_external_link_user_id("user-1", "github")
      .await
      .unwrap();
    let link = session.retrieve_external_link().await.unwrap();
    assert_eq!(link.user_id, "user-1");
    link.check_age().unwrap();
    // Taken, it can only be started once.
    let err = session.retrieve_external_link().await.err().unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let max_age = Session::MAX_EXTERNAL_LINK_AGE.as_secs();
    let expired = unix_timestamp_secs() - max_age - 60;
    session
      .insert_external_link("user-1", "github", expired)
      .await
      .unwrap();
    let link = session.retrieve_external_link().await.unwrap();
    let err = link.check_age().unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("expired"));
    // Used up all the same.
    let err = session.retrieve_external_link().await.err().unwrap();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );
  }

  fn external_login() -> SessionExternalLogin {
    SessionExternalLogin {
      provider_id: String::from("oidc"),
      link_user_id: None,
      state: String::from("state"),
      nonce: None,
      pkce_verifier: None,
      redirect: None,
    }
  }

  /// An external login is completed at the callback within
  /// [Session::MAX_EXTERNAL_LOGIN_AGE], once.
  #[tokio::test]
  async fn test_external_login_expires() {
    let session = session();
    session
      .insert_external_login(&external_login())
      .await
      .unwrap();
    let login = session.retrieve_external_login().await.unwrap();
    assert_eq!(login.state, "state");
    // Taken, it can only be completed once.
    let err = session.retrieve_external_login().await.err().unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let max_age = Session::MAX_EXTERNAL_LOGIN_AGE.as_secs();
    let expired = unix_timestamp_secs() - max_age - 60;
    session
      .insert_external_login_begun_at(&external_login(), expired)
      .await
      .unwrap();
    let err = session.retrieve_external_login().await.err().unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("expired"));
    // Used up all the same.
    let err = session.retrieve_external_login().await.err().unwrap();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );

    // One stored by an earlier version (without when it began) reads
    // as not initiated.
    let session = self::session();
    session
      .0
      .insert("external-login", external_login())
      .await
      .unwrap();
    let err = session.retrieve_external_login().await.err().unwrap();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );
  }

  #[test]
  fn test_check_external_login_age() {
    let max_age = Session::MAX_EXTERNAL_LOGIN_AGE.as_secs();
    let now = 1_000_000;
    for begun_at in [now, now - max_age, now + 30, u64::MAX] {
      check_external_login_age(begun_at, now).unwrap();
    }
    for begun_at in [now - max_age - 1, 0] {
      let err = check_external_login_age(begun_at, now).unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }

  /// A session with the expiry the session layer gives it (idle
  /// for `idle`).
  fn session_idle_for(idle: Duration) -> Session {
    Session(tower_sessions::Session::new(
      None,
      Arc::new(tower_sessions::MemoryStore::default()),
      Some(Expiry::OnInactivity(idle.try_into().unwrap())),
    ))
  }

  /// Each step stored on the session keeps it for the step's max age,
  /// however short the session layer's idle expiry: the user has the
  /// whole step to complete it (at the provider, with an authenticator
  /// app). A session which lives longer already is left alone.
  #[tokio::test]
  async fn test_pending_steps_keep_the_session() {
    let state = passkey_authentication();
    let registration = passkey_registration();
    let totp = test_totp();
    for (step, max_age) in [
      ("totp login", Session::MAX_SECOND_FACTOR_LOGIN_AGE),
      ("passkey login", Session::MAX_SECOND_FACTOR_LOGIN_AGE),
      ("external login", Session::MAX_EXTERNAL_LOGIN_AGE),
      ("external link", Session::MAX_EXTERNAL_LINK_AGE),
      ("totp enrollment", Session::MAX_ENROLLMENT_AGE),
      ("passkey enrollment", Session::MAX_ENROLLMENT_AGE),
    ] {
      for idle in
        [Duration::from_secs(60), Duration::from_secs(86_400)]
      {
        let session = session_idle_for(idle);
        let before = OffsetDateTime::now_utc();
        match step {
          "totp login" => {
            session.insert_totp_login_user_id("user-1").await.unwrap()
          }
          "passkey login" => session
            .insert_passkey_login("user-1", &state)
            .await
            .unwrap(),
          "external login" => session
            .insert_external_login(&external_login())
            .await
            .unwrap(),
          "external link" => session
            .insert_external_link_user_id("user-1", "github")
            .await
            .unwrap(),
          "totp enrollment" => session
            .insert_totp_enrollment("user-1", &totp)
            .await
            .unwrap(),
          _ => session
            .insert_passkey_enrollment("user-1", &registration)
            .await
            .unwrap(),
        }
        if idle > max_age {
          // Unchanged: it lives longer.
          assert_eq!(
            session.0.expiry(),
            Some(Expiry::OnInactivity(idle.try_into().unwrap())),
            "{step}"
          );
        } else {
          let Some(Expiry::AtDateTime(until)) = session.0.expiry()
          else {
            panic!("{step}: {:?}", session.0.expiry());
          };
          // Whole seconds are enough here.
          let kept = (until - before).whole_seconds();
          let max_age = max_age.as_secs() as i64;
          assert!(
            (max_age..max_age + 5).contains(&kept),
            "{step}: {kept}"
          );
        }
      }
    }
  }

  #[test]
  fn test_check_external_link_age() {
    let max_age = Session::MAX_EXTERNAL_LINK_AGE.as_secs();
    let now = 1_000_000;
    for begun_at in [now, now - max_age, now + 30, u64::MAX] {
      check_external_link_age(begun_at, now).unwrap();
    }
    for begun_at in [now - max_age - 1, 0] {
      let err = check_external_link_age(begun_at, now).unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }

  /// A link stored by an earlier version (the user id alone, then
  /// with when it was begun but not for which provider) reads as not
  /// initiated, rather than a server error or a link for any
  /// provider.
  #[tokio::test]
  async fn test_external_link_of_earlier_format_is_not_initiated() {
    let session = session();
    session.0.insert("external-link", "user-1").await.unwrap();
    let err = session.retrieve_external_link().await.err().unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let session = self::session();
    session
      .0
      .insert(
        "external-link-begun",
        ("user-1", unix_timestamp_secs()),
      )
      .await
      .unwrap();
    let err = session.retrieve_external_link().await.err().unwrap();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );
  }

  /// A link is started at the provider it was begun for only.
  #[tokio::test]
  async fn test_external_link_is_bound_to_its_provider() {
    let session = session();
    session
      .insert_external_link_user_id("user-1", "github")
      .await
      .unwrap();
    let link = session.retrieve_external_link().await.unwrap();
    assert_eq!(link.slug, "github");
    link.check_slug("github").unwrap();
    for other in ["oidc", "github-2", "", "GITHUB"] {
      let err = link.check_slug(other).unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{other}");
      assert!(
        format!("{:#}", err.error).contains("another login provider")
      );
    }
  }

  #[tokio::test]
  async fn test_totp_login_completes_once() {
    let session = session();
    session.insert_totp_login_user_id("user-1").await.unwrap();
    session.begin_totp_login_attempt().await.unwrap();
    session.complete_totp_login().await.unwrap();
    // An accepted code ends the login, it can't be completed again.
    let err = session.begin_totp_login_attempt().await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }
}
