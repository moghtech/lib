use std::{
  collections::HashMap,
  sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError},
  time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use data_encoding::BASE32_NOPAD;
use mogh_auth_client::api::login::{
  CompleteTotpLogin, CompleteTotpRecoveryLogin, JwtResponse,
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;
use tracing::{info, instrument, warn};
use zeroize::Zeroizing;

use crate::{
  SecondFactor,
  api::login::{IssueToken, LoginArgs, issue_login},
  bcrypt_pool::spawn_bcrypt,
  middleware::check_user_cidr_whitelist,
};

/// Tracks the latest accepted TOTP step per user, to reject reuse
/// of an already accepted code within its valid window ([RFC 6238 §5.2]).
/// In-memory, so this is best-effort protection scoped to this process.
///
/// [RFC 6238 §5.2]: https://datatracker.ietf.org/doc/html/rfc6238#section-5.2
static ACCEPTED_TOTP_STEPS: LazyLock<Mutex<HashMap<String, u64>>> =
  LazyLock::new(Default::default);

/// Returns whether `step` is fresh for this user (strictly newer than
/// the last accepted step), marking it as used if so.
///
/// This is the default implementation of
/// [AuthImpl::consume_totp_step][crate::AuthImpl::consume_totp_step];
/// see that method to enforce this with app-level storage instead.
pub fn consume_totp_step_in_process(
  user_id: &str,
  step: u64,
) -> bool {
  let mut accepted = ACCEPTED_TOTP_STEPS
    .lock()
    .unwrap_or_else(|poisoned| poisoned.into_inner());
  match accepted.get(user_id) {
    Some(last) if step <= *last => false,
    _ => {
      accepted.insert(user_id.to_string(), step);
      true
    }
  }
}

// ==========================
// = SECOND FACTOR FAILURES =
// ==========================

/// How many second factor codes (TOTP or recovery) can fail for one
/// user within [SECOND_FACTOR_FAILURE_WINDOW]: whatever the session,
/// first factor or client ip they are sent with. Past it, the codes
/// of the user are refused with `429 Too Many Requests` until the
/// oldest failure leaves the window.
///
/// The codes being checked count against it as well, so a burst of
/// codes sent at once can't get more guesses than this. With 6 digit
/// codes accepted one step either side, each guess has about a 3 in
/// a million chance.
///
/// Only a client which passed the first factor (the password, or an
/// external login) can send codes for a user, so somebody without it
/// can't use up the budget and lock the user out. Whoever holds the
/// first factor can though, and keep the user's second factor locked
/// for as long as they like by failing this many codes each window
/// (10 per 15 minutes, per process). The user or an admin then
/// changes the password, or unlinks the external login, the first
/// factor came from. The codes of a first factor are accepted for 10
/// minutes after it passed (`Session::MAX_SECOND_FACTOR_LOGIN_AGE`),
/// however its session is kept alive, so the ones passed before the
/// change stop at most 10 minutes after it. The user's codes are
/// accepted again once the last failures leave the window: at most
/// 25 minutes after the change.
///
/// A failure is any refused code (wrong, already used, or from an ip
/// outside the user's whitelist); server errors are not counted, nor
/// is a second factor which can't be tried anymore (the login
/// expired, or ran out of attempts). Accepted codes don't give the
/// failures back, they leave the window.
///
/// Kept in process memory (like [consume_totp_step_in_process]), so
/// every instance of a replicated app allows this many, and a
/// restart starts over.
pub const MAX_SECOND_FACTOR_FAILURES: usize = 10;

/// See [MAX_SECOND_FACTOR_FAILURES].
pub const SECOND_FACTOR_FAILURE_WINDOW: Duration =
  Duration::from_secs(15 * 60);

/// How often users without failures in the window, nor codes being
/// checked, are dropped from [SECOND_FACTOR_ATTEMPTS].
const SECOND_FACTOR_SWEEP_INTERVAL: Duration =
  Duration::from_secs(60);

static SECOND_FACTOR_ATTEMPTS: LazyLock<Mutex<SecondFactorAttempts>> =
  LazyLock::new(|| {
    Mutex::new(SecondFactorAttempts::new(
      MAX_SECOND_FACTOR_FAILURES,
      SECOND_FACTOR_FAILURE_WINDOW,
    ))
  });

fn second_factor_attempts()
-> MutexGuard<'static, SecondFactorAttempts> {
  // Nothing panics while holding the lock, and the
  // attempts stay valid even if something did.
  SECOND_FACTOR_ATTEMPTS
    .lock()
    .unwrap_or_else(PoisonError::into_inner)
}

/// The second factor codes of every user, see
/// [MAX_SECOND_FACTOR_FAILURES].
struct SecondFactorAttempts {
  max_failures: usize,
  window: Duration,
  /// Users with failures in the window or codes being checked,
  /// by id. Bounded by the users who passed a first factor.
  users: HashMap<String, UserAttempts>,
  last_sweep: Option<Instant>,
}

#[derive(Default)]
struct UserAttempts {
  /// When codes failed, oldest first.
  failures: Vec<Instant>,
  /// Codes being checked.
  in_flight: usize,
  /// Held while a recovery code is checked and used up, see
  /// [SecondFactorAttempt::lock_recovery_codes]. The user stays on
  /// the map while any attempt holds a clone.
  recovery_codes: Arc<tokio::sync::Mutex<()>>,
}

impl UserAttempts {
  fn prune(&mut self, now: Instant, window: Duration) {
    // Saturates to zero rather than panicking if a
    // time is somehow later than now.
    self
      .failures
      .retain(|&time| now.duration_since(time) < window);
  }
}

impl SecondFactorAttempts {
  fn new(max_failures: usize, window: Duration) -> Self {
    Self {
      max_failures,
      window,
      users: Default::default(),
      last_sweep: None,
    }
  }

  /// Reserves one of the remaining attempts of `user_id`, returning
  /// the lock of their recovery codes. Refused with `429` once their
  /// failures, with the codes being checked, use up the budget.
  fn begin(
    &mut self,
    user_id: &str,
    now: Instant,
  ) -> mogh_error::Result<Arc<tokio::sync::Mutex<()>>> {
    self.sweep(now);
    let window = self.window;
    let user = self.users.entry(user_id.to_string()).or_default();
    user.prune(now, window);
    if user.failures.len() >= self.max_failures {
      // Attempts checked at the same time are all recorded,
      // those above the budget have to leave the window too.
      let retry_in = user
        .failures
        .get(user.failures.len() - self.max_failures)
        .map(|&time| window.saturating_sub(now.duration_since(time)))
        .unwrap_or(window);
      return Err(
        anyhow!(
          "Too many invalid codes for this account | Try again in {retry_in:.0?}"
        )
        .status_code(StatusCode::TOO_MANY_REQUESTS),
      );
    }
    if user.failures.len() + user.in_flight >= self.max_failures {
      return Err(
        anyhow!(
          "Too many codes for this account are being checked at once | Try again shortly"
        )
        .status_code(StatusCode::TOO_MANY_REQUESTS),
      );
    }
    user.in_flight += 1;
    Ok(user.recovery_codes.clone())
  }

  /// Ends an attempt of `user_id`, recording a failure if it `failed`.
  fn end(&mut self, user_id: &str, failed: bool, now: Instant) {
    let window = self.window;
    let Some(user) = self.users.get_mut(user_id) else {
      return;
    };
    user.in_flight = user.in_flight.saturating_sub(1);
    user.prune(now, window);
    if failed {
      user.failures.push(now);
    }
    if user.in_flight == 0 && user.failures.is_empty() {
      self.users.remove(user_id);
    }
  }

  /// Drops the users without failures in the window nor codes
  /// being checked, once per [SECOND_FACTOR_SWEEP_INTERVAL].
  fn sweep(&mut self, now: Instant) {
    if self.last_sweep.is_some_and(|last| {
      now.duration_since(last) < SECOND_FACTOR_SWEEP_INTERVAL
    }) {
      return;
    }
    self.last_sweep = Some(now);
    let window = self.window;
    self.users.retain(|_, user| {
      user.prune(now, window);
      user.in_flight > 0 || !user.failures.is_empty()
    });
  }
}

/// A second factor code of the user being checked, holding one of
/// their remaining attempts (see [MAX_SECOND_FACTOR_FAILURES]) until
/// it is [ended](Self::end), or dropped (the request was cancelled).
struct SecondFactorAttempt {
  user_id: String,
  recovery_codes: Arc<tokio::sync::Mutex<()>>,
  ended: bool,
}

impl SecondFactorAttempt {
  fn begin(user_id: &str) -> mogh_error::Result<Self> {
    let recovery_codes =
      second_factor_attempts().begin(user_id, Instant::now())?;
    Ok(Self {
      user_id: user_id.to_string(),
      recovery_codes,
      ended: false,
    })
  }

  /// Ends the attempt with the result of the code, counting a
  /// refused code (not a server error) as a failure.
  fn end<T>(mut self, res: &mogh_error::Result<T>) {
    let failed = matches!(res, Err(e) if !e.status.is_server_error());
    if failed {
      warn!(user_id = self.user_id, "Second factor code refused");
    }
    self.ended = true;
    second_factor_attempts().end(
      &self.user_id,
      failed,
      Instant::now(),
    );
  }

  /// Waits for the other recovery code logins of the user to
  /// finish. Held from loading the user's codes until the used one
  /// is removed, so one code can't be used twice at the same time,
  /// nor the removal of one code undo another's (with storage
  /// which writes back the whole list) within this process.
  async fn lock_recovery_codes(
    &self,
  ) -> tokio::sync::OwnedMutexGuard<()> {
    self.recovery_codes.clone().lock_owned().await
  }
}

impl Drop for SecondFactorAttempt {
  fn drop(&mut self) {
    if !self.ended {
      second_factor_attempts().end(
        &self.user_id,
        false,
        Instant::now(),
      );
    }
  }
}

// =========
// = LOGIN =
// =========

impl Resolve<LoginArgs> for CompleteTotpLogin {
  #[instrument(
    "CompleteTotpLogin",
    skip_all,
    fields(
      ip = args.ip.to_string(),
    )
  )]
  async fn resolve(
    self,
    args: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    // Before the rate limit: a session without a TOTP login (or
    // with one which can't be tried anymore) holds nothing to guess,
    // and is refused without counting against the ip. A client over
    // the limit uses up an attempt of the login all the same (like
    // one over the user's cap).
    let user_id = args.session.begin_totp_login_attempt().await?;
    async {
      let attempt = SecondFactorAttempt::begin(&user_id)?;
      let res = finish_totp_login(args, &user_id, &self.code).await;
      attempt.end(&res);
      res
    }
    // Strict: a burst of guesses sent at once is bounded
    // by the budget as well.
    .with_strict_failure_rate_limit_using_ip(
      args.auth.general_rate_limiter(),
      &args.ip,
    )
    .await
  }
}

async fn finish_totp_login(
  LoginArgs { auth, session, ip }: &LoginArgs,
  user_id: &str,
  code: &str,
) -> mogh_error::Result<JwtResponse> {
  let user = auth.get_user(user_id.to_string()).await?;
  // Unenrolled since the first factor passed (or reset by an admin):
  // the login can't be completed with a code, like a recovery code
  // or a passkey of a user no longer enrolled.
  let totp_secret = user
    .totp_secret()
    .context("User is not enrolled in TOTP 2FA")
    .status_code(StatusCode::UNAUTHORIZED)?;

  check_user_cidr_whitelist(user.as_ref(), *ip)?;

  let secret_bytes = BASE32_NOPAD
    .decode(totp_secret.as_bytes())
    .context("Failed to decode TOTP secret to bytes")?;

  let totp = auth.make_totp(secret_bytes, None)?;

  // The step is the 30s window since epoch
  // which the TOTP is valid for.
  let step = totp
    .check_current(code)
    .context("Invalid TOTP code")
    .status_code(StatusCode::UNAUTHORIZED)?;

  // A code must only be accepted once (RFC 6238).
  if !auth.consume_totp_step(user_id.to_string(), step).await? {
    return Err(
      anyhow!("TOTP code already used. Wait for the next code.")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let kind = session.complete_totp_login().await?;
  let token = issue_login(
    auth.as_ref(),
    user.id(),
    user.username(),
    *ip,
    kind,
    Some(SecondFactor::Totp),
    IssueToken::Now,
  )
  .await?;

  info!(
    user_id = user.id(),
    username = user.username(),
    "TOTP 2FA flow complete, user logged in"
  );

  Ok(token.into())
}

impl Resolve<LoginArgs> for CompleteTotpRecoveryLogin {
  #[instrument(
    "CompleteTotpRecoveryLogin",
    skip_all,
    fields(
      ip = args.ip.to_string(),
    )
  )]
  async fn resolve(
    self,
    args: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    // Before the rate limit, see CompleteTotpLogin.
    let user_id = args.session.begin_totp_login_attempt().await?;
    async {
      let attempt = SecondFactorAttempt::begin(&user_id)?;
      let res = finish_totp_recovery_login(
        args, &attempt, &user_id, &self.code,
      )
      .await;
      attempt.end(&res);
      res
    }
    // Strict: a burst of guesses sent at once is bounded
    // by the budget as well.
    .with_strict_failure_rate_limit_using_ip(
      args.auth.general_rate_limiter(),
      &args.ip,
    )
    .await
  }
}

async fn finish_totp_recovery_login(
  LoginArgs { auth, session, ip }: &LoginArgs,
  attempt: &SecondFactorAttempt,
  user_id: &str,
  code: &str,
) -> mogh_error::Result<JwtResponse> {
  // The user's codes are loaded under the lock, so they
  // include the removal of any code used before.
  let recovery_codes = attempt.lock_recovery_codes().await;

  let user = auth.get_user(user_id.to_string()).await?;
  if user.totp_secret().is_none() {
    return Err(
      anyhow!("User is not enrolled in TOTP 2FA")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  check_user_cidr_whitelist(user.as_ref(), *ip)?;

  let hashed_code =
    find_recovery_code(code, user.hashed_totp_recovery_codes())
      .await?
      .context("Invalid recovery code")
      .status_code(StatusCode::UNAUTHORIZED)?;

  // Each recovery code can only be used once.
  auth
    .remove_totp_recovery_code(user_id.to_string(), hashed_code)
    .await?;
  drop(recovery_codes);

  let kind = session.complete_totp_login().await?;
  let token = issue_login(
    auth.as_ref(),
    user.id(),
    user.username(),
    *ip,
    kind,
    Some(SecondFactor::TotpRecovery),
    IssueToken::Now,
  )
  .await?;

  info!(
    user_id = user.id(),
    username = user.username(),
    "TOTP recovery code flow complete, user logged in"
  );

  Ok(token.into())
}

/// The stored hash (of `hashed_codes`) which the recovery `code`
/// matches. Recovery codes are bcrypt hashed, so the code is
/// verified against each unused one, off the async runtime.
async fn find_recovery_code(
  code: &str,
  hashed_codes: &[String],
) -> anyhow::Result<Option<String>> {
  let code = Zeroizing::new(code.as_bytes().to_vec());
  let hashed_codes = hashed_codes.to_vec();
  spawn_bcrypt(move || {
    hashed_codes
      .into_iter()
      .find(|hash| bcrypt::verify(&*code, hash).unwrap_or(false))
  })
  .await
}

#[cfg(test)]
mod tests {
  use std::{
    net::IpAddr,
    sync::{
      Arc, Mutex,
      atomic::{AtomicUsize, Ordering},
    },
  };

  use crate::{
    AuthImpl, Login, LoginKind, SecondFactor,
    session::Session,
    test_support::{session, stub_auth_impl},
    user::{AuthUserImpl, BoxAuthUser},
  };

  use super::*;

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3));
  const SECRET: &[u8] = b"12345678901234567890";

  struct TestUser {
    id: String,
    recovery_codes: Vec<String>,
    /// Unenrolled from TOTP after the first factor passed.
    unenrolled: bool,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      &self.id
    }
    fn username(&self) -> &str {
      "totp"
    }
    fn totp_secret(&self) -> Option<&str> {
      static ENCODED: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| BASE32_NOPAD.encode(SECRET));
      (!self.unenrolled).then_some(ENCODED.as_str())
    }
    fn hashed_totp_recovery_codes(&self) -> &[String] {
      &self.recovery_codes
    }
  }

  #[derive(Clone)]
  struct TestAuth {
    /// The id of the only user. Unique per test, the second
    /// factor failures are counted per process.
    user_id: String,
    logins: Arc<Mutex<Vec<Login>>>,
    get_user_calls: Arc<AtomicUsize>,
    /// Hashed, like the app would store them.
    recovery_codes: Arc<Mutex<Vec<String>>>,
    /// Keeps the requests in flight, so they overlap.
    delay: Duration,
    /// The user unenrolled from TOTP after the first factor.
    unenrolled: bool,
  }

  impl TestAuth {
    fn with_user(user_id: &str) -> Self {
      Self {
        user_id: user_id.to_string(),
        logins: Default::default(),
        get_user_calls: Default::default(),
        recovery_codes: Default::default(),
        delay: Duration::ZERO,
        unenrolled: false,
      }
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::with_user("totp-hook-user")
    }
    fn app_name(&self) -> &'static str {
      "test"
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<BoxAuthUser>> {
      assert_eq!(user_id, self.user_id);
      self.get_user_calls.fetch_add(1, Ordering::SeqCst);
      let recovery_codes = self.recovery_codes.clone();
      let delay = self.delay;
      let unenrolled = self.unenrolled;
      Box::pin(async move {
        tokio::time::sleep(delay).await;
        let recovery_codes = recovery_codes.lock().unwrap().clone();
        Ok(Box::new(TestUser {
          id: user_id,
          recovery_codes,
          unenrolled,
        }) as BoxAuthUser)
      })
    }
    stub_auth_impl!(handle_request_authentication, jwt_provider);
    fn record_login(
      &self,
      login: Login,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.logins.lock().unwrap().push(login);
      Box::pin(async { Ok(()) })
    }
    /// Reads, filters and writes back the whole list, like an app
    /// whose storage only supports read-modify-write: not atomic.
    /// (The example app uses one conditional update instead.)
    fn remove_totp_recovery_code(
      &self,
      _user_id: String,
      hashed_code: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      let recovery_codes = self.recovery_codes.clone();
      let delay = self.delay;
      Box::pin(async move {
        let remaining = recovery_codes
          .lock()
          .unwrap()
          .iter()
          .filter(|hash| **hash != hashed_code)
          .cloned()
          .collect::<Vec<_>>();
        tokio::time::sleep(delay).await;
        *recovery_codes.lock().unwrap() = remaining;
        Ok(())
      })
    }
  }

  /// A session which passed the first factor of `user_id`.
  async fn pending_login(user_id: &str) -> Session {
    let session = session();
    session.insert_totp_login_user_id(user_id).await.unwrap();
    session
  }

  fn login_args(auth: &TestAuth, session: Session) -> LoginArgs {
    LoginArgs {
      auth: Box::new(auth.clone()),
      session,
      ip: IP,
    }
  }

  /// A code which is not valid now.
  fn wrong_code(auth: &TestAuth) -> String {
    let totp = auth.make_totp(SECRET.to_vec(), None).unwrap();
    ["000000", "111111", "222222", "333333"]
      .into_iter()
      .find(|code| totp.check_current(code).is_none())
      .unwrap()
      .to_string()
  }

  /// A TOTP completion records the login with the kind its first
  /// factor left on the session, and takes both off the session.
  #[tokio::test]
  async fn test_completion_records_the_first_factors_login() {
    let auth = TestAuth::with_user("totp-hook-user");
    let logins = auth.logins.clone();
    let code = auth
      .make_totp(SECRET.to_vec(), None)
      .unwrap()
      .generate_current()
      .to_string();
    let session = pending_login("totp-hook-user").await;
    let provider = LoginKind::Provider {
      provider_id: "oidc".into(),
      provider_name: "OIDC".into(),
    };
    session.insert_login_kind(&provider).await.unwrap();
    let args = login_args(&auth, session);
    let jwt =
      CompleteTotpLogin { code }.resolve(&args).await.unwrap();
    assert_eq!(
      args.auth.jwt_provider().decode_sub(&jwt.jwt).unwrap(),
      "totp-hook-user"
    );
    {
      let logins = logins.lock().unwrap();
      assert_eq!(logins.len(), 1);
      assert_eq!(logins[0].kind, provider);
      assert_eq!(logins[0].second_factor, Some(SecondFactor::Totp));
      assert_eq!(logins[0].ip, IP);
      assert_eq!(logins[0].username, "totp");
    }
    // Nothing is left on the session
    assert!(args.session.begin_totp_login_attempt().await.is_err());
    assert_eq!(
      args.session.take_login_kind().await,
      LoginKind::Local
    );
  }

  /// Codes sent at once, on as many sessions (first factors) as
  /// wanted, get no more guesses than the budget of the user, and
  /// once it is used up the user's codes are refused whatever the
  /// session.
  #[tokio::test]
  async fn test_concurrent_codes_are_bounded_per_user() {
    let auth = TestAuth {
      delay: Duration::from_millis(50),
      ..TestAuth::with_user("burst-user")
    };
    let code = wrong_code(&auth);
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..30 {
      let args = login_args(&auth, pending_login("burst-user").await);
      let code = code.clone();
      requests.spawn(async move {
        CompleteTotpLogin { code }.resolve(&args).await
      });
    }
    let results = requests.join_all().await;
    let checked = results
      .iter()
      .filter(|res| {
        res
          .as_ref()
          .is_err_and(|e| e.status == StatusCode::UNAUTHORIZED)
      })
      .count();
    let refused = results
      .iter()
      .filter(|res| {
        res
          .as_ref()
          .is_err_and(|e| e.status == StatusCode::TOO_MANY_REQUESTS)
      })
      .count();
    assert_eq!(checked, MAX_SECOND_FACTOR_FAILURES);
    assert_eq!(refused, 30 - MAX_SECOND_FACTOR_FAILURES);
    assert_eq!(
      auth.get_user_calls.load(Ordering::SeqCst),
      MAX_SECOND_FACTOR_FAILURES
    );

    // The budget is the user's: a new first factor (session)
    // doesn't get more, not even with the right code.
    let valid = auth
      .make_totp(SECRET.to_vec(), None)
      .unwrap()
      .generate_current()
      .to_string();
    let args = login_args(&auth, pending_login("burst-user").await);
    let err = CompleteTotpLogin { code: valid }
      .resolve(&args)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(format!("{:#}", err.error).contains("Try again in"));
    let err = CompleteTotpRecoveryLogin {
      code: "recovery".into(),
    }
    .resolve(&args)
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    // Other users are not affected
    let other = TestAuth::with_user("burst-other-user");
    let args =
      login_args(&other, pending_login("burst-other-user").await);
    let err = CompleteTotpLogin {
      code: wrong_code(&other),
    }
    .resolve(&args)
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// The same recovery code sent twice at once, on two sessions,
  /// logs in once, and two codes used at once are both removed,
  /// also with storage which writes back the whole list.
  #[tokio::test]
  async fn test_recovery_code_is_used_once_concurrently() {
    let auth = TestAuth {
      delay: Duration::from_millis(20),
      ..TestAuth::with_user("recovery-race-user")
    };
    *auth.recovery_codes.lock().unwrap() = vec![
      bcrypt::hash("code-one", 4).unwrap(),
      bcrypt::hash("code-two", 4).unwrap(),
      bcrypt::hash("code-three", 4).unwrap(),
    ];
    let first =
      login_args(&auth, pending_login("recovery-race-user").await);
    let second =
      login_args(&auth, pending_login("recovery-race-user").await);
    let (first, second) = tokio::join!(
      CompleteTotpRecoveryLogin {
        code: "code-one".into()
      }
      .resolve(&first),
      CompleteTotpRecoveryLogin {
        code: "code-one".into()
      }
      .resolve(&second),
    );
    assert!(
      first.is_ok() != second.is_ok(),
      "The code logged in {} times",
      first.is_ok() as u8 + second.is_ok() as u8
    );
    assert_eq!(auth.recovery_codes.lock().unwrap().len(), 2);

    let first =
      login_args(&auth, pending_login("recovery-race-user").await);
    let second =
      login_args(&auth, pending_login("recovery-race-user").await);
    let (first, second) = tokio::join!(
      CompleteTotpRecoveryLogin {
        code: "code-two".into()
      }
      .resolve(&first),
      CompleteTotpRecoveryLogin {
        code: "code-three".into()
      }
      .resolve(&second),
    );
    first.unwrap();
    second.unwrap();
    // Neither removal undid the other.
    assert!(auth.recovery_codes.lock().unwrap().is_empty());
  }

  /// The codes of a first factor which passed longer than
  /// `Session::MAX_SECOND_FACTOR_LOGIN_AGE` ago are refused, the
  /// right ones too (the password may have changed since), and the
  /// login is removed. Nothing is checked, so no failure of the user
  /// is counted.
  #[tokio::test]
  async fn test_expired_login_is_refused() {
    let auth = TestAuth::with_user("expired-login-user");
    *auth.recovery_codes.lock().unwrap() =
      vec![bcrypt::hash("code-one", 4).unwrap()];
    let expired = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_secs()
      - Session::MAX_SECOND_FACTOR_LOGIN_AGE.as_secs()
      - 60;
    let expired_login = || async {
      let session = session();
      session
        .insert_totp_login("expired-login-user", expired)
        .await
        .unwrap();
      login_args(&auth, session)
    };
    let valid = auth
      .make_totp(SECRET.to_vec(), None)
      .unwrap()
      .generate_current()
      .to_string();

    let args = expired_login().await;
    let err = CompleteTotpLogin {
      code: valid.clone(),
    }
    .resolve(&args)
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("expired"));
    // Removed, the login starts over.
    let err = CompleteTotpRecoveryLogin {
      code: "code-one".into(),
    }
    .resolve(&args)
    .await
    .unwrap_err();
    assert!(
      format!("{:#}", err.error).contains("not been initiated")
    );

    let args = expired_login().await;
    let err = CompleteTotpRecoveryLogin {
      code: "code-one".into(),
    }
    .resolve(&args)
    .await
    .unwrap_err();
    assert!(format!("{:#}", err.error).contains("expired"));

    // No code was checked, nor failure counted.
    assert_eq!(auth.get_user_calls.load(Ordering::SeqCst), 0);
    assert_eq!(auth.recovery_codes.lock().unwrap().len(), 1);
    assert!(
      !second_factor_attempts()
        .users
        .contains_key("expired-login-user")
    );
    // A new first factor logs in.
    let args =
      login_args(&auth, pending_login("expired-login-user").await);
    CompleteTotpLogin { code: valid }
      .resolve(&args)
      .await
      .unwrap();
  }

  /// A user who unenrolled from TOTP (or was reset by an admin) after
  /// the first factor passed can't complete the login with a code:
  /// `401`, like the recovery code and passkey completions, not a
  /// server error. It counts as a refused code.
  #[tokio::test]
  async fn test_unenrolled_user_is_refused() {
    let auth = TestAuth {
      unenrolled: true,
      ..TestAuth::with_user("unenrolled-user")
    };
    *auth.recovery_codes.lock().unwrap() =
      vec![bcrypt::hash("code-one", 4).unwrap()];
    let code = TestAuth::with_user("unenrolled-user")
      .make_totp(SECRET.to_vec(), None)
      .unwrap()
      .generate_current()
      .to_string();
    let args =
      login_args(&auth, pending_login("unenrolled-user").await);
    let err =
      CompleteTotpLogin { code }.resolve(&args).await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("not enrolled"));
    let err = CompleteTotpRecoveryLogin {
      code: "code-one".into(),
    }
    .resolve(&args)
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(format!("{:#}", err.error).contains("not enrolled"));
    // Both were refused codes of the user.
    assert_eq!(
      second_factor_attempts().users["unenrolled-user"]
        .failures
        .len(),
      2
    );
    assert!(auth.logins.lock().unwrap().is_empty());
  }

  #[test]
  fn test_second_factor_attempts_budget() {
    let window = Duration::from_secs(60);
    let mut attempts = SecondFactorAttempts::new(3, window);
    let start = Instant::now();
    // Codes being checked hold the budget...
    for _ in 0..3 {
      attempts.begin("user", start).unwrap();
    }
    let err = attempts.begin("user", start).unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    // ...an accepted code gives its attempt back...
    attempts.end("user", false, start);
    attempts.begin("user", start).unwrap();
    // ...a refused one uses it up.
    for _ in 0..3 {
      attempts.end("user", true, start);
    }
    let err = attempts.begin("user", start).unwrap_err();
    assert!(format!("{:#}", err.error).contains("Try again in 60s"));
    // Other users have their own budget.
    attempts.begin("other", start).unwrap();
    attempts.end("other", false, start);
    // The failures leave the window.
    let later = start + window;
    attempts.begin("user", later).unwrap();
    attempts.end("user", false, later);
    // Users without failures or attempts are dropped.
    assert!(attempts.users.is_empty());
  }

  #[test]
  fn test_second_factor_attempts_sweep() {
    let window = Duration::from_secs(60);
    let mut attempts = SecondFactorAttempts::new(3, window);
    let start = Instant::now();
    attempts.begin("failed", start).unwrap();
    attempts.end("failed", true, start);
    attempts.begin("checking", start).unwrap();
    assert_eq!(attempts.users.len(), 2);
    let later = start + window + SECOND_FACTOR_SWEEP_INTERVAL;
    attempts.begin("new", later).unwrap();
    // The failure left the window, the code being checked stays.
    assert!(!attempts.users.contains_key("failed"));
    assert!(attempts.users.contains_key("checking"));
  }

  #[test]
  fn test_consume_totp_step_rejects_replay() {
    // First use of a step is accepted, replay is rejected.
    assert!(consume_totp_step_in_process("replay-user", 100));
    assert!(!consume_totp_step_in_process("replay-user", 100));
  }

  #[test]
  fn test_consume_totp_step_rejects_older_step() {
    // A code from an older window than the last accepted one
    // is rejected, even within skew.
    assert!(consume_totp_step_in_process("older-step-user", 100));
    assert!(!consume_totp_step_in_process("older-step-user", 99));
  }

  #[test]
  fn test_consume_totp_step_accepts_newer_step() {
    assert!(consume_totp_step_in_process("newer-step-user", 100));
    assert!(consume_totp_step_in_process("newer-step-user", 101));
    assert!(!consume_totp_step_in_process("newer-step-user", 101));
  }

  #[test]
  fn test_consume_totp_step_isolated_per_user() {
    assert!(consume_totp_step_in_process("user-a", 100));
    // Same step for a different user is still accepted.
    assert!(consume_totp_step_in_process("user-b", 100));
  }

  #[tokio::test]
  async fn test_find_recovery_code() {
    // The lookup used by CompleteTotpRecoveryLogin: find the
    // stored hash matching the provided code.
    let hashes = [
      bcrypt::hash("code-one", 4).unwrap(),
      bcrypt::hash("code-two", 4).unwrap(),
    ];
    let found =
      find_recovery_code("code-two", &hashes).await.unwrap();
    assert_eq!(found.as_ref(), Some(&hashes[1]));
    let missing =
      find_recovery_code("code-three", &hashes).await.unwrap();
    assert!(missing.is_none());
  }
}
