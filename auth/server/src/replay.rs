//! Refusing a signed request the second time it arrives:
//! [SeenSignatures], the store an app's
//! [AuthImpl::accept_signed_request] remembers signatures in, and
//! [check_timestamp_tolerance], the bound on the tolerance it is
//! meant for. The auth server doesn't call either by itself: the
//! default hook accepts every request, an app opts in from its own.
//!
//! ```ignore
//! use mogh_auth_server::replay::SeenSignatures;
//!
//! fn accept_signed_request(
//!   &self,
//!   accepted: AcceptedSignature,
//! ) -> DynFuture<mogh_error::Result<()>> {
//!   static SEEN: SeenSignatures = SeenSignatures::new();
//!   let res = SEEN.accept_once(self, &accepted);
//!   Box::pin(async move { res })
//! }
//! ```
//!
//! A request signature covers the host, method, path and query,
//! timestamp, nonce and body, and the auth server refuses one whose
//! `X-API-TIMESTAMP` is further than
//! [AuthImpl::signing_key_timestamp_tolerance_ms] from its clock.
//! Within that window the same request could still be sent again by
//! whoever captured it. Each signature is unique (a client signs
//! every request, and every retry, with a new random nonce) and has
//! one accepted form (the auth server verifies an Ed25519 signature
//! strictly: a canonical one, in canonical base64, so nobody can turn
//! it into another which verifies), so one seen before is a replay:
//! 401.
//!
//! The auth server checks the timestamp once, when the headers
//! arrive (within the tolerance of it), and reads the body after
//! (the time a large body takes doesn't count against the
//! tolerance), within [AuthImpl::signed_request_body_timeout] (408
//! once that passes, while the body is read). So the whole request
//! is bounded by its own timestamp: its body is in within the
//! tolerance plus the body timeout of it (the window, which the
//! store reads from the app's own [AuthImpl] on every check, so the
//! two can't drift apart), a signature checked later than that is
//! refused all the same (401, [SIGNED_AT_ANOTHER_TIME]: the client
//! signs anew), and a signature is remembered until past it (plus a
//! second). A replay whose headers arrive in time but whose body is
//! held back until the original's entry would have expired is
//! refused either way.
//!
//! Only signatures which verified, of signers which authenticated,
//! reach the hook, so only those are remembered (a forged one can't
//! fill the store or block a real one). The store holds a 32 byte
//! digest and a deadline per signature, for the window (expired ones
//! are pruned once more than 1024 are kept, at most once a second):
//! its size follows the rate of signed requests the app accepts,
//! times the window. Hence [MAX_TIMESTAMP_TOLERANCE_MS].
//!
//! The store is the memory of one process. Behind a load balancer
//! spreading requests over several instances of the app (or right
//! after a restart) a replay can land where the signature wasn't
//! seen: TLS stays the primary protection. An app which runs
//! several instances and wants every replay refused keeps the
//! signatures in a store they share instead, as
//! [AuthImpl::accept_signed_request] describes.

use std::{
  collections::BTreeMap,
  sync::Mutex,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use mogh_auth_client::signature::SIGNED_AT_ANOTHER_TIME;
use mogh_error::{AddStatusCodeError as _, StatusCode};
use sha2::{Digest as _, Sha256};

use crate::{AcceptedSignature, AuthImpl};

/// The largest [AuthImpl::signing_key_timestamp_tolerance_ms]
/// [check_timestamp_tolerance] lets an app start with: the tolerance
/// is the replay window of a captured request where [SeenSignatures]
/// didn't see it (another instance, a restart) as much as the clock
/// difference it allows, and the store keeps every signature for
/// it. A minute is plenty for any clock NTP keeps.
pub const MAX_TIMESTAMP_TOLERANCE_MS: u64 = 60_000;

/// Beyond the window ([window_ms]), so a signature is forgotten
/// only once a request carrying it can't be accepted any more.
const EVICTION_SLACK_MS: i64 = 1_000;

/// Past this many remembered signatures, expired ones are pruned
/// (at most once every [PRUNE_EVERY_MS]).
const PRUNE_ABOVE: usize = 1_024;

const PRUNE_EVERY_MS: u64 = 1_000;

/// An error for a [AuthImpl::signing_key_timestamp_tolerance_ms]
/// above [MAX_TIMESTAMP_TOLERANCE_MS], which the app should not start
/// with. For the app's startup, next to
/// [check_signed_request_hosts](crate::middleware::check_signed_request_hosts),
/// with the name of its own config key as the context:
///
/// ```ignore
/// mogh_auth_server::replay::check_timestamp_tolerance(&MyAuthImpl)
///   .context("Invalid 'signed_request_timestamp_tolerance_ms' config")?;
/// ```
pub fn check_timestamp_tolerance<I: AuthImpl + ?Sized>(
  auth: &I,
) -> anyhow::Result<()> {
  let tolerance = auth.signing_key_timestamp_tolerance_ms();
  if tolerance > MAX_TIMESTAMP_TOLERANCE_MS {
    return Err(anyhow!(
      "The signed request timestamp tolerance is {tolerance}ms, at most {MAX_TIMESTAMP_TOLERANCE_MS}ms (a minute) are accepted: it is how long a captured signed request can be replayed where its signature wasn't seen, as much as the clock difference allowed"
    ));
  }
  Ok(())
}

/// The signatures of the signed requests an app accepted, each
/// until a request carrying it can't be accepted any more: see the
/// [module docs](self). One per app, in a static, checked from its
/// [AuthImpl::accept_signed_request] with [Self::accept_once].
pub struct SeenSignatures {
  seen: Mutex<Seen>,
}

struct Seen {
  /// sha256 of the signature → when it may be forgotten (unix ms).
  signatures: BTreeMap<[u8; 32], i64>,
  last_prune: i64,
}

impl Default for SeenSignatures {
  fn default() -> SeenSignatures {
    SeenSignatures::new()
  }
}

impl SeenSignatures {
  /// An empty store, for a `static`.
  pub const fn new() -> SeenSignatures {
    SeenSignatures {
      seen: Mutex::new(Seen {
        signatures: BTreeMap::new(),
        last_prune: 0,
      }),
    }
  }

  /// Remembers the `accepted` signature: `401 Invalid client
  /// credentials` if it was seen already, `401`
  /// [SIGNED_AT_ANOTHER_TIME] if its request completed longer than
  /// the window of `auth` (its
  /// [AuthImpl::signing_key_timestamp_tolerance_ms] plus its
  /// [AuthImpl::signed_request_body_timeout]) after its timestamp:
  /// the auth server checked the timestamp before the body arrived,
  /// not now. Checks and remembers in one step, so of two copies
  /// arriving together one is refused.
  pub fn accept_once<I: AuthImpl + ?Sized>(
    &self,
    auth: &I,
    accepted: &AcceptedSignature,
  ) -> mogh_error::Result<()> {
    self.accept_at(
      &accepted.signature,
      accepted.timestamp,
      now_ms(),
      window_ms(auth),
    )
  }

  fn accept_at(
    &self,
    signature: &str,
    timestamp: i64,
    now: i64,
    window_ms: i64,
  ) -> mogh_error::Result<()> {
    // A signature verified with this timestamp (it is signed), so a
    // request carrying it is only ever accepted up to the window:
    // one remembered until past it can't come back unnoticed.
    let age = now.saturating_sub(timestamp);
    if age > window_ms {
      return Err(signed_too_long_ago(age));
    }
    let digest: [u8; 32] = Sha256::digest(signature.trim()).into();
    let forget_at = timestamp
      .saturating_add(window_ms)
      .saturating_add(EVICTION_SLACK_MS);
    let mut seen =
      self.seen.lock().unwrap_or_else(|e| e.into_inner());
    // Measured either way, so a clock set back doesn't hold the
    // pruning off until it caught up again.
    if seen.signatures.len() > PRUNE_ABOVE
      && now.abs_diff(seen.last_prune) >= PRUNE_EVERY_MS
    {
      seen.signatures.retain(|_, forget_at| *forget_at > now);
      seen.last_prune = now;
    }
    match seen.signatures.get(&digest) {
      Some(previous) if *previous > now => {
        Err(crate::middleware::invalid_client_credentials())
      }
      _ => {
        seen.signatures.insert(digest, forget_at);
        Ok(())
      }
    }
  }
}

fn now_ms() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|now| i64::try_from(now.as_millis()).unwrap_or(i64::MAX))
    .unwrap_or_default()
}

/// How long after its timestamp a signed request may still be
/// accepted (ms): the tolerance plus the body timeout of `auth`.
fn window_ms<I: AuthImpl + ?Sized>(auth: &I) -> i64 {
  let body_timeout_ms =
    u64::try_from(auth.signed_request_body_timeout().as_millis())
      .unwrap_or(u64::MAX);
  i64::try_from(
    auth
      .signing_key_timestamp_tolerance_ms()
      .saturating_add(body_timeout_ms),
  )
  .unwrap_or(i64::MAX)
}

/// A request which verified, checked later after its timestamp
/// than any is accepted (its body took too long). It is the time
/// which is refused, not the key: said as the auth server says it
/// of a timestamp outside its tolerance, so a client signs anew
/// rather than take its key for one the app doesn't know.
fn signed_too_long_ago(age_ms: i64) -> mogh_error::Error {
  anyhow!(
    "{SIGNED_AT_ANOTHER_TIME}: the request completed {age_ms}ms after its X-API-TIMESTAMP"
  )
  .status_code(StatusCode::UNAUTHORIZED)
}

#[cfg(test)]
mod tests {
  use std::{net::IpAddr, time::Duration};

  use axum::extract::Request;

  use super::*;
  use crate::{
    DynFuture, RequestAuthentication, middleware::accepted_signature,
    provider::jwt::JwtProvider, user::BoxAuthUser,
  };

  /// The window of the default 1 s tolerance and 30 s body timeout.
  const WINDOW: i64 = 1_000 + 30_000;

  fn signature() -> String {
    format!("replay-test-{}", uuid::Uuid::new_v4())
  }

  /// An app with the given tolerance and body timeout, whose hook
  /// remembers the signatures it accepts, as the module docs show.
  struct ReplayGuarded {
    tolerance_ms: u64,
    body_timeout: Duration,
  }

  impl ReplayGuarded {
    const DEFAULTS: ReplayGuarded = ReplayGuarded {
      tolerance_ms: 1_000,
      body_timeout: Duration::from_secs(30),
    };
  }

  impl AuthImpl for ReplayGuarded {
    fn new() -> Self {
      ReplayGuarded::DEFAULTS
    }
    fn get_user(
      &self,
      _user_id: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthUser>> {
      unreachable!("no user is looked up here")
    }
    fn handle_request_authentication(
      &self,
      _auth: RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      _req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      unreachable!("no request is authenticated here")
    }
    fn signing_key_timestamp_tolerance_ms(&self) -> u64 {
      self.tolerance_ms
    }
    fn signed_request_body_timeout(&self) -> Duration {
      self.body_timeout
    }
    fn accept_signed_request(
      &self,
      accepted: AcceptedSignature,
    ) -> DynFuture<mogh_error::Result<()>> {
      static SEEN: SeenSignatures = SeenSignatures::new();
      let res = SEEN.accept_once(self, &accepted);
      Box::pin(async move { res })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      unreachable!("no token is issued or checked here")
    }
  }

  fn accepted(timestamp: i64) -> AcceptedSignature {
    AcceptedSignature {
      public_key: String::from("key"),
      host: String::from("example.com"),
      timestamp,
      nonce: String::from("0123456789abcdef0123456789abcdef"),
      signature: signature(),
    }
  }

  /// A signature is accepted once, refused again while a request
  /// carrying it could still be accepted, and forgotten after.
  #[test]
  fn signatures_are_accepted_once() {
    let seen = SeenSignatures::new();
    let now = 1_758_800_000_000;
    let signature = signature();
    seen.accept_at(&signature, now, now, WINDOW).unwrap();
    let err = seen
      .accept_at(&signature, now, now + 500, WINDOW)
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert_eq!(err.error.to_string(), "Invalid client credentials");
    // Still remembered up to the window plus the slack.
    assert!(
      seen
        .accept_at(&signature, now, now + WINDOW, WINDOW)
        .is_err()
    );
    // Past the window: refused for its age, whether remembered or
    // not.
    assert!(
      seen
        .accept_at(&signature, now, now + WINDOW + 1, WINDOW)
        .is_err()
    );
    // Another signature is its own, and so is another store.
    let other = super::tests::signature();
    seen.accept_at(&other, now, now, WINDOW).unwrap();
    SeenSignatures::new()
      .accept_at(&signature, now, now, WINDOW)
      .unwrap();
  }

  /// The bypass: the auth server checks the timestamp when the
  /// headers arrive, the replay check runs once the body did. A
  /// replay whose headers came in time but whose body was held back
  /// past the tolerance plus a second (when a cache kept for the
  /// tolerance alone would have forgotten the original) is still
  /// refused.
  #[test]
  fn replays_with_a_late_body_are_refused() {
    let seen = SeenSignatures::new();
    let timestamp = 1_758_800_000_000;
    let signature = signature();
    seen
      .accept_at(&signature, timestamp, timestamp + 5, WINDOW)
      .unwrap();
    for late in [2_001, 3_000, 10_000, WINDOW] {
      let err = seen
        .accept_at(&signature, timestamp, timestamp + late, WINDOW)
        .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{late}");
    }
  }

  /// A signature first checked later than the window after its
  /// timestamp (its body arrived that late) is refused, said as a
  /// time refused, and not remembered in place of anything.
  #[test]
  fn signatures_older_than_the_window_are_refused() {
    let seen = SeenSignatures::new();
    let timestamp = 1_758_800_000_000;
    let late = signature();
    let err = seen
      .accept_at(&late, timestamp, timestamp + WINDOW + 1, WINDOW)
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(
      err.error.to_string().starts_with(SIGNED_AT_ANOTHER_TIME),
      "{:#}",
      err.error
    );
    assert!(seen.seen.lock().unwrap().signatures.is_empty());
    // A legitimately slow body, within the window: accepted once.
    let slow = signature();
    seen
      .accept_at(&slow, timestamp, timestamp + WINDOW, WINDOW)
      .unwrap();
    assert!(
      seen
        .accept_at(&slow, timestamp, timestamp + WINDOW, WINDOW)
        .is_err()
    );
  }

  /// A timestamp from the future (a client clock ahead, within the
  /// tolerance) is remembered from it, not from now.
  #[test]
  fn future_timestamps_are_remembered_long_enough() {
    let seen = SeenSignatures::new();
    let now = 1_758_800_000_000;
    let signature = signature();
    seen.accept_at(&signature, now + 900, now, WINDOW).unwrap();
    assert!(
      seen
        .accept_at(&signature, now + 900, now + 900 + WINDOW, WINDOW)
        .is_err()
    );
  }

  /// Signatures are kept to their deadline: past [PRUNE_ABOVE] of
  /// them the expired ones are dropped, at most once a second, the
  /// live ones stay (and are still refused).
  #[test]
  fn expired_signatures_are_pruned() {
    let seen = SeenSignatures::new();
    let len = || seen.seen.lock().unwrap().signatures.len();
    let accept = |timestamp, now| {
      seen
        .accept_at(&signature(), timestamp, now, WINDOW)
        .unwrap()
    };
    let t0 = 1_758_800_000_000;
    // Signed a window ago: forgotten at t0 + 1 s.
    for _ in 0..=PRUNE_ABOVE {
      accept(t0 - WINDOW, t0);
    }
    assert_eq!(len(), PRUNE_ABOVE + 1);
    // Forgotten at t0 + 1.2 s. The first of them prunes (there are
    // more than PRUNE_ABOVE), nothing has expired yet.
    for _ in 0..=PRUNE_ABOVE {
      accept(t0 + 200 - WINDOW, t0);
    }
    assert_eq!(len(), 2 * (PRUNE_ABOVE + 1));
    // A second later the first batch has expired: the next check
    // drops it, and keeps the rest.
    let live = signature();
    seen
      .accept_at(&live, t0 + 1_000, t0 + 1_000, WINDOW)
      .unwrap();
    assert_eq!(len(), PRUNE_ABOVE + 2);
    // The second batch has expired by half a second after that
    // prune, and stays until a second has passed.
    accept(t0 + 1_500, t0 + 1_500);
    assert_eq!(len(), PRUNE_ABOVE + 3);
    accept(t0 + 2_000, t0 + 2_000);
    assert_eq!(len(), 3);
    // What is live is still refused.
    assert!(
      seen
        .accept_at(&live, t0 + 1_000, t0 + 2_000, WINDOW)
        .is_err()
    );
  }

  /// The window is the app's own tolerance plus its body timeout,
  /// read on every check.
  #[test]
  fn the_window_is_the_apps_tolerance_and_body_timeout() {
    let auth = ReplayGuarded {
      tolerance_ms: 1_000,
      body_timeout: Duration::from_secs(3),
    };
    assert_eq!(window_ms(&auth), 4_000);
    assert_eq!(window_ms(&ReplayGuarded::DEFAULTS), WINDOW);
    let seen = SeenSignatures::new();
    let now = now_ms();
    // A body which took most of the window: accepted, once.
    let slow = accepted(now - 3_500);
    seen.accept_once(&auth, &slow).unwrap();
    assert!(seen.accept_once(&auth, &slow).is_err());
    // Past it.
    let err =
      seen.accept_once(&auth, &accepted(now - 4_500)).unwrap_err();
    assert!(
      err.error.to_string().starts_with(SIGNED_AT_ANOTHER_TIME),
      "{:#}",
      err.error
    );
    // A longer body timeout widens it.
    let patient = ReplayGuarded {
      body_timeout: Duration::from_secs(10),
      ..auth
    };
    seen.accept_once(&patient, &accepted(now - 4_500)).unwrap();
    // Neither overflows.
    let endless = ReplayGuarded {
      tolerance_ms: u64::MAX,
      body_timeout: Duration::MAX,
    };
    assert_eq!(window_ms(&endless), i64::MAX);
    seen.accept_once(&endless, &accepted(i64::MIN)).unwrap();
  }

  /// A verified request always carries its signature: the auth
  /// server refuses (401) one whose signature headers can't be read
  /// back, rather than hand the hook nothing to check. The hook of
  /// an app using the store refuses a signature it has seen.
  #[tokio::test]
  async fn missing_signatures_fail_closed() {
    let signed =
      RequestAuthentication::PublicKey(String::from("key"));
    let err =
      accepted_signature(&signed, &axum::http::HeaderMap::new())
        .err()
        .unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let accepted = accepted(now_ms());
    let auth = ReplayGuarded::DEFAULTS;
    auth.accept_signed_request(accepted.clone()).await.unwrap();
    let err = auth.accept_signed_request(accepted).await.unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// At most a minute, the default (1 s) and the bound itself
  /// included.
  #[test]
  fn the_tolerance_is_at_most_a_minute() {
    check_timestamp_tolerance(&ReplayGuarded::DEFAULTS).unwrap();
    for (tolerance_ms, accepted) in [
      (0, true),
      (MAX_TIMESTAMP_TOLERANCE_MS, true),
      (MAX_TIMESTAMP_TOLERANCE_MS + 1, false),
      (u64::MAX, false),
    ] {
      let auth = ReplayGuarded {
        tolerance_ms,
        ..ReplayGuarded::DEFAULTS
      };
      let res = check_timestamp_tolerance(&auth);
      assert_eq!(res.is_ok(), accepted, "{tolerance_ms}");
      if let Err(e) = res {
        let e = e.to_string();
        assert!(
          e.contains(&format!("{tolerance_ms}ms"))
            && e.contains("60000ms"),
          "{e}"
        );
      }
    }
  }
}
