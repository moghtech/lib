//! Bounds the bcrypt work of the server.
//!
//! A bcrypt hash or verify takes tens to hundreds of milliseconds of
//! CPU (by its cost). Run on an async worker, a handful at once
//! (unauthenticated logins, guesses at an api key's secret) would
//! stall every other request of the server, so it runs on tokio's
//! blocking pool. That pool has hundreds of threads and an unbounded
//! queue, which every other blocking task shares (file io, the DNS
//! lookups of outgoing requests). So at most one bcrypt per available
//! core runs at a time for each budget, the others wait their turn on
//! an async semaphore without holding a thread. A request which is
//! dropped while it waits (the client disconnects) never runs its
//! bcrypt.
//!
//! There are two budgets, so a flood of one kind waits behind itself:
//! - logins ([spawn_bcrypt]): passwords and recovery codes, of logins,
//!   sign ups, password changes and 2fa enrollment, and the passwords
//!   apps hash with [hash_password].
//! - api keys ([spawn_api_key_bcrypt]): the secret of every request
//!   naming an api key which exists (an unknown key is refused
//!   without a bcrypt), and the secrets of new api keys. Anybody who
//!   knows a key id can send guesses at its secret, they don't queue
//!   ahead of password logins.

use std::{
  num::NonZero,
  sync::{Arc, LazyLock},
  thread::available_parallelism,
};

use anyhow::Context as _;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

fn available_cores() -> usize {
  available_parallelism().map(NonZero::get).unwrap_or(1)
}

/// One permit per available core.
fn core_permits() -> Arc<Semaphore> {
  Arc::new(Semaphore::new(available_cores()))
}

/// The budget of [spawn_bcrypt].
static LOGIN_PERMITS: LazyLock<Arc<Semaphore>> =
  LazyLock::new(core_permits);

/// The budget of [spawn_api_key_bcrypt].
static API_KEY_PERMITS: LazyLock<Arc<Semaphore>> =
  LazyLock::new(core_permits);

/// Runs the bcrypt work `f` of a login (password, recovery code) on
/// tokio's blocking pool, at most one per available core at a time
/// (see [the module][self]).
pub(crate) async fn spawn_bcrypt<T: Send + 'static>(
  f: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
  spawn_bcrypt_with(&LOGIN_PERMITS, f).await
}

/// Runs the bcrypt work `f` of an api key secret on tokio's blocking
/// pool, at most one per available core at a time, on a budget of its
/// own (see [the module][self]).
pub(crate) async fn spawn_api_key_bcrypt<T: Send + 'static>(
  f: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
  spawn_bcrypt_with(&API_KEY_PERMITS, f).await
}

/// Runs `f` on tokio's blocking pool once one of the `permits` is
/// free, holding it until `f` is done.
async fn spawn_bcrypt_with<T: Send + 'static>(
  permits: &Arc<Semaphore>,
  f: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
  let permit = permits
    .clone()
    .acquire_owned()
    .await
    .context("bcrypt permits closed")?;
  tokio::task::spawn_blocking(move || {
    // Held until the work is done, also when the caller
    // stops waiting for it (the client disconnects).
    let _permit = permit;
    f()
  })
  .await
  .context("bcrypt task failed")
}

/// The bcrypt hash of `secret`, off the async runtime
/// (see [spawn_bcrypt]).
pub(crate) async fn bcrypt_hash(
  secret: &[u8],
  cost: u32,
) -> anyhow::Result<String> {
  let secret = Zeroizing::new(secret.to_vec());
  spawn_bcrypt(move || bcrypt::hash(&*secret, cost))
    .await?
    .context("Failed to hash secret")
}

/// The bcrypt hash of a password, at `cost`, as the server hashes
/// the password of a sign up or of `UpdatePassword`: off the async
/// runtime, on the server's budget of login bcrypt work (at most one
/// per available core at a time, shared with the logins, waiting its
/// turn without holding a thread), its copy of the password wiped
/// once hashed.
///
/// For an app which sets passwords itself (eg. an admin creating a
/// user with one): hashed here, they take their turn with the
/// server's logins rather than add bcrypt work of their own next to
/// them. Pass the app's
/// [AuthImpl::local_auth_bcrypt_cost][crate::AuthImpl::local_auth_bcrypt_cost],
/// and validate the password first
/// ([AuthImpl::validate_password][crate::AuthImpl::validate_password]):
/// bcrypt only uses the first 72 bytes. Fails (`500`) for a cost
/// outside bcrypt's 4 to 31.
pub async fn hash_password(
  password: &str,
  cost: u32,
) -> mogh_error::Result<String> {
  bcrypt_hash(password.as_bytes(), cost)
    .await
    .context("Failed to hash the password")
    .map_err(Into::into)
}

/// Whether `secret` matches the bcrypt `hash`, off the async
/// runtime (see [spawn_bcrypt]). Errors if the hash is malformed.
pub(crate) async fn bcrypt_verify(
  secret: &[u8],
  hash: &str,
) -> anyhow::Result<bool> {
  let secret = Zeroizing::new(secret.to_vec());
  let hash = hash.to_string();
  spawn_bcrypt(move || bcrypt::verify(&*secret, &hash))
    .await?
    .context("Failed to verify secret")
}

/// Takes every permit of the api key budget, so tests can check that
/// api key bcrypt work waits for them.
#[cfg(test)]
pub(crate) async fn hold_api_key_permits()
-> tokio::sync::OwnedSemaphorePermit {
  API_KEY_PERMITS
    .clone()
    .acquire_many_owned(available_cores() as u32)
    .await
    .unwrap()
}

/// Takes every permit of the login budget, so tests can check that
/// login bcrypt work waits for them.
#[cfg(test)]
async fn hold_login_permits() -> tokio::sync::OwnedSemaphorePermit {
  LOGIN_PERMITS
    .clone()
    .acquire_many_owned(available_cores() as u32)
    .await
    .unwrap()
}

#[cfg(test)]
mod tests {
  use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
  };

  use super::*;

  /// Runs `count` jobs of `work` through `permits` at once, and
  /// returns how many ran at the same time at most.
  async fn peak_concurrency(
    permits: &Arc<Semaphore>,
    count: usize,
    work: Duration,
  ) -> usize {
    let running = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut jobs = tokio::task::JoinSet::new();
    for _ in 0..count {
      let permits = permits.clone();
      let running = running.clone();
      let peak = peak.clone();
      jobs.spawn(async move {
        spawn_bcrypt_with(&permits, move || {
          let now = running.fetch_add(1, Ordering::SeqCst) + 1;
          peak.fetch_max(now, Ordering::SeqCst);
          std::thread::sleep(work);
          running.fetch_sub(1, Ordering::SeqCst);
        })
        .await
      });
    }
    for res in jobs.join_all().await {
      res.unwrap();
    }
    peak.load(Ordering::SeqCst)
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn test_concurrent_bcrypt_never_exceeds_permits() {
    for permits in [1, 3] {
      let semaphore = Arc::new(Semaphore::new(permits));
      let peak = peak_concurrency(
        &semaphore,
        4 * permits,
        Duration::from_millis(20),
      )
      .await;
      assert!(
        (1..=permits).contains(&peak),
        "{peak} ran at once with {permits} permits"
      );
      // All given back.
      assert_eq!(semaphore.available_permits(), permits);
    }
  }

  /// Bcrypt work waiting for a permit doesn't hold a blocking thread:
  /// other blocking work (file io, DNS lookups) isn't queued behind a
  /// flood of it.
  #[test]
  fn test_waiting_bcrypt_does_not_hold_blocking_threads() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(1)
      .max_blocking_threads(2)
      .enable_all()
      .build()
      .unwrap();
    runtime.block_on(async {
      let permits = Arc::new(Semaphore::new(1));
      let flood = (0..20)
        .map(|_| {
          let permits = permits.clone();
          tokio::spawn(async move {
            spawn_bcrypt_with(&permits, || {
              std::thread::sleep(Duration::from_millis(50))
            })
            .await
          })
        })
        .collect::<Vec<_>>();
      // Let the flood start.
      tokio::time::sleep(Duration::from_millis(10)).await;
      let start = Instant::now();
      tokio::task::spawn_blocking(|| ()).await.unwrap();
      // The flood takes a second to get through, one at a time.
      // Queued in the blocking pool instead, this would wait for
      // half of it.
      assert!(
        start.elapsed() < Duration::from_millis(250),
        "waited {:?} for a blocking thread",
        start.elapsed()
      );
      for job in flood {
        job.await.unwrap().unwrap();
      }
    });
  }

  #[tokio::test]
  async fn test_api_key_bcrypt_waits_for_its_permits() {
    let held = hold_api_key_permits().await;
    let job = tokio::spawn(spawn_api_key_bcrypt(|| 1));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!job.is_finished(), "ran without a permit");
    // Logins have their own budget.
    assert!(
      tokio::time::timeout(
        Duration::from_secs(5),
        spawn_bcrypt(|| 2)
      )
      .await
      .is_ok(),
      "logins waited for the api key budget"
    );
    drop(held);
    assert_eq!(job.await.unwrap().unwrap(), 1);
  }

  /// An app's password hash takes its turn on the login budget: with
  /// every permit taken it waits, then hashes the password so a login
  /// with it verifies.
  #[tokio::test]
  async fn test_hash_password_takes_the_login_budget() {
    let held = hold_login_permits().await;
    let hash = tokio::spawn(hash_password("a-password", 4));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!hash.is_finished(), "hashed without a permit");
    drop(held);
    let hash = hash.await.unwrap().unwrap();
    assert!(bcrypt_verify(b"a-password", &hash).await.unwrap());
    assert!(!bcrypt_verify(b"another", &hash).await.unwrap());
    // A cost bcrypt refuses is a server error.
    let err = hash_password("a-password", 3).await.unwrap_err();
    assert!(err.status.is_server_error());
  }

  #[tokio::test]
  async fn test_bcrypt_hash_and_verify() {
    let hash = bcrypt_hash(b"password", 4).await.unwrap();
    assert!(bcrypt_verify(b"password", &hash).await.unwrap());
    assert!(!bcrypt_verify(b"other", &hash).await.unwrap());
    assert!(bcrypt_verify(b"password", "not a hash").await.is_err());
  }
}
