use std::{
  sync::{
    RwLock,
    atomic::{AtomicU64, Ordering},
  },
  time::Duration,
};

use tokio::time::Instant;

/// One value loaded on demand (eg. a listing from the database),
/// served from memory for `ttl` after it is loaded, then dropped.
///
/// Made for a value which is read on every request, often an
/// unauthenticated one (eg. the login providers a login page
/// lists, the token issuers every token exchange checks), and
/// changed rarely, through the app:
///
/// - Concurrent readers which miss wait for one load, rather than
///   each hitting the database.
/// - The app calls [invalidate](LoadCache::invalidate) after every
///   write, which drops the value right away. So `ttl` only bounds
///   how long a change made elsewhere (directly on the database, or
///   by another process) goes unnoticed.
/// - A load which started before an invalidation returns its result
///   to its caller, but never caches it: it may predate the write.
/// - A failed load caches nothing. The readers which waited for it
///   share its failure ([LoadFailed]) rather than each loading again
///   in turn; the next reader to come loads again.
/// - The value is dropped once `ttl` is over, not just hidden until
///   the next load replaces it: what is cached may be secret (eg.
///   decrypted client secrets, wiped on drop), and must not sit in
///   memory for as long as nobody happens to ask again.
///
/// The cache is meant to be a `static` ([new](LoadCache::new) is
/// `const`): [read_or_load](LoadCache::read_or_load) takes
/// `&'static self`, as it spawns a task which drops the value at
/// expiry. It caches on a tokio runtime only, where it can spawn
/// that task.
///
/// ```
/// use std::time::Duration;
/// use mogh_cache::LoadCache;
///
/// static PROVIDERS: LoadCache<Vec<String>> =
///   LoadCache::new(Duration::from_secs(30));
///
/// async fn query_providers() -> anyhow::Result<Vec<String>> {
///   Ok(vec![String::from("github")])
/// }
///
/// /// Misses included, served from memory.
/// async fn get_provider(
///   name: &str,
/// ) -> anyhow::Result<Option<String>> {
///   PROVIDERS
///     .read_or_load(query_providers, |providers| {
///       // Only what is asked for is cloned.
///       providers.iter().find(|provider| *provider == name).cloned()
///     })
///     .await
/// }
///
/// async fn create_provider(name: String) -> anyhow::Result<()> {
///   // Written to the database, then:
///   PROVIDERS.invalidate();
///   Ok(())
/// }
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> anyhow::Result<()> {
/// #   let github = get_provider("github").await?;
/// #   assert_eq!(github.as_deref(), Some("github"));
/// #   assert!(get_provider("gitlab").await?.is_none());
/// #   create_provider(String::from("gitlab")).await?;
/// #   assert!(PROVIDERS.read(Vec::len).is_none());
/// #   Ok(())
/// # }
/// ```
pub struct LoadCache<T> {
  ttl: Duration,
  /// The value, and when it was loaded.
  entry: RwLock<Option<(Instant, T)>>,
  /// Bumped by every [LoadCache::invalidate]: a load that started
  /// before a write must not store its (pre-write) result after it.
  generation: AtomicU64,
  /// Concurrent misses await one load instead of each hitting the
  /// database.
  loading: tokio::sync::Mutex<()>,
  /// Bumped (holding `loading`) by every load which fails: a caller
  /// which saw a lower count before it waited queued behind a
  /// failure, and shares it rather than loading again.
  failures: AtomicU64,
}

/// The error of a [LoadCache::read_or_load] caller which waited for
/// another caller's load, which failed: it shares that failure
/// rather than loading again right away (in a database outage, each
/// of the callers queued behind a load would otherwise wait for every
/// load ahead of it to time out). The failing load's own error went
/// to the caller which ran it. The next call loads again: retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadFailed;

impl std::fmt::Display for LoadFailed {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(
      "The load this request waited for failed (its error went to the request which ran it): retry",
    )
  }
}

impl std::error::Error for LoadFailed {}

impl<T> LoadCache<T> {
  /// A cache which serves a value for `ttl` after it is loaded.
  /// Writes through the app [invalidate](LoadCache::invalidate) the
  /// cache right away, so `ttl` only bounds how long a change made
  /// elsewhere (directly on the database) goes unnoticed.
  pub const fn new(ttl: Duration) -> LoadCache<T> {
    LoadCache {
      ttl,
      entry: RwLock::new(None),
      generation: AtomicU64::new(0),
      loading: tokio::sync::Mutex::const_new(()),
      failures: AtomicU64::new(0),
    }
  }

  /// Drops the cached value (running its `Drop`), and keeps a load
  /// already in flight from caching its result. Call it after every
  /// write to what the value is loaded from.
  pub fn invalidate(&self) {
    self.generation.fetch_add(1, Ordering::SeqCst);
    *self.entry.write().unwrap_or_else(|e| e.into_inner()) = None;
  }

  /// Reads the cached value, if loaded less than `ttl` ago. Never
  /// loads. `read` picks what the caller needs from it, so only that
  /// is cloned (every clone of a secret is another copy to wipe).
  pub fn read<R>(&self, read: impl FnOnce(&T) -> R) -> Option<R> {
    self
      .entry
      .read()
      .unwrap_or_else(|e| e.into_inner())
      .as_ref()
      .filter(|(loaded_at, _)| loaded_at.elapsed() < self.ttl)
      .map(|(_, value)| read(value))
  }

  /// [read](LoadCache::read), loading (and caching) the value with
  /// `load` when there is none, or it expired.
  ///
  /// Concurrent callers which miss wait for one load: the first
  /// loads, and the others read what it cached. A failed load
  /// returns its error to its caller and caches nothing, and the
  /// callers which waited for it share its failure: they return
  /// [LoadFailed] (into `E`), at about the time of that one load,
  /// rather than each loading again in turn. Only callers which come
  /// after the failure load again. Dropping the returned future (eg.
  /// a cancelled request) drops its load, which is no failure: the
  /// next caller in line loads. A load overtaken by an
  /// [invalidate](LoadCache::invalidate) returns its result to its
  /// caller, without caching it.
  ///
  /// The cached value is dropped once it expires, by a task spawned
  /// here on the tokio runtime, not just hidden until the next load
  /// replaces it: what is cached may be secret (decrypted client
  /// secrets, wiped on drop), and must not sit in memory for as long
  /// as nobody happens to ask again. That task is why this takes
  /// `&'static self`. Outside a tokio runtime no task could drop it,
  /// so nothing is cached: every call loads. The runtime needs its
  /// timer (as `#[tokio::main]` sets up) for the task to run.
  pub async fn read_or_load<R, E, F>(
    &'static self,
    load: impl FnOnce() -> F,
    read: impl Fn(&T) -> R,
  ) -> Result<R, E>
  where
    T: Send + Sync,
    F: Future<Output = Result<T, E>>,
    E: From<LoadFailed>,
  {
    if let Some(read) = self.read(&read) {
      return Ok(read);
    }
    // Before waiting: a failure counted after this is one of a load
    // ahead of us.
    let failures = self.failures.load(Ordering::SeqCst);
    let _loading = self.loading.lock().await;
    // The load ahead of us may have finished while we waited.
    if let Some(read) = self.read(&read) {
      return Ok(read);
    }
    // Or failed: its outcome is ours too.
    if self.failures.load(Ordering::SeqCst) != failures {
      return Err(LoadFailed.into());
    }
    let generation = self.generation.load(Ordering::SeqCst);
    let value = match load().await {
      Ok(value) => value,
      Err(e) => {
        // Still holding `loading`: every caller waiting now sees it.
        self.failures.fetch_add(1, Ordering::SeqCst);
        return Err(e);
      }
    };
    let result = read(&value);
    let mut entry =
      self.entry.write().unwrap_or_else(|e| e.into_inner());
    // The generation is checked under the write lock invalidate
    // also takes. Outside a tokio runtime there is no task to drop
    // the value at expiry, so it is not cached.
    if self.generation.load(Ordering::SeqCst) == generation
      && let Ok(runtime) = tokio::runtime::Handle::try_current()
    {
      *entry = Some((Instant::now(), value));
      runtime.spawn(self.drop_expired());
    }
    Ok(result)
  }

  /// Drops the entry once its ttl is over, unless a newer one took
  /// its place (that one has its own sweep).
  async fn drop_expired(&'static self) {
    tokio::time::sleep(self.ttl).await;
    let mut entry =
      self.entry.write().unwrap_or_else(|e| e.into_inner());
    if entry
      .as_ref()
      .is_some_and(|(loaded_at, _)| loaded_at.elapsed() >= self.ttl)
    {
      *entry = None;
    }
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicBool, AtomicUsize};

  use super::*;

  const TTL: Duration = Duration::from_secs(60);

  /// The caches are statics where they are used.
  fn leak<T>(cache: LoadCache<T>) -> &'static LoadCache<T> {
    Box::leak(Box::new(cache))
  }

  fn is_empty<T>(cache: &LoadCache<T>) -> bool {
    cache.entry.read().unwrap().is_none()
  }

  /// The error of the loads here: the loader's own, or the one of a
  /// caller which waited for a load that failed.
  #[derive(Debug, PartialEq)]
  enum TestError {
    Load(&'static str),
    Waited,
  }

  impl From<LoadFailed> for TestError {
    fn from(LoadFailed: LoadFailed) -> TestError {
      TestError::Waited
    }
  }

  /// An expired value is dropped (running its `Drop`, which wipes
  /// cached secrets), not merely hidden from readers, without
  /// anyone reading it again.
  #[tokio::test(start_paused = true)]
  async fn expired_values_are_dropped() {
    static DROPPED: AtomicBool = AtomicBool::new(false);
    struct Secret;
    impl Drop for Secret {
      fn drop(&mut self) {
        DROPPED.store(true, Ordering::SeqCst);
      }
    }
    let cache = leak(LoadCache::<Secret>::new(TTL));
    cache
      .read_or_load(|| async { Ok::<_, TestError>(Secret) }, |_| ())
      .await
      .unwrap();
    tokio::time::sleep(TTL / 2).await;
    assert!(!DROPPED.load(Ordering::SeqCst));
    assert!(cache.read(|_| ()).is_some());
    tokio::time::sleep(TTL).await;
    assert!(DROPPED.load(Ordering::SeqCst));
    assert!(is_empty(cache));
  }

  #[tokio::test]
  async fn loads_once_until_invalidated() {
    let cache = leak(LoadCache::<Vec<u32>>::new(TTL));
    assert!(cache.read(|value| value.len()).is_none());
    let load = |value: u32| {
      move || async move { Ok::<_, TestError>(vec![value]) }
    };
    let first = cache.read_or_load(load(1), Vec::clone).await;
    assert_eq!(first.unwrap(), [1]);
    // Served from memory: the loader is not consulted.
    let second = cache.read_or_load(load(2), Vec::clone).await;
    assert_eq!(second.unwrap(), [1]);
    cache.invalidate();
    assert!(is_empty(cache));
    let third = cache.read_or_load(load(3), Vec::clone).await;
    assert_eq!(third.unwrap(), [3]);
  }

  #[tokio::test]
  async fn expired_and_failed_loads_are_not_served() {
    let cache = leak(LoadCache::<u32>::new(Duration::ZERO));
    cache
      .read_or_load(
        || async { Ok::<_, TestError>(1) },
        |value| *value,
      )
      .await
      .unwrap();
    assert!(cache.read(|value| *value).is_none());

    let cache = leak(LoadCache::<u32>::new(TTL));
    let failed = cache
      .read_or_load(
        || async { Err(TestError::Load("database down")) },
        |value| *value,
      )
      .await;
    assert_eq!(failed, Err(TestError::Load("database down")));
    assert!(is_empty(cache));
    // The next read loads again.
    let loaded = cache
      .read_or_load(
        || async { Ok::<_, TestError>(2) },
        |value| *value,
      )
      .await;
    assert_eq!(loaded, Ok(2));
  }

  /// A write landing while a load is in flight wins: the load's
  /// (pre-write) result is returned to its caller, never cached.
  #[tokio::test]
  async fn a_load_never_caches_over_an_invalidation() {
    let cache = leak(LoadCache::<u32>::new(TTL));
    let stale = cache
      .read_or_load(
        || async {
          cache.invalidate();
          Ok::<_, TestError>(1)
        },
        |value| *value,
      )
      .await;
    assert_eq!(stale.unwrap(), 1);
    assert!(is_empty(cache));
  }

  /// Readers which miss while a load is in flight wait for it, and
  /// read what it cached, rather than each loading.
  #[tokio::test(start_paused = true)]
  async fn concurrent_misses_share_one_load() {
    static LOADS: AtomicUsize = AtomicUsize::new(0);
    let cache = leak(LoadCache::<u32>::new(TTL));
    let load = || async {
      LOADS.fetch_add(1, Ordering::SeqCst);
      tokio::time::sleep(Duration::from_secs(1)).await;
      Ok::<_, TestError>(7)
    };
    let readers = (0..10)
      .map(|_| tokio::spawn(cache.read_or_load(load, |value| *value)))
      .collect::<Vec<_>>();
    for reader in readers {
      assert_eq!(reader.await.unwrap(), Ok(7));
    }
    assert_eq!(LOADS.load(Ordering::SeqCst), 1);
  }

  /// Callers which queued behind a failing load share its failure,
  /// rather than each loading again in turn: during a database
  /// outage the k-th would answer after k load timeouts. Only callers
  /// arriving after the failure load again.
  #[tokio::test(start_paused = true)]
  async fn waiters_share_a_failed_load() {
    static LOADS: AtomicUsize = AtomicUsize::new(0);
    const LOAD_TIME: Duration = Duration::from_secs(30);
    let cache = leak(LoadCache::<u32>::new(TTL));
    let failing = || async {
      LOADS.fetch_add(1, Ordering::SeqCst);
      tokio::time::sleep(LOAD_TIME).await;
      Err::<u32, _>(TestError::Load("database down"))
    };
    let start = Instant::now();
    // The first loads, the ten others miss while it is in flight.
    let callers = (0..11)
      .map(|_| {
        tokio::spawn(async move {
          let res = cache.read_or_load(failing, |value| *value).await;
          (res, start.elapsed())
        })
      })
      .collect::<Vec<_>>();
    let mut waited = 0;
    for caller in callers {
      let (res, elapsed) = caller.await.unwrap();
      // All at about one load's time.
      assert!(
        elapsed < LOAD_TIME + Duration::from_secs(1),
        "{elapsed:?}"
      );
      match res {
        Err(TestError::Load(_)) => {}
        Err(TestError::Waited) => waited += 1,
        Ok(_) => panic!("loaded"),
      }
    }
    assert_eq!(waited, 10);
    assert_eq!(LOADS.load(Ordering::SeqCst), 1);
    assert!(is_empty(cache));
    // A caller arriving after the failure loads again.
    let again = cache
      .read_or_load(
        || async { Ok::<_, TestError>(3) },
        |value| *value,
      )
      .await;
    assert_eq!(again, Ok(3));
  }

  /// A load dropped with its caller (a cancelled request) is no
  /// failure: the next caller in line loads, rather than share one.
  #[tokio::test(start_paused = true)]
  async fn a_dropped_load_is_no_failure_to_share() {
    let cache = leak(LoadCache::<u32>::new(TTL));
    let slow = || async {
      tokio::time::sleep(Duration::from_secs(30)).await;
      Ok::<_, TestError>(1)
    };
    let first =
      tokio::spawn(cache.read_or_load(slow, |value| *value));
    // Queued behind the first's load.
    tokio::task::yield_now().await;
    let waiter = tokio::spawn(cache.read_or_load(
      || async { Ok::<_, TestError>(2) },
      |value| *value,
    ));
    tokio::task::yield_now().await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert_eq!(waiter.await.unwrap(), Ok(2));
    assert_eq!(cache.read(|value| *value), Some(2));
  }

  /// Outside a tokio runtime no task could drop the value at
  /// expiry, so it is not cached: every call loads, and none panics.
  #[test]
  fn nothing_is_cached_outside_a_tokio_runtime() {
    use std::{
      pin::pin,
      task::{Context, Poll, Waker},
    };

    let cache = leak(LoadCache::<u32>::new(TTL));
    for value in [1, 2] {
      let read = pin!(cache.read_or_load(
        || async move { Ok::<_, TestError>(value) },
        |value| *value
      ));
      // Nothing to wait for: ready on the first poll.
      let Poll::Ready(read) =
        read.poll(&mut Context::from_waker(Waker::noop()))
      else {
        panic!("pending");
      };
      assert_eq!(read, Ok(value));
      assert!(is_empty(cache));
    }
  }

  /// The sweep of a replaced value leaves the newer value, which is
  /// dropped by its own sweep, a ttl after it was loaded.
  #[tokio::test(start_paused = true)]
  async fn a_sweep_leaves_a_newer_value() {
    let cache = leak(LoadCache::<u32>::new(TTL));
    let load =
      |value: u32| move || async move { Ok::<_, TestError>(value) };
    cache.read_or_load(load(1), |value| *value).await.unwrap();
    tokio::time::sleep(TTL / 2).await;
    cache.invalidate();
    cache.read_or_load(load(2), |value| *value).await.unwrap();
    // Past the first value's sweep (at the ttl).
    tokio::time::sleep(TTL * 3 / 4).await;
    assert_eq!(cache.read(|value| *value), Some(2));
    // Past the second value's sweep (at 1.5 times the ttl).
    tokio::time::sleep(TTL / 2).await;
    assert!(is_empty(cache));
  }
}
