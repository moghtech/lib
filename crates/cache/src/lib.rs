use std::{
  collections::{HashMap, HashSet},
  hash::Hash,
  sync::Arc,
  time::Duration,
};

use tokio::{
  sync::{Mutex, RwLock},
  time::Instant,
};

mod load_cache;

pub use load_cache::LoadCache;

/// Lets concurrent / rapid fire calls of an action share one run
/// and its result, which is reused for `timeout` after it is set.
///
/// A caller takes the entry for its key with
/// [get_lock](TimeoutCache::get_lock) and locks it for the length of
/// the action. Concurrent callers for the same key wait on that
/// lock, then find the result in [CacheEntry::fresh_res]:
///
/// ```
/// # use std::time::Duration;
/// # use mogh_cache::TimeoutCache;
/// # async fn pull(image: &str) -> anyhow::Result<String> {
/// #   Ok(image.to_string())
/// # }
/// # async fn cached_pull(
/// #   cache: &TimeoutCache<String, String>,
/// #   image: String,
/// # ) -> anyhow::Result<String> {
/// let lock = cache.get_lock(image.clone()).await;
/// let mut entry = lock.lock().await;
/// if let Some(res) = entry.fresh_res() {
///   return res;
/// }
/// let res = pull(&image).await;
/// entry.set(&res);
/// res
/// # }
/// ```
///
/// The cache prunes itself, so keys taken from request input (an
/// image name, a repo path) don't grow it for the life of the
/// process: when [get_lock](TimeoutCache::get_lock) has grown the
/// map to twice the entries it kept at its last prune (and to at
/// least 64), it drops the entries whose result is no longer fresh.
/// The map therefore stays within twice the most entries in use at
/// once, at an amortized constant cost per new key.
///
/// An entry a caller still holds (between
/// [get_lock](TimeoutCache::get_lock) and dropping the handle) is
/// never removed, by the pruning or by
/// [remove](TimeoutCache::remove), [retain](TimeoutCache::retain)
/// and [prune](TimeoutCache::prune). So eviction can't let a second
/// caller run the same action at the same time.
pub struct TimeoutCache<K, Res> {
  timeout: Duration,
  entries: Mutex<Entries<K, Res>>,
}

/// The map grows to at least this many entries
/// before [TimeoutCache::get_lock] prunes it.
const PRUNE_MIN_LEN: usize = 64;

struct Entries<K, Res> {
  map: HashMap<K, Arc<Mutex<CacheEntry<Res>>>>,
  /// [TimeoutCache::get_lock] prunes once the map has this many
  /// entries: twice what the last prune kept, so the cost of a
  /// prune is spread over as many new keys as it kept.
  prune_at: usize,
}

impl<K, Res> Entries<K, Res> {
  /// Keeps the entries a caller holds and those `keep` returns
  /// true for, then moves the next automatic prune to twice what
  /// is left.
  fn retain(
    &mut self,
    mut keep: impl FnMut(&K, &CacheEntry<Res>) -> bool,
  ) {
    self.map.retain(|key, entry| {
      if is_held(entry) {
        return true;
      }
      // Nobody else can reach an unheld entry, the lock is free.
      match entry.try_lock() {
        Ok(entry) => keep(key, &entry),
        Err(_) => true,
      }
    });
    self.prune_at = (self.map.len() * 2).max(PRUNE_MIN_LEN);
  }

  /// Drops the unheld entries without a fresh result,
  /// returning how many it dropped.
  fn prune(&mut self) -> usize {
    let len = self.map.len();
    let now = Instant::now();
    self.retain(|_, entry| entry.is_fresh_at(now));
    len - self.map.len()
  }
}

impl<K: Eq + Hash, Res> TimeoutCache<K, Res> {
  /// A cache whose results are reused for `timeout` after they
  /// are set.
  pub fn new(timeout: Duration) -> Self {
    Self {
      timeout,
      entries: Mutex::new(Entries {
        map: HashMap::new(),
        prune_at: PRUNE_MIN_LEN,
      }),
    }
  }

  /// How long a result is reused after it is set.
  pub fn timeout(&self) -> Duration {
    self.timeout
  }

  /// The entry for `key`, created without a result if there is
  /// none. Lock it for the length of the action, see
  /// [TimeoutCache].
  ///
  /// When this adds a key and the map has reached twice the
  /// entries the last prune kept (and at least 64), it also prunes
  /// the entries without a fresh result which no caller holds.
  pub async fn get_lock(
    &self,
    key: K,
  ) -> Arc<Mutex<CacheEntry<Res>>> {
    let mut entries = self.entries.lock().await;
    let timeout = self.timeout;
    let entry = entries
      .map
      .entry(key)
      .or_insert_with(|| {
        Arc::new(Mutex::new(CacheEntry::new(timeout)))
      })
      .clone();
    if entries.map.len() >= entries.prune_at {
      // The entry just taken is held, so it stays.
      entries.prune();
    }
    entry
  }

  /// The number of cached keys.
  pub async fn len(&self) -> usize {
    self.entries.lock().await.map.len()
  }

  pub async fn is_empty(&self) -> bool {
    self.entries.lock().await.map.is_empty()
  }

  /// Removes the entry for `key`, unless a caller still holds it
  /// (between [get_lock](TimeoutCache::get_lock) and dropping the
  /// handle). Returns whether an entry was removed.
  pub async fn remove(&self, key: &K) -> bool {
    let mut entries = self.entries.lock().await;
    match entries.map.get(key) {
      Some(entry) if !is_held(entry) => {
        entries.map.remove(key);
        true
      }
      _ => false,
    }
  }

  /// Keeps only the entries `keep` returns true for. Entries a
  /// caller still holds are always kept, without calling `keep`.
  pub async fn retain(
    &self,
    keep: impl FnMut(&K, &CacheEntry<Res>) -> bool,
  ) {
    self.entries.lock().await.retain(keep);
  }

  /// Removes the entries without a fresh result (see
  /// [CacheEntry::is_fresh]) which no caller holds, returning how
  /// many were removed. [get_lock](TimeoutCache::get_lock) already
  /// does this as the map grows, so calling it is only needed to
  /// free the results of a cache which stopped growing sooner.
  pub async fn prune(&self) -> usize {
    self.entries.lock().await.prune()
  }
}

/// Whether a caller holds a handle to the entry. Only called under
/// the map lock, where no new handle can be taken, so a count that
/// reads as unheld stays unheld.
fn is_held<Res>(entry: &Arc<Mutex<CacheEntry<Res>>>) -> bool {
  Arc::strong_count(entry) > 1 || Arc::weak_count(entry) > 0
}

/// The result of the last run of an action of a [TimeoutCache],
/// see [fresh_res](CacheEntry::fresh_res) and
/// [set](CacheEntry::set).
pub struct CacheEntry<Res> {
  /// The cache's timeout.
  timeout: Duration,
  /// The last result and when it was set, None until the first set.
  last: Option<(Instant, anyhow::Result<Res>)>,
}

impl<Res> CacheEntry<Res> {
  fn new(timeout: Duration) -> Self {
    CacheEntry {
      timeout,
      last: None,
    }
  }

  /// When the result was last [set](CacheEntry::set),
  /// None until the first set.
  pub fn last_set(&self) -> Option<Instant> {
    self.last.as_ref().map(|(set_at, _)| *set_at)
  }

  /// Whether the entry has a result set less than the cache's
  /// timeout ago, which [fresh_res](CacheEntry::fresh_res) returns.
  pub fn is_fresh(&self) -> bool {
    self.is_fresh_at(Instant::now())
  }

  fn is_fresh_at(&self, now: Instant) -> bool {
    self.last.as_ref().is_some_and(|(set_at, _)| {
      now.saturating_duration_since(*set_at) < self.timeout
    })
  }
}

impl<Res: Clone> CacheEntry<Res> {
  /// A copy of the result set less than the cache's timeout ago,
  /// errors included, or None when the action has to run (again).
  pub fn fresh_res(&self) -> Option<anyhow::Result<Res>> {
    if !self.is_fresh() {
      return None;
    }
    let (_, res) = self.last.as_ref()?;
    Some(res.as_ref().map_err(clone_anyhow_error).cloned())
  }

  /// Stores a copy of the action's result, reused for the cache's
  /// timeout from now. Set it after the action finished, so waiting
  /// callers get the whole timeout.
  pub fn set(&mut self, res: &anyhow::Result<Res>) {
    let res = res.as_ref().map_err(clone_anyhow_error).cloned();
    self.last = Some((Instant::now(), res));
  }
}

fn clone_anyhow_error(e: &anyhow::Error) -> anyhow::Error {
  let mut reasons =
    e.chain().map(|e| e.to_string()).collect::<Vec<_>>();
  // Always guaranteed to be at least one reason
  // Need to start the chain with the last reason
  let mut e = anyhow::Error::msg(reasons.pop().unwrap());
  // Need to reverse reason application from lowest context to highest context.
  for reason in reasons.into_iter().rev() {
    e = e.context(reason)
  }
  e
}

#[derive(Debug)]
pub struct CloneCache<K: PartialEq + Eq + Hash, T: Clone>(
  RwLock<HashMap<K, T>>,
);

impl<K: PartialEq + Eq + Hash, T: Clone> Default
  for CloneCache<K, T>
{
  fn default() -> Self {
    Self(RwLock::new(HashMap::new()))
  }
}

// Note. No `Debug` bounds: cached values are often
// secrets (tokens, provider configs) without a `Debug` impl.
impl<K: PartialEq + Eq + Hash + Clone, T: Clone> CloneCache<K, T> {
  pub async fn get(&self, key: &K) -> Option<T> {
    self.0.read().await.get(key).cloned()
  }

  pub async fn get_keys(&self) -> Vec<K> {
    let cache = self.0.read().await;
    cache.keys().cloned().collect()
  }

  pub async fn get_values(&self) -> Vec<T> {
    let cache = self.0.read().await;
    cache.values().cloned().collect()
  }

  pub async fn get_entries(&self) -> Vec<(K, T)> {
    let cache = self.0.read().await;
    cache.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
  }

  pub async fn insert<Key>(&self, key: Key, val: T) -> Option<T>
  where
    Key: Into<K>,
  {
    self.0.write().await.insert(key.into(), val)
  }

  pub async fn remove(&self, key: &K) -> Option<T> {
    self.0.write().await.remove(key)
  }

  ///Retains only the elements specified by the predicate.
  ///
  /// In other words, remove all pairs (k, v) for which f(&k, &mut v) returns false. The elements are visited in unsorted (and unspecified) order.
  pub async fn retain(&self, retain: impl FnMut(&K, &mut T) -> bool) {
    self.0.write().await.retain(retain);
  }

  pub async fn get_or_insert_with(
    &self,
    key: &K,
    default: impl FnOnce() -> T,
  ) -> T {
    let mut lock = self.0.write().await;
    match lock.get(key).cloned() {
      Some(item) => item,
      None => {
        let item: T = default();
        lock.insert(key.clone(), item.clone());
        item
      }
    }
  }
}

impl<K: PartialEq + Eq + Hash + Clone, T: Clone + Default>
  CloneCache<K, T>
{
  pub async fn get_or_insert_default(&self, key: &K) -> T {
    self.get_or_insert_with(key, T::default).await
  }
}

pub struct CloneVecCache<T: Clone>(RwLock<Vec<T>>);

impl<T: Clone> Default for CloneVecCache<T> {
  fn default() -> Self {
    Self(RwLock::new(Vec::new()))
  }
}

impl<T: Clone> CloneVecCache<T> {
  pub async fn find(
    &self,
    find: impl FnMut(&&T) -> bool,
  ) -> Option<T> {
    self.0.read().await.iter().find(find).cloned()
  }

  pub async fn list(&self) -> Vec<T> {
    self.0.read().await.clone()
  }

  pub async fn insert(
    &self,
    find: impl FnMut(&T) -> bool,
    mut val: T,
  ) -> Option<T> {
    let mut cache = self.0.write().await;
    let index = cache.iter().position(find);
    if let Some(index) = index {
      std::mem::swap(&mut cache[index], &mut val);
      Some(val)
    } else {
      cache.push(val);
      None
    }
  }

  pub async fn remove(
    &self,
    find: impl FnMut(&T) -> bool,
  ) -> Option<T> {
    let mut cache = self.0.write().await;
    let index = cache.iter().position(find)?;
    Some(cache.swap_remove(index))
  }

  pub async fn retain(&self, keep: impl FnMut(&T) -> bool) {
    self.0.write().await.retain(keep);
  }
}

pub struct SetCache<K>(Mutex<HashSet<K>>);

impl<K> Default for SetCache<K> {
  fn default() -> Self {
    Self(Default::default())
  }
}

impl<K: Eq + Hash> SetCache<K> {
  pub async fn contains(&self, key: &K) -> bool {
    self.0.lock().await.contains(key)
  }

  pub async fn insert(&self, key: K) -> bool {
    self.0.lock().await.insert(key)
  }

  pub async fn remove(&self, key: &K) -> bool {
    self.0.lock().await.remove(key)
  }

  pub async fn retain(&self, retain: impl FnMut(&K) -> bool) {
    self.0.lock().await.retain(retain);
  }
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicUsize, Ordering};

  use super::*;

  #[tokio::test]
  async fn clone_cache_does_not_need_debug() {
    // Eg. a secret, which deliberately has no Debug impl.
    #[derive(Clone, PartialEq, Eq, Hash)]
    struct NoDebugKey(u8);
    #[derive(Clone)]
    struct NoDebugValue(&'static str);

    let cache = CloneCache::<NoDebugKey, NoDebugValue>::default();
    assert!(
      cache
        .insert(NoDebugKey(1), NoDebugValue("a"))
        .await
        .is_none()
    );
    assert_eq!(cache.get(&NoDebugKey(1)).await.unwrap().0, "a");
    let value = cache
      .get_or_insert_with(&NoDebugKey(2), || NoDebugValue("b"))
      .await;
    assert_eq!(value.0, "b");
    assert_eq!(cache.get_keys().await.len(), 2);
    assert_eq!(cache.remove(&NoDebugKey(1)).await.unwrap().0, "a");
  }

  #[test]
  fn clone_anyhow_error_preserves_context_chain() {
    let e = anyhow::anyhow!("root cause")
      .context("middle context")
      .context("top context");
    let cloned = clone_anyhow_error(&e);
    let original =
      e.chain().map(|e| e.to_string()).collect::<Vec<_>>();
    let clone =
      cloned.chain().map(|e| e.to_string()).collect::<Vec<_>>();
    assert_eq!(
      original,
      vec!["top context", "middle context", "root cause"]
    );
    assert_eq!(original, clone);
    assert_eq!(format!("{e:#}"), format!("{cloned:#}"));
  }

  #[test]
  fn clone_anyhow_error_single_message() {
    let e = anyhow::anyhow!("only reason");
    let cloned = clone_anyhow_error(&e);
    assert_eq!(cloned.chain().count(), 1);
    assert_eq!(cloned.to_string(), "only reason");
  }

  const TIMEOUT: Duration = Duration::from_secs(5);

  #[tokio::test]
  async fn timeout_cache_returns_same_entry_for_same_key() {
    let cache = TimeoutCache::<&str, u64>::new(TIMEOUT);
    assert_eq!(cache.timeout(), TIMEOUT);
    let a = cache.get_lock("key").await;
    let b = cache.get_lock("key").await;
    assert!(Arc::ptr_eq(&a, &b));
    let c = cache.get_lock("other").await;
    assert!(!Arc::ptr_eq(&a, &c));
  }

  #[tokio::test(start_paused = true)]
  async fn timeout_cache_reuses_result_until_timeout() {
    let cache = TimeoutCache::<&str, u64>::new(TIMEOUT);
    let entry = cache.get_lock("key").await;
    {
      let mut entry = entry.lock().await;
      // No result yet: the action has to run.
      assert!(entry.last_set().is_none());
      assert!(!entry.is_fresh());
      assert!(entry.fresh_res().is_none());
      entry.set(&Ok(42));
    }
    // The cached result is visible through another handle.
    let entry = cache.get_lock("key").await;
    let mut entry = entry.lock().await;
    assert_eq!(entry.last_set(), Some(Instant::now()));
    assert_eq!(entry.fresh_res().unwrap().unwrap(), 42);
    tokio::time::advance(TIMEOUT - Duration::from_millis(1)).await;
    assert_eq!(entry.fresh_res().unwrap().unwrap(), 42);
    // Stale from the timeout on.
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(!entry.is_fresh());
    assert!(entry.fresh_res().is_none());
    // Errors are cached too, cloned with context intact.
    let err: anyhow::Result<u64> =
      Err(anyhow::anyhow!("inner").context("outer"));
    entry.set(&err);
    let cloned = entry.fresh_res().unwrap().unwrap_err();
    assert_eq!(format!("{cloned:#}"), "outer: inner");
  }

  #[tokio::test(start_paused = true)]
  async fn timeout_cache_zero_timeout_never_reuses() {
    let cache = TimeoutCache::<&str, u64>::new(Duration::ZERO);
    let entry = cache.get_lock("key").await;
    let mut entry = entry.lock().await;
    entry.set(&Ok(1));
    assert!(entry.fresh_res().is_none());
  }

  /// Sets the entry for `key` to a result, now.
  async fn set_now(
    cache: &TimeoutCache<&str, u64>,
    key: &'static str,
  ) {
    cache.get_lock(key).await.lock().await.set(&Ok(1));
  }

  #[tokio::test(start_paused = true)]
  async fn timeout_cache_prune_drops_stale_unheld_entries() {
    let cache = TimeoutCache::<&str, u64>::new(TIMEOUT);
    set_now(&cache, "stale").await;
    set_now(&cache, "held").await;
    set_now(&cache, "locked").await;
    tokio::time::advance(TIMEOUT).await;
    set_now(&cache, "fresh").await;
    // A caller between get_lock and dropping the handle.
    let held = cache.get_lock("held").await;
    // A caller mid action, holding the entry lock.
    let locked = cache.get_lock("locked").await;
    let guard = locked.lock().await;
    assert_eq!(cache.len().await, 4);

    assert_eq!(cache.prune().await, 1);
    assert_eq!(cache.len().await, 3);
    // The stale entry is gone: the next caller starts over.
    let entry = cache.get_lock("stale").await;
    assert!(entry.lock().await.last_set().is_none());
    drop(entry);
    // Held entries survive, so a second caller still waits on the
    // same one instead of running the action alongside.
    assert!(Arc::ptr_eq(&held, &cache.get_lock("held").await));
    assert!(Arc::ptr_eq(&locked, &cache.get_lock("locked").await));

    drop(guard);
    drop(locked);
    drop(held);
    // "stale" (recreated without a result) + "held" + "locked".
    assert_eq!(cache.prune().await, 3);
    assert_eq!(cache.len().await, 1);
    assert!(!cache.is_empty().await);
    tokio::time::advance(TIMEOUT).await;
    assert_eq!(cache.prune().await, 1);
    assert!(cache.is_empty().await);
  }

  /// Every key is used once, as when keys come from request input:
  /// the cache drops the stale ones by itself as it grows.
  #[tokio::test(start_paused = true)]
  async fn timeout_cache_prunes_itself_as_it_grows() {
    let cache = TimeoutCache::<u64, u64>::new(TIMEOUT);
    // Held throughout, and long stale: never dropped.
    let held = cache.get_lock(u64::MAX).await;
    for i in 0..1_000 {
      cache.get_lock(i).await.lock().await.set(&Ok(i));
      // At most 10 results are fresh at once, so with the held
      // entries, a prune keeps few enough for the floor to apply.
      tokio::time::advance(TIMEOUT / 10).await;
      assert!(cache.len().await <= PRUNE_MIN_LEN, "{i}");
    }
    assert!(Arc::ptr_eq(&held, &cache.get_lock(u64::MAX).await));
    // The last results are still there to be reused.
    let entry = cache.get_lock(999).await;
    assert_eq!(entry.lock().await.fresh_res().unwrap().unwrap(), 999);
  }

  /// Fresh results are never pruned: the map grows to hold all of
  /// them, pruning again at twice what it kept.
  #[tokio::test(start_paused = true)]
  async fn timeout_cache_keeps_fresh_entries_when_it_grows() {
    let cache = TimeoutCache::<u64, u64>::new(TIMEOUT);
    for i in 0..200 {
      cache.get_lock(i).await.lock().await.set(&Ok(i));
    }
    assert_eq!(cache.len().await, 200);
    tokio::time::advance(TIMEOUT).await;
    // Nothing is pruned until the map doubles what the last
    // prune kept (128 at the 128th key) ...
    for i in 200..255 {
      cache.get_lock(i).await.lock().await.set(&Ok(i));
    }
    assert_eq!(cache.len().await, 255);
    // ... then the 256th key drops the 200 stale ones.
    cache.get_lock(255).await.lock().await.set(&Ok(255));
    assert_eq!(cache.len().await, 56);
  }

  #[tokio::test]
  async fn timeout_cache_remove_skips_held_entry() {
    let cache = TimeoutCache::<&str, u64>::new(TIMEOUT);
    assert!(!cache.remove(&"missing").await);
    let held = cache.get_lock("key").await;
    held.lock().await.set(&Ok(7));
    assert!(!cache.remove(&"key").await);
    assert!(Arc::ptr_eq(&held, &cache.get_lock("key").await));
    // A weak handle can come back, it counts as held too.
    let weak = Arc::downgrade(&held);
    drop(held);
    assert!(!cache.remove(&"key").await);
    drop(weak);
    assert!(cache.remove(&"key").await);
    assert!(cache.is_empty().await);
    let entry = cache.get_lock("key").await;
    assert!(entry.lock().await.fresh_res().is_none());
  }

  #[tokio::test]
  async fn timeout_cache_retain() {
    let cache = TimeoutCache::<&str, u64>::new(TIMEOUT);
    cache.get_lock("a").await.lock().await.set(&Ok(1));
    cache.get_lock("b").await.lock().await.set(&Ok(2));
    let held = cache.get_lock("c").await;
    let mut seen = Vec::new();
    cache
      .retain(|key, entry| {
        seen.push(*key);
        matches!(entry.fresh_res(), Some(Ok(2)))
      })
      .await;
    seen.sort();
    // The held entry isn't offered to 'keep', and stays.
    assert_eq!(seen, vec!["a", "b"]);
    assert_eq!(cache.len().await, 2);
    assert!(Arc::ptr_eq(&held, &cache.get_lock("c").await));
  }

  #[tokio::test]
  async fn clone_cache_insert_get_remove() {
    let cache = CloneCache::<String, u64>::default();
    assert_eq!(cache.get(&"a".to_string()).await, None);
    assert_eq!(cache.insert("a", 1).await, None);
    // Insert returns previous value
    assert_eq!(cache.insert("a", 2).await, Some(1));
    assert_eq!(cache.get(&"a".to_string()).await, Some(2));
    assert_eq!(cache.remove(&"a".to_string()).await, Some(2));
    assert_eq!(cache.get(&"a".to_string()).await, None);
  }

  #[tokio::test]
  async fn clone_cache_entries_and_retain() {
    let cache = CloneCache::<u64, u64>::default();
    for i in 0..5 {
      cache.insert(i, i * 10).await;
    }
    assert_eq!(cache.get_keys().await.len(), 5);
    assert_eq!(cache.get_values().await.len(), 5);
    cache.retain(|k, _| *k % 2 == 0).await;
    let mut entries = cache.get_entries().await;
    entries.sort();
    assert_eq!(entries, vec![(0, 0), (2, 20), (4, 40)]);
  }

  #[tokio::test]
  async fn clone_cache_get_or_insert_with_only_inserts_once() {
    let cache =
      Arc::new(CloneCache::<String, Arc<AtomicUsize>>::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..32 {
      let cache = cache.clone();
      let calls = calls.clone();
      handles.push(tokio::spawn(async move {
        cache
          .get_or_insert_with(&"key".to_string(), || {
            calls.fetch_add(1, Ordering::SeqCst);
            Arc::new(AtomicUsize::new(0))
          })
          .await
      }));
    }
    let mut entries = Vec::new();
    for handle in handles {
      entries.push(handle.await.unwrap());
    }
    // Exactly one default was inserted, and everyone got it.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let first = &entries[0];
    assert!(entries.iter().all(|e| Arc::ptr_eq(first, e)));
  }

  #[tokio::test]
  async fn clone_cache_get_or_insert_default() {
    let cache = CloneCache::<u8, u64>::default();
    assert_eq!(cache.get_or_insert_default(&1).await, 0);
    cache.insert(2u8, 7).await;
    assert_eq!(cache.get_or_insert_default(&2).await, 7);
  }

  #[tokio::test]
  async fn clone_vec_cache_insert_replaces_matching() {
    let cache = CloneVecCache::<(u8, &str)>::default();
    assert_eq!(
      cache.insert(|(id, _)| *id == 1, (1, "a")).await,
      None
    );
    assert_eq!(
      cache.insert(|(id, _)| *id == 2, (2, "b")).await,
      None
    );
    // Replacing returns the previous value.
    assert_eq!(
      cache.insert(|(id, _)| *id == 1, (1, "c")).await,
      Some((1, "a"))
    );
    assert_eq!(cache.list().await.len(), 2);
    assert_eq!(cache.find(|(id, _)| *id == 1).await, Some((1, "c")));
  }

  #[tokio::test]
  async fn clone_vec_cache_remove_and_retain() {
    let cache = CloneVecCache::<u64>::default();
    for i in 0..5 {
      cache.insert(|v| *v == i, i).await;
    }
    assert_eq!(cache.remove(|v| *v == 3).await, Some(3));
    assert_eq!(cache.remove(|v| *v == 3).await, None);
    cache.retain(|v| *v < 2).await;
    let mut list = cache.list().await;
    list.sort();
    assert_eq!(list, vec![0, 1]);
  }

  #[tokio::test]
  async fn set_cache_behavior() {
    let cache = SetCache::<u64>::default();
    assert!(!cache.contains(&1).await);
    assert!(cache.insert(1).await);
    // Second insert of same key returns false
    assert!(!cache.insert(1).await);
    assert!(cache.contains(&1).await);
    cache.insert(2).await;
    cache.retain(|&k| k == 2).await;
    assert!(!cache.contains(&1).await);
    assert!(cache.remove(&2).await);
    assert!(!cache.remove(&2).await);
  }
}
