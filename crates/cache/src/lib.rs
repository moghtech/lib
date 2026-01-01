use std::{collections::HashMap, hash::Hash, sync::Arc};

use tokio::sync::{Mutex, RwLock};

/// Prevents simultaneous / rapid fire access to an action,
/// returning the cached result instead in these situations.
#[derive(Default)]
pub struct TimeoutCache<K, Res>(
  Mutex<HashMap<K, Arc<Mutex<CacheEntry<Res>>>>>,
);

impl<K: Eq + Hash, Res: Default> TimeoutCache<K, Res> {
  pub async fn get_lock(
    &self,
    key: K,
  ) -> Arc<Mutex<CacheEntry<Res>>> {
    let mut lock = self.0.lock().await;
    lock.entry(key).or_default().clone()
  }
}

pub struct CacheEntry<Res> {
  /// The last cached ts
  pub last_ts: i64,
  /// The last cached result
  pub res: anyhow::Result<Res>,
}

impl<Res: Default> Default for CacheEntry<Res> {
  fn default() -> Self {
    CacheEntry {
      last_ts: 0,
      res: Ok(Res::default()),
    }
  }
}

impl<Res: Clone> CacheEntry<Res> {
  pub fn set(&mut self, res: &anyhow::Result<Res>, timestamp: i64) {
    self.res = res.as_ref().map_err(clone_anyhow_error).cloned();
    self.last_ts = timestamp;
  }

  pub fn clone_res(&self) -> anyhow::Result<Res> {
    self.res.as_ref().map_err(clone_anyhow_error).cloned()
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

impl<K: PartialEq + Eq + Hash + std::fmt::Debug + Clone, T: Clone>
  CloneCache<K, T>
{
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
    T: std::fmt::Debug,
    Key: Into<K> + std::fmt::Debug,
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

impl<
  K: PartialEq + Eq + Hash + std::fmt::Debug + Clone,
  T: Clone + Default,
> CloneCache<K, T>
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

impl<T: Clone + Default> CloneVecCache<T> {
  pub async fn find_or_insert_default(
    &self,
    find: impl FnMut(&&T) -> bool,
  ) -> T {
    let mut cache = self.0.write().await;
    match cache.iter().find(find).cloned() {
      Some(item) => item,
      None => {
        let item: T = Default::default();
        cache.push(item.clone());
        item
      }
    }
  }
}
