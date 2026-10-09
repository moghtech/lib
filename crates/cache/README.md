# Mogh Cache

```rust
use std::sync::OnceLock;
use mogh_cache::CloneCache;

type Cache = CloneCache<i64, i64>;

pub fn cache() -> &'static Cache {
  static CACHE: OnceLock<Cache> = OnceLock::new();
  CACHE.get_or_init(Default::default)
}

let entry: Option<i64> = cache().get(&0).await;
```

## TimeoutCache

Lets concurrent / rapid fire calls of an action share one run and
its result, reused for the cache's timeout after it is set:

```rust
use std::{sync::OnceLock, time::Duration};
use mogh_cache::TimeoutCache;

fn pull_cache() -> &'static TimeoutCache<String, Log> {
  static CACHE: OnceLock<TimeoutCache<String, Log>> = OnceLock::new();
  CACHE.get_or_init(|| TimeoutCache::new(Duration::from_secs(5)))
}

let lock = pull_cache().get_lock(image.clone()).await;
// Concurrent callers for the same key wait here.
let mut entry = lock.lock().await;
if let Some(res) = entry.fresh_res() {
  return res;
}
let res = pull(&image).await;
// Set after the action, so the waiting callers reuse it.
entry.set(&res);
res
```

The cache prunes itself: when `get_lock` has grown the map to twice
the entries it kept at its last prune (and to at least 64), it drops
the entries whose result is no longer fresh. Keys taken from request
input (an image name, a repo path) therefore can't grow it for the
life of the process, and no periodic task is needed. Entries a caller
still holds are never removed, so pruning can't let two callers run
the action at the same time. `prune`, `retain` and `remove` stay
available to free results sooner.

## LoadCache

One value loaded on demand (eg. a listing from the database), served
from memory for a time to live, for values read on every request
(often unauthenticated ones, like the login providers a login page
lists) and changed rarely, through the app:

```rust
use std::time::Duration;
use mogh_cache::LoadCache;

static PROVIDERS: LoadCache<Vec<Provider>> =
  LoadCache::new(Duration::from_secs(30));

// Misses included, served from memory. The closure picks what the
// caller needs, so only that is cloned.
let provider = PROVIDERS
  .read_or_load(query_providers, |providers| {
    providers.iter().find(|p| p.id == id).cloned()
  })
  .await?;

// After every write through the app:
PROVIDERS.invalidate();
```

- Concurrent readers which miss wait for one load, rather than each
  hitting the database.
- `invalidate` drops the value right away, so the time to live only
  bounds how long a change made elsewhere (directly on the database)
  goes unnoticed. A load which started before an invalidation returns
  its result to its caller, but never caches it.
- A failed load caches nothing: the next read loads again. The error
  type is the loader's.
- The value is dropped once it expires, not just hidden until the next
  load: what is cached may be secret (decrypted client secrets, wiped
  on drop), and must not sit in memory for as long as nobody asks
  again. A task spawned by `read_or_load` drops it, so the cache is a
  `static` (`new` is `const`), and caches only on a tokio runtime
  (with its timer): outside one, every call loads.
