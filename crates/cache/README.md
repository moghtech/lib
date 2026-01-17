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