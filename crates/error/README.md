# Mogh Error

```rust
use mogh_error::AddStatusCode as _;

fn fallible() -> mogh_error::Result<()> {
  let user = get_user().await.status_code(http::StatusCode::UNAUTHORIZED)?;
  ...
  Ok(())
}
```