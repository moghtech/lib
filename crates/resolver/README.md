# Mogh Resolver

Declare your API in the Rust type system.

## Declare API

```rust
/// User entity
#[derive(Serialize, Deserialize)]
pub struct User {
  pub id: i64,
  pub username: String,
}

/// Get User request 
#[derive(Serialize, Deserialize, Debug, Resolve)]
#[response(User)]
pub struct GetUser {
  pub id: i64,
}
```

## Implement API

The API can be implemented using any transport. A common one is HTTP, for example using axum:

```rust
impl Resolve<()> for GetUser {
  async fn resolve(self, _: &()) -> Result<User, std::convert::Infallible> {
    Ok(User { id: self.id, username: String::new("example") }))
  }
}

struct Response(axum::response::Response);

impl<T> From<T> for Response
where
  T: serde::Serialize,
{
  fn from(value: T) -> Self {
    Response(axum::Json(value).into_response())
  }
}

#[derive(Deserialize, Resolve)]
#[response(Response)]
#[error(Response)]
enum Request {
  GetUser(GetUser),
}

let app = Router::new()
  .route(
    "/",
    post(
      |Json(req): Json<Request>| async move {
        match req.resolve(&()).await {
          Ok(res) => res.0,
          Err(err) => err.0,
        }
      },
    ),
  );

let listener = tokio::net::TcpListener::bind("127.0.0.1:5555")
  .await?;

axum::serve(listener, app).await?;
```

## Call API

```rust
fn reqwest() -> &'static reqwest::Client {
  static REQWEST: OnceLock<reqwest::Client> = OnceLock::new();
  REQWEST.get_or_init(reqwest::Client::default)
}

async fn resolve<T>(req: &T) -> Result<T::Response, Error> {
  let res = client
    .post("http://127.0.0.1:5555")
    .json(req)
    .send()
    .await?;
  if res.status().is_success() {
    res.json().await
  } else {
    // handle error
  }
}

// knows response is "User" type
let user = resolve(&GetUser { id: 0 })
  .await
  .unwrap(); 
```