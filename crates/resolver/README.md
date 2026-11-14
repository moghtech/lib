# Mogh Resolver

Declare your API in the Rust type system.

## Declare API

```rust
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};

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

`#[response(..)]` names the response type, `#[error(..)]` the error type
(default `std::convert::Infallible`). `HasResponse::req_type()` is the type's
name (`"GetUser"`), the `"type"` of a tagged request
(`{ "type": "GetUser", "params": { "id": 0 } }`).

## Implement API

The API can be implemented using any transport. A common one is HTTP, for
example using axum, with every request in one tagged enum which the derive
resolves by resolving the variant's request:

```rust
use axum::{
  Json, Router, http::StatusCode, response::IntoResponse,
  routing::post,
};
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct User {
  pub id: i64,
  pub username: String,
}

#[derive(Deserialize, Resolve)]
#[response(User)]
#[error(String)]
pub struct GetUser {
  pub id: i64,
}

impl Resolve for GetUser {
  async fn resolve(self, _: &()) -> Result<User, String> {
    if self.id < 0 {
      return Err(String::from("Invalid user id"));
    }
    Ok(User { id: self.id, username: String::from("example") })
  }
}

/// The response of any request.
struct Response(axum::response::Response);

impl<T: Serialize> From<T> for Response {
  fn from(value: T) -> Self {
    Response(Json(value).into_response())
  }
}

/// The error of any request.
struct Error(axum::response::Response);

impl From<String> for Error {
  fn from(message: String) -> Self {
    Error((StatusCode::INTERNAL_SERVER_ERROR, message).into_response())
  }
}

/// `{ "type": "GetUser", "params": { "id": 0 } }`
#[derive(Deserialize, Resolve)]
#[serde(tag = "type", content = "params")]
#[response(Response)]
#[error(Error)]
enum Request {
  GetUser(GetUser),
}

async fn serve() -> std::io::Result<()> {
  let app = Router::new().route(
    "/",
    post(|Json(req): Json<Request>| async move {
      match req.resolve(&()).await {
        Ok(res) => res.0,
        Err(err) => err.0,
      }
    }),
  );
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:5555").await?;
  axum::serve(listener, app).await
}
```

## Call API

```rust
use std::sync::OnceLock;

use mogh_resolver::{HasResponse, Resolve};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Deserialize)]
pub struct User {
  pub id: i64,
  pub username: String,
}

#[derive(Serialize, Resolve)]
#[response(User)]
pub struct GetUser {
  pub id: i64,
}

fn reqwest() -> &'static reqwest::Client {
  static REQWEST: OnceLock<reqwest::Client> = OnceLock::new();
  REQWEST.get_or_init(reqwest::Client::default)
}

/// The tagged request the server takes.
#[derive(Serialize)]
struct Tagged<'a, T> {
  r#type: &'static str,
  params: &'a T,
}

async fn resolve<T>(req: &T) -> reqwest::Result<T::Response>
where
  T: HasResponse + Serialize,
  T::Response: DeserializeOwned,
{
  reqwest()
    .post("http://127.0.0.1:5555")
    .json(&Tagged { r#type: T::req_type(), params: req })
    .send()
    .await?
    .error_for_status()?
    .json()
    .await
}

async fn get_user() -> reqwest::Result<User> {
  // Knows the response is a `User`.
  resolve(&GetUser { id: 0 }).await
}
```
