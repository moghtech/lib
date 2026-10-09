# Mogh Error

De/serialize `anyhow` errors as json (`{ "error": "...", "trace": [...] }`),
and return them from axum handlers with a customizable status code.

```rust
use mogh_error::AddStatusCode as _;

fn fallible() -> mogh_error::Result<()> {
  let user = get_user().await.status_code(http::StatusCode::UNAUTHORIZED)?;
  ...
  Ok(())
}
```

## Server errors send the full trace by default

An `Error` response body carries the top-level message and the whole
context chain as `trace`, for every status. Every `?` on a foreign error
gives a `500`, so by default callers can see internal details such as
database driver messages, request urls, internal hostnames and file paths.

Apps can hide these for server errors (5xx) on the routes whose callers
must not see them, typically the ones reachable without authentication,
with a layer on that router (feature `axum`):

```rust
use mogh_error::{ServerErrorDetail, hide_server_error_details};

let app = Router::new()
  .nest(
    "/login",
    login_router().layer(hide_server_error_details(
      // The status code's reason ("Internal Server Error"), empty trace.
      ServerErrorDetail::Generic,
    )),
  )
  // Authenticated, keeps the details the UI shows.
  .nest("/api", api_router());
```

The layer rebuilds the body from the error itself (never reading the body
back, so there is no size limit) and logs what it hid as a `tracing`
warning with the method, path (never the query) and the whole chain, under
the `mogh_error` target (an app logging only some targets has to add it),
or calls the hook given to `.on_hidden(..)` instead. `.except(|path| ..)`
leaves some paths of the router alone, eg. the authenticated part of a
router built by a library. `ServerErrorDetail::Message` keeps the top-level
message, which may still name internals. A 5xx response that isn't an
`Error` (eg. a panic handler's) gets the status reason.

Or for the whole process, once at startup:

```rust
// Top-level message only, empty trace.
mogh_error::set_server_error_detail(mogh_error::ServerErrorDetail::Message);
// Or the status code's reason ("Internal Server Error"), empty trace.
mogh_error::set_server_error_detail(mogh_error::ServerErrorDetail::Generic);
```

This is a process wide app setting: libraries should not call it. Where both
apply, the one hiding more wins: a layer never shows more than the process
wide setting.

Client errors (4xx) keep their full message and trace. Every 5xx response
built from an `Error` carries the full error in a `ServerError` extension
(never sent to the caller), whatever its body shows, so a middleware can
log it.

## Refusals which are not attempts

`mogh_rate_limit` counts every error of a rate limited attempt as a failed
guess. An authentication refusal which is not a guess (an authentic but
expired token, an ended session, a server error) is marked so it is not
counted:

```rust
Err(anyhow!("Session ended").status_code(StatusCode::UNAUTHORIZED).uncounted())
```

`is_uncounted()` finds the mark below context added later. The marker,
`NotAnAttempt`, is transparent: the message, causes and status stay as they
are, so the response and `{:#}` don't change. The marked error's own type is
reached through `NotAnAttempt.0` when downcasting.

## `/{variant}` routes

Resolver apis take a request either as a tagged body on one route
(`POST /read` with `{ "type": "GetUser", "params": {..} }`) or with the type
in the path (`POST /read/GetUser` with the params as the body).
`variant_request` builds the tagged request from the second form
(feature `axum`):

```rust
use mogh_error::{Json, Variant, variant_request};

async fn variant_handler(
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<Response> {
  let request: ReadRequest = variant_request(&variant, params)?;
  handler(Json(request)).await
}
```

An unknown variant or params of the wrong shape answer
`422 Unprocessable Entity`, as axum's `Json` does for the tagged body. The
error names the field and what was expected (`title: invalid type, expected
a string`), never the params' values, which can be secrets, and shows at most
64 characters of the variant.

`variant_request_raw(&variant, &params)` takes the params as JSON text (a
`&serde_json::value::RawValue`, eg. borrowed from a websocket frame which
tunnels `{ "type", "params" }` requests, or a body taken as
`Json<Box<RawValue>>`), which serde reads straight into the request without a
`serde_json::Value` of it first. It refuses alike, without the position of the
error in the params' text (the field names the place).

`without_values(&message)` (any feature) is the rule both use: a serde error
message without the value it names (`invalid type: string "hunter2", expected
u64` becomes `invalid type, expected u64`), for parse errors of any input which
can carry secrets, before they are answered or logged.

## Receiving errors

`deserialize_error` / `deserialize_error_bytes` rebuild the anyhow chain from
a peer's json. The rebuilt chain is capped at `MAX_TRACE_DEPTH` (64) trace
entries: deeper entries are folded into the last one, joined with `": "`, so
`{:#}` renders the same text. anyhow drops a chain recursively, so an
unbounded trace from a peer could otherwise overflow the stack.

## Features

- `axum`: `Error`, `Result`, `Json`, the `AddStatusCode` helpers for axum
  handlers, the `hide_server_error_details` layer, and `variant_request` /
  `variant_request_raw` / `Variant` for `/{variant}` routes (it turns on
  serde_json's `raw_value`).
- `utoipa`: derives `utoipa::ToSchema` for `Serror`. Since 1.0.6 this is
  **utoipa 6**. Apps still on utoipa 5 need `mogh_error = "=1.0.5"` until they
  move to utoipa 6.
