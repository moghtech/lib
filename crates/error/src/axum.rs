use std::{
  pin::Pin,
  sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
  },
  task::{Context, Poll},
};

use anyhow::{Context as _, anyhow};
use axum::{
  body::Body,
  extract::{FromRequest, OriginalUri, rejection::JsonRejection},
  http::{Method, Request, Uri},
  response::IntoResponse,
};
use serde::{
  Deserialize, Serialize,
  de::{DeserializeOwned, value::MapDeserializer},
};
use serde_json::value::RawValue;
use tower::{Layer, Service};

pub use axum::http::{
  HeaderMap, HeaderValue, StatusCode,
  header::{self, IntoHeaderName},
};

use crate::{NotAnAttempt, Serror, serialize_error, without_values};

pub type Result<T> = std::result::Result<T, Error>;

/// How much of an [Error] with a server error (5xx) status its
/// response body carries. Set it for the whole process with
/// [set_server_error_detail], or for the routes of a router with
/// [hide_server_error_details]. Other statuses always carry the
/// full message and trace, as those messages are meant for the
/// caller.
///
/// Ordered from the most detail to the least: where both settings
/// apply, the one hiding more wins.
#[derive(
  Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord,
)]
#[repr(u8)]
#[non_exhaustive]
pub enum ServerErrorDetail {
  /// The top-level message and the full context chain (`trace`).
  /// This is the default.
  #[default]
  Full = 0,
  /// Only the top-level message, with an empty `trace`. An error
  /// returned with `?` and no added context has the inner error's
  /// own message on top, which may still name internal hosts, urls
  /// or paths.
  Message = 1,
  /// The status code's canonical reason (eg "Internal Server
  /// Error") as the message, with an empty `trace`.
  Generic = 2,
}

static SERVER_ERROR_DETAIL: AtomicU8 =
  AtomicU8::new(ServerErrorDetail::Full as u8);

/// Sets how much detail every [Error] response with a server error
/// (5xx) status carries, for the whole process.
///
/// The default, [ServerErrorDetail::Full], sends the full anyhow
/// context chain to the caller, for every status. Every `?` on a
/// foreign error gives a 500, so the caller can see internal
/// details such as database driver messages, request urls, internal
/// hostnames and file paths. Apps whose callers should not see these
/// can opt in to hiding them here, typically once at startup, or
/// only on some routes (eg. the ones reachable without
/// authentication) with [hide_server_error_details].
///
/// The response carries the full error in a [ServerError]
/// extension either way, so a middleware can still log it.
///
/// This is an app wide setting: libraries should not call it.
pub fn set_server_error_detail(detail: ServerErrorDetail) {
  SERVER_ERROR_DETAIL.store(detail as u8, Ordering::Relaxed);
}

/// The current process wide [ServerErrorDetail], see
/// [set_server_error_detail].
pub fn server_error_detail() -> ServerErrorDetail {
  match SERVER_ERROR_DETAIL.load(Ordering::Relaxed) {
    1 => ServerErrorDetail::Message,
    2 => ServerErrorDetail::Generic,
    _ => ServerErrorDetail::Full,
  }
}

/// Response extension holding the full error of every server error
/// (5xx) response built from an [Error], whatever its body carries
/// (see [set_server_error_detail] and [hide_server_error_details]).
/// Response extensions are not sent to the caller. Read it in a
/// middleware to log server errors:
///
/// ```
/// use axum::{Router, middleware::map_response, response::Response};
/// use mogh_error::ServerError;
///
/// async fn log_server_errors(res: Response) -> Response {
///   if let Some(ServerError(e)) = res.extensions().get() {
///     eprintln!("{} | {e:#}", res.status());
///   }
///   res
/// }
///
/// let app: Router = Router::new().layer(map_response(log_server_errors));
/// ```
#[derive(Debug, Clone)]
pub struct ServerError(pub Arc<anyhow::Error>);

#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> Result<T> {
  Result::Ok(value)
}

/// Intermediate error type which can be converted to from any error using `?`.
/// The standard `impl From<E> for Error` will attach StatusCode::INTERNAL_SERVER_ERROR,
/// so if an alternative StatusCode is desired, you should use `.status_code` ([AddStatusCode] or [AddStatusCodeError])
/// to add the status before using `?`, and [Error::header] to add headers.
///
/// The response body is the serialized [Serror]: the top-level
/// message and, by default, the full context chain as `trace`, for
/// every status. See [set_server_error_detail] and
/// [hide_server_error_details] to hide the details of server errors
/// (5xx).
#[derive(Debug)]
pub struct Error {
  pub status: StatusCode,
  pub headers: Option<HeaderMap>,
  pub error: anyhow::Error,
}

impl Error {
  pub fn msg<M>(message: M) -> Error
  where
    M: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
  {
    Self {
      status: StatusCode::INTERNAL_SERVER_ERROR,
      headers: None,
      error: anyhow::Error::msg(message),
    }
  }

  pub fn status_code(mut self, status_code: StatusCode) -> Error {
    self.status = status_code;
    self
  }

  pub fn header(
    mut self,
    name: impl IntoHeaderName,
    value: HeaderValue,
  ) -> Error {
    if let Some(headers) = &mut self.headers {
      headers.append(name, value);
      return self;
    }
    let mut headers = HeaderMap::with_capacity(1);
    headers.append(name, value);
    self.headers(headers)
  }

  pub fn headers(mut self, headers: HeaderMap) -> Error {
    self.headers = Some(headers);
    self
  }

  /// Marks the error as a refusal which is not a guess, so that
  /// `mogh_rate_limit` does not count it as a failed attempt: an
  /// authentication refusal of an authentic but expired token, of
  /// an ended session, or a server error. See [NotAnAttempt]: the
  /// message, causes and status stay as they are.
  pub fn uncounted(mut self) -> Error {
    if !self.is_uncounted() {
      self.error = anyhow::Error::new(NotAnAttempt(self.error));
    }
    self
  }

  /// Whether the error was marked with
  /// [uncounted](Error::uncounted), also below context added after.
  pub fn is_uncounted(&self) -> bool {
    self.error.chain().any(|e| e.is::<NotAnAttempt>())
  }
}

impl Error {
  /// Builds the response, applying `server_error_detail` if the
  /// status is a server error (5xx), which also get the full error
  /// as a [ServerError] extension.
  fn response_with_detail(
    self,
    server_error_detail: ServerErrorDetail,
  ) -> axum::response::Response {
    let server_error = self.status.is_server_error();
    let detail = if server_error {
      server_error_detail
    } else {
      ServerErrorDetail::Full
    };
    let body = match detail {
      ServerErrorDetail::Full => serialize_error(&self.error),
      ServerErrorDetail::Message => {
        serialize_message(self.error.to_string())
      }
      ServerErrorDetail::Generic => {
        serialize_message(generic_message(self.status))
      }
    };
    let mut response = axum::response::Response::new(Body::new(body));
    *response.status_mut() = self.status;

    let headers = response.headers_mut();
    headers.append(
      "Content-Type",
      HeaderValue::from_static("application/json"),
    );
    if let Some(self_headers) = self.headers {
      headers.extend(self_headers);
    }

    if server_error {
      response
        .extensions_mut()
        .insert(ServerError(Arc::new(self.error)));
    }

    response
  }
}

/// The message of a server error under [ServerErrorDetail::Generic]:
/// the status code's canonical reason.
fn generic_message(status: StatusCode) -> String {
  status
    .canonical_reason()
    .unwrap_or("Server Error")
    .to_string()
}

/// Serializes a [Serror] with the message and no trace.
fn serialize_message(error: String) -> String {
  let serror = Serror {
    error,
    trace: Vec::new(),
  };
  serde_json::to_string(&serror)
    .unwrap_or_else(|_| format!("{serror:#?}"))
}

/// A layer hiding the details of the server errors (5xx) of the
/// routes it wraps: their response bodies carry only as much as
/// `detail` allows (but never more than the process wide
/// [set_server_error_detail] does), and what was hidden is logged,
/// as a `tracing` warning by default (see
/// [on_hidden](HideServerErrorDetailsLayer::on_hidden)).
///
/// Use it where the callers must not see internal details, such as
/// the routes reachable without authentication, while authenticated
/// apis keep the details a UI shows:
///
/// ```
/// use axum::Router;
/// use mogh_error::{ServerErrorDetail, hide_server_error_details};
///
/// fn app(login: Router, api: Router) -> Router {
///   Router::new()
///     .nest(
///       "/login",
///       login.layer(hide_server_error_details(
///         ServerErrorDetail::Generic,
///       )),
///     )
///     .nest("/api", api)
/// }
/// ```
///
/// Add it last (outermost) on the router, so it also covers the
/// errors of that router's own middlewares (eg. authentication).
/// [except](HideServerErrorDetailsLayer::except) leaves some of the
/// router's paths alone (eg. an authenticated sub-router).
///
/// The default log is under the `mogh_error` target: an app logging
/// only some targets (mogh_logger's `LogConfig::targets`) has to
/// include it, or log from [on_hidden](HideServerErrorDetailsLayer::on_hidden).
///
/// The body is rebuilt from the response's [ServerError] extension,
/// never read, so there is no size limit on the error, and the log
/// has the whole chain. A server error response which did not come
/// from an [Error] (eg. an extractor's or a panic handler's) has no
/// such extension: its body is replaced with the status reason
/// unread, whatever `detail` is (short of
/// [Full](ServerErrorDetail::Full)), and the log has no error.
///
/// [ServerErrorDetail::Message] keeps the top-level message, which
/// may still carry internals: an error returned with `?` without
/// context has the inner error's message on top, and a context
/// added by a library may repeat its causes. Use
/// [ServerErrorDetail::Generic] where nothing internal may show.
/// [ServerErrorDetail::Full] makes the layer do nothing.
pub fn hide_server_error_details(
  detail: ServerErrorDetail,
) -> HideServerErrorDetailsLayer {
  HideServerErrorDetailsLayer {
    detail,
    on_hidden: Arc::new(log_hidden_details),
    except: None,
  }
}

/// What [hide_server_error_details] hid from the caller of a
/// request, for its [on_hidden](HideServerErrorDetailsLayer::on_hidden)
/// hook.
#[derive(Debug, Clone, Copy)]
pub struct HiddenDetails<'a> {
  pub method: &'a Method,
  /// The request's whole path (also when the layer is on a nested
  /// router), without the query, which may carry codes or tokens.
  pub path: &'a str,
  pub status: StatusCode,
  /// The full error, or None when the response did not come from
  /// an [Error].
  pub error: Option<&'a anyhow::Error>,
}

type OnHidden = Arc<dyn Fn(&HiddenDetails<'_>) + Send + Sync>;
type Except = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The default [on_hidden](HideServerErrorDetailsLayer::on_hidden)
/// hook: a `tracing` warning with the method, path, status and the
/// whole error chain.
fn log_hidden_details(hidden: &HiddenDetails<'_>) {
  let HiddenDetails {
    method,
    path,
    status,
    error,
  } = hidden;
  match error {
    Some(error) => tracing::warn!(
      %method,
      path,
      %status,
      "Server error, details hidden from the caller | {error:#}"
    ),
    None => tracing::warn!(
      %method,
      path,
      %status,
      "Server error, details hidden from the caller"
    ),
  }
}

/// See [hide_server_error_details].
#[derive(Clone)]
pub struct HideServerErrorDetailsLayer {
  detail: ServerErrorDetail,
  on_hidden: OnHidden,
  except: Option<Except>,
}

impl HideServerErrorDetailsLayer {
  /// Called with what the layer hid from the caller, for each
  /// server error whose body it replaced, instead of the default
  /// `tracing` warning.
  pub fn on_hidden(
    mut self,
    on_hidden: impl Fn(&HiddenDetails<'_>) + Send + Sync + 'static,
  ) -> Self {
    self.on_hidden = Arc::new(on_hidden);
    self
  }

  /// Leaves the responses to the requests whose path `except`
  /// returns true for unchanged. It gets the path as the router the
  /// layer is on sees it: on a router nested at `/auth`, a request
  /// for `/auth/manage/x` has the path `/manage/x`.
  ///
  /// For a router built elsewhere whose sub-routes need other rules,
  /// eg. a library's router with an authenticated part (keeping the
  /// details its UI shows) or a part answering its own error format.
  pub fn except(
    mut self,
    except: impl Fn(&str) -> bool + Send + Sync + 'static,
  ) -> Self {
    self.except = Some(Arc::new(except));
    self
  }
}

impl<S> Layer<S> for HideServerErrorDetailsLayer {
  type Service = HideServerErrorDetails<S>;

  fn layer(&self, inner: S) -> Self::Service {
    HideServerErrorDetails {
      inner,
      detail: self.detail,
      on_hidden: self.on_hidden.clone(),
      except: self.except.clone(),
    }
  }
}

/// The service of [hide_server_error_details].
#[derive(Clone)]
pub struct HideServerErrorDetails<S> {
  inner: S,
  detail: ServerErrorDetail,
  on_hidden: OnHidden,
  except: Option<Except>,
}

impl<S, B> Service<Request<B>> for HideServerErrorDetails<S>
where
  S: Service<Request<B>, Response = axum::response::Response>,
  S::Future: Send + 'static,
{
  type Response = axum::response::Response;
  type Error = S::Error;
  type Future = Pin<
    Box<
      dyn Future<
          Output = std::result::Result<
            axum::response::Response,
            S::Error,
          >,
        > + Send,
    >,
  >;

  fn poll_ready(
    &mut self,
    cx: &mut Context<'_>,
  ) -> Poll<std::result::Result<(), S::Error>> {
    self.inner.poll_ready(cx)
  }

  fn call(&mut self, req: Request<B>) -> Self::Future {
    if let Some(except) = &self.except
      && except(req.uri().path())
    {
      return Box::pin(self.inner.call(req));
    }
    let detail = self.detail;
    let on_hidden = self.on_hidden.clone();
    let method = req.method().clone();
    // The whole uri, also within a nested router.
    let uri: Uri = match req.extensions().get::<OriginalUri>() {
      Some(OriginalUri(uri)) => uri.clone(),
      None => req.uri().clone(),
    };
    let future = self.inner.call(req);
    Box::pin(async move {
      let res = future.await?;
      std::result::Result::Ok(hide_details(
        res,
        detail,
        |status, error| {
          on_hidden(&HiddenDetails {
            method: &method,
            path: uri.path(),
            status,
            error,
          })
        },
      ))
    })
  }
}

/// Rebuilds the body of a server error (5xx) response with what
/// `detail` (or the process wide setting, if it hides more) allows,
/// calling `on_hidden` with what was hidden. Other responses, and
/// all of them under [ServerErrorDetail::Full], pass unchanged.
fn hide_details(
  mut res: axum::response::Response,
  detail: ServerErrorDetail,
  on_hidden: impl FnOnce(StatusCode, Option<&anyhow::Error>),
) -> axum::response::Response {
  let status = res.status();
  if !status.is_server_error() || detail == ServerErrorDetail::Full {
    return res;
  }
  // Never show more than the body built under the process wide
  // setting already does.
  let detail = detail.max(server_error_detail());
  let error = res
    .extensions()
    .get::<ServerError>()
    .map(|ServerError(error)| error.clone());
  let message = match (detail, &error) {
    (ServerErrorDetail::Message, Some(error)) => error.to_string(),
    // Without an Error, the message would have to be parsed out
    // of a body of unknown shape and size: the reason it is.
    _ => generic_message(status),
  };
  on_hidden(status, error.as_deref());
  let headers = res.headers_mut();
  // Both described the body being replaced.
  headers.remove(header::CONTENT_LENGTH);
  headers.remove(header::CONTENT_ENCODING);
  headers.insert(
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json"),
  );
  *res.body_mut() = Body::new(serialize_message(message));
  res
}

impl IntoResponse for Error {
  /// The body is the serialized [Serror]. For a server error (5xx)
  /// status, it carries as much detail as [set_server_error_detail]
  /// allows (all of it by default).
  fn into_response(self) -> axum::response::Response {
    self.response_with_detail(server_error_detail())
  }
}

impl From<Error> for axum::response::Response {
  fn from(value: Error) -> Self {
    value.into_response()
  }
}

impl<E> From<E> for Error
where
  E: Into<anyhow::Error>,
{
  fn from(err: E) -> Self {
    Self {
      status: StatusCode::INTERNAL_SERVER_ERROR,
      headers: None,
      error: err.into(),
    }
  }
}

/// Convenience trait to convert any Error into serror::Error by adding status
/// and converting error into anyhow error.
pub trait AddStatusCodeError: Into<anyhow::Error> {
  fn status_code(self, status_code: StatusCode) -> Error {
    Error {
      status: status_code,
      headers: None,
      error: self.into(),
    }
  }
}

impl<E> AddStatusCodeError for E where E: Into<anyhow::Error> {}

/// Convenience trait to convert Result into serror::Result by adding status to the inner error, if it exists.
pub trait AddStatusCode<T, E>:
  Into<std::result::Result<T, E>>
where
  E: Into<anyhow::Error>,
{
  fn status_code(self, status_code: StatusCode) -> Result<T> {
    self.into().map_err(|e| e.status_code(status_code))
  }
}

impl<R, T, E> AddStatusCode<T, E> for R
where
  R: Into<std::result::Result<T, E>>,
  E: Into<anyhow::Error>,
{
}

/// Wrapper for axum::Json that converts parsing error to serror::Error
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(JsonError))]
pub struct Json<T>(pub T);

impl<T: Serialize> IntoResponse for Json<T> {
  fn into_response(self) -> axum::response::Response {
    axum::Json(self.0).into_response()
  }
}

pub struct JsonError(Error);

/// Convert the JsonRejection into JsonError(serror::Error)
impl From<JsonRejection> for JsonError {
  fn from(rejection: JsonRejection) -> Self {
    Self(Error {
      status: rejection.status(),
      headers: Default::default(),
      error: anyhow::Error::msg(rejection.body_text()),
    })
  }
}

impl IntoResponse for JsonError {
  fn into_response(self) -> axum::response::Response {
    self.0.into_response()
  }
}

/// The path parameter of a `/{variant}` route, the name of the
/// request, for [variant_request]:
///
/// ```
/// use axum::{extract::Path, response::Response};
/// use mogh_error::{Json, Variant, variant_request};
///
/// #[derive(serde::Deserialize)]
/// #[serde(tag = "type", content = "params")]
/// enum ReadRequest {
///   GetVersion {},
/// }
///
/// async fn variant_handler(
///   Path(Variant { variant }): Path<Variant>,
///   Json(params): Json<serde_json::Value>,
/// ) -> mogh_error::Result<Response> {
///   let request: ReadRequest = variant_request(&variant, params)?;
///   // Handled like the body of the tagged route.
///   # let _ = request;
///   # todo!()
/// }
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct Variant {
  pub variant: String,
}

/// The request a `/{variant}` route names, the tagged request
/// (`{ "type": variant, "params": params }`, a
/// `#[serde(tag = "type", content = "params")]` enum) built from its
/// path and its body.
///
/// An unknown variant, or params of the wrong shape, is the caller's
/// error: `422 Unprocessable Entity`, as axum's `Json` extractor
/// answers for the same request sent to the tagged route, never a
/// `500`. The error names the variant (it comes from the path: its
/// first 64 characters), the field (eg. `title`) and what was
/// expected, never the params' values, which can be secrets
/// (`invalid type: string "hunter2", expected u64` is reported as
/// `invalid type, expected u64`, see [without_values]).
pub fn variant_request<R: DeserializeOwned>(
  variant: &str,
  params: serde_json::Value,
) -> Result<R> {
  // The tag first: given the params first, serde's derive buffers
  // them until it knows the variant, and the field path is lost.
  let request = MapDeserializer::<_, serde_json::Error>::new(
    [
      ("type", serde_json::Value::from(variant)),
      ("params", params),
    ]
    .into_iter(),
  );
  serde_path_to_error::deserialize(request)
    .map_err(|e| variant_request_error(variant, e))
}

/// [variant_request] with the params as JSON text, eg. a [RawValue]
/// borrowed from a larger message (the frame of a websocket which
/// tunnels requests, or a body taken as `Json<Box<RawValue>>`):
/// serde reads them straight into `R`, without building a
/// [serde_json::Value] of them first.
///
/// Refused as [variant_request] refuses (the same `422` and
/// messages), without the position of the error (`at line 1 column
/// 12`), which would count in the params' text alone: the field
/// names the place.
///
/// ```
/// use mogh_error::{StatusCode, variant_request_raw};
/// use serde_json::value::RawValue;
///
/// #[derive(Debug, PartialEq, serde::Deserialize)]
/// #[serde(tag = "type", content = "params")]
/// enum WriteRequest {
///   SetLimit { limit: u64 },
/// }
///
/// let params = RawValue::from_string(r#"{ "limit": 5 }"#.into())?;
/// let request: WriteRequest =
///   variant_request_raw("SetLimit", &params).unwrap();
/// assert_eq!(request, WriteRequest::SetLimit { limit: 5 });
///
/// let params = RawValue::from_string(r#"{ "limit": "hunter2" }"#.into())?;
/// let e = variant_request_raw::<WriteRequest>("SetLimit", &params).unwrap_err();
/// assert_eq!(e.status, StatusCode::UNPROCESSABLE_ENTITY);
/// assert_eq!(
///   format!("{:#}", e.error),
///   "Invalid SetLimit params: limit: invalid type, expected u64"
/// );
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn variant_request_raw<R: DeserializeOwned>(
  variant: &str,
  params: &RawValue,
) -> Result<R> {
  // A string always serializes.
  let tag = serde_json::value::to_raw_value(variant)
    .context("Failed to read the request type")?;
  // The tag first, as variant_request does.
  let request = MapDeserializer::<_, serde_json::Error>::new(
    [("type", &*tag), ("params", params)].into_iter(),
  );
  serde_path_to_error::deserialize(request)
    .map_err(|e| variant_request_error(variant, e))
}

/// The most characters of a request's variant an error shows: it
/// comes from the caller, as long as they like.
const MAX_SHOWN_VARIANT_CHARS: usize = 64;

/// The `422` of a request built by [variant_request] /
/// [variant_request_raw] which doesn't deserialize.
fn variant_request_error(
  variant: &str,
  e: serde_path_to_error::Error<serde_json::Error>,
) -> Error {
  let path = e.path().to_string();
  let e = e.into_inner();
  let mut message = e.to_string();
  // Read from JSON text, the error has its position in the text of
  // the tag or of the params alone: the field names the place.
  let at = format!(" at line {} column {}", e.line(), e.column());
  if e.line() != 0
    && let Some(len) = message.strip_suffix(&at).map(str::len)
  {
    message.truncate(len);
  }
  let message = without_values(&message);
  let variant = variant
    .chars()
    .take(MAX_SHOWN_VARIANT_CHARS)
    .collect::<String>();
  let error = match path.strip_prefix("params") {
    Some(field) => {
      let field = field.strip_prefix('.').unwrap_or(field);
      let message = if field.is_empty() {
        message
      } else {
        format!("{field}: {message}")
      };
      // The variant is known by now.
      anyhow!(message).context(format!("Invalid {variant} params"))
    }
    // Debug escaped: an unknown variant can be anything.
    None if path == "type" => anyhow!(message)
      .context(format!("Unknown request type {variant:?}")),
    None => anyhow!(message).context("Invalid request"),
  };
  error.status_code(StatusCode::UNPROCESSABLE_ENTITY)
}

pub struct Response(pub axum::response::Response);

impl<T> From<T> for Response
where
  T: Serialize,
{
  fn from(value: T) -> Response {
    let res = match serde_json::to_string(&value)
      .context("Failed to serialize response body")
    {
      std::result::Result::Ok(body) => {
        axum::response::Response::builder()
          .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
          )
          .body(axum::body::Body::from(body))
          .unwrap()
      }
      Err(e) => Error::from(e).into_response(),
    };
    Response(res)
  }
}

pub enum JsonString {
  Ok(String),
  Err(serde_json::Error),
}

impl<T> From<T> for JsonString
where
  T: Serialize,
{
  fn from(value: T) -> JsonString {
    match serde_json::to_string(&value) {
      std::result::Result::Ok(body) => JsonString::Ok(body),
      Err(e) => JsonString::Err(e),
    }
  }
}

impl JsonString {
  pub fn into_response(self) -> axum::response::Response {
    match self {
      JsonString::Ok(body) => axum::response::Response::builder()
        .header(
          header::CONTENT_TYPE,
          HeaderValue::from_static("application/json"),
        )
        .body(axum::body::Body::from(body))
        .unwrap(),
      JsonString::Err(error) => Error::from(
        anyhow::Error::from(error)
          .context("Failed to serialize response body"),
      )
      .into_response(),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::Serror;

  /// The response bodies here are fully buffered,
  /// so they resolve without a runtime.
  fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    loop {
      match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(value) => return value,
        std::task::Poll::Pending => std::thread::yield_now(),
      }
    }
  }

  fn body_string(response: axum::response::Response) -> String {
    let bytes = block_on(axum::body::to_bytes(
      response.into_body(),
      usize::MAX,
    ))
    .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
  }

  #[test]
  fn error_defaults_to_internal_server_error() {
    let error = Error::msg("boom");
    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(error.headers.is_none());
  }

  #[test]
  fn question_mark_conversion_uses_internal_server_error() {
    fn fails() -> Result<()> {
      Err(std::io::Error::other("io failure"))?;
      Ok(())
    }
    let error = fails().unwrap_err();
    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error.error.to_string(), "io failure");
  }

  #[test]
  fn status_code_and_header_builders() {
    let error = Error::msg("boom")
      .status_code(StatusCode::BAD_REQUEST)
      .header(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic"),
      )
      .header(header::RETRY_AFTER, HeaderValue::from_static("30"));
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    let headers = error.headers.as_ref().unwrap();
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Basic");
    assert_eq!(headers[header::RETRY_AFTER], "30");
  }

  #[test]
  fn into_response_maps_status_headers_and_body() {
    let response = Error::msg("root cause")
      .status_code(StatusCode::UNAUTHORIZED)
      .header(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic"),
      )
      .into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
      response.headers()[header::CONTENT_TYPE],
      "application/json"
    );
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Basic");
    let serror: Serror =
      serde_json::from_str(&body_string(response)).unwrap();
    assert_eq!(serror.error, "root cause");
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn into_response_serializes_context_chain() {
    let error: Error = anyhow::Context::context(
      std::result::Result::<(), _>::Err(anyhow::anyhow!(
        "root cause"
      )),
      "top level",
    )
    .unwrap_err()
    .into();
    let serror: Serror =
      serde_json::from_str(&body_string(error.into_response()))
        .unwrap();
    assert_eq!(serror.error, "top level");
    assert_eq!(serror.trace, vec!["root cause"]);
  }

  fn internal_error() -> Error {
    anyhow::anyhow!("connection refused (db.internal:5432)")
      .context("Failed to query users")
      .into()
  }

  fn server_error(
    response: &axum::response::Response,
  ) -> Option<String> {
    response
      .extensions()
      .get::<ServerError>()
      .map(|ServerError(e)| format!("{e:#}"))
  }

  #[test]
  fn server_error_detail_defaults_to_full() {
    assert_eq!(ServerErrorDetail::default(), ServerErrorDetail::Full);
    let response =
      internal_error().response_with_detail(ServerErrorDetail::Full);
    // Attached whatever the body carries.
    assert_eq!(
      server_error(&response).unwrap(),
      "Failed to query users: connection refused (db.internal:5432)"
    );
    let serror: Serror =
      serde_json::from_str(&body_string(response)).unwrap();
    assert_eq!(serror.error, "Failed to query users");
    assert_eq!(
      serror.trace,
      vec!["connection refused (db.internal:5432)"]
    );
  }

  #[test]
  fn server_error_detail_message_drops_trace() {
    let response = internal_error()
      .header(header::RETRY_AFTER, HeaderValue::from_static("30"))
      .response_with_detail(ServerErrorDetail::Message);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
      response.headers()[header::CONTENT_TYPE],
      "application/json"
    );
    assert_eq!(response.headers()[header::RETRY_AFTER], "30");
    assert_eq!(
      server_error(&response).unwrap(),
      "Failed to query users: connection refused (db.internal:5432)"
    );
    let serror: Serror =
      serde_json::from_str(&body_string(response)).unwrap();
    assert_eq!(serror.error, "Failed to query users");
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn server_error_detail_generic_uses_canonical_reason() {
    let response = internal_error()
      .status_code(StatusCode::SERVICE_UNAVAILABLE)
      .response_with_detail(ServerErrorDetail::Generic);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(server_error(&response).is_some());
    let body = body_string(response);
    assert!(!body.contains("db.internal"));
    let serror: Serror = serde_json::from_str(&body).unwrap();
    assert_eq!(serror.error, "Service Unavailable");
    assert!(serror.trace.is_empty());
  }

  #[test]
  fn server_error_detail_leaves_client_errors_alone() {
    let response = internal_error()
      .status_code(StatusCode::BAD_REQUEST)
      .response_with_detail(ServerErrorDetail::Generic);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // The body has it all, there is nothing to log.
    assert!(server_error(&response).is_none());
    let serror: Serror =
      serde_json::from_str(&body_string(response)).unwrap();
    assert_eq!(serror.error, "Failed to query users");
    assert_eq!(serror.trace.len(), 1);
  }

  #[test]
  fn custom_headers_override_default_content_type() {
    let response = Error::msg("boom")
      .header(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
      )
      .into_response();
    assert_eq!(
      response.headers()[header::CONTENT_TYPE],
      "text/plain"
    );
  }

  #[test]
  fn add_status_code_on_results() {
    let result: std::result::Result<(), std::io::Error> =
      Err(std::io::Error::other("io failure"));
    let error =
      result.status_code(StatusCode::NOT_FOUND).unwrap_err();
    assert_eq!(error.status, StatusCode::NOT_FOUND);

    let ok: std::result::Result<i64, std::io::Error> =
      std::result::Result::Ok(42);
    let ok = ok.status_code(StatusCode::NOT_FOUND).unwrap();
    assert_eq!(ok, 42);
  }

  #[test]
  fn response_from_serializable_value() {
    let Response(response) =
      Response::from(serde_json::json!({ "a": 1 }));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response.headers()[header::CONTENT_TYPE],
      "application/json"
    );
    assert_eq!(body_string(response), r#"{"a":1}"#);
  }

  #[test]
  fn response_from_unserializable_value_is_serror() {
    // serde_json rejects non string map keys
    let value =
      std::collections::HashMap::from([((1, 2), 3), ((4, 5), 6)]);
    let Response(response) = Response::from(value);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
      response.headers()[header::CONTENT_TYPE],
      "application/json"
    );
    let serror: Serror =
      serde_json::from_str(&body_string(response)).unwrap();
    assert_eq!(serror.error, "Failed to serialize response body");
    assert_eq!(serror.trace.len(), 1);

    let response = JsonString::from(std::collections::HashMap::from(
      [((1, 2), 3)],
    ))
    .into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let serror: Serror =
      serde_json::from_str(&body_string(response)).unwrap();
    assert_eq!(serror.error, "Failed to serialize response body");
  }

  fn chain(e: &anyhow::Error) -> Vec<String> {
    e.chain().map(|e| e.to_string()).collect()
  }

  #[test]
  fn uncounted_errors_render_and_respond_unchanged() {
    let original = || {
      anyhow::anyhow!("token expired at 1700000000")
        .context("Failed to authenticate")
    };
    let error = Error::from(original())
      .status_code(StatusCode::UNAUTHORIZED)
      .header(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer"),
      );
    assert!(!error.is_uncounted());
    let error = error.uncounted();
    assert!(error.is_uncounted());
    assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    assert_eq!(chain(&error.error), chain(&original()));
    assert_eq!(
      format!("{:#}", error.error),
      format!("{:#}", original())
    );
    let response = error.into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
      response.headers()[header::WWW_AUTHENTICATE],
      "Bearer"
    );
    let serror: Serror =
      serde_json::from_str(&body_string(response)).unwrap();
    assert_eq!(serror.error, "Failed to authenticate");
    assert_eq!(serror.trace, ["token expired at 1700000000"]);
    // A single message too.
    let error = Error::msg("Session ended").uncounted();
    assert!(error.is_uncounted());
    assert_eq!(chain(&error.error), ["Session ended"]);
    assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
  }

  #[test]
  fn uncounted_survives_context_added_after() {
    // Eg. mogh_rate_limit's note of the attempts left, or an app's
    // context on the way out.
    let mut error = Error::msg("Session ended")
      .status_code(StatusCode::UNAUTHORIZED)
      .uncounted();
    error.error =
      error.error.context("Failed to authenticate request");
    assert!(error.is_uncounted());
    assert_eq!(
      chain(&error.error),
      ["Failed to authenticate request", "Session ended"]
    );
    assert_eq!(
      format!("{:#}", error.error),
      "Failed to authenticate request: Session ended"
    );
    assert!(error.error.downcast_ref::<NotAnAttempt>().is_some());
  }

  #[test]
  fn uncounted_marks_once() {
    let error = Error::msg("boom").uncounted().uncounted();
    let markers = error
      .error
      .chain()
      .filter(|e| e.is::<NotAnAttempt>())
      .count();
    assert_eq!(markers, 1);
    assert_eq!(chain(&error.error), ["boom"]);
  }

  #[derive(Debug, PartialEq, serde::Deserialize)]
  #[serde(tag = "type", content = "params")]
  enum TestRequest {
    GetUser(GetUser),
    SetLimit(SetLimit),
  }

  #[derive(Debug, PartialEq, serde::Deserialize)]
  struct GetUser {
    id: String,
  }

  #[derive(Debug, PartialEq, serde::Deserialize)]
  struct SetLimit {
    limit: u64,
    kind: Option<LimitKind>,
    ids: Vec<u64>,
  }

  #[derive(Debug, PartialEq, serde::Deserialize)]
  enum LimitKind {
    Soft,
    Hard,
  }

  /// The status and the whole error chain.
  fn variant_error(
    variant: &str,
    params: serde_json::Value,
  ) -> (StatusCode, String) {
    let e =
      variant_request::<TestRequest>(variant, params).unwrap_err();
    (e.status, format!("{:#}", e.error))
  }

  #[test]
  fn variant_request_builds_the_tagged_request() {
    let request: TestRequest =
      variant_request("GetUser", serde_json::json!({ "id": "1" }))
        .unwrap();
    assert_eq!(
      request,
      TestRequest::GetUser(GetUser {
        id: String::from("1")
      })
    );
    let request: TestRequest = variant_request(
      "SetLimit",
      serde_json::json!({ "limit": 5, "kind": "Hard", "ids": [1] }),
    )
    .unwrap();
    assert_eq!(
      request,
      TestRequest::SetLimit(SetLimit {
        limit: 5,
        kind: Some(LimitKind::Hard),
        ids: vec![1],
      })
    );
  }

  #[test]
  fn variant_request_unknown_variant_is_unprocessable() {
    let (status, error) =
      variant_error("Nope", serde_json::json!({}));
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
      error,
      "Unknown request type \"Nope\": unknown variant, expected `GetUser` or `SetLimit`"
    );
    // The variant comes from the path: shown, but escaped.
    let (_, error) = variant_error("No\npe", serde_json::json!({}));
    assert!(error.starts_with("Unknown request type \"No\\npe\":"));
    // Into a 422 response, the cause as its trace.
    let response =
      variant_request::<TestRequest>("Nope", serde_json::json!({}))
        .unwrap_err()
        .into_response();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let serror: Serror =
      serde_json::from_str(&body_string(response)).unwrap();
    assert_eq!(serror.error, "Unknown request type \"Nope\"");
    assert_eq!(
      serror.trace,
      ["unknown variant, expected `GetUser` or `SetLimit`"]
    );
  }

  /// The variant comes from the caller (a path, a websocket frame),
  /// as long as they like: an error shows it cut short.
  #[test]
  fn variant_request_shows_a_long_variant_cut_short() {
    let (status, error) =
      variant_error(&"x".repeat(1000), serde_json::json!({}));
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
      error.starts_with(&format!(
        "Unknown request type \"{}\": unknown variant",
        "x".repeat(64)
      )),
      "{error}"
    );
  }

  #[test]
  fn variant_request_bad_params_name_the_field_not_the_value() {
    for (params, expected) in [
      (
        serde_json::json!({ "limit": "hunter2", "ids": [] }),
        "limit: invalid type, expected u64",
      ),
      (
        // The value can't fake the end of the message.
        serde_json::json!({ "limit": "hunter2, expected x", "ids": [] }),
        "limit: invalid type, expected u64",
      ),
      (
        serde_json::json!({ "limit": -2023, "ids": [] }),
        "limit: invalid value, expected u64",
      ),
      (
        serde_json::json!({ "limit": 1, "kind": "hunter2", "ids": [] }),
        "kind: unknown variant, expected `Soft` or `Hard`",
      ),
      (
        serde_json::json!({ "limit": 1, "ids": [1, "hunter2"] }),
        "ids[1]: invalid type, expected u64",
      ),
      (serde_json::json!({ "ids": [] }), "missing field `limit`"),
      (
        serde_json::json!("hunter2"),
        "invalid type, expected struct SetLimit",
      ),
    ] {
      let (status, error) = variant_error("SetLimit", params.clone());
      assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{params}"
      );
      assert_eq!(
        error,
        format!("Invalid SetLimit params: {expected}"),
        "{params}"
      );
      assert!(!error.contains("hunter2"), "{error}");
      assert!(!error.contains("2023"), "{error}");
    }
  }

  fn raw(params: &serde_json::Value) -> Box<RawValue> {
    serde_json::value::to_raw_value(params).unwrap()
  }

  #[test]
  fn variant_request_raw_builds_the_tagged_request() {
    // Any key order.
    let params = RawValue::from_string(String::from(
      r#"{ "ids": [1], "kind": "Hard", "limit": 5 }"#,
    ))
    .unwrap();
    let request: TestRequest =
      variant_request_raw("SetLimit", &params).unwrap();
    assert_eq!(
      request,
      TestRequest::SetLimit(SetLimit {
        limit: 5,
        kind: Some(LimitKind::Hard),
        ids: vec![1],
      })
    );
    let request: TestRequest = variant_request_raw(
      "GetUser",
      &raw(&serde_json::json!({ "id": "1" })),
    )
    .unwrap();
    assert_eq!(
      request,
      TestRequest::GetUser(GetUser {
        id: String::from("1")
      })
    );
  }

  /// Refused as variant_request refuses: the same status and
  /// messages, no value, no position in the params' text.
  #[test]
  fn variant_request_raw_refuses_like_variant_request() {
    let long = "x".repeat(1000);
    for (variant, params) in [
      ("Nope", serde_json::json!({})),
      ("No\npe", serde_json::json!({})),
      (long.as_str(), serde_json::json!({})),
      (
        "SetLimit",
        serde_json::json!({ "limit": "hunter2", "ids": [] }),
      ),
      (
        "SetLimit",
        serde_json::json!({ "limit": "hunter2, expected x", "ids": [] }),
      ),
      ("SetLimit", serde_json::json!({ "limit": -2023, "ids": [] })),
      (
        "SetLimit",
        serde_json::json!({ "limit": 1, "kind": "hunter2", "ids": [] }),
      ),
      (
        "SetLimit",
        serde_json::json!({ "limit": 1, "ids": [1, "hunter2"] }),
      ),
      ("SetLimit", serde_json::json!({ "ids": [] })),
      ("SetLimit", serde_json::json!("hunter2")),
    ] {
      let expected = variant_error(variant, params.clone());
      let e =
        variant_request_raw::<TestRequest>(variant, &raw(&params))
          .unwrap_err();
      let shown = format!("{:#}", e.error);
      assert_eq!((e.status, shown.clone()), expected, "{params}");
      assert!(!shown.contains("hunter2"), "{shown}");
      assert!(!shown.contains("2023"), "{shown}");
      assert!(!shown.contains(" column "), "{shown}");
    }
  }

  #[test]
  fn json_string_from_serializable_value() {
    let json = JsonString::from(serde_json::json!({ "a": 1 }));
    let response = json.into_response();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_string(response), r#"{"a":1}"#);
  }
}
