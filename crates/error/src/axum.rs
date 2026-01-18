use anyhow::Context as _;
use axum::{
  body::Body,
  extract::{FromRequest, rejection::JsonRejection},
  http::{
    HeaderMap, HeaderValue, StatusCode,
    header::{CONTENT_TYPE, IntoHeaderName},
  },
  response::IntoResponse,
};
use serde::Serialize;

use crate::serialize_error;

pub type Result<T> = std::result::Result<T, Error>;

#[allow(non_snake_case)]
pub fn Ok<T>(value: T) -> Result<T> {
  Result::Ok(value)
}

/// Intermediate error type which can be converted to from any error using `?`.
/// The standard `impl From<E> for Error` will attach StatusCode::INTERNAL_SERVER_ERROR,
/// so if an alternative StatusCode is desired, you should use `.status_code` ([AddStatusCode] or [AddStatusCodeError])
/// to add the status and `.header` ([AddHeader] or [AddHeaderError]) before using `?`.
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
}

impl IntoResponse for Error {
  fn into_response(self) -> axum::response::Response {
    let mut response = axum::response::Response::new(Body::new(
      serialize_error(&self.error),
    ));
    *response.status_mut() = self.status;

    let headers = response.headers_mut();
    headers.append(
      "Content-Type",
      HeaderValue::from_static("application/json"),
    );
    if let Some(self_headers) = self.headers {
      headers.extend(self_headers);
    }

    response
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

/// Convenience trait to convert any Error into serror::Error by adding headers
/// and converting error into anyhow error.
pub trait AddHeadersError: Into<anyhow::Error> {
  fn header(
    self,
    name: impl IntoHeaderName,
    value: HeaderValue,
  ) -> Error {
    let mut headers = HeaderMap::with_capacity(1);
    headers.append(name, value);
    Error {
      headers: Some(headers),
      status: StatusCode::INTERNAL_SERVER_ERROR,
      error: self.into(),
    }
  }
  fn headers(self, headers: HeaderMap) -> Error {
    Error {
      headers: Some(headers),
      status: StatusCode::INTERNAL_SERVER_ERROR,
      error: self.into(),
    }
  }
}

impl<E> AddHeadersError for E where E: Into<anyhow::Error> {}

/// Convenience trait to add headers to a serror::Result directly.
pub trait AddHeaders<T, E>: Into<std::result::Result<T, E>>
where
  E: Into<anyhow::Error>,
{
  fn header(
    self,
    name: impl IntoHeaderName,
    value: HeaderValue,
  ) -> Result<T> {
    self.into().map_err(|e| e.header(name, value))
  }

  /// Some headers might want to be attached in both Ok case and Err case.
  /// Borrow headers here so they can be used later, as they will only be cloned in err case.
  fn headers(self, headers: &HeaderMap) -> Result<T> {
    self.into().map_err(|e| e.headers(headers.clone()))
  }
}

impl<R, T, E> AddHeaders<T, E> for R
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
            CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
          )
          .body(axum::body::Body::from(body))
          .unwrap()
      }
      Err(e) => axum::response::Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(
          CONTENT_TYPE,
          HeaderValue::from_static("application/json"),
        )
        .body(axum::body::Body::from(serialize_error(&e)))
        .unwrap(),
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
          CONTENT_TYPE,
          HeaderValue::from_static("application/json"),
        )
        .body(axum::body::Body::from(body))
        .unwrap(),
      JsonString::Err(error) => axum::response::Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header(
          CONTENT_TYPE,
          HeaderValue::from_static("application/json"),
        )
        .body(axum::body::Body::from(serialize_error(
          &anyhow::Error::from(error)
            .context("Failed to serialize response body"),
        )))
        .unwrap(),
    }
  }
}
