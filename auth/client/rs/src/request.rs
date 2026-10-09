//! Calling the auth api with [reqwest].
//!
//! The functions here are async and take a [reqwest::Client]. The
//! `blocking` feature adds the same functions for a
//! `reqwest::blocking::Client` in `request::blocking`.
//!
//! `address` is where the auth api is mounted, eg.
//! `https://example.com/auth`. [login] and [token_exchange] need no
//! credentials (a login with a second factor needs a client keeping
//! the session cookie, see [login]). [manage] sends none itself: give
//! the client default headers with them, a jwt
//! (`Authorization: Bearer <jwt>`) or an api key (`X-API-KEY` /
//! `X-API-SECRET`).
//!
//! Build the client with `reqwest::redirect::Policy::none()`, so it
//! follows no redirects. reqwest follows up to 10 by default, and on
//! a redirect to another host strips only `Authorization` and
//! cookies: api key headers go along to wherever the redirect points
//! (the login page a proxy in front of the server sends requests to,
//! a domain which moved), and a `307` / `308` sends the body again
//! too (the password of `LoginLocalUser` / `UpdatePassword`). The
//! functions here take a redirect which is not followed as an error.
//!
//! A request with a signing key is signed on its own, right before it
//! goes out, over the host of the server and its exact path, query
//! and body (see [crate::signature]). With the `pki` feature,
//! `signed_manage` sends a manage request so, and `signed_post` any
//! signed JSON `POST` (a `SignedPost`), eg. to the app's own api. Both
//! send a request once more, signed anew, when the server refused its
//! timestamp: the time to set up a connection counts against it.
//!
//! Responses are read with a limit, so whatever answers in place of
//! the auth api (a proxy's error page, an endpoint streaming without
//! end) is not read without end: an error body up to
//! [MAX_ERROR_BODY_BYTES] (cut there, the error saying so), a
//! successful one up to [MAX_SUCCESS_BODY_BYTES] (a longer one is an
//! error). They are parsed by [parse_response]. The same is there for
//! the responses of any other JSON api: [json_response] with its own
//! limit, [error_text] for the text of an error body, and
//! [read_body].

use anyhow::{Context, anyhow};
use mogh_error::deserialize_error_bytes;
use mogh_resolver::HasResponse;
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::api::{
  login::MoghAuthLoginRequest,
  manage::MoghAuthManageRequest,
  token::{
    TokenExchangeError, TokenExchangeRequest, TokenExchangeResponse,
  },
};

/// How much of the body of a response which is no success is read
/// ([error_text]). The errors of a server are a few lines; whatever
/// answers in its place (the html error page of a proxy, an endpoint
/// streaming without end) is not read without end, nor kept whole as
/// the error message.
pub const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// How much of a successful response of the auth api is read: the
/// largest (a TOTP enrollment with its QR code, the list of login
/// providers) are some KiB. A longer body is an error.
pub const MAX_SUCCESS_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Call the unauthenticated login api.
///
/// A login with a second factor takes more than one request:
/// `LoginLocalUser` / `ExchangeExternalForJwt` answer `Totp` or
/// `Passkey`, and `CompleteTotpLogin` / `CompleteTotpRecoveryLogin` /
/// `CompletePasskeyLogin` finish it. The server keeps the pending
/// login in the session, so these must be sent with a client which
/// keeps the session cookie: one built with
/// `reqwest::ClientBuilder::cookie_store(true)` (reqwest's `cookies`
/// feature), as the example app's client does (`ExampleClient::new`
/// in `example/client/rs` of the repository). Without it the second
/// step is refused (`401`, "TOTP login has not been initiated for
/// this session").
pub async fn login<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthLoginRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/login", request_body(&request)).await
}

/// Call the authenticated management api.
pub async fn manage<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthManageRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/manage", request_body(&request)).await
}

/// RFC 8693 Token Exchange: exchange a token issued by an external
/// login provider for an app token at the `/token` endpoint.
pub async fn token_exchange(
  reqwest: &reqwest::Client,
  address: &str,
  request: &TokenExchangeRequest,
) -> anyhow::Result<TokenExchangeResponse> {
  let res = reqwest
    .post(request_url(address, "/token"))
    .form(request)
    .send()
    .await
    .context("failed to reach Mogh Auth API")?;
  read_response(res, MAX_SUCCESS_BODY_BYTES, parse_token_response)
    .await
}

async fn post<B: Serialize, R: DeserializeOwned>(
  reqwest: &reqwest::Client,
  address: &str,
  endpoint: &str,
  body: B,
) -> anyhow::Result<R> {
  let res = reqwest
    .post(request_url(address, endpoint))
    .json(&body)
    .send()
    .await
    .context("failed to reach Mogh Auth API")?;
  json_response(res, MAX_SUCCESS_BODY_BYTES).await
}

/// A response body, read up to a limit ([read_body]).
///
/// Its Debug output shows only the length: a body may hold secrets.
pub struct LimitedBody {
  /// The body, at most the limit.
  pub bytes: Vec<u8>,
  /// Whether the body goes on past the limit. The rest of it was not
  /// read.
  pub truncated: bool,
}

impl std::fmt::Debug for LimitedBody {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("LimitedBody")
      .field("len", &self.bytes.len())
      .field("truncated", &self.truncated)
      .finish()
  }
}

/// Reads the body of `res`, up to `max_bytes` of it, as it arrives:
/// a longer body (or one which never ends) is not read further, nor
/// buffered. [LimitedBody::truncated] says whether it went on.
pub async fn read_body(
  mut res: reqwest::Response,
  max_bytes: usize,
) -> anyhow::Result<LimitedBody> {
  let mut bytes = Vec::new();
  while let Some(chunk) = res
    .chunk()
    .await
    .context("Failed to read the response body")?
  {
    let room = max_bytes - bytes.len();
    if chunk.len() > room {
      bytes.extend_from_slice(&chunk[..room]);
      return Ok(LimitedBody {
        bytes,
        truncated: true,
      });
    }
    bytes.extend_from_slice(&chunk);
  }
  Ok(LimitedBody {
    bytes,
    truncated: false,
  })
}

/// The body of a response which is no success, as the text of its
/// error: read up to [MAX_ERROR_BODY_BYTES] ([read_body]), invalid
/// utf8 replaced. A longer body is cut there, and the text ends
/// saying so. A body which can't be read gives the reason instead.
pub async fn error_text(res: reqwest::Response) -> String {
  error_text_of(read_body(res, MAX_ERROR_BODY_BYTES).await)
}

/// Reads a response of a JSON api ([read_body]) and parses it with
/// [parse_response]: the value of a successful one, read up to
/// `max_bytes` (a longer body is an error, which keeps none of it),
/// else the error of the server, read up to [MAX_ERROR_BODY_BYTES]
/// ([error_text]). The status is the outermost context of an error.
///
/// `max_bytes` is the most a successful response of the api may
/// have: [MAX_SUCCESS_BODY_BYTES] for the auth api, which the
/// request functions here read their responses with.
pub async fn json_response<T: DeserializeOwned>(
  res: reqwest::Response,
  max_bytes: usize,
) -> anyhow::Result<T> {
  read_response(res, max_bytes, parse_response).await
}

/// Reads a response for `parse`: a successful body up to `max_bytes`
/// ([success_body]), an error body as [error_text].
async fn read_response<T>(
  res: reqwest::Response,
  max_bytes: usize,
  parse: fn(StatusCode, &[u8]) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
  let status = res.status();
  if status.is_success() {
    let body = read_body(res, max_bytes).await;
    parse(status, &success_body(status, body, max_bytes)?)
  } else {
    parse(status, error_text(res).await.as_bytes())
  }
}

/// Calls the authenticated management api with a request signed
/// with a signing key: `POST {address}/manage`, signed for its host,
/// path and body ([signed_post], which says how a refused timestamp is
/// retried).
///
/// `keys` is the key pair of the signing key's private key, parsed
/// once ([signing_keys][crate::signature::signing_keys]). Where a
/// proxy in front of the server strips a prefix of the path, or the
/// server knows itself by another host than the address has, send a
/// [SignedPost] for `{address}/manage` with what the server receives.
#[cfg(feature = "pki")]
pub async fn signed_manage<T>(
  reqwest: &reqwest::Client,
  address: &str,
  keys: &mogh_pki::EncodedKeyPair,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthManageRequest,
  T::Response: DeserializeOwned,
{
  let post = SignedPost::new(
    &request_url(address, "/manage"),
    keys,
    &request_body(&request),
  )?;
  signed_post(reqwest, &post, MAX_SUCCESS_BODY_BYTES).await
}

/// Sends `post`, signed right before it goes out, and reads the
/// response with [json_response] (a successful body up to
/// `max_bytes`).
///
/// The signature is made before the request is sent, so the time to
/// connect (DNS, TCP and TLS of a new connection) counts against the
/// timestamp tolerance of the server, a second by default: on a slow
/// link the first request over a new connection can arrive too late.
/// The server tells so (`401`,
/// [SIGNED_AT_ANOTHER_TIME][crate::signature::SIGNED_AT_ANOTHER_TIME]),
/// which it finds out before anything else and counts against
/// nobody. Then the request goes out once more, signed anew (a new
/// timestamp and nonce, the same body), over a connection opened
/// before it is signed: an unsigned `HEAD` to the url opens it, which
/// carries no credentials, so the server refuses (or answers) it
/// without counting it against the client. Only once: any other
/// answer, a second refusal included, is the result.
#[cfg(feature = "pki")]
pub async fn signed_post<T: DeserializeOwned>(
  reqwest: &reqwest::Client,
  post: &SignedPost<'_>,
  max_bytes: usize,
) -> anyhow::Result<T> {
  let res = send_signed(reqwest, post).await?;
  if res.status() != StatusCode::UNAUTHORIZED {
    return json_response(res, max_bytes).await;
  }
  let refusal = error_text(res).await;
  if !refusal.contains(crate::signature::SIGNED_AT_ANOTHER_TIME) {
    return parse_response(
      StatusCode::UNAUTHORIZED,
      refusal.as_bytes(),
    );
  }
  // Best effort, the request is sent anyway. The answer has no body,
  // the connection goes back to the pool for the request to take.
  if let Ok(res) = reqwest.head(post.url.clone()).send().await {
    let _ = res.bytes().await;
  }
  json_response(send_signed(reqwest, post).await?, max_bytes).await
}

/// One attempt of [signed_post], signed now.
#[cfg(feature = "pki")]
async fn send_signed(
  reqwest: &reqwest::Client,
  post: &SignedPost<'_>,
) -> anyhow::Result<reqwest::Response> {
  let headers = post.attempt_headers()?;
  reqwest
    .post(post.url.clone())
    .headers(headers)
    .body(post.body.clone())
    .send()
    .await
    .context("Failed to send the signed request")
}

/// A `POST` of a JSON body signed with a signing key (see
/// [crate::signature]), which [signed_post] sends.
///
/// [SignedPost::new] signs it for the host, path and query of the url
/// it is sent to. Where the server receives it otherwise, set what it
/// is signed for before sending:
/// - [host][Self::host]: the server knows itself by another host than
///   the url has (eg. reached through a tunnel at another address):
///   one of the hosts the server is configured with.
/// - [path_and_query][Self::path_and_query]: a proxy in front of the
///   server strips a prefix of the path: the path the server
///   receives.
///
/// It has no Debug: the body may hold secrets.
#[cfg(feature = "pki")]
pub struct SignedPost<'a> {
  /// Where the request is sent. [SignedPost::new] takes the host and
  /// path and query it is signed for from it, changing it after
  /// doesn't change those.
  pub url: reqwest::Url,
  /// The host it is signed for ([url_host][crate::signature::url_host]
  /// of the url by default).
  pub host: String,
  /// The path and query it is signed for (those of the url by
  /// default).
  pub path_and_query: String,
  /// The key pair of the signing key
  /// ([signing_keys][crate::signature::signing_keys]).
  pub keys: &'a mogh_pki::EncodedKeyPair,
  /// The JSON body, sent and signed exactly as it is.
  pub body: Vec<u8>,
  /// Headers sent along, unsigned (eg. a trace context). Credentials
  /// are refused: the server takes them over the signature.
  pub headers: reqwest::header::HeaderMap,
}

/// The error for a signed request which carries other credentials.
/// The server would take those over the signature, and count what
/// it makes of them against the client: it is not sent.
#[cfg(feature = "pki")]
const OTHER_CREDENTIALS: &str = "The request carries other credentials (a `user:password@` in the url, an Authorization header or an api key), which the server takes over the signature";

#[cfg(feature = "pki")]
impl<'a> SignedPost<'a> {
  /// `body` as JSON, to `url`, signed with `keys` for the host, path
  /// and query of the url. A url which carries credentials
  /// (`user:password@`) is an error, which doesn't repeat them.
  pub fn new(
    url: &str,
    keys: &'a mogh_pki::EncodedKeyPair,
    body: &impl Serialize,
  ) -> anyhow::Result<Self> {
    let url = reqwest::Url::parse(url.trim())
      .context("Invalid url, expected eg. https://example.com")?;
    if has_credentials(&url) {
      anyhow::bail!(OTHER_CREDENTIALS);
    }
    Ok(SignedPost {
      host: crate::signature::url_origin_host(&url)?,
      path_and_query: crate::signature::url_path_and_query(&url),
      url,
      keys,
      body: serde_json::to_vec(body)
        .context("Failed to serialize the request body")?,
      headers: Default::default(),
    })
  }

  /// The headers of an attempt: the content type, [Self::headers],
  /// and the signature, made now.
  fn attempt_headers(
    &self,
  ) -> anyhow::Result<reqwest::header::HeaderMap> {
    use reqwest::header::{
      AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue,
    };
    if has_credentials(&self.url)
      || self.headers.contains_key(AUTHORIZATION)
      || self.headers.contains_key("x-api-key")
      || self.headers.contains_key("x-api-secret")
    {
      anyhow::bail!(OTHER_CREDENTIALS);
    }
    let mut headers = HeaderMap::new();
    headers.insert(
      CONTENT_TYPE,
      HeaderValue::from_static("application/json"),
    );
    headers.extend(self.headers.clone());
    let signed = crate::signature::signed_request_headers_with_keys(
      self.keys,
      &self.host,
      "POST",
      &self.path_and_query,
      &self.body,
    )?;
    for (header, value) in signed {
      headers.insert(
        header,
        HeaderValue::from_str(&value)
          .context("Invalid signature header")?,
      );
    }
    Ok(headers)
  }
}

/// Whether the url carries credentials (`user:password@`), which
/// reqwest sends as Authorization.
#[cfg(feature = "pki")]
fn has_credentials(url: &reqwest::Url) -> bool {
  !url.username().is_empty() || url.password().is_some()
}

/// The request functions for a [reqwest::blocking::Client],
/// with the same names and behavior as the async ones.
#[cfg(feature = "blocking")]
pub mod blocking {
  use std::io::Read as _;

  use anyhow::Context;
  use reqwest::StatusCode;
  use serde::{Serialize, de::DeserializeOwned};

  use crate::api::{
    login::MoghAuthLoginRequest,
    manage::MoghAuthManageRequest,
    token::{TokenExchangeRequest, TokenExchangeResponse},
  };

  #[cfg(feature = "pki")]
  use super::SignedPost;
  use super::{
    LimitedBody, MAX_ERROR_BODY_BYTES, MAX_SUCCESS_BODY_BYTES,
    error_text_of, parse_response, parse_token_response,
    request_body, request_url, success_body,
  };

  /// Call the unauthenticated login api.
  ///
  /// A login with a second factor needs a client which keeps the
  /// session cookie, see [super::login].
  pub fn login<T>(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghAuthLoginRequest,
    T::Response: DeserializeOwned,
  {
    post(reqwest, address, "/login", request_body(&request))
  }

  /// Call the authenticated management api.
  pub fn manage<T>(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghAuthManageRequest,
    T::Response: DeserializeOwned,
  {
    post(reqwest, address, "/manage", request_body(&request))
  }

  /// RFC 8693 Token Exchange: exchange a token issued by an external
  /// login provider for an app token at the `/token` endpoint.
  pub fn token_exchange(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    request: &TokenExchangeRequest,
  ) -> anyhow::Result<TokenExchangeResponse> {
    let res = reqwest
      .post(request_url(address, "/token"))
      .form(request)
      .send()
      .context("failed to reach Mogh Auth API")?;
    read_response(res, MAX_SUCCESS_BODY_BYTES, parse_token_response)
  }

  fn post<B: Serialize, R: DeserializeOwned>(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    endpoint: &str,
    body: B,
  ) -> anyhow::Result<R> {
    let res = reqwest
      .post(request_url(address, endpoint))
      .json(&body)
      .send()
      .context("failed to reach Mogh Auth API")?;
    json_response(res, MAX_SUCCESS_BODY_BYTES)
  }

  /// [super::signed_manage]: calls the authenticated management api
  /// with a request signed with a signing key.
  #[cfg(feature = "pki")]
  pub fn signed_manage<T>(
    reqwest: &reqwest::blocking::Client,
    address: &str,
    keys: &mogh_pki::EncodedKeyPair,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghAuthManageRequest,
    T::Response: DeserializeOwned,
  {
    let post = SignedPost::new(
      &request_url(address, "/manage"),
      keys,
      &request_body(&request),
    )?;
    signed_post(reqwest, &post, MAX_SUCCESS_BODY_BYTES)
  }

  /// [super::signed_post]: sends `post`, signed right before it goes
  /// out, once more when the server refused its timestamp.
  #[cfg(feature = "pki")]
  pub fn signed_post<T: DeserializeOwned>(
    reqwest: &reqwest::blocking::Client,
    post: &SignedPost<'_>,
    max_bytes: usize,
  ) -> anyhow::Result<T> {
    let res = send_signed(reqwest, post)?;
    if res.status() != StatusCode::UNAUTHORIZED {
      return json_response(res, max_bytes);
    }
    let refusal = error_text(res);
    if !refusal.contains(crate::signature::SIGNED_AT_ANOTHER_TIME) {
      return parse_response(
        StatusCode::UNAUTHORIZED,
        refusal.as_bytes(),
      );
    }
    // Opens the connection the request goes out over, see
    // [super::signed_post].
    if let Ok(res) = reqwest.head(post.url.clone()).send() {
      let _ = res.bytes();
    }
    json_response(send_signed(reqwest, post)?, max_bytes)
  }

  #[cfg(feature = "pki")]
  fn send_signed(
    reqwest: &reqwest::blocking::Client,
    post: &SignedPost<'_>,
  ) -> anyhow::Result<reqwest::blocking::Response> {
    let headers = post.attempt_headers()?;
    reqwest
      .post(post.url.clone())
      .headers(headers)
      .body(post.body.clone())
      .send()
      .context("Failed to send the signed request")
  }

  /// [super::read_body]: reads the body of `res`, up to `max_bytes`
  /// of it.
  pub fn read_body(
    res: reqwest::blocking::Response,
    max_bytes: usize,
  ) -> anyhow::Result<LimitedBody> {
    let mut bytes = Vec::new();
    // One byte past the limit tells a longer body from one which
    // just fits.
    let limit = u64::try_from(max_bytes)
      .unwrap_or(u64::MAX)
      .saturating_add(1);
    res
      .take(limit)
      .read_to_end(&mut bytes)
      .context("Failed to read the response body")?;
    let truncated = bytes.len() > max_bytes;
    bytes.truncate(max_bytes);
    Ok(LimitedBody { bytes, truncated })
  }

  /// [super::error_text]: the body of a response which is no
  /// success, as the text of its error.
  pub fn error_text(res: reqwest::blocking::Response) -> String {
    error_text_of(read_body(res, MAX_ERROR_BODY_BYTES))
  }

  /// [super::json_response]: reads a response of a JSON api and
  /// parses it with [parse_response].
  pub fn json_response<T: DeserializeOwned>(
    res: reqwest::blocking::Response,
    max_bytes: usize,
  ) -> anyhow::Result<T> {
    read_response(res, max_bytes, parse_response)
  }

  fn read_response<T>(
    res: reqwest::blocking::Response,
    max_bytes: usize,
    parse: fn(StatusCode, &[u8]) -> anyhow::Result<T>,
  ) -> anyhow::Result<T> {
    let status = res.status();
    if status.is_success() {
      let body = read_body(res, max_bytes);
      parse(status, &success_body(status, body, max_bytes)?)
    } else {
      parse(status, error_text(res).as_bytes())
    }
  }
}

/// The bytes of a successful body which [read_body] read up to
/// `max_bytes`. A longer one is an error, which keeps none of it: the
/// body may hold secrets.
fn success_body(
  status: StatusCode,
  body: anyhow::Result<LimitedBody>,
  max_bytes: usize,
) -> anyhow::Result<Vec<u8>> {
  let body = body.context(status)?;
  if body.truncated {
    return Err(
      anyhow!(
        "The response body is longer than {max_bytes} bytes, more than a response of this api has"
      )
      .context(status),
    );
  }
  Ok(body.bytes)
}

/// The text of an error body which [read_body] read up to
/// [MAX_ERROR_BODY_BYTES], see [error_text].
fn error_text_of(body: anyhow::Result<LimitedBody>) -> String {
  let LimitedBody {
    mut bytes,
    truncated,
  } = match body {
    Ok(body) => body,
    Err(e) => return format!("{e:#}"),
  };
  if !truncated {
    return String::from_utf8_lossy(&bytes).into_owned();
  }
  // The limit may fall inside a character: the text ends before it.
  if let Err(e) = std::str::from_utf8(&bytes)
    && e.error_len().is_none()
  {
    bytes.truncate(e.valid_up_to());
  }
  format!(
    "{}... (cut at {MAX_ERROR_BODY_BYTES} bytes, the body is longer)",
    String::from_utf8_lossy(&bytes)
  )
}

/// The token endpoint uses the OAuth error format,
/// the returned error can be downcast to [TokenExchangeError].
///
/// A successful response which fails to parse is not included
/// in the error, it carries the app token.
fn parse_token_response(
  status: StatusCode,
  body: &[u8],
) -> anyhow::Result<TokenExchangeResponse> {
  if status.is_success() {
    return serde_json::from_slice(body).map_err(|e| {
      success_body_error(&e, body)
        .context("failed to deserialize token response")
        .context(status)
    });
  }
  if !status.is_redirection()
    && let Ok(error) =
      serde_json::from_slice::<TokenExchangeError>(body)
  {
    return Err(anyhow::Error::new(error).context(status));
  }
  // Any other error body, or a redirect.
  parse_response(status, body)
}

/// Builds the tagged request body expected by the auth server:
/// `{ "type": "<RequestType>", "params": <request> }`
fn request_body<T: Serialize + HasResponse>(
  request: &T,
) -> serde_json::Value {
  json!({
    "type": T::req_type(),
    "params": request
  })
}

/// Joins the server address and endpoint path,
/// tolerating a trailing slash on the address.
fn request_url(address: &str, endpoint: &str) -> String {
  format!("{}{endpoint}", address.trim_end_matches('/'))
}

/// Parses the body of a response of a JSON api: the value of a
/// successful (2xx) response, else the error the body carries (a
/// [Serror][mogh_error::Serror], or the body itself as the message).
/// Either way the status is the outermost context of the error, so
/// it can be read back with `error.downcast_ref::<StatusCode>()`.
///
/// Use it for any JSON api whose successful bodies hold secrets (a
/// JWT, an api key secret, recovery codes, a stored secret's value),
/// as the request functions here do: the values of a successful body
/// which fails to parse (eg. from a server of another version) never
/// make it into the error, which then ends up in logs. serde quotes
/// the value it trips over (`invalid type: string "..."`), so the
/// error keeps serde's message with every value redacted, and the
/// size of the body. Only a body which isn't JSON at all, eg. the
/// html page of a proxy, is kept, up to its first 200 characters.
///
/// The body of an error status is kept: it is the error message of
/// the server. A redirect (`3xx`, which a client following no
/// redirects gets) is an error saying so.
///
/// ```
/// use mogh_auth_client::{
///   api::manage::ConfirmTotpEnrollmentResponse,
///   request::parse_response,
/// };
/// use reqwest::StatusCode;
///
/// let res: ConfirmTotpEnrollmentResponse = parse_response(
///   StatusCode::OK,
///   br#"{"recovery_codes":["code-1"]}"#,
/// )?;
/// assert_eq!(res.recovery_codes, ["code-1"]);
///
/// // A body of another shape (serde's message would quote the
/// // string): the error doesn't repeat its values.
/// let err = parse_response::<ConfirmTotpEnrollmentResponse>(
///   StatusCode::OK,
///   br#"{"recovery_codes":"s3cr3t-code"}"#,
/// )
/// .unwrap_err();
/// let message = format!("{err:#}");
/// assert!(message.contains("invalid type: string [redacted]"));
/// assert!(!message.contains("s3cr3t"));
/// assert_eq!(err.downcast_ref::<StatusCode>(), Some(&StatusCode::OK));
/// # anyhow::Ok(())
/// ```
pub fn parse_response<T: DeserializeOwned>(
  status: StatusCode,
  body: &[u8],
) -> anyhow::Result<T> {
  if status.is_success() {
    serde_json::from_slice(body).map_err(|e| {
      success_body_error(&e, body)
        .context("failed to deserialize response body")
        .context(status)
    })
  } else if status.is_redirection() {
    // A client which follows no redirects (see the module docs) gets
    // the redirect itself, whose body says nothing of use.
    Err(
      anyhow!(
        "The server redirected the request, which is not followed: is the address right?"
      )
      .context(status),
    )
  } else {
    Err(deserialize_error_bytes(body).context(status))
  }
}

/// How much of a successful non json body the error keeps.
const BODY_PREVIEW_CHARS: usize = 200;

/// The error for a successful response body which failed to parse,
/// without any of the values it contains. The serde error message
/// quotes values (`invalid type: string "..."`), so they are redacted.
/// A body which doesn't look like json is kept up to
/// [BODY_PREVIEW_CHARS] characters.
fn success_body_error(
  e: &serde_json::Error,
  body: &[u8],
) -> anyhow::Error {
  let message = redact_serde_message(&e.to_string());
  if matches!(
    body.trim_ascii_start().first(),
    None | Some(b'{' | b'[' | b'"')
  ) || matches!(e.classify(), serde_json::error::Category::Data)
  {
    return anyhow!("{message} ({} bytes)", body.len());
  }
  let body = String::from_utf8_lossy(body);
  let preview = match body.char_indices().nth(BODY_PREVIEW_CHARS) {
    Some((end, _)) => format!("{}...", &body[..end]),
    None => body.into_owned(),
  };
  anyhow!("{message} | body: {preview}")
}

/// Redacts the values of the input from a serde error message,
/// keeping the names which come from the types. serde writes an
/// unknown enum variant or field in backticks without escaping it,
/// so it may hold backticks or quotes itself: it is redacted whole,
/// and the names expected after it stay readable
/// (`unknown variant [redacted], expected `Jwt` or `Totp``). So does
/// the field of a `missing field` / `duplicate field` error. Other
/// values are redacted by [redact_serde_values].
fn redact_serde_message(message: &str) -> String {
  // serde's wording only counts at the start of the message
  // (serde_json appends ` at line N column M`): text like it
  // anywhere else is inside a value.
  for wording in ["unknown variant ", "unknown field "] {
    let Some(name) = message
      .strip_prefix(wording)
      .and_then(|rest| rest.strip_prefix('`'))
    else {
      continue;
    };
    // The name runs up to serde's own `, expected` / `, there are
    // no`, the last one, as the name may hold these too. What
    // follows are the names of the type (`&'static str`).
    let end = ["`, expected ", "`, there are no "]
      .into_iter()
      .filter_map(|marker| name.rfind(marker))
      .max();
    let after = end.map_or("", |end| &name[end + 1..]);
    return format!("{wording}[redacted]{after}");
  }
  for wording in ["missing field `", "duplicate field `"] {
    // serde names these fields with a `&'static str` of the type.
    let Some(end) = message
      .strip_prefix(wording)
      .and_then(|rest| rest.find('`'))
    else {
      continue;
    };
    let (field, rest) = message.split_at(wording.len() + end + 1);
    return format!("{field}{}", redact_serde_values(rest));
  }
  redact_serde_values(message)
}

/// Redacts the values serde writes into its messages: strings in
/// double quotes, escaped (`string "a \"b\""`), a character in
/// backticks, unescaped (it may be a backtick itself), and numbers
/// and booleans in backticks. An unterminated one is redacted to
/// the end.
fn redact_serde_values(message: &str) -> String {
  let mut out = String::with_capacity(message.len());
  let mut rest = message;
  while let Some(start) = rest.find(['"', '`']) {
    let (before, quoted) = rest.split_at(start);
    out.push_str(before);
    out.push_str("[redacted]");
    // Both quotes are ascii, so `quoted[1..]` is on a char boundary,
    // and the end (past the closing quote) is its offset + 2.
    let inner = &quoted[1..];
    let end = if quoted.starts_with('"') {
      // The closing quote, skipping escaped characters.
      let mut escaped = false;
      inner.char_indices().find_map(|(i, c)| {
        if escaped {
          escaped = false;
        } else if c == '\\' {
          escaped = true;
        } else if c == '"' {
          return Some(i + 2);
        }
        None
      })
    } else if before.ends_with("character ") {
      // One char, then the closing backtick.
      inner.chars().next().and_then(|c| {
        let close = c.len_utf8();
        inner[close..].starts_with('`').then_some(close + 2)
      })
    } else {
      inner.find('`').map(|i| i + 2)
    };
    let Some(end) = end else {
      // Unterminated, redact the rest.
      return out;
    };
    rest = &quoted[end..];
  }
  out.push_str(rest);
  out
}

#[cfg(test)]
mod tests {
  use reqwest::StatusCode;
  use serde_json::json;

  use super::*;
  use crate::api::login::{
    GetLoginOptions, JwtOrTwoFactor, JwtResponse, LoginLocalUser,
  };
  #[cfg(feature = "pki")]
  use crate::api::manage::GetUserIdResponse;
  use crate::api::manage::{
    ConfirmTotpEnrollmentResponse, CreateApiKeyResponse,
    UpdateUsername,
  };
  use crate::test_server::{Answer, serve};

  /// How an error body cut at [MAX_ERROR_BODY_BYTES] ends.
  fn cut_note() -> String {
    format!(
      "... (cut at {MAX_ERROR_BODY_BYTES} bytes, the body is longer)"
    )
  }

  /// `/100`: 100 bytes. `/jwt`: a [JwtResponse]. `/endless`: a
  /// body which never ends. Anything else: an error (502) whose body
  /// never ends.
  fn body_server() -> String {
    serve(|request, _| match request.path.as_str() {
      "/100" => Answer::Body("200 OK", vec![b'a'; 100]),
      "/jwt" => {
        Answer::Body("200 OK", br#"{"jwt":"ey.jwt"}"#.to_vec())
      }
      "/endless" => Answer::Endless("200 OK"),
      _ => Answer::Endless("502 Bad Gateway"),
    })
    .0
  }

  #[tokio::test]
  async fn test_read_body_stops_at_the_limit() {
    let address = body_server();
    let get = |path: &str| reqwest::get(format!("{address}{path}"));
    for (max, len, truncated) in [
      (0, 0, true),
      (10, 10, true),
      (99, 99, true),
      (100, 100, false),
      (101, 100, false),
      (1000, 100, false),
    ] {
      let body =
        read_body(get("/100").await.unwrap(), max).await.unwrap();
      assert_eq!(body.bytes, vec![b'a'; len], "{max}");
      assert_eq!(body.truncated, truncated, "{max}");
    }
    // A body which never ends is read up to the limit.
    let body = read_body(get("/endless").await.unwrap(), 100_000)
      .await
      .unwrap();
    assert_eq!(body.bytes.len(), 100_000);
    assert!(body.truncated);
  }

  #[tokio::test]
  async fn test_error_text_is_limited() {
    let address = body_server();
    let res = reqwest::get(format!("{address}/error")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    let text = error_text(res).await;
    assert_eq!(
      text,
      format!("{}{}", "x".repeat(MAX_ERROR_BODY_BYTES), cut_note())
    );
  }

  #[tokio::test]
  async fn test_json_response_reads_limited_bodies() {
    let address = body_server();
    let get = |path: &str| reqwest::get(format!("{address}{path}"));
    let res: JwtResponse =
      json_response(get("/jwt").await.unwrap(), 1024)
        .await
        .unwrap();
    assert_eq!(res.jwt, "ey.jwt");
    // A successful body longer than the limit: none of it is kept.
    let err = json_response::<JwtResponse>(
      get("/endless").await.unwrap(),
      1024,
    )
    .await
    .unwrap_err();
    assert_eq!(
      err.downcast_ref::<StatusCode>(),
      Some(&StatusCode::OK)
    );
    let msg = format!("{err:#}");
    assert!(msg.contains("longer than 1024 bytes"), "{msg}");
    assert!(!msg.contains("xxx"), "{msg}");
    // An error body is cut, and says so.
    let err = json_response::<JwtResponse>(
      get("/error").await.unwrap(),
      1024,
    )
    .await
    .unwrap_err();
    assert_eq!(
      err.downcast_ref::<StatusCode>(),
      Some(&StatusCode::BAD_GATEWAY)
    );
    let msg = format!("{err:#}");
    assert!(
      msg.ends_with(&cut_note()),
      "{}",
      &msg[msg.len() - 100..]
    );
    assert!(msg.len() < MAX_ERROR_BODY_BYTES + 100, "{}", msg.len());
  }

  /// What answers in place of the auth api is read with the limits:
  /// a body which never ends is no hang, nor an error message of
  /// any size.
  #[tokio::test]
  async fn test_request_functions_read_limited_bodies() {
    for status in ["200 OK", "502 Bad Gateway"] {
      let (address, received) =
        serve(move |_, _| Answer::Endless(status));
      let client = reqwest::Client::new();
      let errors = [
        login(&client, &address, GetLoginOptions {})
          .await
          .unwrap_err(),
        manage(
          &client,
          &address,
          UpdateUsername {
            username: "x".into(),
          },
        )
        .await
        .unwrap_err(),
        token_exchange(
          &client,
          &address,
          &TokenExchangeRequest::id_token("t"),
        )
        .await
        .unwrap_err(),
      ];
      for err in errors {
        let msg = format!("{err:#}");
        assert!(msg.len() < MAX_ERROR_BODY_BYTES + 100, "{status}");
      }
      // Sent where and as the auth api takes them.
      let received = received.lock().unwrap();
      let sent = received
        .iter()
        .map(|request| {
          (
            request.method.as_str(),
            request.path.as_str(),
            request.header("content-type").unwrap_or_default(),
          )
        })
        .collect::<Vec<_>>();
      assert_eq!(
        sent,
        [
          ("POST", "/login", "application/json"),
          ("POST", "/manage", "application/json"),
          ("POST", "/token", "application/x-www-form-urlencoded"),
        ]
      );
      let json = |request: &crate::test_server::Received| {
        serde_json::from_slice::<serde_json::Value>(&request.body)
          .unwrap()
      };
      assert_eq!(
        json(&received[0]),
        json!({ "type": "GetLoginOptions", "params": {} })
      );
      assert_eq!(
        json(&received[1]),
        json!({ "type": "UpdateUsername", "params": { "username": "x" } })
      );
      assert!(
        String::from_utf8_lossy(&received[2].body)
          .contains("subject_token=t&")
      );
    }
  }

  #[cfg(feature = "blocking")]
  #[test]
  fn test_blocking_reads_limited_bodies() {
    let address = body_server();
    let client = reqwest::blocking::Client::new();
    let get = |path: &str| {
      client.get(format!("{address}{path}")).send().unwrap()
    };
    for (max, len, truncated) in [
      (0, 0, true),
      (99, 99, true),
      (100, 100, false),
      (101, 100, false),
    ] {
      let body = blocking::read_body(get("/100"), max).unwrap();
      assert_eq!(body.bytes, vec![b'a'; len], "{max}");
      assert_eq!(body.truncated, truncated, "{max}");
    }
    let body = blocking::read_body(get("/endless"), 100_000).unwrap();
    assert_eq!(body.bytes.len(), 100_000);
    assert!(body.truncated);
    assert_eq!(
      blocking::error_text(get("/error")),
      format!("{}{}", "x".repeat(MAX_ERROR_BODY_BYTES), cut_note())
    );
    let res: JwtResponse =
      blocking::json_response(get("/jwt"), 1024).unwrap();
    assert_eq!(res.jwt, "ey.jwt");
    let msg = format!(
      "{:#}",
      blocking::json_response::<JwtResponse>(get("/endless"), 1024)
        .unwrap_err()
    );
    assert!(msg.contains("longer than 1024 bytes"), "{msg}");

    for status in ["200 OK", "502 Bad Gateway"] {
      let (address, _) = serve(move |_, _| Answer::Endless(status));
      let errors = [
        blocking::login(&client, &address, GetLoginOptions {})
          .unwrap_err(),
        blocking::token_exchange(
          &client,
          &address,
          &TokenExchangeRequest::id_token("t"),
        )
        .unwrap_err(),
      ];
      for err in errors {
        let msg = format!("{err:#}");
        assert!(msg.len() < MAX_ERROR_BODY_BYTES + 100, "{status}");
      }
    }
  }

  #[test]
  fn test_error_text_cuts_before_a_character() {
    // 2.5 characters of 2 bytes each.
    let bytes = "é".repeat(10).as_bytes()[..5].to_vec();
    let text = error_text_of(Ok(LimitedBody {
      bytes,
      truncated: true,
    }));
    assert_eq!(text, format!("éé{}", cut_note()));
    // A body which fits keeps its invalid utf8, replaced.
    let text = error_text_of(Ok(LimitedBody {
      bytes: b"a\xffb".to_vec(),
      truncated: false,
    }));
    assert_eq!(text, "a\u{FFFD}b");
  }

  /// The 401 of a request whose timestamp the server refused.
  #[cfg(feature = "pki")]
  fn timestamp_refusal() -> Vec<u8> {
    json!({
      "error": format!(
        "{}: X-API-TIMESTAMP is 1500ms from it, 1000ms are tolerated",
        crate::signature::SIGNED_AT_ANOTHER_TIME
      ),
      "trace": [],
    })
    .to_string()
    .into_bytes()
  }

  /// Answers GetUserId to a POST, after refusing the timestamp of the
  /// first `refusals` POSTs. Anything else (the HEAD opening a
  /// connection) is refused as having no credentials.
  #[cfg(feature = "pki")]
  fn signing_server(
    refusals: usize,
  ) -> (String, crate::test_server::Requests) {
    let posts = std::sync::atomic::AtomicUsize::new(0);
    serve(move |request, _| {
      if request.method != "POST" {
        return Answer::Body(
          "401 Unauthorized",
          br#"{"error":"Invalid client credentials","trace":[]}"#
            .to_vec(),
        );
      }
      if posts.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        < refusals
      {
        Answer::Body("401 Unauthorized", timestamp_refusal())
      } else {
        Answer::Body("200 OK", br#"{"id":"user-id"}"#.to_vec())
      }
    })
  }

  /// What the server received: the method of each request, and that
  /// every POST is signed for `host` and `path` over its body, which
  /// is `body`, each with its own nonce.
  #[cfg(feature = "pki")]
  fn assert_signed(
    received: &[crate::test_server::Received],
    methods: &[&str],
    keys: &mogh_pki::EncodedKeyPair,
    host: &str,
    path: &str,
    body: &serde_json::Value,
  ) {
    use crate::signature::{
      API_HOST_HEADER, API_NONCE_HEADER, API_PUBLIC_KEY_HEADER,
      API_SIGNATURE_HEADER, API_TIMESTAMP_HEADER, SignedRequest,
    };
    assert_eq!(
      received
        .iter()
        .map(|r| r.method.as_str())
        .collect::<Vec<_>>(),
      methods
    );
    let mut nonces = Vec::new();
    for request in received {
      if request.method != "POST" {
        // Nothing to open a connection with but the url.
        assert!(request.header(API_SIGNATURE_HEADER).is_none());
        assert!(request.body.is_empty());
        continue;
      }
      assert_eq!(request.path, path);
      assert_eq!(
        request.header("content-type"),
        Some("application/json")
      );
      let sent =
        serde_json::from_slice::<serde_json::Value>(&request.body)
          .unwrap();
      assert_eq!(&sent, body);
      assert_eq!(
        request.header(API_PUBLIC_KEY_HEADER),
        Some(keys.public.as_str())
      );
      assert_eq!(request.header(API_HOST_HEADER), Some(host));
      let nonce = request.header(API_NONCE_HEADER).unwrap();
      mogh_pki::signature::verify(
        &keys.public,
        SignedRequest {
          host,
          method: "POST",
          path_and_query: path,
          timestamp: request
            .header(API_TIMESTAMP_HEADER)
            .unwrap()
            .parse()
            .unwrap(),
          nonce,
          body: &request.body,
        }
        .message()
        .as_bytes(),
        request.header(API_SIGNATURE_HEADER).unwrap(),
      )
      .unwrap();
      nonces.push(nonce.to_string());
    }
    // Signed anew, never sent again as it was.
    let count = nonces.len();
    nonces.dedup();
    assert_eq!(nonces.len(), count);
  }

  /// A request refused for its timestamp goes out once more, signed
  /// anew, over a connection opened before; once only. Other refusals
  /// are the result.
  #[cfg(feature = "pki")]
  #[tokio::test]
  async fn test_signed_manage_retries_a_refused_timestamp_once() {
    use mogh_pki::{EncodedKeyPair, PkiKind};

    use crate::api::manage::GetUserId;

    let keys = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    let client = reqwest::Client::new();
    let body = json!({ "type": "GetUserId", "params": {} });
    for (refusals, methods) in [
      (0, &["POST"][..]),
      (1, &["POST", "HEAD", "POST"]),
      (2, &["POST", "HEAD", "POST"]),
    ] {
      let (address, received) = signing_server(refusals);
      let host = address.strip_prefix("http://").unwrap();
      let res =
        signed_manage(&client, &address, &keys, GetUserId {}).await;
      if refusals < 2 {
        assert_eq!(res.unwrap().id, "user-id", "{refusals}");
      } else {
        let err = res.unwrap_err();
        assert_eq!(
          err.downcast_ref::<StatusCode>(),
          Some(&StatusCode::UNAUTHORIZED)
        );
        assert!(
          format!("{err:#}")
            .contains(crate::signature::SIGNED_AT_ANOTHER_TIME)
        );
      }
      assert_signed(
        &received.lock().unwrap(),
        methods,
        &keys,
        host,
        "/manage",
        &body,
      );
    }

    // Another refusal is not sent again.
    let (address, received) = serve(|_, _| {
      Answer::Body(
        "401 Unauthorized",
        br#"{"error":"Invalid client credentials","trace":[]}"#
          .to_vec(),
      )
    });
    let err = signed_manage(&client, &address, &keys, GetUserId {})
      .await
      .unwrap_err();
    assert_eq!(
      format!("{err:#}"),
      "401 Unauthorized: Invalid client credentials"
    );
    assert_eq!(received.lock().unwrap().len(), 1);
  }

  /// Signed for what the server receives, with the headers sent
  /// along; other credentials are refused before anything is sent.
  #[cfg(feature = "pki")]
  #[tokio::test]
  async fn test_signed_post() {
    use mogh_pki::{EncodedKeyPair, PkiKind};
    use reqwest::header::HeaderValue;

    let keys = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    let client = reqwest::Client::new();
    let (address, received) = signing_server(1);
    let body = json!({ "type": "GetUserId", "params": {} });

    // Through a proxy which strips `/prefix`, to a server which
    // knows itself as `example.com`.
    let mut post = SignedPost::new(
      &format!("{address}/prefix/read?x=1"),
      &keys,
      &body,
    )
    .unwrap();
    post.host = "example.com".into();
    post.path_and_query = "/read?x=1".into();
    post
      .headers
      .insert("traceparent", HeaderValue::from_static("00-trace"));
    let res: GetUserIdResponse =
      signed_post(&client, &post, MAX_SUCCESS_BODY_BYTES)
        .await
        .unwrap();
    assert_eq!(res.id, "user-id");
    let received = received.lock().unwrap().clone();
    assert_eq!(received[0].path, "/prefix/read?x=1");
    for request in [&received[0], &received[2]] {
      assert_eq!(request.header("traceparent"), Some("00-trace"));
    }
    let as_received = received
      .into_iter()
      .map(|mut request| {
        request.path = "/read?x=1".into();
        request
      })
      .collect::<Vec<_>>();
    assert_signed(
      &as_received,
      &["POST", "HEAD", "POST"],
      &keys,
      "example.com",
      "/read?x=1",
      &body,
    );

    // Other credentials: nothing is sent.
    let (address, received) = signing_server(0);
    let with_user = address.replacen("://", "://user:hunter2@", 1);
    let Err(err) = SignedPost::new(&with_user, &keys, &body) else {
      panic!("A url with credentials was taken");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("carries other credentials"), "{msg}");
    assert!(!msg.contains("hunter2"), "{msg}");
    for header in ["authorization", "x-api-key", "x-api-secret"] {
      let mut post = SignedPost::new(&address, &keys, &body).unwrap();
      post
        .headers
        .insert(header, HeaderValue::from_static("S_s3cr3t_S"));
      let err = signed_post::<GetUserIdResponse>(
        &client,
        &post,
        MAX_SUCCESS_BODY_BYTES,
      )
      .await
      .unwrap_err();
      let msg = format!("{err:#}");
      assert!(msg.contains("carries other credentials"), "{msg}");
      assert!(!msg.contains("s3cr3t"), "{msg}");
    }
    assert!(received.lock().unwrap().is_empty());
  }

  #[cfg(all(feature = "pki", feature = "blocking"))]
  #[test]
  fn test_blocking_signed_manage_retries_a_refused_timestamp_once() {
    use mogh_pki::{EncodedKeyPair, PkiKind};

    use crate::api::manage::GetUserId;

    let keys = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    let client = reqwest::blocking::Client::new();
    let body = json!({ "type": "GetUserId", "params": {} });
    for (refusals, methods) in [
      (0, &["POST"][..]),
      (1, &["POST", "HEAD", "POST"]),
      (2, &["POST", "HEAD", "POST"]),
    ] {
      let (address, received) = signing_server(refusals);
      let host = address.strip_prefix("http://").unwrap();
      let res = blocking::signed_manage(
        &client,
        &address,
        &keys,
        GetUserId {},
      );
      if refusals < 2 {
        assert_eq!(res.unwrap().id, "user-id", "{refusals}");
      } else {
        assert!(
          format!("{:#}", res.unwrap_err())
            .contains(crate::signature::SIGNED_AT_ANOTHER_TIME)
        );
      }
      assert_signed(
        &received.lock().unwrap(),
        methods,
        &keys,
        host,
        "/manage",
        &body,
      );
    }
  }

  /// Api key headers go along to wherever a redirect points, unless
  /// the client follows none (see the module docs): then the redirect
  /// is an error saying so, and the other host gets nothing.
  #[tokio::test]
  async fn test_redirects_are_errors_with_a_client_following_none() {
    use crate::api::manage::GetUserId;
    use reqwest::header::{HeaderMap, HeaderValue};

    let (elsewhere, received) = serve(|_, _| {
      Answer::Body("200 OK", br#"{"id":"user-id"}"#.to_vec())
    });
    let (address, _) = serve(move |_, _| {
      Answer::Redirect(format!("{elsewhere}/manage"))
    });
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("K_key_K"));
    headers
      .insert("x-api-secret", HeaderValue::from_static("S_s3cr3t_S"));

    let following_none = reqwest::Client::builder()
      .default_headers(headers.clone())
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .unwrap();
    let err = manage(&following_none, &address, GetUserId {})
      .await
      .unwrap_err();
    assert_eq!(
      err.downcast_ref::<StatusCode>(),
      Some(&StatusCode::TEMPORARY_REDIRECT)
    );
    assert_eq!(
      format!("{err:#}"),
      "307 Temporary Redirect: The server redirected the request, which is not followed: is the address right?"
    );
    assert!(received.lock().unwrap().is_empty());

    // Why: reqwest's default client follows, and strips only
    // Authorization (and cookies) going to another host. A 307 sends
    // the body again too.
    let following = reqwest::Client::builder()
      .default_headers(headers)
      .build()
      .unwrap();
    manage(&following, &address, GetUserId {}).await.unwrap();
    let received = received.lock().unwrap();
    assert_eq!(
      received[0].header("x-api-secret"),
      Some("S_s3cr3t_S")
    );
    assert_eq!(received[0].method, "POST");
    assert!(!received[0].body.is_empty());
  }

  /// A body may hold secrets.
  #[test]
  fn test_limited_body_debug_shows_no_bytes() {
    let body = LimitedBody {
      bytes: b"s3cr3t".to_vec(),
      truncated: false,
    };
    assert_eq!(
      format!("{body:?}"),
      "LimitedBody { len: 6, truncated: false }"
    );
  }

  #[test]
  fn test_request_body_tags_type_and_params() {
    let body = request_body(&LoginLocalUser {
      username: "user".into(),
      password: "pass".into(),
    });
    assert_eq!(
      body,
      json!({
        "type": "LoginLocalUser",
        "params": {
          "username": "user",
          "password": "pass",
        }
      })
    );
  }

  #[test]
  fn test_request_body_empty_params() {
    let body = request_body(&GetLoginOptions {});
    assert_eq!(
      body,
      json!({
        "type": "GetLoginOptions",
        "params": {}
      })
    );
  }

  #[test]
  fn test_request_body_manage_request() {
    let body = request_body(&UpdateUsername {
      username: "new-name".into(),
    });
    assert_eq!(
      body,
      json!({
        "type": "UpdateUsername",
        "params": { "username": "new-name" }
      })
    );
  }

  #[test]
  fn test_request_url() {
    assert_eq!(
      request_url("http://localhost:9120", "/login"),
      "http://localhost:9120/login"
    );
    // A trailing slash on the address must not
    // produce a double slash in the url.
    assert_eq!(
      request_url("http://localhost:9120/", "/manage"),
      "http://localhost:9120/manage"
    );
  }

  #[test]
  fn test_parse_response_success() {
    let res: JwtResponse =
      parse_response(StatusCode::OK, br#"{"jwt":"abc123"}"#).unwrap();
    assert_eq!(res.jwt, "abc123");
  }

  #[test]
  fn test_parse_response_success_status_bad_body_keeps_body() {
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      b"unexpected html",
    )
    .unwrap_err();
    // The error keeps a body which isn't json for debugging,
    // eg. the html page of a proxy.
    let msg = format!("{err:#}");
    assert!(msg.contains("unexpected html"), "{msg}");
    assert!(msg.contains("200"), "{msg}");
    // Truncated
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      format!("<html>{}", "é".repeat(1000)).as_bytes(),
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("<html>"), "{msg}");
    assert!(msg.len() < 800, "{msg}");
  }

  #[test]
  fn test_parse_response_success_status_json_body_is_not_kept() {
    // A 200 with credentials the client can't parse, eg. after a
    // server update changed the response.
    let err = parse_response::<CreateApiKeyResponse>(
      StatusCode::OK,
      br#"{"result":{"key":"K_abc_K","secret":"S_s3cr3t_S"}}"#,
    )
    .unwrap_err();
    for msg in [format!("{err:#}"), format!("{err:?}")] {
      assert!(!msg.contains("s3cr3t"), "{msg}");
      assert!(!msg.contains("K_abc_K"), "{msg}");
      assert!(msg.contains("200"), "{msg}");
      // The missing field helps to debug the mismatch.
      assert!(msg.contains("missing field `key`"), "{msg}");
    }

    // The serde error quotes a scalar of the wrong type
    // (invalid type: integer `1234567`, expected a string).
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      br#"{"jwt":1234567}"#,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("1234567"), "{msg}");
    assert!(msg.contains("invalid type"), "{msg}");
    let err = parse_response::<ConfirmTotpEnrollmentResponse>(
      StatusCode::OK,
      br#"{"recovery_codes":"code-1,code-2"}"#,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("code-1"), "{msg}");
    assert!(msg.contains("invalid type"), "{msg}");

    // Truncated json isn't kept either.
    let err = parse_response::<JwtOrTwoFactor>(
      StatusCode::OK,
      br#"{"type":"Jwt","data":{"jwt":"secret.app.jw"#,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("secret.app"), "{msg}");
  }

  /// The status is the outermost context, whatever went wrong.
  #[test]
  fn test_parse_response_errors_carry_the_status() {
    for (status, body) in [
      (StatusCode::OK, &br#"{"jwt":1}"#[..]),
      (StatusCode::OK, b"<html>"),
      (StatusCode::OK, b""),
      (StatusCode::UNAUTHORIZED, br#"{"error":"invalid token"}"#),
      (StatusCode::BAD_GATEWAY, b"<html>bad gateway</html>"),
    ] {
      let err =
        parse_response::<JwtResponse>(status, body).unwrap_err();
      assert_eq!(err.downcast_ref::<StatusCode>(), Some(&status));
    }
  }

  /// The body is parsed as the bytes it is: invalid utf8 in a
  /// successful body is an error (a lossy text of it would parse,
  /// with other values), and an error body of invalid utf8 is
  /// previewed.
  #[test]
  fn test_parse_response_invalid_utf8() {
    let err = parse_response::<JwtResponse>(
      StatusCode::OK,
      b"{\"jwt\":\"ab\xffcd\"}",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(!msg.contains("ab"), "{msg}");
    let err = parse_response::<JwtResponse>(
      StatusCode::INTERNAL_SERVER_ERROR,
      b"broken \xff body",
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("not valid utf8"), "{msg}");
    assert!(msg.contains("broken"), "{msg}");
  }

  #[test]
  fn test_parse_response_error_status_keeps_body() {
    let err = parse_response::<JwtResponse>(
      StatusCode::UNAUTHORIZED,
      br#"{"error":"invalid token"}"#,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("invalid token"));
    assert!(msg.contains("401"));
  }

  #[test]
  fn test_redact_serde_message() {
    assert_eq!(
      redact_serde_message(
        r#"invalid type: string "a \"quoted\" secret", expected u64 at line 1 column 3"#
      ),
      "invalid type: string [redacted], expected u64 at line 1 column 3"
    );
    assert_eq!(
      redact_serde_message(
        "invalid value: integer `123`, expected x"
      ),
      "invalid value: integer [redacted], expected x"
    );
    // The names expected after an unknown one are the type's.
    assert_eq!(
      redact_serde_message(
        "unknown variant `secret`, expected `Jwt`"
      ),
      "unknown variant [redacted], expected `Jwt`"
    );
    assert_eq!(
      redact_serde_message(
        "unknown field `secret`, there are no fields"
      ),
      "unknown field [redacted], there are no fields"
    );
    assert_eq!(
      redact_serde_message("missing field `jwt` at line 1 column 2"),
      "missing field `jwt` at line 1 column 2"
    );
    assert_eq!(
      redact_serde_message(
        "duplicate field `jwt` at line 1 column 9"
      ),
      "duplicate field `jwt` at line 1 column 9"
    );
    assert_eq!(
      redact_serde_message(r#"unterminated "secret"#),
      "unterminated [redacted]"
    );
    assert_eq!(
      redact_serde_message("unterminated `secret"),
      "unterminated [redacted]"
    );
    assert_eq!(redact_serde_message("no quotes"), "no quotes");
    // A character is written in backticks unescaped.
    let err = <serde_json::Error as serde::de::Error>::invalid_type(
      serde::de::Unexpected::Char('`'),
      &"a secret",
    );
    assert_eq!(
      redact_serde_message(&err.to_string()),
      "invalid type: character [redacted], expected a secret"
    );
  }

  /// serde writes an unknown enum variant (or field) in backticks
  /// without escaping it: a backtick in the value used to end the
  /// redacted part early, leaking the rest, and `missing field`
  /// text in the value was kept as if it were serde's.
  #[test]
  fn test_redact_serde_message_unknown_names_holding_quotes() {
    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Strict {
      port: u16,
    }
    for value in [
      "x`s3cr3t",
      "a`b`c`s3cr3t`d",
      "`s3cr3t`",
      "x\"s3cr3t\"",
      "x\"s3cr3t",
      "x`missing field `s3cr3t",
      "x`, missing field `s3cr3t`",
      "x`, expected `s3cr3t",
      "x`, expected `s3cr3t`, expected `x",
      "x`, there are no s3cr3t",
      "multi\nline`s3cr3t",
    ] {
      let body = json!({ "type": value, "data": {} }).to_string();
      let err = parse_response::<JwtOrTwoFactor>(
        StatusCode::OK,
        body.as_bytes(),
      )
      .unwrap_err();
      for msg in [format!("{err:#}"), format!("{err:?}")] {
        assert!(!msg.contains("s3cr3t"), "{value:?}: {msg}");
        assert!(
          msg.contains(
            "unknown variant [redacted], expected one of `Jwt`, `Passkey`, `Totp` at line 1 column"
          ),
          "{value:?}: {msg}"
        );
      }

      let err = serde_json::from_str::<Strict>(
        &json!({ "port": 1, value: 1 }).to_string(),
      )
      .unwrap_err();
      let msg = redact_serde_message(&err.to_string());
      assert!(!msg.contains("s3cr3t"), "{value:?}: {msg}");
      assert!(
        msg.starts_with("unknown field [redacted], expected `port`"),
        "{value:?}: {msg}"
      );

      // A string is redacted whole, whatever it holds.
      let err =
        serde_json::from_str::<u16>(&json!(value).to_string())
          .unwrap_err();
      let msg = redact_serde_message(&err.to_string());
      assert!(
        msg.starts_with(
          "invalid type: string [redacted], expected u16"
        ),
        "{value:?}: {msg}"
      );
    }
    // serde's wording only counts at the start of the message.
    for message in [
      "invalid value: integer `1`, missing field `s3cr3t`",
      "custom: duplicate field `s3cr3t`",
    ] {
      let msg = redact_serde_message(message);
      assert!(!msg.contains("s3cr3t"), "{message:?}: {msg}");
    }
  }

  #[test]
  fn test_parse_token_response_error_is_downcastable() {
    let err = parse_token_response(
      reqwest::StatusCode::BAD_REQUEST,
      br#"{"error":"invalid_grant","error_description":"expired"}"#,
    )
    .unwrap_err();
    let error = err.downcast_ref::<TokenExchangeError>().unwrap();
    assert_eq!(error.error, "invalid_grant");
    assert_eq!(error.error_description.as_deref(), Some("expired"));
    assert!(
      parse_token_response(reqwest::StatusCode::OK, b"not json")
        .is_err()
    );
  }

  /// An error which is not in the OAuth format (eg. the page of a
  /// proxy in front of the token endpoint) is kept as the message.
  #[test]
  fn test_parse_token_response_other_errors() {
    for (body, message) in [
      (&b"<html>bad gateway</html>"[..], "<html>bad gateway</html>"),
      (br#"{"message":"down"}"#, r#"{"message":"down"}"#),
    ] {
      let err =
        parse_token_response(reqwest::StatusCode::BAD_GATEWAY, body)
          .unwrap_err();
      assert!(err.downcast_ref::<TokenExchangeError>().is_none());
      assert_eq!(
        format!("{err:#}"),
        format!("502 Bad Gateway: {message}")
      );
    }
  }

  /// A redirect of the token endpoint says so, as for the other
  /// requests.
  #[test]
  fn test_parse_token_response_redirect() {
    let err = parse_token_response(
      reqwest::StatusCode::FOUND,
      br#"{"error":"invalid_request"}"#,
    )
    .unwrap_err();
    assert!(err.downcast_ref::<TokenExchangeError>().is_none());
    assert_eq!(
      format!("{err:#}"),
      "302 Found: The server redirected the request, which is not followed: is the address right?"
    );
  }

  #[test]
  fn test_parse_token_response_success_status_bad_body() {
    // Does not include the successful response on a parse failure
    let err = parse_token_response(
      reqwest::StatusCode::OK,
      br#"{"access_token":"secret.app.jwt","expires_in":"soon"}"#,
    )
    .unwrap_err();
    for msg in [format!("{err:#}"), format!("{err:?}")] {
      assert!(!msg.contains("secret.app.jwt"), "{msg}");
      assert!(!msg.contains("soon"), "{msg}");
      assert!(msg.contains("200"), "{msg}");
    }
  }

  #[test]
  fn test_parse_token_response_success() {
    let response = parse_token_response(
      reqwest::StatusCode::OK,
      br#"{"access_token":"jwt","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}"#,
    )
    .unwrap();
    assert_eq!(response.access_token, "jwt");
    assert_eq!(response.expires_in, 3600);
  }

  /// The async functions exist next to the blocking ones, so a
  /// build enabling `blocking` for one crate doesn't break another
  /// using the async functions.
  #[cfg(feature = "blocking")]
  #[allow(unused)]
  fn test_blocking_is_additive() {
    async fn login_async(
      client: &reqwest::Client,
    ) -> anyhow::Result<crate::api::login::GetLoginOptionsResponse>
    {
      login(client, "http://localhost", GetLoginOptions {}).await
    }
    fn login_blocking(
      client: &reqwest::blocking::Client,
    ) -> anyhow::Result<crate::api::login::GetLoginOptionsResponse>
    {
      blocking::login(client, "http://localhost", GetLoginOptions {})
    }
    async fn token_async(
      client: &reqwest::Client,
    ) -> anyhow::Result<TokenExchangeResponse> {
      token_exchange(
        client,
        "http://localhost",
        &TokenExchangeRequest::id_token("t"),
      )
      .await
    }
    fn token_blocking(
      client: &reqwest::blocking::Client,
    ) -> anyhow::Result<TokenExchangeResponse> {
      blocking::token_exchange(
        client,
        "http://localhost",
        &TokenExchangeRequest::id_token("t"),
      )
    }
  }
}
