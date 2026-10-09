use std::{
  net::IpAddr,
  sync::Arc,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, anyhow};
use axum::{
  body::{Body, Bytes},
  extract::{
    FromRequest as _, FromRequestParts, OriginalUri, Request,
  },
  http::{
    HeaderMap, HeaderValue, Method, Uri, Version,
    header::{AUTHORIZATION, ORIGIN},
  },
  middleware::Next,
  response::Response,
};
use http_body_util::Limited;
use mogh_auth_client::{
  api::manage::REAUTHENTICATION_REQUIRED,
  signature::{
    API_HOST_HEADER, API_NONCE_HEADER, API_PUBLIC_KEY_HEADER,
    API_SIGNATURE_HEADER, API_TIMESTAMP_HEADER,
    SIGNED_AT_ANOTHER_TIME, SIGNED_FOR_ANOTHER_HOST, SignedRequest,
    url_host, valid_host, valid_nonce,
  },
};
use mogh_error::{AddStatusCode, AddStatusCodeError as _};
use mogh_pki::{PkiKind, SpkiPublicKey};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_request_ip::RequestIp;
use reqwest::StatusCode;
use tracing::{debug, error};

use crate::{
  AcceptedSignature, AuthImpl, DynFuture, RequestAuthentication,
  api_key::{
    AuthApiKeyImpl, StoredApiKey, StoredSigningKey, expired,
  },
  bcrypt_pool::spawn_api_key_bcrypt,
  user::{AuthUserImpl, BoxAuthUser},
};

pub use mogh_request_ip::cidr::check_cidr_whitelist;

const API_KEY_HEADER: &str = "x-api-key";

/// Authenticates the request with
/// [AuthImpl::handle_request_authentication], for use with
/// `axum::middleware::from_fn`.
///
/// The body of a request signed with a signing key is read first,
/// the signature covers it ([read_signed_request_body]). A signed
/// request which can't verify (eg. a stale timestamp) is refused
/// before that. One which authenticated is handed to
/// [AuthImpl::accept_signed_request] before it is handled.
///
/// The request is handed on with [AuthenticatedAt]: when the user
/// logged in for a session token, `None` for an api key or signing
/// key. The app's handlers extract it to require a recent login
/// for what should need one ([require_recent_login]). A hook which
/// attached an [AuthenticatedAt] of its own (eg. for a token of the
/// app's own whose login it knows) keeps it.
pub async fn authenticate_request<
  I: AuthImpl,
  const REQUIRE_USER_ENABLED: bool,
>(
  RequestIp(ip): RequestIp,
  OriginalUri(uri): OriginalUri,
  req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  let auth = I::new();

  let (req, body) = read_signed_request_body(&auth, ip, req).await?;

  let req_auth = extract_request_authentication_rate_limited(
    &auth,
    ip,
    req.method(),
    &uri,
    req.headers(),
    &body,
  )
  .await?;

  let accepted = accepted_signature(&req_auth, req.headers())?;
  let authenticated_at = login_time(&auth, &req_auth);

  let mut req = auth
    .handle_request_authentication(
      req_auth,
      ip,
      REQUIRE_USER_ENABLED,
      req,
    )
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &ip,
    )
    .await?;

  accept_signed_request(&auth, ip, accepted, &mut req).await?;

  if req.extensions().get::<AuthenticatedAt>().is_none() {
    req
      .extensions_mut()
      .insert(AuthenticatedAt(authenticated_at));
  }

  Ok(next.run(req).await)
}

/// When the user logged in for the session token `req_auth` holds
/// ([JwtClaims::authenticated_at][crate::provider::jwt::JwtClaims::authenticated_at]),
/// see [AuthenticatedAt]. `None` for api keys, signing keys and a
/// token [AuthImpl::jwt_provider] did not issue.
fn login_time<I: AuthImpl + ?Sized>(
  auth: &I,
  req_auth: &RequestAuthentication,
) -> Option<u64> {
  match req_auth {
    RequestAuthentication::Jwt(jwt) => auth
      .jwt_provider()
      .decode_claims(jwt)
      .ok()
      // The login, not the token: tokens issued by token exchange
      // carry when the provider authenticated the user.
      .map(|claims| claims.authenticated_at()),
    RequestAuthentication::ApiKey { .. }
    | RequestAuthentication::PublicKey(_) => None,
  }
}

/// The signature a request authenticated as `req_auth` was signed
/// with: its headers, which were verified
/// ([extract_request_authentication_rate_limited]). `None` for a
/// request which
/// authenticated with other credentials.
///
/// For a middleware of an app's own to hand to
/// [accept_signed_request], as [authenticate_request] does.
pub fn accepted_signature(
  req_auth: &RequestAuthentication,
  headers: &HeaderMap,
) -> mogh_error::Result<Option<AcceptedSignature>> {
  let RequestAuthentication::PublicKey(public_key) = req_auth else {
    return Ok(None);
  };
  // Each was read to verify the signature. Should one not be
  // there, the request is refused rather than go on unseen.
  let timestamp = signed_header(headers, API_TIMESTAMP_HEADER)?
    .parse()
    .context(
      "X-API-TIMESTAMP is not a unix timestamp in milliseconds",
    )
    .status_code(StatusCode::UNAUTHORIZED)?;
  let header = |header| {
    signed_header(headers, header).map(|value| value.to_string())
  };
  Ok(Some(AcceptedSignature {
    public_key: public_key.clone(),
    host: header(API_HOST_HEADER)?,
    timestamp,
    nonce: header(API_NONCE_HEADER)?,
    signature: header(API_SIGNATURE_HEADER)?,
  }))
}

/// A request whose signature the app accepted
/// ([accept_signed_request]), so it is asked once per request, also
/// where a route sits behind two middlewares of the auth server.
#[derive(Clone, Copy)]
struct SignatureAccepted;

/// Hands the signature of a signed request which authenticated
/// ([accepted_signature]) to [AuthImpl::accept_signed_request], right
/// before the request is handled. Its refusal counts against
/// [AuthImpl::general_rate_limiter] for the `ip`, like any credential
/// which is presented and not taken.
///
/// [authenticate_request] and the auth management api call it, and
/// so does [Authenticated::finish] for a middleware of an app's own
/// built on [authenticate_user]. One built on
/// [extract_request_authentication_rate_limited] calls it once the
/// signer is authenticated, or the app is never asked.
pub async fn accept_signed_request<I: AuthImpl>(
  auth: &I,
  ip: IpAddr,
  accepted: Option<AcceptedSignature>,
  req: &mut Request,
) -> mogh_error::Result<()> {
  let Some(accepted) = accepted else {
    return Ok(());
  };
  if req.extensions().get::<SignatureAccepted>().is_some() {
    return Ok(());
  }
  auth
    .accept_signed_request(accepted)
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &ip,
    )
    .await?;
  req.extensions_mut().insert(SignatureAccepted);
  Ok(())
}

/// Reads the body of a request signed with a signing key (it carries
/// X-API-SIGNATURE), which the signature covers, and puts it back.
/// Returns the request and the body to verify the signature with
/// ([extract_request_authentication_rate_limited]).
///
/// The X-API-TIMESTAMP is checked here, once, when the headers have
/// arrived and before the body is read. The signature is verified
/// against that timestamp afterwards ([SignedRequestBody]), so the
/// time the body takes to arrive (eg. a large body over a slow link)
/// doesn't count against [AuthImpl::signing_key_timestamp_tolerance_ms].
///
/// Other requests are returned as they are, with an empty body: theirs
/// isn't read. So is a signed request which also carries a jwt or an
/// api key: [extract_request_authentication_rate_limited] takes those
/// first, its signature isn't checked.
///
/// A signed request which fails for a reason known without the body
/// is refused right away (UNAUTHORIZED, as its verification would):
/// signing keys are not enabled
/// ([AuthImpl::signing_keys_enabled]), the X-API-TIMESTAMP is not ~now,
/// the X-API-HOST is none of the hosts of this server, or one of the
/// headers of a signed request is missing, given twice or malformed.
/// These refusals cost the server next to nothing, they
/// don't count against
/// [AuthImpl::general_rate_limiter]. Passing such a request on without
/// its body would not do: its signature would be checked against the
/// empty body while the handler gets the unread one. A client which
/// the [AuthImpl::general_rate_limiter] has locked out for the `ip` is
/// refused (TOO_MANY_REQUESTS) before its body is read too, as it
/// would be right after.
///
/// Anybody can send a current timestamp though: the body of a request
/// which gets this far is read (up to the limit), even when its
/// signature turns out to be invalid, like any JSON endpoint reads it.
///
/// Read once per request: the body (and the timestamp checked for it)
/// stays on the request, and a second middleware of the auth server
/// on the route (eg. [authenticate_request] around a router nesting
/// the auth management api) verifies the signature with it. Reading
/// it again would check the timestamp after the upload, and after the
/// first middleware authenticated the request.
///
/// The body has [AuthImpl::signed_request_body_timeout] (30 seconds
/// by default) to arrive, else the request is REQUEST_TIMEOUT. The
/// timestamp was checked before it, so without the timeout a request
/// could be accepted however long after: its headers sent in time,
/// its body held back.
///
/// The body of a CONNECT request over HTTP/2 or later (eg. a
/// websocket) is the tunnel, it isn't read either: it is signed as
/// empty. Before HTTP/2 a CONNECT request has no body, and one sent
/// regardless is read and signed like any other.
///
/// The body is limited to [AuthImpl::signed_request_body_limit]
/// (2 MB by default), and like axum's body extractors to the
/// `axum::extract::DefaultBodyLimit` of the router when it is applied
/// outside of the middleware, else 2 MB: whichever is smaller. A
/// router which raises or disables its limit (eg. for uploads)
/// doesn't raise how much of an unauthenticated signed request is
/// buffered, and raising only the knob doesn't get past the router's
/// limit (or the 2 MB default). A larger body is PAYLOAD_TOO_LARGE.
pub async fn read_signed_request_body<I: AuthImpl>(
  auth: &I,
  ip: IpAddr,
  mut req: Request,
) -> mogh_error::Result<(Request, SignedRequestBody)> {
  let headers = req.headers();
  if !headers.contains_key(API_SIGNATURE_HEADER)
    || headers.contains_key(AUTHORIZATION)
    || headers.contains_key(API_KEY_HEADER)
  {
    return Ok((req, SignedRequestBody::default()));
  }
  // A middleware of the auth server outside of this one read it.
  if let Some(ReadSignedBody(body)) = req.extensions().get() {
    let body = body.clone();
    return Ok((req, body));
  }
  let timestamp =
    Some(check_signed_request(auth, headers, None)?.timestamp);
  // Only there the body is the tunnel. Before HTTP/2 a body sent with
  // a CONNECT request would reach the handler as any other does.
  if req.method() == Method::CONNECT
    && req.version() >= Version::HTTP_2
  {
    let body = SignedRequestBody {
      body: Bytes::new(),
      timestamp,
    };
    req.extensions_mut().insert(ReadSignedBody(body.clone()));
    return Ok((req, body));
  }
  // Only looked up: an attempt which succeeds records nothing.
  async { Ok::<_, mogh_error::Error>(()) }
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &ip,
    )
    .await?;
  // The router's limit (if any) still applies inside
  // read_request_body, the smaller one refuses.
  let limit = auth.signed_request_body_limit();
  let req = req.map(|body| Body::new(Limited::new(body, limit)));
  // The timestamp was checked, the body is still to come: it doesn't
  // get to arrive whenever it suits the sender.
  let timeout = auth.signed_request_body_timeout();
  let (mut req, body) =
    tokio::time::timeout(timeout, read_request_body(req))
      .await
      .map_err(|_| {
        anyhow!(
          "The body of the signed request did not arrive within {timeout:?}"
        )
        .status_code(StatusCode::REQUEST_TIMEOUT)
      })??;
  let body = SignedRequestBody { body, timestamp };
  req.extensions_mut().insert(ReadSignedBody(body.clone()));
  Ok((req, body))
}

/// The body [read_signed_request_body] read (and the X-API-TIMESTAMP
/// it checked), on the request it put the body back on, for a second
/// middleware of the auth server on the route. A request extension is
/// set by the server only, and the type is private: what is reused
/// is what the server read itself.
#[derive(Clone)]
struct ReadSignedBody(SignedRequestBody);

/// The body of a request as [read_signed_request_body] read it, to
/// verify its signature with
/// ([extract_request_authentication_rate_limited]).
/// Empty when it wasn't read.
///
/// It carries the X-API-TIMESTAMP of the request which was found ~now
/// when the headers arrived, and the signature is verified against it
/// without checking it again. A body made from [Bytes] (`.into()`)
/// carries none, the timestamp is then checked when the signature is
/// verified.
#[derive(Debug, Clone, Default)]
pub struct SignedRequestBody {
  body: Bytes,
  /// Checked by [read_signed_request_body].
  timestamp: Option<i64>,
}

impl SignedRequestBody {
  /// The request body the signature covers.
  pub fn body(&self) -> &Bytes {
    &self.body
  }
}

impl From<Bytes> for SignedRequestBody {
  fn from(body: Bytes) -> Self {
    SignedRequestBody {
      body,
      timestamp: None,
    }
  }
}

/// Reads the body of the request (limited like axum's body
/// extractors, by the router's `axum::extract::DefaultBodyLimit`,
/// else 2 MB) and puts it back. A body which is too large (also for
/// a `Limited` wrapped around it) is PAYLOAD_TOO_LARGE.
pub(crate) async fn read_request_body(
  req: Request,
) -> mogh_error::Result<(Request, Bytes)> {
  let (parts, body) = req.into_parts();
  let body = Bytes::from_request(
    Request::from_parts(parts.clone(), body),
    &(),
  )
  .await
  .map_err(|rejection| {
    anyhow!(rejection.body_text()).status_code(rejection.status())
  })?;
  Ok((Request::from_parts(parts, Body::from(body.clone())), body))
}

/// Maps the credential headers of a request to
/// [RequestAuthentication], for middleware: the `Authorization` jwt
/// ([extract_request_jwt]), else the X-API-KEY / X-API-SECRET api key,
/// else the public key of a request signature, which is verified
/// (its signing key enabled, its timestamp ~now, signed for a host of
/// this server, over this request and its body). None of them is
/// authenticated as a client's yet, see [RequestAuthentication].
///
/// Requests without credentials are UNAUTHORIZED, and credentials
/// which are presented
/// but unusable count against [AuthImpl::general_rate_limiter] for the
/// `ip`. That is most of all an invalid request signature, which
/// costs the server reading the body and verifying a signature to
/// find out about, so it shouldn't be free to send them in a loop.
///
/// Requests without any credentials are not counted: a UI which isn't
/// logged in yet sends those, and would lock its own login out.
///
/// `body` is the request body for the signature of a signed request
/// to be verified with, see [read_signed_request_body].
///
/// [AuthImpl::accept_signed_request] is not called here (the signer
/// is not authenticated yet): a middleware built on this calls
/// [accept_signed_request] itself, as [authenticate_request] does.
pub async fn extract_request_authentication_rate_limited<
  I: AuthImpl,
>(
  auth: &I,
  ip: IpAddr,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
  body: &SignedRequestBody,
) -> mogh_error::Result<RequestAuthentication> {
  async {
    extract_request_authentication(auth, method, uri, headers, body)
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await?
  .context("Invalid client credentials")
  .status_code(StatusCode::UNAUTHORIZED)
}

/// Maps the request credential headers to [RequestAuthentication],
/// trying [extract_request_jwt], [extract_request_api_key],
/// and [verify_request_signature] in order.
///
/// `body` is only used to verify a request signature, which covers
/// it: pass what [read_signed_request_body] read for requests carrying
/// X-API-SIGNATURE. Its X-API-TIMESTAMP was checked then, the signature
/// is verified against it ([SignedRequestBody]).
///
/// DANGER ⚠️ This does not authenticate the credentials
/// (see [RequestAuthentication]). Authentication happens downstream
/// in [AuthImpl::handle_request_authentication] /
/// [AuthImpl::get_user_id_from_request_authentication].
///
/// Returns `Ok(None)` when the request carries no credentials.
pub(crate) fn extract_request_authentication<I: AuthImpl>(
  auth: &I,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
  body: &SignedRequestBody,
) -> mogh_error::Result<Option<RequestAuthentication>> {
  if let Some(jwt) = extract_request_jwt(headers)? {
    return Ok(Some(RequestAuthentication::Jwt(jwt)));
  }

  if let Some((key, secret)) = extract_request_api_key(headers)? {
    return Ok(Some(RequestAuthentication::ApiKey { key, secret }));
  }

  if let Some(public_key) = verify_request_signature(
    auth,
    method,
    uri,
    headers,
    &body.body,
    body.timestamp,
  )? {
    return Ok(Some(RequestAuthentication::PublicKey(public_key)));
  }

  Ok(None)
}

/// Extracts the jwt from the AUTHORIZATION header, stripping the
/// `Bearer` scheme, which is matched case insensitively
/// (RFC 7235). A value without a scheme is taken as the jwt.
///
/// Another scheme (eg. the `Basic` credentials of a proxy in front
/// of the app) is refused, UNAUTHORIZED "Unsupported authorization
/// scheme". It is no guess at a credential of this server, so the
/// refusal is uncounted ([mogh_error::Error::uncounted]).
///
/// DANGER ⚠️ The jwt is not validated here, see
/// [get_jwt_user_id].
pub fn extract_request_jwt(
  headers: &HeaderMap,
) -> mogh_error::Result<Option<String>> {
  let Some(authorization) = headers.get(AUTHORIZATION) else {
    return Ok(None);
  };
  let maybe_bearer = authorization
    .to_str()
    .context("AUTHORIZATION is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?
    .trim();
  let jwt = match maybe_bearer
    .split_once(|c: char| c.is_ascii_whitespace())
  {
    Some((scheme, jwt)) if scheme.eq_ignore_ascii_case("bearer") => {
      jwt.trim_start()
    }
    // A jwt has no whitespace: this is another scheme.
    Some(_) => {
      return Err(
        anyhow!("Unsupported authorization scheme")
          .status_code(StatusCode::UNAUTHORIZED)
          .uncounted(),
      );
    }
    None => maybe_bearer,
  };
  Ok(Some(jwt.to_string()))
}

/// Extracts the (key, secret) from the
/// X-API-KEY / X-API-SECRET headers.
///
/// DANGER ⚠️ The secret is not validated here, see
/// [verify_api_key].
pub(crate) fn extract_request_api_key(
  headers: &HeaderMap,
) -> mogh_error::Result<Option<(String, String)>> {
  let Some(key) = headers.get(API_KEY_HEADER) else {
    return Ok(None);
  };
  let key = key
    .to_str()
    .context("X-API-KEY is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?
    .trim()
    .to_string();
  let secret = headers
    .get("x-api-secret")
    .context(
      "Request headers have X-API-KEY but missing X-API-SECRET",
    )
    .status_code(StatusCode::UNAUTHORIZED)?
    .to_str()
    .context("X-API-SECRET is not valid UTF-8")
    .status_code(StatusCode::UNAUTHORIZED)?
    .trim()
    .to_string();
  Ok(Some((key, secret)))
}

/// Verifies the signature of a request signed with a signing key,
/// from its X-API-PUBLIC-KEY / X-API-HOST / X-API-TIMESTAMP /
/// X-API-NONCE / X-API-SIGNATURE headers, and returns the client
/// public key. `Ok(None)` for a request without X-API-SIGNATURE.
///
/// Signing keys must be enabled ([AuthImpl::signing_keys_enabled]),
/// else the request is UNAUTHORIZED. The timestamp must be ~now
/// ([AuthImpl::signing_key_timestamp_tolerance_ms]), the host the
/// request is signed for (X-API-HOST) must be one of this server's
/// ([AuthImpl::host], or one of [AuthImpl::extra_hosts]), and the
/// signature must verify with the public key over the message
/// binding that host, the method, path and query, timestamp, nonce
/// and `body` ([SignedRequest::message]). This proves the client
/// holds the private key for the returned public key, and signed
/// this request for this server, nothing more.
///
/// The host is what the client signed, never where the request
/// arrived (its Host header): whoever passes a request on to another
/// server sets that too. A request signed for another host is
/// answered with [SIGNED_FOR_ANOTHER_HOST], and one signed at
/// another time with [SIGNED_AT_ANOTHER_TIME]: neither is about the
/// key, and a client can tell.
///
/// Each of the headers has one form which is accepted, and is given
/// once, so the request has one spelling: the returned public key is
/// the header as it was sent.
///
/// `body` is the request body, as read by [read_signed_request_body]
/// (empty for a CONNECT request over HTTP/2 or later).
///
/// The signature is verified against the X-API-TIMESTAMP
/// [read_signed_request_body] already `checked` when the headers
/// arrived, without checking it against the time again: the time the
/// body takes to arrive doesn't count. With `None`, it is checked
/// against the time this is called at.
///
/// DANGER ⚠️ The public key must still be matched to a known client.
fn verify_request_signature<I: AuthImpl>(
  auth: &I,
  method: &Method,
  uri: &Uri,
  headers: &HeaderMap,
  body: &[u8],
  checked: Option<i64>,
) -> mogh_error::Result<Option<String>> {
  if !headers.contains_key(API_SIGNATURE_HEADER) {
    return Ok(None);
  }

  // The signature covers each of these, it only verifies for the
  // ones the client signed.
  let SignedRequestHead {
    timestamp,
    public_key,
    host,
    nonce,
    signature,
  } = check_signed_request(auth, headers, checked)?;

  // Fails for anything which wasn't signed for this exact request
  // (host, method, path and query, timestamp, nonce, body).
  let message =
    signed_request_message(host, method, uri, timestamp, nonce, body);
  mogh_pki::signature::verify(
    &public_key,
    message.as_bytes(),
    signature,
  )
  .map_err(|_| {
    anyhow!("Invalid client credentials")
      .status_code(StatusCode::UNAUTHORIZED)
  })?;

  Ok(Some(public_key.into_inner()))
}

/// What a request signature covers, shared with the client
/// ([SignedRequest::message]), for the request as the server has it.
///
/// - `host`: the host the request is signed for (its X-API-HOST),
///   one of the hosts of this server ([signed_request_hosts]).
/// - `method`: as it was received, methods are case sensitive.
/// - Only the path and query of `uri` are covered, never its scheme
///   and host: an HTTP/2 request (or an HTTP/1.1 request in absolute
///   form) has them in its uri, while the client signs the path and
///   query.
pub(crate) fn signed_request_message(
  host: &str,
  method: &Method,
  uri: &Uri,
  timestamp: i64,
  nonce: &str,
  body: &[u8],
) -> String {
  SignedRequest {
    host,
    method: method.as_str(),
    path_and_query: uri
      .path_and_query()
      .map(|path_and_query| path_and_query.as_str())
      .unwrap_or("/"),
    timestamp,
    nonce,
    body,
  }
  .message()
}

/// What a signed request needs to verify, found out without the
/// body (see [read_signed_request_body]).
struct SignedRequestHead<'a> {
  /// The X-API-TIMESTAMP, which is ~now.
  timestamp: i64,
  /// The X-API-PUBLIC-KEY, a well formed Ed25519 key in the form
  /// signing keys are stored with.
  public_key: SpkiPublicKey,
  /// The X-API-HOST, which is one of the hosts of this server.
  host: &'a str,
  /// The X-API-NONCE, which is well formed.
  nonce: &'a str,
  /// The X-API-SIGNATURE, which is well formed.
  signature: &'a str,
}

/// Checks what can be checked of a signed request without its body
/// (see [read_signed_request_body]): signing keys are enabled, the
/// X-API-TIMESTAMP is ~now (unless it was `checked` before), the
/// X-API-HOST is a host of this server, and the X-API-PUBLIC-KEY,
/// X-API-NONCE and X-API-SIGNATURE are well formed. UNAUTHORIZED
/// otherwise.
fn check_signed_request<'a, I: AuthImpl>(
  auth: &I,
  headers: &'a HeaderMap,
  checked: Option<i64>,
) -> mogh_error::Result<SignedRequestHead<'a>> {
  // Apps which don't use signing keys have them off (the default),
  // which is not an error of the server. Anybody can send the
  // header, so this isn't worth more than a debug log.
  if !auth.signing_keys_enabled() {
    debug!(
      "Refused a request signed with a signing key | AuthImpl::signing_keys_enabled is off"
    );
    return Err(
      anyhow!("Signing keys are not enabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let timestamp = match checked {
    Some(timestamp) => timestamp,
    None => {
      let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis() as i64;
      check_request_timestamp(auth, headers, now)?
    }
  };

  // The key the client claims to have signed with. Refused unless it
  // is an Ed25519 key (one of another algorithm, as signing keys
  // were before 7.0, could never verify), in the one form keys are
  // stored and compared in.
  let public_key = signed_header(headers, API_PUBLIC_KEY_HEADER)?;
  let parsed =
    SpkiPublicKey::from_maybe_pem(PkiKind::Signature, public_key)
      .context("X-API-PUBLIC-KEY is not an Ed25519 public key")
      .status_code(StatusCode::UNAUTHORIZED)?;
  if parsed.as_str() != public_key {
    return Err(
      anyhow!(
        "X-API-PUBLIC-KEY is not in the form of a stored public key (base64 spki der)"
      )
      .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let nonce = signed_header(headers, API_NONCE_HEADER)?;
  if !valid_nonce(nonce) {
    return Err(
      anyhow!(
        "X-API-NONCE is not 16 to 64 characters of A-Z a-z 0-9 - _"
      )
      .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  // What could never verify is refused here, rather than after the
  // body was read for it.
  let signature = signed_header(headers, API_SIGNATURE_HEADER)?;
  if !mogh_pki::signature::well_formed(signature) {
    return Err(
      anyhow!(
        "X-API-SIGNATURE is not a signature (64 bytes, base64)"
      )
      .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  // The host the client made the request for. A claim until the
  // signature verifies (which covers it), and only accepted as one
  // of the hosts of this server: the same key may be known to
  // another server, and a request made for that one is none for
  // this one.
  let host = signed_header(headers, API_HOST_HEADER)?;
  if !valid_host(host) {
    return Err(
      anyhow!(
        "X-API-HOST is not a host as a request is signed for it (lowercase host[:port])"
      )
      .status_code(StatusCode::UNAUTHORIZED),
    );
  }
  let hosts = signed_request_hosts(auth)?;
  if !hosts.iter().any(|known| known == host) {
    // Anybody can send the header: not worth more than a debug log.
    // The client is told, and tells whoever runs it.
    debug!(
      "Refused a signed request: it is signed for '{host}', which is none of the hosts of this server ({hosts:?})"
    );
    // A client which signs the port though it is the default of the
    // scheme would never match, whatever the server lists.
    let hint = [":443", ":80"]
      .iter()
      .filter_map(|port| host.strip_suffix(port))
      .find(|without| hosts.iter().any(|known| known == without))
      .map(|without| {
        format!(
          " (it takes them for '{without}': the default port of the scheme is left out of the host)"
        )
      })
      .unwrap_or_default();
    return Err(
      anyhow!(
        "{SIGNED_FOR_ANOTHER_HOST}: '{host}' is none of the hosts it takes signed requests for{hint}"
      )
      .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  Ok(SignedRequestHead {
    timestamp,
    public_key: parsed,
    host,
    nonce,
    signature,
  })
}

/// The value of a header of a signed request, which is given once.
/// With two values, which of them counts would be up to whoever
/// reads them: an app remembering the requests it has seen could go
/// by another one than the signature was verified with.
fn signed_header<'a>(
  headers: &'a HeaderMap,
  header: &'static str,
) -> mogh_error::Result<&'a str> {
  // Only spelled out for a refusal.
  let name = || header.to_ascii_uppercase();
  let mut values = headers.get_all(header).iter();
  let value = values
    .next()
    .with_context(|| {
      format!(
        "Request headers have X-API-SIGNATURE but missing {}",
        name()
      )
    })
    .status_code(StatusCode::UNAUTHORIZED)?;
  if values.next().is_some() {
    return Err(
      anyhow!("{} is given more than once", name())
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }
  value
    .to_str()
    .with_context(|| format!("{} is not valid UTF-8", name()))
    .status_code(StatusCode::UNAUTHORIZED)
}

/// The hosts this server takes signed requests for: [AuthImpl::host]
/// and [AuthImpl::extra_hosts], each as a client signs it
/// ([url_host]).
///
/// An origin which has no host is a misconfiguration, not the
/// client's fault: they are logged (the first time) and left out.
/// Without any host left, the client only learns that much
/// (INTERNAL_SERVER_ERROR). Apps find out at startup with
/// [check_signed_request_hosts].
pub fn signed_request_hosts<I: AuthImpl>(
  auth: &I,
) -> mogh_error::Result<Vec<String>> {
  static LOGGED: std::sync::Once = std::sync::Once::new();

  let mut hosts = Vec::new();
  let mut unusable = Vec::new();
  for (config, origin, host) in signed_request_origins(auth) {
    match host {
      Ok(host) => {
        if !hosts.contains(&host) {
          hosts.push(host);
        }
      }
      Err(e) => unusable.push(format!(
        "AuthImpl::{config} {} ({e:#})",
        shown_origin(origin)
      )),
    }
  }
  if !unusable.is_empty() {
    // Every signed request gets here: said once.
    LOGGED.call_once(|| {
      error!(
        "Requests signed for these can't be verified, each needs an origin like 'https://example.com' | {}",
        unusable.join(" | ")
      )
    });
  }
  if hosts.is_empty() {
    return Err(mogh_error::Error::msg(
      "Failed to verify the request signature",
    ));
  }
  Ok(hosts)
}

/// The hosts this server takes signed requests for
/// ([signed_request_hosts]), or what is wrong with them: an origin
/// of [AuthImpl::host] or [AuthImpl::extra_hosts] which a host can't
/// be read from (it has no scheme, or is no http(s) url).
///
/// For an app with [AuthImpl::signing_keys_enabled] to call when it
/// starts: such an origin otherwise only shows once clients sign
/// requests, in the log (once) and as a `401` to each request
/// signed for it (a `500`, when no origin is left to sign for).
pub fn check_signed_request_hosts<I: AuthImpl>(
  auth: &I,
) -> anyhow::Result<Vec<String>> {
  let mut hosts = Vec::new();
  for (config, origin, host) in signed_request_origins(auth) {
    let host = host.with_context(|| {
      format!(
        "AuthImpl::{config} needs an origin like 'https://example.com', got {}",
        shown_origin(origin)
      )
    })?;
    if !hosts.contains(&host) {
      hosts.push(host);
    }
  }
  Ok(hosts)
}

/// An origin no host can be read from, as it is shown to whoever
/// configured it: not at all when it may carry credentials, and
/// without a query or fragment (what could sit there, as a token,
/// is nothing a log should hold).
fn shown_origin(origin: &str) -> String {
  if origin.contains('@') {
    return String::from("one with credentials (not shown)");
  }
  match origin.split_once(['?', '#']) {
    Some((shown, _)) => {
      format!("'{shown}' (what follows it not shown)")
    }
    None => format!("'{origin}'"),
  }
}

/// The origins of [AuthImpl::host] and [AuthImpl::extra_hosts], with
/// the method they are from and the host a client signs for each.
fn signed_request_origins<I: AuthImpl>(
  auth: &I,
) -> impl Iterator<Item = (&'static str, &str, anyhow::Result<String>)>
{
  std::iter::once(("host", auth.host()))
    .chain(
      auth
        .extra_hosts()
        .iter()
        .map(|origin| ("extra_hosts", origin.as_str())),
    )
    .map(|(config, origin)| (config, origin, url_host(origin)))
}

/// The X-API-TIMESTAMP of a signed request, once it is within
/// [AuthImpl::signing_key_timestamp_tolerance_ms] of `now` (unix
/// milliseconds), UNAUTHORIZED otherwise: [SIGNED_AT_ANOTHER_TIME]
/// for one which is not, so a client can tell its clock (or a slow
/// connection) from its key.
fn check_request_timestamp<I: AuthImpl>(
  auth: &I,
  headers: &HeaderMap,
  now: i64,
) -> mogh_error::Result<i64> {
  let timestamp = signed_header(headers, API_TIMESTAMP_HEADER)?;
  // One spelling: the digits of the number as the client signed it,
  // without a sign, spaces or leading zeros.
  let timestamp = Some(timestamp)
    .filter(|timestamp| {
      !timestamp.is_empty()
        && timestamp.bytes().all(|byte| byte.is_ascii_digit())
        && (*timestamp == "0" || !timestamp.starts_with('0'))
    })
    .and_then(|timestamp| timestamp.parse::<i64>().ok())
    .context(
      "X-API-TIMESTAMP is not a unix timestamp in milliseconds",
    )
    .status_code(StatusCode::UNAUTHORIZED)?;

  // Ensure timestamp is ~now. The subtraction saturates,
  // the timestamp is untrusted and can be anything.
  let tolerance =
    i64::try_from(auth.signing_key_timestamp_tolerance_ms())
      .unwrap_or(i64::MAX);
  let off = now.saturating_sub(timestamp).saturating_abs();
  if off > tolerance {
    return Err(
      anyhow!(
        "{SIGNED_AT_ANOTHER_TIME}: X-API-TIMESTAMP is {off}ms from it, {tolerance}ms are tolerated"
      )
      .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  Ok(timestamp)
}

/// The user of a request authenticated with [authenticate_user],
/// attached by [Authenticated::finish] for the handlers to extract:
/// those of the auth management api, and of a middleware of an app's
/// own built on it (eg. the supporter api).
#[derive(Clone)]
pub struct UserExtractor(pub Arc<BoxAuthUser>);

impl<S: Send + Sync> FromRequestParts<S> for UserExtractor {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    parts
      .extensions
      .get()
      .cloned()
      .context("Missing authorization credentials")
      .status_code(StatusCode::UNAUTHORIZED)
  }
}

/// When the user logged in to get the token the request is
/// authenticated with (unix seconds), see
/// [JwtClaims::authenticated_at][crate::provider::jwt::JwtClaims::authenticated_at].
/// `None` for credentials without a login: api keys, signing keys,
/// and tokens not issued by [AuthImpl::jwt_provider]. Attached by
/// [authenticate_request] for the app's handlers, and with
/// [UserExtractor] by [Authenticated::finish]. A request without it
/// (another middleware of the app's own) is refused, UNAUTHORIZED.
///
/// What [require_recent_login] takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedAt(pub Option<u64>);

impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedAt {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    parts
      .extensions
      .get()
      .copied()
      .context("Missing authorization credentials")
      .status_code(StatusCode::UNAUTHORIZED)
  }
}

/// Refuses a session whose login is older than
/// [AuthImpl::reauthentication_window_secs], with the auth
/// management api's refusal: `403 Forbidden`, a message starting
/// with [REAUTHENTICATION_REQUIRED]. For the requests of an app's
/// own api which should need a recent login as the account requests
/// of the auth management api do: writes which mint lasting access
/// (a user with admin rights, an api key for another user, an
/// onboarding key) or widen it (a cidr whitelist, re-enabling a
/// key). A token which leaked is then not enough for them.
///
/// `authenticated_at` is the request's [AuthenticatedAt], which
/// [authenticate_request] attaches:
///
/// - `Some(login)`, a session token of [AuthImpl::jwt_provider]:
///   accepted when the user logged in at most the window ago, with
///   the clock skew the token validation tolerates
///   ([JwtProvider::validation][crate::provider::jwt::JwtProvider::validation]).
///   The login of a token from token exchange is when the provider
///   authenticated the user (see
///   [AuthImpl::reauthentication_window_secs]).
/// - `None`, a credential without a login: an api key or signing
///   key (the automation credentials), or a token
///   [AuthImpl::jwt_provider] did not issue. Accepted: unlike the
///   account requests of the auth management api, which refuse
///   them, what they may do in the app's api is the app's call.
///
/// A window of `0` accepts every session.
///
/// ```ignore
/// async fn handler(
///   Extension(user): Extension<User>,
///   AuthenticatedAt(authenticated_at): AuthenticatedAt,
///   Json(request): Json<WriteRequest>,
/// ) -> mogh_error::Result<Response> {
///   if matches!(request, WriteRequest::CreateServiceUser(_)) {
///     require_recent_login(&AppAuthImpl, authenticated_at)?;
///   }
///   // ...
/// }
/// ```
///
/// Clients recognize the refusal like the management api's:
/// `isReauthenticationRequired(e)` in the typescript client, which
/// `mogh_ui` answers by sending the user to log in again.
pub fn require_recent_login<I: AuthImpl + ?Sized>(
  auth: &I,
  authenticated_at: Option<u64>,
) -> mogh_error::Result<()> {
  check_login_age(
    auth.reauthentication_window_secs(),
    auth.jwt_provider().validation().leeway,
    authenticated_at,
    unix_timestamp_ms() / 1_000,
  )
}

/// Whether a login at `authenticated_at` is recent at `now` (unix
/// seconds): within `window_secs` (`0` accepts any), tolerating
/// `leeway_secs` of clock skew. `None` (no login) is accepted, see
/// [require_recent_login]. The auth management api decides first
/// which requests need it, and what a credential without a login
/// may do.
pub(crate) fn check_login_age(
  window_secs: u64,
  leeway_secs: u64,
  authenticated_at: Option<u64>,
  now: u64,
) -> mogh_error::Result<()> {
  if window_secs == 0 {
    return Ok(());
  }
  let Some(at) = authenticated_at else {
    return Ok(());
  };
  // Token validation already refuses tokens issued further in the
  // future than the leeway, a token from the future can't count as
  // recent forever here (`saturating_sub` makes its age zero).
  if at <= now.saturating_add(leeway_secs)
    && now.saturating_sub(at) <= window_secs
  {
    return Ok(());
  }
  Err(
    anyhow!(
      "{REAUTHENTICATION_REQUIRED}: log in again to continue, this needs a login within the last {}",
      format_window(window_secs)
    )
    .status_code(StatusCode::FORBIDDEN),
  )
}

fn format_window(secs: u64) -> String {
  if secs >= 120 && secs.is_multiple_of(60) {
    format!("{} minutes", secs / 60)
  } else {
    format!("{secs} seconds")
  }
}

/// A request whose credentials authenticated a user
/// ([authenticate_user]), not yet handed on. The middleware applies
/// its own policy to [Self::user] (the auth management api lets a
/// disabled user only ask who they are, the supporter api refuses
/// them), then calls [Self::finish].
pub struct Authenticated {
  /// The request, its body put back when it was read (a request
  /// signed with a signing key).
  pub req: Request,
  /// The user the credentials authenticated, the cidr whitelists of
  /// the user and of the api key / signing key checked.
  pub user: BoxAuthUser,
  /// When the user logged in, see [AuthenticatedAt].
  pub authenticated_at: Option<u64>,
  /// The signature of a request signed with a signing key
  /// ([accepted_signature]), which [Self::finish] hands to
  /// [AuthImpl::accept_signed_request].
  pub accepted: Option<AcceptedSignature>,
  /// The client ip the request was authenticated for.
  pub ip: IpAddr,
}

/// Authenticates the user of a request as the auth management api
/// does, for a middleware of an app's own which needs the user and
/// leaves the credential checks to the auth server (eg. the
/// supporter api). In the order which matters:
///
/// 1. The body of a request signed with a signing key is read, its
///    X-API-TIMESTAMP checked before ([read_signed_request_body]).
/// 2. The credentials are extracted, a request signature verified,
///    unusable ones counted against [AuthImpl::general_rate_limiter]
///    ([extract_request_authentication_rate_limited]).
/// 3. The user is authenticated and loaded, the cidr whitelists of
///    the key and the user enforced, a refusal counted
///    ([get_user_from_request_authentication]).
///
/// Then the middleware applies its policy to the user, and calls
/// [Authenticated::finish], which hands the signature of a signed
/// request to [AuthImpl::accept_signed_request] only then: an app
/// refusing replays remembers the signatures of requests which go on
/// to be handled, not of the ones its policy refused.
pub async fn authenticate_user<I: AuthImpl>(
  auth: &I,
  ip: IpAddr,
  uri: &Uri,
  req: Request,
) -> mogh_error::Result<Authenticated> {
  // The signature of a signed request covers the body. One which
  // can't verify is refused before it is read.
  let (req, body) = read_signed_request_body(auth, ip, req).await?;

  let req_auth = extract_request_authentication_rate_limited(
    auth,
    ip,
    req.method(),
    uri,
    req.headers(),
    &body,
  )
  .await?;

  let accepted = accepted_signature(&req_auth, req.headers())?;
  let authenticated_at = login_time(auth, &req_auth);

  // Enforces the api key and user cidr whitelists.
  let user = get_user_from_request_authentication(auth, req_auth, ip)
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &ip,
    )
    .await?;

  Ok(Authenticated {
    req,
    user,
    authenticated_at,
    accepted,
    ip,
  })
}

impl Authenticated {
  /// The request goes on to be handled: hands the signature of a
  /// signed request to the app ([accept_signed_request], which may
  /// refuse a replay), attaches [UserExtractor] and
  /// [AuthenticatedAt], and sets the user of the
  /// [request_context][crate::request_context] (when there is one).
  /// Returns the request to run the handler with.
  pub async fn finish<I: AuthImpl>(
    self,
    auth: &I,
  ) -> mogh_error::Result<Request> {
    let Authenticated {
      mut req,
      user,
      authenticated_at,
      accepted,
      ip,
    } = self;
    accept_signed_request(auth, ip, accepted, &mut req).await?;
    crate::context::set_request_user_id(user.id());
    req.extensions_mut().insert(UserExtractor(Arc::new(user)));
    req
      .extensions_mut()
      .insert(AuthenticatedAt(authenticated_at));
    Ok(req)
  }
}

/// Authenticates the request credentials with
/// [AuthImpl::get_user_id_from_request_authentication] (which enforces
/// the api key cidr whitelist), loads the user with [AuthImpl::get_user],
/// and checks the request `ip` against the user's
/// [AuthUserImpl::cidr_whitelist] with [check_user_cidr_whitelist].
///
/// Used by [authenticate_user], and can be used to implement
/// [AuthImpl::handle_request_authentication].
pub async fn get_user_from_request_authentication<
  I: AuthImpl + ?Sized,
>(
  auth: &I,
  req_auth: RequestAuthentication,
  ip: IpAddr,
) -> mogh_error::Result<BoxAuthUser> {
  let user_id = auth
    .get_user_id_from_request_authentication(req_auth, ip)
    .await?;
  let user = auth.get_user(user_id).await?;
  check_user_cidr_whitelist(user.as_ref(), ip)?;
  Ok(user)
}

/// Ensure the request `ip` is allowed by the user's
/// [AuthUserImpl::cidr_whitelist], returning FORBIDDEN if not.
/// An empty whitelist allows all ips.
pub fn check_user_cidr_whitelist(
  user: &dyn AuthUserImpl,
  ip: IpAddr,
) -> mogh_error::Result<()> {
  check_cidr_whitelist(ip, user.cidr_whitelist())
}

/// Ensure the request `ip` is allowed by the api key's
/// [AuthApiKeyImpl::cidr_whitelist], returning FORBIDDEN if not.
/// An empty whitelist allows all ips.
pub fn check_api_key_cidr_whitelist(
  api_key: &dyn AuthApiKeyImpl,
  ip: IpAddr,
) -> mogh_error::Result<()> {
  check_cidr_whitelist(ip, api_key.cidr_whitelist())
}

/// Helper for authenticating [RequestAuthentication::Jwt]:
/// validates the jwt (signature, expiry, iss / aud) with
/// [AuthImpl::jwt_provider] and returns the user id (`sub`),
/// returning UNAUTHORIZED if invalid. An authentic token which only
/// expired is refused uncounted
/// ([JwtProvider::decode_claims][crate::provider::jwt::JwtProvider::decode_claims]).
pub fn get_jwt_user_id<I: AuthImpl + ?Sized>(
  auth: &I,
  jwt: &str,
) -> mogh_error::Result<String> {
  auth
    .jwt_provider()
    .decode_sub(jwt)
    .status_code(StatusCode::UNAUTHORIZED)
}

/// Helper for authenticating [RequestAuthentication::ApiKey] and
/// [RequestAuthentication::PublicKey], the keys' half of the default
/// [AuthImpl::get_user_id_from_request_authentication]: the key from
/// [AuthImpl::get_api_key] (its secret verified) or
/// [AuthImpl::get_signing_key] (the request's signature verified
/// before), the request `ip` checked against the key's
/// [AuthApiKeyImpl::cidr_whitelist] ([check_api_key_cidr_whitelist],
/// FORBIDDEN), then the id of the user who owns it.
///
/// For an app overriding the method to check more of a jwt (eg. the
/// sessions it ended), which leaves the keys to this rather than
/// copying the default:
///
/// ```ignore
/// fn get_user_id_from_request_authentication(
///   &self,
///   auth: RequestAuthentication,
///   ip: IpAddr,
/// ) -> DynFuture<mogh_error::Result<String>> {
///   match auth {
///     RequestAuthentication::Jwt(jwt) => Box::pin(session_user_id(jwt)),
///     auth => get_key_user_id(self, auth, ip),
///   }
/// }
/// ```
///
/// A [RequestAuthentication::Jwt] is refused with a server error: it
/// is the caller's own branch ([get_jwt_user_id] in the default), and
/// authenticating it here would skip what the caller adds to it.
pub fn get_key_user_id<I: AuthImpl + ?Sized>(
  auth: &I,
  req_auth: RequestAuthentication,
  ip: IpAddr,
) -> DynFuture<mogh_error::Result<String>> {
  let api_key = match req_auth {
    RequestAuthentication::ApiKey { key, secret } => {
      auth.get_api_key(key, secret)
    }
    RequestAuthentication::PublicKey(public_key) => {
      auth.get_signing_key(public_key)
    }
    RequestAuthentication::Jwt(_) => {
      return Box::pin(async {
        Err(
          anyhow!(
            "get_key_user_id authenticates api keys and signing keys, a jwt is the caller's to authenticate"
          )
          .status_code(StatusCode::INTERNAL_SERVER_ERROR),
        )
      });
    }
  };
  Box::pin(async move {
    let api_key = api_key.await?;
    check_api_key_cidr_whitelist(api_key.as_ref(), ip)?;
    Ok(api_key.user_id().to_string())
  })
}

/// Helper for implementing [AuthImpl::get_api_key] (prefer
/// [verify_api_key], which also refuses expired keys): bcrypt verifies
/// the incoming secret against the stored hash, returning
/// UNAUTHORIZED for an unknown key (`None`) or a secret which doesn't
/// match.
///
/// bcrypt runs on tokio's blocking thread pool: at most one api key
/// secret is verified per available core at a time, the other
/// requests wait their turn without holding a thread. Api keys have a
/// budget of their own: a flood of guesses at the secret of a key
/// waits behind itself, not ahead of password logins or other
/// blocking work (file io, the DNS lookups of outgoing requests). A
/// request dropped while it waits (the client disconnects) doesn't
/// run its bcrypt.
///
/// A key which doesn't exist is refused right away, without a
/// bcrypt: the timing tells that it doesn't exist, which is no
/// secret (key ids are random, listed by UIs and logged at
/// creation), while a hash would let anybody spend the budget with
/// made up keys.
///
/// `_auth` is no longer used (a verification costs what the stored
/// hash says), it stays for the callers.
pub async fn verify_api_key_secret_async<I: AuthImpl + ?Sized>(
  _auth: &I,
  secret: String,
  hashed_secret: Option<String>,
) -> mogh_error::Result<()> {
  verify_api_key_secret(secret, hashed_secret).await
}

/// [verify_api_key_secret_async], for the futures of the defaults of
/// [AuthImpl], which can't hold it.
async fn verify_api_key_secret(
  secret: String,
  hashed_secret: Option<String>,
) -> mogh_error::Result<()> {
  let Some(hashed_secret) = hashed_secret else {
    return Err(refuse_unknown_api_key());
  };
  let verified = spawn_api_key_bcrypt(move || {
    bcrypt::verify(secret, &hashed_secret)
  })
  .await
  .context("Failed to run api secret verification")?
  // A stored hash which doesn't parse.
  .context("Invalid client credentials")
  .status_code(StatusCode::UNAUTHORIZED)?;
  if verified {
    Ok(())
  } else {
    Err(invalid_client_credentials())
  }
}

/// The refusal of an api key which doesn't exist: the one `401` of
/// any refused key, counted against the rate limiter like a wrong
/// secret, and right away. Every unknown key goes through here, and
/// nowhere else.
///
/// It costs no bcrypt. A dummy hash of the secret (as an unknown
/// username's login gets) would make a made up key take as long to
/// refuse as a wrong secret, hiding whether the key exists. Key ids
/// are 238 random bits which UIs list and the server logs at
/// creation, so whether one exists is no secret worth hiding, while
/// the hash let anybody spend the bcrypt budget of every api key
/// with made up ones (concurrent requests each got one before the
/// rate limiter locked them out), and the real keys' requests
/// waited behind them. Now only a request naming a real key costs a
/// bcrypt.
fn refuse_unknown_api_key() -> mogh_error::Error {
  invalid_client_credentials()
}

/// Authenticates an api key ([AuthImpl::get_api_key] does with the
/// key [AuthImpl::find_api_key] found): the request's X-API-SECRET is
/// verified against the stored hash ([verify_api_key_secret_async]:
/// off the async runtime, on a bounded budget of its own; a key which
/// doesn't exist (`None`) is refused without one), then an expired
/// key is refused. After the verification, so its timing doesn't
/// tell an expired key apart. Every refusal is the same `401 Invalid
/// client credentials`.
///
/// Returns the key, for an app overriding [AuthImpl::get_api_key] to
/// refuse what else it refuses (eg. a key which can be disabled).
///
/// `_auth` is no longer used (a verification costs what the stored
/// hash says), it stays for the callers.
pub async fn verify_api_key<I: AuthImpl + ?Sized>(
  _auth: &I,
  stored: Option<StoredApiKey>,
  secret: String,
) -> mogh_error::Result<StoredApiKey> {
  verify_stored_api_key(stored, secret).await
}

/// [verify_api_key], for the futures of the defaults of [AuthImpl],
/// which can't hold it.
pub(crate) async fn verify_stored_api_key(
  stored: Option<StoredApiKey>,
  secret: String,
) -> mogh_error::Result<StoredApiKey> {
  let hashed_secret =
    stored.as_ref().map(|stored| stored.hashed_secret.clone());
  verify_api_key_secret(secret, hashed_secret).await?;
  match stored {
    Some(stored) if !expired(stored.expires, unix_timestamp_ms()) => {
      Ok(stored)
    }
    _ => Err(invalid_client_credentials()),
  }
}

/// Authenticates a signing key ([AuthImpl::get_signing_key] does with
/// the key [AuthImpl::find_signing_key] found; its signature verified
/// before): refused when there is none, or it expired, with
/// `401 Invalid client credentials`.
///
/// Returns the key, for an app overriding [AuthImpl::get_signing_key]
/// to refuse what else it refuses.
pub fn verify_signing_key(
  stored: Option<StoredSigningKey>,
) -> mogh_error::Result<StoredSigningKey> {
  match stored {
    Some(stored) if !expired(stored.expires, unix_timestamp_ms()) => {
      Ok(stored)
    }
    _ => Err(invalid_client_credentials()),
  }
}

/// The one refusal of credentials which don't authenticate, so it
/// doesn't tell what was wrong with them.
/// Whether a web browser sent the request from a page of another
/// site. Unauthenticated endpoints which count failures against the
/// client ip refuse such a request before anything counts.
///
/// A form post, or a post whose body the handler reads whatever its
/// content type (eg. `text/plain`), is a CORS "simple" request: any
/// page can have its visitors' browsers send one (an auto-submitted
/// form, a `no-cors` fetch), from their ip, without asking them.
/// Failing such requests on purpose, a page could get everybody
/// behind that ip refused by a rate limiter shared with their logins
/// and api requests. Clients which are not browsers (CLIs, CI jobs,
/// Vault agents, other servers) send neither header this looks at:
/// - `Sec-Fetch-Site`, which browsers set and pages can't: only
///   `same-origin` (a page of the app itself) and `none` (the user)
///   pass. `same-site` doesn't: another app on a sibling subdomain.
/// - Without it (browsers before fetch metadata), the `Origin` of a
///   post must be one the app is reached at: [AuthImpl::host] or
///   one of [AuthImpl::extra_hosts], compared as origins (scheme,
///   host and port, a default port being the same as none). `null`
///   (a sandboxed page) is none of them.
///
/// The `/token` endpoint refuses these with an OAuth error
/// ([check_not_cross_site][crate::api::token::check_not_cross_site]).
/// An app's own such endpoints (eg. a Vault compatible login, which
/// reads a body of any content type) call this first and answer in
/// their own error format, before anything is counted.
///
/// ⚠️ An `Origin` without `Sec-Fetch-Site` is compared with
/// [AuthImpl::host], whose default panics: an app calling this
/// implements it.
pub fn is_cross_site_browser_request<I: AuthImpl + ?Sized>(
  auth: &I,
  headers: &HeaderMap,
) -> bool {
  match headers.get("sec-fetch-site") {
    Some(site) => {
      !matches!(site.as_bytes(), b"same-origin" | b"none")
    }
    None => headers
      .get(ORIGIN)
      .is_some_and(|origin| !is_app_origin(auth, origin)),
  }
}

/// Whether `origin` (an `Origin` header) is [AuthImpl::host] or one of
/// [AuthImpl::extra_hosts], compared as origins: scheme, host and
/// port, a default port being the same as none.
fn is_app_origin<I: AuthImpl + ?Sized>(
  auth: &I,
  origin: &HeaderValue,
) -> bool {
  let Some(origin) = origin
    .to_str()
    .ok()
    .and_then(|origin| reqwest::Url::parse(origin).ok())
    .map(|origin| origin.origin())
    .filter(|origin| origin.is_tuple())
  else {
    return false;
  };
  std::iter::once(auth.host())
    .chain(auth.extra_hosts().iter().map(String::as_str))
    .filter_map(|host| reqwest::Url::parse(host.trim()).ok())
    .any(|host| host.origin() == origin)
}

fn invalid_client_credentials() -> mogh_error::Error {
  anyhow!("Invalid client credentials")
    .status_code(StatusCode::UNAUTHORIZED)
}

fn unix_timestamp_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
  use axum::http::HeaderValue;

  use super::*;
  use crate::{DynFuture, provider::jwt::JwtProvider};

  struct TestAuth;

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      TestAuth
    }
    fn get_user(
      &self,
      _user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      Box::pin(async { Err(anyhow!("unimplemented").into()) })
    }
    fn handle_request_authentication(
      &self,
      _auth: RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      Box::pin(async { Ok(req) })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      static PROVIDER: std::sync::LazyLock<JwtProvider> =
        std::sync::LazyLock::new(|| {
          JwtProvider::new(b"secret", 60_000)
        });
      &PROVIDER
    }
    // Low cost to keep the verifications of the tests fast.
    fn api_secret_bcrypt_cost(&self) -> u32 {
      4
    }
  }

  /// Compile-time assertion that [authenticate_request] remains
  /// compatible with `axum::middleware::from_fn`, since it is only
  /// instantiated that way downstream.
  #[allow(dead_code)]
  fn assert_authenticate_request_layers<I: AuthImpl>() -> axum::Router
  {
    axum::Router::new()
      .layer(axum::middleware::from_fn(
        authenticate_request::<I, true>,
      ))
      .layer(axum::middleware::from_fn(
        authenticate_request::<I, false>,
      ))
  }

  /// Reached at `https://app.example.com`, and at an address inside
  /// the network.
  struct CrossSiteAuth;

  impl AuthImpl for CrossSiteAuth {
    fn new() -> Self {
      CrossSiteAuth
    }
    fn host(&self) -> &str {
      "https://app.example.com"
    }
    fn extra_hosts(&self) -> &[String] {
      static EXTRA: std::sync::LazyLock<Vec<String>> =
        std::sync::LazyLock::new(|| {
          vec![String::from(" http://10.0.0.5:9120/ ")]
        });
      &EXTRA
    }
    crate::test_support::stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
  }

  /// Fetch metadata decides, else the `Origin` of the request must
  /// be the app's host or one of its extra hosts.
  #[test]
  fn test_is_cross_site_browser_request() {
    let headers = |headers: &[(&'static str, &'static str)]| {
      let mut map = HeaderMap::new();
      for (name, value) in headers {
        map.append(*name, HeaderValue::from_static(value));
      }
      map
    };
    let cross_site = |list: &[(&'static str, &'static str)]| {
      is_cross_site_browser_request(&CrossSiteAuth, &headers(list))
    };
    // Clients which are not browsers, and the app's own pages.
    for list in [
      &[][..],
      &[("sec-fetch-site", "same-origin")],
      &[("sec-fetch-site", "none")],
      &[("origin", "https://app.example.com")],
      &[("origin", "https://app.example.com:443")],
      &[("origin", "https://APP.example.com")],
      &[("origin", "http://10.0.0.5:9120")],
      // Fetch metadata can't be set by a page: it decides.
      &[
        ("sec-fetch-site", "same-origin"),
        ("origin", "https://reached.another.way"),
      ],
      // Only the first of a repeated header counts, as everywhere.
      &[
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-site", "cross-site"),
      ],
    ] {
      assert!(!cross_site(list), "{list:?}");
    }
    // Pages of other sites, sandboxed pages, other ports / schemes,
    // and an origin which doesn't parse.
    for list in [
      &[("sec-fetch-site", "cross-site")][..],
      &[("sec-fetch-site", "same-site")],
      &[("sec-fetch-site", "SAME-ORIGIN")],
      &[("sec-fetch-site", "")],
      &[
        ("sec-fetch-site", "cross-site"),
        ("origin", "https://app.example.com"),
      ],
      &[("origin", "https://evil.example")],
      &[("origin", "null")],
      &[("origin", "http://app.example.com")],
      &[("origin", "https://app.example.com:8443")],
      &[("origin", "https://app.example.com.evil.example")],
      &[("origin", "http://10.0.0.5")],
      &[("origin", "not an origin")],
    ] {
      assert!(cross_site(list), "{list:?}");
    }
    // An origin which isn't even text.
    let mut map = HeaderMap::new();
    map.insert(
      ORIGIN,
      HeaderValue::from_bytes(b"https://app.example.com\xff")
        .unwrap(),
    );
    assert!(is_cross_site_browser_request(&CrossSiteAuth, &map));
  }

  #[test]
  fn test_extract_api_key_missing_key() {
    let headers = HeaderMap::new();
    assert!(extract_request_api_key(&headers).unwrap().is_none());
  }

  #[test]
  fn test_extract_api_key_missing_secret_errors() {
    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("K_abc_K"));
    let err = extract_request_api_key(&headers).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_extract_malformed_headers_are_unauthorized() {
    // Header values are bytes, not necessarily UTF-8.
    let not_utf8 = HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap();

    let mut headers = HeaderMap::new();
    headers.insert("authorization", not_utf8.clone());
    let err = extract_request_jwt(&headers).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", not_utf8.clone());
    headers.insert("x-api-secret", HeaderValue::from_static("S"));
    let err = extract_request_api_key(&headers).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("K"));
    headers.insert("x-api-secret", not_utf8);
    let err = extract_request_api_key(&headers).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_extract_api_key_trims_values() {
    let mut headers = HeaderMap::new();
    headers
      .insert("x-api-key", HeaderValue::from_static(" K_abc_K "));
    headers
      .insert("x-api-secret", HeaderValue::from_static(" S_def_S "));
    let (key, secret) =
      extract_request_api_key(&headers).unwrap().unwrap();
    assert_eq!(key, "K_abc_K");
    assert_eq!(secret, "S_def_S");
  }

  #[test]
  fn test_extract_jwt_no_authorization_header() {
    let headers = HeaderMap::new();
    assert!(extract_request_jwt(&headers).unwrap().is_none());
  }

  #[test]
  fn test_extract_jwt_strips_bearer_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "authorization",
      HeaderValue::from_static(" Bearer some.jwt.token "),
    );
    assert_eq!(
      extract_request_jwt(&headers).unwrap().unwrap(),
      "some.jwt.token"
    );
  }

  #[test]
  fn test_extract_jwt_bearer_scheme_is_case_insensitive() {
    // RFC 7235: the scheme is case insensitive, and any
    // whitespace may separate it from the token.
    for authorization in [
      "bearer some.jwt.token",
      "BEARER some.jwt.token",
      "Bearer  some.jwt.token",
      "Bearer\tsome.jwt.token",
    ] {
      let mut headers = HeaderMap::new();
      headers.insert(
        "authorization",
        HeaderValue::from_static(authorization),
      );
      assert_eq!(
        extract_request_jwt(&headers).unwrap().unwrap(),
        "some.jwt.token",
        "{authorization:?}"
      );
    }
  }

  #[test]
  fn test_extract_jwt_without_bearer_prefix() {
    let mut headers = HeaderMap::new();
    headers.insert(
      "authorization",
      HeaderValue::from_static("some.jwt.token"),
    );
    assert_eq!(
      extract_request_jwt(&headers).unwrap().unwrap(),
      "some.jwt.token"
    );
  }

  /// Another scheme carries no jwt: refused, and uncounted (eg. the
  /// basic auth of a proxy in front of the app, passed on).
  #[test]
  fn test_extract_jwt_refuses_other_schemes_uncounted() {
    for authorization in [
      "Basic dXNlcjpwYXNz",
      "basic dXNlcjpwYXNz",
      "Digest a=b, c=d",
    ] {
      let mut headers = HeaderMap::new();
      headers.insert(
        "authorization",
        HeaderValue::from_static(authorization),
      );
      let err = extract_request_jwt(&headers).unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
      assert_eq!(
        format!("{:#}", err.error),
        "Unsupported authorization scheme"
      );
      assert!(err.is_uncounted(), "{authorization}");
      // As the middleware sees it.
      let err = extract_request_authentication(
        &TestAuth,
        &Method::POST,
        &Uri::from_static("/read"),
        &headers,
        &SignedRequestBody::default(),
      )
      .err()
      .unwrap();
      assert!(err.is_uncounted(), "{authorization}");
    }
  }

  #[test]
  fn test_extract_jwt_does_not_validate() {
    // Extraction is a pure header mapping; validation is downstream.
    let mut headers = HeaderMap::new();
    headers
      .insert("authorization", HeaderValue::from_static("not-a-jwt"));
    assert_eq!(
      extract_request_jwt(&headers).unwrap().unwrap(),
      "not-a-jwt"
    );
  }

  #[test]
  fn test_get_jwt_user_id_round_trip() {
    let jwt =
      TestAuth.jwt_provider().encode_sub("user-1").unwrap().jwt;
    assert_eq!(get_jwt_user_id(&TestAuth, &jwt).unwrap(), "user-1");
  }

  #[test]
  fn test_get_jwt_user_id_rejects_forged() {
    let forged = JwtProvider::new(b"other", 60_000)
      .encode_sub("user-1")
      .unwrap()
      .jwt;
    let err = get_jwt_user_id(&TestAuth, &forged).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_get_jwt_user_id_rejects_garbage() {
    let err = get_jwt_user_id(&TestAuth, "not-a-jwt").unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // A guess, counted. So is a forged token.
    assert!(!err.is_uncounted());
    let forged = JwtProvider::new(b"other", 60_000)
      .encode_sub("user-1")
      .unwrap()
      .jwt;
    let err = get_jwt_user_id(&TestAuth, &forged).unwrap_err();
    assert!(!err.is_uncounted());
  }

  /// A token this app issued which only expired is refused without
  /// counting against the client.
  #[test]
  fn test_get_jwt_user_id_refuses_expired_uncounted() {
    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_secs();
    // Past the leeway of the validation.
    let expired = jsonwebtoken::encode(
      &jsonwebtoken::Header::default(),
      &crate::provider::jwt::BorrowedJwtClaims {
        sub: "user-1",
        iss: crate::provider::jwt::DEFAULT_ISS_AUD,
        aud: crate::provider::jwt::DEFAULT_ISS_AUD,
        iat: now - 120,
        exp: now - 60,
        auth_time: None,
        jti: None,
      },
      &jsonwebtoken::EncodingKey::from_secret(b"secret"),
    )
    .unwrap();
    let err = get_jwt_user_id(&TestAuth, &expired).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(err.is_uncounted());
  }

  #[tokio::test]
  async fn test_verify_api_key_secret_async() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    verify_api_key_secret_async(
      &TestAuth,
      "S_def_S".into(),
      Some(hashed.clone()),
    )
    .await
    .unwrap();
    for (secret, hashed) in [
      ("S_wrong_S", Some(hashed)),
      // Unknown key
      ("S_def_S", None),
      // A stored hash which doesn't parse.
      ("S_def_S", Some(String::from("not-a-bcrypt-hash"))),
    ] {
      let err =
        verify_api_key_secret_async(&TestAuth, secret.into(), hashed)
          .await
          .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }

  /// Api key secrets are verified on the bounded budget of api keys:
  /// with every permit taken, a verification waits.
  #[tokio::test]
  async fn test_verify_api_key_secret_async_is_bounded() {
    let hashed = bcrypt::hash("S_def_S", 4).unwrap();
    let held = crate::bcrypt_pool::hold_api_key_permits().await;
    // A wrong secret of a key which exists.
    let verify = tokio::spawn(verify_api_key_secret_async(
      &TestAuth,
      "S_guess_S".into(),
      Some(hashed),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!verify.is_finished(), "verified without a permit");
    drop(held);
    let err = verify.await.unwrap().unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// A key which doesn't exist is refused right away, without a
  /// bcrypt on the budget of api keys (all of it taken here): a made
  /// up key costs a lookup, not a hash. The refusal counts like any
  /// other (it isn't marked uncounted).
  #[tokio::test]
  async fn test_unknown_api_keys_cost_no_bcrypt() {
    let _held = crate::bcrypt_pool::hold_api_key_permits().await;
    let refused = tokio::time::timeout(
      std::time::Duration::from_secs(1),
      async {
        let verified = verify_api_key_secret_async(
          &TestAuth,
          "S_def_S".into(),
          None,
        )
        .await;
        let stored =
          verify_api_key(&TestAuth, None, "S_def_S".into()).await;
        (verified, stored)
      },
    )
    .await
    .expect("an unknown key waited for the bcrypt budget");
    for err in [refused.0.unwrap_err(), refused.1.unwrap_err()] {
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
      assert_eq!(
        format!("{:#}", err.error),
        "Invalid client credentials"
      );
      assert!(!err.is_uncounted());
    }
  }

  /// [TestAuth] with signing keys enabled, so signatures are checked.
  #[derive(Clone, Copy)]
  struct KeyedAuth {
    timestamp_tolerance_ms: u64,
    signed_body_limit: usize,
    signed_body_timeout: std::time::Duration,
  }

  const KEYED: KeyedAuth = KeyedAuth {
    timestamp_tolerance_ms: 1_000,
    signed_body_limit: 2 * 1024 * 1024,
    signed_body_timeout: std::time::Duration::from_secs(30),
  };

  /// The host of [KeyedAuth], as a client signs it.
  const HOST: &str = "example.com";
  /// The extra host of [KeyedAuth], as a client signs it.
  const EXTRA_HOST: &str = "10.0.0.5:9120";

  impl AuthImpl for KeyedAuth {
    fn new() -> Self {
      KEYED
    }
    fn host(&self) -> &str {
      "https://example.com"
    }
    fn extra_hosts(&self) -> &[String] {
      static EXTRA_HOSTS: std::sync::LazyLock<Vec<String>> =
        std::sync::LazyLock::new(|| {
          vec![String::from("http://10.0.0.5:9120")]
        });
      &EXTRA_HOSTS
    }
    fn signing_keys_enabled(&self) -> bool {
      true
    }
    fn signing_key_timestamp_tolerance_ms(&self) -> u64 {
      self.timestamp_tolerance_ms
    }
    fn signed_request_body_limit(&self) -> usize {
      self.signed_body_limit
    }
    fn signed_request_body_timeout(&self) -> std::time::Duration {
      self.signed_body_timeout
    }
    fn general_rate_limiter(&self) -> &mogh_rate_limit::RateLimiter {
      static LIMITER: std::sync::LazyLock<
        std::sync::Arc<mogh_rate_limit::RateLimiter>,
      > = std::sync::LazyLock::new(|| {
        mogh_rate_limit::RateLimiter::new(
          false,
          2,
          std::time::Duration::from_secs(60),
        )
      });
      &LIMITER
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      TestAuth.get_user(user_id)
    }
    fn handle_request_authentication(
      &self,
      auth: RequestAuthentication,
      ip: IpAddr,
      require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      TestAuth.handle_request_authentication(
        auth,
        ip,
        require_user_enabled,
        req,
      )
    }
    fn jwt_provider(&self) -> &JwtProvider {
      TestAuth.jwt_provider()
    }
  }

  fn now_ms() -> i64 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap()
      .as_millis() as i64
  }

  const NONCE: &str = "0123456789abcdef0123456789abcdef";

  /// The credentials of a signed request, as its headers carry them.
  #[derive(Debug, Clone)]
  struct Signed {
    public_key: String,
    host: String,
    timestamp: String,
    nonce: String,
    signature: String,
  }

  impl Signed {
    fn headers(&self) -> HeaderMap {
      let mut headers = HeaderMap::new();
      for (header, value) in [
        (API_PUBLIC_KEY_HEADER, &self.public_key),
        (API_HOST_HEADER, &self.host),
        (API_TIMESTAMP_HEADER, &self.timestamp),
        (API_NONCE_HEADER, &self.nonce),
        (API_SIGNATURE_HEADER, &self.signature),
      ] {
        headers.insert(header, HeaderValue::from_str(value).unwrap());
      }
      headers
    }

    /// The headers without `header`.
    fn headers_without(&self, header: &str) -> HeaderMap {
      let mut headers = self.headers();
      headers.remove(header).unwrap();
      headers
    }
  }

  /// A new client key pair, and the request it signed for the
  /// server at `host`.
  fn sign_for(
    host: &str,
    method: &Method,
    uri: &Uri,
    timestamp: i64,
    body: &[u8],
  ) -> Signed {
    let client =
      mogh_pki::EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    let signature = mogh_pki::signature::sign(
      &client.private,
      signed_request_message(
        host, method, uri, timestamp, NONCE, body,
      )
      .as_bytes(),
    )
    .unwrap();
    Signed {
      public_key: client.public().to_string(),
      host: host.to_string(),
      timestamp: timestamp.to_string(),
      nonce: NONCE.to_string(),
      signature,
    }
  }

  /// The public key of a signed request, its signature verified and
  /// its timestamp checked now ([verify_request_signature]).
  fn extract_request_public_key<I: AuthImpl>(
    auth: &I,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
  ) -> mogh_error::Result<Option<String>> {
    verify_request_signature(auth, method, uri, headers, body, None)
  }

  /// [sign_for] the [HOST] of [KeyedAuth].
  fn sign(
    method: &Method,
    uri: &Uri,
    timestamp: i64,
    body: &[u8],
  ) -> Signed {
    sign_for(HOST, method, uri, timestamp, body)
  }

  /// A request body, eg. of `POST /auth/manage`.
  const BODY: &[u8] = br#"{"type":"ListTrustedIssuers","params":{}}"#;

  /// `body` not read by [read_signed_request_body]: the timestamp is
  /// checked when the signature is verified.
  fn unchecked_body(body: &'static [u8]) -> SignedRequestBody {
    Bytes::from_static(body).into()
  }

  #[test]
  fn test_extract_public_key_round_trip() {
    let uri = Uri::from_static("/read");
    let signed = sign(&Method::POST, &uri, now_ms(), BODY);
    let extracted = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &signed.headers(),
      BODY,
    )
    .unwrap()
    .unwrap();
    assert_eq!(extracted, signed.public_key);
  }

  /// What [extract_request_public_key] refuses `headers` with: the
  /// message of the UNAUTHORIZED error.
  fn refusal(headers: &HeaderMap, uri: &Uri) -> String {
    let err = extract_request_public_key(
      &KEYED,
      &Method::POST,
      uri,
      headers,
      BODY,
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{headers:?}");
    err.error.to_string()
  }

  /// A request is accepted when it was signed for a host of this
  /// server: the same key may be registered at another one, and a
  /// request made for that one is not a request for this one.
  #[test]
  fn test_extract_public_key_is_bound_to_the_hosts_of_the_server() {
    let uri = Uri::from_static("/read");
    let now = now_ms();
    // AuthImpl::host, AuthImpl::extra_hosts.
    for host in [HOST, EXTRA_HOST] {
      let signed = sign_for(host, &Method::POST, &uri, now, BODY);
      let extracted = extract_request_public_key(
        &KEYED,
        &Method::POST,
        &uri,
        &signed.headers(),
        BODY,
      )
      .unwrap_or_else(|e| panic!("{host}: {:#}", e.error))
      .unwrap();
      assert_eq!(extracted, signed.public_key, "{host}");
    }
    // Another server, or this one at another port: the answer says
    // so, with the host the request was signed for.
    for host in [
      "other.example.com",
      "example.com.evil.test",
      "example.com:8443",
      "10.0.0.5",
      "10.0.0.5:9121",
    ] {
      let signed = sign_for(host, &Method::POST, &uri, now, BODY);
      let message = refusal(&signed.headers(), &uri);
      assert!(
        message.starts_with(SIGNED_FOR_ANOTHER_HOST),
        "{host}: {message}"
      );
      assert!(message.contains(&format!("'{host}'")), "{message}");
      assert!(!message.contains("default port"), "{message}");
    }
    // A client which signs the default port is told what to sign.
    let signed =
      sign_for("example.com:443", &Method::POST, &uri, now, BODY);
    let message = refusal(&signed.headers(), &uri);
    assert!(
      message.starts_with(SIGNED_FOR_ANOTHER_HOST)
        && message.contains("'example.com:443'")
        && message.contains("it takes them for 'example.com'"),
      "{message}"
    );
    // What is no host in the form it is signed in (another case, the
    // origin, nothing) is no host of any server.
    for host in ["EXAMPLE.com", "https://example.com", "", "a b"] {
      let signed = sign_for(host, &Method::POST, &uri, now, BODY);
      let message = refusal(&signed.headers(), &uri);
      assert!(message.starts_with("X-API-HOST is not"), "{message}");
      assert!(!message.contains("EXAMPLE"), "{message}");
    }

    // The host named has to be the host signed: a request made for
    // another server doesn't become one for this server by saying so.
    let relabeled = Signed {
      host: HOST.to_string(),
      ..sign_for("other.example.com", &Method::POST, &uri, now, BODY)
    };
    assert_eq!(
      refusal(&relabeled.headers(), &uri),
      "Invalid client credentials"
    );
    // Nor a request for one host of this server one for its other.
    let relabeled = Signed {
      host: EXTRA_HOST.to_string(),
      ..sign_for(HOST, &Method::POST, &uri, now, BODY)
    };
    assert_eq!(
      refusal(&relabeled.headers(), &uri),
      "Invalid client credentials"
    );
  }

  /// The host is the one the client signed, checked against the hosts
  /// the server is configured with. What the request says about where
  /// it arrived (the Host header, the authority of the uri) doesn't
  /// count: whoever passes on a request captured at another server
  /// sends that along too.
  #[test]
  fn test_extract_public_key_ignores_the_request_host() {
    use axum::http::header::HOST as HOST_HEADER;

    let now = now_ms();
    let path = Uri::from_static("/auth/manage?x=1");
    let signed = sign(&Method::POST, &path, now, BODY);
    // Over HTTP/2 the server sees the scheme and authority in the
    // request uri, the client signs the path and query only. Behind
    // a proxy the Host is whatever the proxy sends.
    for uri in [
      "/auth/manage?x=1",
      "https://example.com/auth/manage?x=1",
      "http://127.0.0.1:9120/auth/manage?x=1",
    ] {
      for host in [None, Some("example.com"), Some("127.0.0.1:9120")]
      {
        let mut headers = signed.headers();
        if let Some(host) = host {
          headers.insert(HOST_HEADER, HeaderValue::from_static(host));
        }
        let extracted = extract_request_public_key(
          &KEYED,
          &Method::POST,
          &Uri::from_static(uri),
          &headers,
          BODY,
        )
        .unwrap_or_else(|e| panic!("{uri} {host:?}: {:#}", e.error))
        .unwrap();
        assert_eq!(extracted, signed.public_key, "{uri} {host:?}");
      }
    }
    // The path and query are still covered.
    assert_eq!(
      refusal(
        &signed.headers(),
        &Uri::from_static("https://example.com/auth/manage?x=2")
      ),
      "Invalid client credentials"
    );

    // A request signed for another server, passed on to this one
    // with everything it said there, also as addressed to this one.
    let passed_on =
      sign_for("other.example.com", &Method::POST, &path, now, BODY);
    for (uri, host) in [
      ("/auth/manage?x=1", "other.example.com"),
      (
        "https://other.example.com/auth/manage?x=1",
        "other.example.com",
      ),
      ("/auth/manage?x=1", "example.com"),
      ("https://example.com/auth/manage?x=1", "example.com"),
    ] {
      let mut headers = passed_on.headers();
      headers.insert(HOST_HEADER, HeaderValue::from_static(host));
      let message = refusal(&headers, &Uri::from_static(uri));
      assert!(
        message.starts_with(SIGNED_FOR_ANOTHER_HOST),
        "{uri} {host}: {message}"
      );
    }
  }

  /// A request signed for a host the server isn't configured with is
  /// refused saying so, before its signature is looked at. Otherwise
  /// it looks like a key the server doesn't know, and nothing tells
  /// the client (or the operator) that it is the server's hosts, or
  /// the address of the client, which have to change.
  #[test]
  fn test_extract_public_key_explains_an_unknown_host() {
    let now = now_ms();
    let path = Uri::from_static("/read");
    let signed =
      sign_for("cicada-core:9120", &Method::POST, &path, now, BODY);
    let message = refusal(&signed.headers(), &path);
    assert_eq!(
      message,
      format!(
        "{SIGNED_FOR_ANOTHER_HOST}: 'cicada-core:9120' is none of the hosts it takes signed requests for"
      )
    );
    // It is the answer before the signature is looked at (and before
    // the body is read, see test_read_signed_request_body_refuses_unverifiable):
    // a request for another path says the same.
    let other_path = sign_for(
      "cicada-core:9120",
      &Method::POST,
      &Uri::from_static("/write"),
      now,
      BODY,
    );
    assert_eq!(refusal(&other_path.headers(), &path), message);
    // Only a host in the form one is signed in is repeated: the
    // answer can't be made to say anything else, at any length.
    let long = "a".repeat(300);
    for host in [
      "evil.test' <- add this ('x",
      "Cicada-Core:9120",
      long.as_str(),
    ] {
      let named = Signed {
        host: host.to_string(),
        ..signed.clone()
      };
      let message = refusal(&named.headers(), &path);
      assert!(message.starts_with("X-API-HOST is not"), "{message}");
      assert!(!message.contains("add this"), "{message}");
      assert!(message.len() < 120, "{message}");
    }
  }

  /// [KeyedAuth] at other hosts.
  struct HostsAuth {
    host: &'static str,
    extra_hosts: Vec<String>,
  }

  impl HostsAuth {
    fn new(host: &'static str, extra_hosts: &[&str]) -> HostsAuth {
      HostsAuth {
        host,
        extra_hosts: extra_hosts
          .iter()
          .map(|host| host.to_string())
          .collect(),
      }
    }
  }

  impl AuthImpl for HostsAuth {
    fn new() -> Self {
      HostsAuth::new("https://example.com", &[])
    }
    fn host(&self) -> &str {
      self.host
    }
    fn extra_hosts(&self) -> &[String] {
      &self.extra_hosts
    }
    fn signing_keys_enabled(&self) -> bool {
      true
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      TestAuth.get_user(user_id)
    }
    fn handle_request_authentication(
      &self,
      auth: RequestAuthentication,
      ip: IpAddr,
      require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      TestAuth.handle_request_authentication(
        auth,
        ip,
        require_user_enabled,
        req,
      )
    }
    fn jwt_provider(&self) -> &JwtProvider {
      TestAuth.jwt_provider()
    }
  }

  /// The hosts are the origins of the app as a client signs them:
  /// lowercase, without the default port, a path or the scheme.
  #[test]
  fn test_signed_request_hosts() {
    let hosts = |host, extra_hosts: &[&str]| {
      signed_request_hosts(&HostsAuth::new(host, extra_hosts))
    };
    assert_eq!(
      signed_request_hosts(&KEYED).unwrap(),
      [HOST, EXTRA_HOST]
    );
    assert_eq!(
      hosts("HTTPS://Example.COM:443/app/", &[]).unwrap(),
      ["example.com"]
    );
    assert_eq!(
      hosts(
        "http://localhost:9120",
        &[
          "https://example.com:8443",
          "http://[::1]:9120",
          // Known already.
          "http://LOCALHOST:9120/",
          "https://example.com:8443/auth",
        ]
      )
      .unwrap(),
      ["localhost:9120", "example.com:8443", "[::1]:9120"]
    );

    // An origin without a scheme has no host to tell: left out (and
    // logged), the others still work.
    assert_eq!(
      hosts("example.com", &["https://example.com", "10.0.0.5:9120"])
        .unwrap(),
      ["example.com"]
    );
    assert_eq!(
      hosts("https://example.com", &["", "localhost:9120"]).unwrap(),
      ["example.com"]
    );
    // With none left, it is the server which is misconfigured.
    for (host, extra_hosts) in [
      ("example.com", [].as_slice()),
      ("", &[]),
      ("localhost:9120", &["10.0.0.5:9120", ""]),
    ] {
      let err = hosts(host, extra_hosts).unwrap_err();
      assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
      // A signed request then fails the same, whatever it was signed
      // for.
      let uri = Uri::from_static("/read");
      let signed = sign(&Method::POST, &uri, now_ms(), b"");
      let err = extract_request_public_key(
        &HostsAuth::new(host, extra_hosts),
        &Method::POST,
        &uri,
        &signed.headers(),
        b"",
      )
      .unwrap_err();
      assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
      assert_eq!(
        err.error.to_string(),
        "Failed to verify the request signature"
      );
    }
  }

  /// What an app checks its origins with at startup: the same hosts,
  /// and an error for an origin a request can never be signed for,
  /// where requests go on with the others.
  #[test]
  fn test_check_signed_request_hosts() {
    let check = |host, extra_hosts: &[&str]| {
      check_signed_request_hosts(&HostsAuth::new(host, extra_hosts))
    };
    assert_eq!(
      check_signed_request_hosts(&KEYED).unwrap(),
      [HOST, EXTRA_HOST]
    );
    assert_eq!(
      check(
        "http://localhost:9120",
        &["https://example.com:8443", "http://LOCALHOST:9120/"]
      )
      .unwrap(),
      ["localhost:9120", "example.com:8443"]
    );
    for (host, extra_hosts, config) in [
      ("example.com", [].as_slice(), "AuthImpl::host"),
      ("", &[], "AuthImpl::host"),
      (
        "https://example.com",
        &["10.0.0.5:9120"],
        "AuthImpl::extra_hosts",
      ),
      ("https://example.com", &[""], "AuthImpl::extra_hosts"),
      (
        "https://example.com",
        &["https://*.example.com"],
        "AuthImpl::extra_hosts",
      ),
      (
        "https://example.com",
        &["ftp://example.com"],
        "AuthImpl::extra_hosts",
      ),
    ] {
      let err = check(host, extra_hosts).unwrap_err().to_string();
      assert!(
        err.starts_with(config),
        "{host} {extra_hosts:?}: {err}"
      );
    }
    // What sits in a query is not repeated either.
    let err = format!(
      "{:#}",
      check("example.com/app?token=hunter2", &[]).unwrap_err()
    );
    assert!(err.contains("'example.com/app'"), "{err}");
    assert!(!err.contains("hunter2"), "{err}");
    // An origin with credentials is none, and isn't repeated.
    for (host, extra_hosts) in [
      ("https://user:hunter2@example.com", [].as_slice()),
      ("https://example.com", &["http://hunter2@10.0.0.5:9120"]),
    ] {
      let err =
        format!("{:#}", check(host, extra_hosts).unwrap_err());
      assert!(
        err.contains("one with credentials (not shown)")
          && err.contains("carries credentials"),
        "{err}"
      );
      assert!(!err.contains("hunter2"), "{err}");
    }
  }

  #[test]
  fn test_extract_public_key_at_other_hosts() {
    let uri = Uri::from_static("/read");
    let now = now_ms();
    let auth = HostsAuth::new(
      "http://localhost:9120",
      &["https://example.com:8443", "not an origin"],
    );
    for (host, accepted) in [
      ("localhost:9120", true),
      ("example.com:8443", true),
      ("localhost", false),
      ("localhost:80", false),
      ("example.com", false),
      ("not an origin", false),
    ] {
      let signed = sign_for(host, &Method::POST, &uri, now, BODY);
      let extracted = extract_request_public_key(
        &auth,
        &Method::POST,
        &uri,
        &signed.headers(),
        BODY,
      );
      match extracted {
        Ok(extracted) => {
          assert!(accepted, "{host}");
          assert_eq!(extracted.unwrap(), signed.public_key, "{host}");
        }
        Err(e) => {
          assert!(!accepted, "{host}: {:#}", e.error);
          assert_eq!(e.status, StatusCode::UNAUTHORIZED, "{host}");
          // Nothing to sign instead: the server isn't 'localhost'.
          assert!(
            !e.error.to_string().contains("default port"),
            "{host}: {:#}",
            e.error
          );
        }
      }
    }

    // The default port of either scheme, signed by a client: it is
    // told what the server takes instead.
    for (origin, signed_host, takes) in [
      ("http://example.com", "example.com:80", "example.com"),
      ("http://example.com:80", "example.com:80", "example.com"),
      ("https://example.com", "example.com:443", "example.com"),
      ("http://[::1]", "[::1]:80", "[::1]"),
    ] {
      let signed =
        sign_for(signed_host, &Method::POST, &uri, now, BODY);
      let err = extract_request_public_key(
        &HostsAuth::new(origin, &[]),
        &Method::POST,
        &uri,
        &signed.headers(),
        BODY,
      )
      .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{origin}");
      assert_eq!(
        err.error.to_string(),
        format!(
          "{SIGNED_FOR_ANOTHER_HOST}: '{signed_host}' is none of the hosts it takes signed requests for (it takes them for '{takes}': the default port of the scheme is left out of the host)"
        ),
        "{origin}"
      );
    }
    // The port of the other scheme is a port like any other.
    let signed =
      sign_for("example.com:80", &Method::POST, &uri, now, BODY);
    extract_request_public_key(
      &HostsAuth::new("https://example.com:80", &[]),
      &Method::POST,
      &uri,
      &signed.headers(),
      BODY,
    )
    .unwrap()
    .unwrap();
  }

  #[test]
  fn test_extract_public_key_rejections_are_unauthorized() {
    let uri = Uri::from_static("/read");
    let now = now_ms();
    let signed = sign(&Method::POST, &uri, now, BODY);
    let stale = now - 60_000;
    let stale_signed = sign(&Method::POST, &uri, stale, BODY);
    let other_body: &[u8] =
      br#"{"type":"CreateTrustedIssuer","params":{}}"#;
    let other_key =
      mogh_pki::EncodedKeyPair::generate(PkiKind::Signature)
        .unwrap()
        .public
        .into_inner();
    // As signing keys were before 7.0.
    let x25519_key =
      mogh_pki::EncodedKeyPair::generate(PkiKind::Mutual)
        .unwrap()
        .public
        .into_inner();

    let with_signature = |signature: &str| Signed {
      signature: signature.to_string(),
      ..signed.clone()
    };
    let with_timestamp = |timestamp: String| Signed {
      timestamp,
      ..signed.clone()
    };
    let with_nonce = |nonce: &str| Signed {
      nonce: nonce.to_string(),
      ..signed.clone()
    };
    let with_public_key = |public_key: &str| Signed {
      public_key: public_key.to_string(),
      ..signed.clone()
    };
    let pem_key =
      SpkiPublicKey::from(signed.public_key.clone()).as_pem();
    // The lowercase method is another method.
    let lowercase = Method::from_bytes(b"post").unwrap();

    let post = || Method::POST;
    let cases = [
      // Signed for another uri / method
      (post(), Uri::from_static("/write"), signed.clone(), BODY),
      (Method::GET, uri.clone(), signed.clone(), BODY),
      (lowercase, uri.clone(), signed.clone(), BODY),
      // Signed for another body on the same method and path
      (post(), uri.clone(), signed.clone(), other_body),
      (post(), uri.clone(), signed.clone(), b"".as_slice()),
      // The timestamp doesn't match the signed one
      (
        post(),
        uri.clone(),
        with_timestamp((now + 1).to_string()),
        BODY,
      ),
      // Nor the nonce
      (
        post(),
        uri.clone(),
        with_nonce("fedcba9876543210fedcba9876543210"),
        BODY,
      ),
      // A correctly signed, but old request (replay)
      (post(), uri.clone(), stale_signed, BODY),
      // Signed by another key than the one claimed
      (post(), uri.clone(), with_public_key(&other_key), BODY),
      // Garbage
      (post(), uri.clone(), with_signature("not-base64!"), BODY),
      (post(), uri.clone(), with_signature("AAAA"), BODY),
      (post(), uri.clone(), with_signature(""), BODY),
      (post(), uri.clone(), with_timestamp("soon".into()), BODY),
      (post(), uri.clone(), with_timestamp(String::new()), BODY),
      // The timestamp which was signed, spelled another way
      (post(), uri.clone(), with_timestamp(format!("+{now}")), BODY),
      (post(), uri.clone(), with_timestamp(format!("0{now}")), BODY),
      (post(), uri.clone(), with_timestamp(format!(" {now}")), BODY),
      (post(), uri.clone(), with_timestamp(format!("{now} ")), BODY),
      // So the public key
      (
        post(),
        uri.clone(),
        with_public_key(&format!(" {}", signed.public_key)),
        BODY,
      ),
      (
        post(),
        uri.clone(),
        with_public_key(&pem_key.replace('\n', "")),
        BODY,
      ),
      // Must not overflow: the largest timestamp, and digits which
      // are none
      (
        post(),
        uri.clone(),
        with_timestamp(i64::MAX.to_string()),
        BODY,
      ),
      (
        post(),
        uri.clone(),
        with_timestamp(String::from("9223372036854775808")),
        BODY,
      ),
      (post(), uri.clone(), with_timestamp("9".repeat(40)), BODY),
      // Nor a time before 1970
      (
        post(),
        uri.clone(),
        with_timestamp(i64::MIN.to_string()),
        BODY,
      ),
      (
        post(),
        uri.clone(),
        with_timestamp(String::from("-1")),
        BODY,
      ),
      // No nonce the server takes
      (post(), uri.clone(), with_nonce(""), BODY),
      (post(), uri.clone(), with_nonce("0123456789abcde"), BODY),
      (post(), uri.clone(), with_nonce("0123456789abcde|"), BODY),
      (post(), uri.clone(), with_nonce(&"a".repeat(65)), BODY),
      // No Ed25519 public key
      (post(), uri.clone(), with_public_key(""), BODY),
      (post(), uri.clone(), with_public_key("nope"), BODY),
      (post(), uri.clone(), with_public_key(&x25519_key), BODY),
      // The identity, a key of low order
      (
        post(),
        uri.clone(),
        with_public_key(
          "MCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ),
        BODY,
      ),
    ];
    for (method, uri, signed, body) in cases {
      let err = extract_request_public_key(
        &KEYED,
        &method,
        &uri,
        &signed.headers(),
        body,
      )
      .unwrap_err();
      assert_eq!(
        err.status,
        StatusCode::UNAUTHORIZED,
        "{method} {uri} {signed:?} {body:?}"
      );
    }

    // A missing header
    for header in [
      API_PUBLIC_KEY_HEADER,
      API_HOST_HEADER,
      API_TIMESTAMP_HEADER,
      API_NONCE_HEADER,
    ] {
      let err = extract_request_public_key(
        &KEYED,
        &Method::POST,
        &uri,
        &signed.headers_without(header),
        BODY,
      )
      .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{header}");
      assert!(
        err
          .error
          .to_string()
          .contains(&format!("missing {}", header.to_uppercase())),
        "{header}: {:#}",
        err.error
      );
    }
    // A header given twice, though both values are the same: which
    // of two counts is not left to whoever reads them.
    for header in [
      API_PUBLIC_KEY_HEADER,
      API_HOST_HEADER,
      API_TIMESTAMP_HEADER,
      API_NONCE_HEADER,
      API_SIGNATURE_HEADER,
    ] {
      let mut headers = signed.headers();
      let value = headers.get(header).unwrap().clone();
      headers.append(header, value);
      assert_eq!(
        refusal(&headers, &uri),
        format!("{} is given more than once", header.to_uppercase()),
      );
    }
    // A stale request says so: it is not about the key.
    let message = refusal(
      &sign(&Method::POST, &uri, stale, BODY).headers(),
      &uri,
    );
    assert!(
      message.starts_with(SIGNED_AT_ANOTHER_TIME)
        && message.contains("1000ms are tolerated"),
      "{message}"
    );
    // What is no signature is told so too, one which doesn't verify
    // is not.
    assert!(
      refusal(&with_signature("AAAA").headers(), &uri)
        .starts_with("X-API-SIGNATURE is not a signature")
    );
    assert_eq!(
      refusal(&with_public_key(&other_key).headers(), &uri),
      "Invalid client credentials"
    );
    // An old client sends the signature and timestamp only, and a key
    // from before 7.0 is no Ed25519 key: both are told so.
    let err = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &with_public_key(&x25519_key).headers(),
      BODY,
    )
    .unwrap_err();
    assert_eq!(
      err.error.to_string(),
      "X-API-PUBLIC-KEY is not an Ed25519 public key"
    );
    assert!(
      format!("{:#}", err.error).contains("this is an X25519 key"),
      "{:#}",
      err.error
    );

    // Without the signature there are no credentials at all.
    assert!(
      extract_request_public_key(
        &KEYED,
        &Method::POST,
        &uri,
        &signed.headers_without(API_SIGNATURE_HEADER),
        BODY,
      )
      .unwrap()
      .is_none()
    );
    // The request itself is fine.
    extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &signed.headers(),
      BODY,
    )
    .unwrap()
    .unwrap();
  }

  /// The public key has one form in the header, the one signing keys
  /// are stored with: it is returned as it was sent, and a request
  /// has one spelling an app can remember it by.
  #[test]
  fn test_extract_public_key_has_one_form() {
    let uri = Uri::from_static("/read");
    let signed = sign(&Method::POST, &uri, now_ms(), BODY);
    let extracted = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &signed.headers(),
      BODY,
    )
    .unwrap()
    .unwrap();
    assert_eq!(extracted, signed.public_key);
    let padded = Signed {
      public_key: format!("  {}  ", signed.public_key),
      ..signed.clone()
    };
    assert!(
      refusal(&padded.headers(), &uri)
        .starts_with("X-API-PUBLIC-KEY is not in the form")
    );

    // The same key in another encoding which reads as it: the
    // algorithm with its parameters spelled out as NULL. It names
    // the key the request was signed with, in a form no key is
    // stored in.
    let der = data_encoding::BASE64
      .decode(signed.public_key.as_bytes())
      .unwrap();
    assert_eq!(der.len(), 44);
    let mut with_null = vec![
      0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05,
      0x00, 0x03, 0x21, 0x00,
    ];
    with_null.extend_from_slice(&der[12..]);
    let with_null = data_encoding::BASE64.encode(&with_null);
    assert_eq!(
      SpkiPublicKey::from_maybe_pem(PkiKind::Signature, &with_null)
        .unwrap()
        .as_str(),
      signed.public_key
    );
    let aliased = Signed {
      public_key: with_null,
      ..signed.clone()
    };
    assert!(
      refusal(&aliased.headers(), &uri)
        .starts_with("X-API-PUBLIC-KEY is not in the form")
    );
    // As pem, on one line as a header holds it.
    let pem = Signed {
      public_key: SpkiPublicKey::from(signed.public_key.clone())
        .as_pem()
        .replace('\n', " "),
      ..signed.clone()
    };
    let message = refusal(&pem.headers(), &uri);
    assert!(
      message.starts_with("X-API-PUBLIC-KEY is not"),
      "{message}"
    );
  }

  #[test]
  fn test_extract_public_key_timestamp_tolerance_is_configurable() {
    let uri = Uri::from_static("/read");
    // Eg. a client whose clock is 20 seconds behind.
    let timestamp = now_ms() - 20_000;
    let signed = sign(&Method::POST, &uri, timestamp, b"");
    let headers = signed.headers();
    let err = extract_request_public_key(
      &KEYED,
      &Method::POST,
      &uri,
      &headers,
      b"",
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let tolerant = KeyedAuth {
      timestamp_tolerance_ms: 30_000,
      ..KEYED
    };
    let extracted = extract_request_public_key(
      &tolerant,
      &Method::POST,
      &uri,
      &headers,
      b"",
    )
    .unwrap()
    .unwrap();
    assert_eq!(extracted, signed.public_key);
    // Still bounded.
    let timestamp = now_ms() - 40_000;
    let signed = sign(&Method::POST, &uri, timestamp, b"");
    assert!(
      extract_request_public_key(
        &tolerant,
        &Method::POST,
        &uri,
        &signed.headers(),
        b"",
      )
      .is_err()
    );
  }

  /// A request whose signature doesn't verify: it was made by
  /// another key than the request names.
  fn invalid_signature(uri: &Uri) -> HeaderMap {
    let now = now_ms();
    Signed {
      signature: sign(&Method::POST, uri, now, BODY).signature,
      ..sign(&Method::POST, uri, now, BODY)
    }
    .headers()
  }

  #[tokio::test]
  async fn test_unusable_credentials_are_rate_limited() {
    let uri = Uri::from_static("/read");
    let ip: IpAddr = "203.0.113.50".parse().unwrap();
    let invalid = invalid_signature(&uri);
    // The limiter of KeyedAuth allows 2 failures.
    for _ in 0..2 {
      let err = extract_request_authentication_rate_limited(
        &KEYED,
        ip,
        &Method::POST,
        &uri,
        &invalid,
        &unchecked_body(BODY),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
    // Now even a valid signature isn't looked at.
    let signed = sign(&Method::POST, &uri, now_ms(), BODY);
    let err = extract_request_authentication_rate_limited(
      &KEYED,
      ip,
      &Method::POST,
      &uri,
      &signed.headers(),
      &unchecked_body(BODY),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
  }

  #[tokio::test]
  async fn test_missing_credentials_are_not_rate_limited() {
    let uri = Uri::from_static("/read");
    let ip: IpAddr = "203.0.113.51".parse().unwrap();
    // Eg. a UI which isn't logged in yet.
    for _ in 0..10 {
      let err = extract_request_authentication_rate_limited(
        &KEYED,
        ip,
        &Method::POST,
        &uri,
        &HeaderMap::new(),
        &SignedRequestBody::default(),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
    let signed = sign(&Method::POST, &uri, now_ms(), BODY);
    let extracted = extract_request_authentication_rate_limited(
      &KEYED,
      ip,
      &Method::POST,
      &uri,
      &signed.headers(),
      &unchecked_body(BODY),
    )
    .await
    .ok()
    .unwrap();
    assert!(matches!(
      extracted,
      RequestAuthentication::PublicKey(key) if key == signed.public_key
    ));
  }

  /// The default for apps which don't use signing keys: a signed
  /// request is refused as such, it is not a server error (and
  /// [AuthImpl::host], which such an app may not implement, is not
  /// asked for).
  #[test]
  fn test_extract_public_key_is_not_enabled_by_default() {
    let uri = Uri::from_static("/read");
    let signed = sign(&Method::POST, &uri, now_ms(), b"");
    // TestAuth doesn't enable signing keys.
    for headers in [
      signed.headers(),
      Signed {
        timestamp: String::from("garbage"),
        ..signed.clone()
      }
      .headers(),
      signed.headers_without(API_PUBLIC_KEY_HEADER),
    ] {
      let err = extract_request_public_key(
        &TestAuth,
        &Method::POST,
        &uri,
        &headers,
        b"",
      )
      .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
      assert_eq!(
        err.error.to_string(),
        "Signing keys are not enabled"
      );
    }
  }

  #[test]
  fn test_signed_request_message_format() {
    // sha256 of the empty body.
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for uri in [
      "/auth/manage?x=1",
      // HTTP/2: the host is the one given, not the uri's.
      "https://other.example.com:9120/auth/manage?x=1",
    ] {
      let uri = Uri::from_static(uri);
      let message = signed_request_message(
        HOST,
        &Method::POST,
        &uri,
        1234,
        NONCE,
        b"",
      );
      assert_eq!(
        message,
        format!(
          "mogh-signed-request-v1\nexample.com\nPOST\n/auth/manage?x=1\n1234\n{NONCE}\n{empty}"
        )
      );
    }
    assert_eq!(
      signed_request_message(
        EXTRA_HOST,
        &Method::POST,
        &Uri::from_static("/read"),
        1234,
        NONCE,
        b"{}"
      ),
      format!(
        "mogh-signed-request-v1\n10.0.0.5:9120\nPOST\n/read\n1234\n{NONCE}\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
      )
    );
  }

  /// A signature in form: 64 bytes, of no request.
  const NO_SIGNATURE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

  /// A request with a signature (not a valid one) at `timestamp`.
  fn signed_request(
    timestamp: Option<i64>,
    body: impl Into<Body>,
  ) -> Request {
    let public_key =
      mogh_pki::EncodedKeyPair::generate(PkiKind::Signature)
        .unwrap()
        .public
        .into_inner();
    let mut request = Request::post("/read")
      .header(API_SIGNATURE_HEADER, NO_SIGNATURE)
      .header(API_PUBLIC_KEY_HEADER, public_key)
      .header(API_HOST_HEADER, HOST)
      .header(API_NONCE_HEADER, NONCE);
    if let Some(timestamp) = timestamp {
      request =
        request.header(API_TIMESTAMP_HEADER, timestamp.to_string());
    }
    request.body(body.into()).unwrap()
  }

  fn unsigned_request(body: impl Into<Body>) -> Request {
    Request::post("/read").body(body.into()).unwrap()
  }

  /// Not locked out by the limiter of [KeyedAuth].
  const READ_IP: IpAddr =
    IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 52));

  #[tokio::test]
  async fn test_read_signed_request_body() {
    // Put back for the handler.
    let (req, body) = read_signed_request_body(
      &KEYED,
      READ_IP,
      signed_request(Some(now_ms()), BODY),
    )
    .await
    .unwrap();
    assert_eq!(body.body(), BODY);
    let (_, handler_body) = read_request_body(req).await.unwrap();
    assert_eq!(handler_body, BODY);

    // The body of other requests isn't read.
    let (req, body) = read_signed_request_body(
      &KEYED,
      READ_IP,
      unsigned_request(BODY),
    )
    .await
    .unwrap();
    assert!(body.body().is_empty());
    let (_, handler_body) = read_request_body(req).await.unwrap();
    assert_eq!(handler_body, BODY);

    // Nor the tunnel of a CONNECT request, which is what its body is
    // over HTTP/2 and later (eg. a websocket).
    for version in [Version::HTTP_2, Version::HTTP_3] {
      let mut connect = signed_request(Some(now_ms()), BODY);
      *connect.method_mut() = Method::CONNECT;
      *connect.version_mut() = version;
      let (req, body) =
        read_signed_request_body(&KEYED, READ_IP, connect)
          .await
          .unwrap();
      assert!(body.body().is_empty(), "{version:?}");
      let (_, handler_body) = read_request_body(req).await.unwrap();
      assert_eq!(handler_body, BODY, "{version:?}");
    }
    // Before, a CONNECT request has no body. One sent regardless
    // would reach the handler: it is read to be verified, like any
    // other.
    for version in [Version::HTTP_10, Version::HTTP_11] {
      let mut connect = signed_request(Some(now_ms()), BODY);
      *connect.method_mut() = Method::CONNECT;
      *connect.version_mut() = version;
      let (req, body) =
        read_signed_request_body(&KEYED, READ_IP, connect)
          .await
          .unwrap();
      assert_eq!(body.body(), BODY, "{version:?}");
      let (_, handler_body) = read_request_body(req).await.unwrap();
      assert_eq!(handler_body, BODY, "{version:?}");
    }
  }

  /// A CONNECT request signed as it is over HTTP/2 (without a body)
  /// doesn't authenticate one with a body sent before HTTP/2, where
  /// the handler would get that body: as the middleware reads the
  /// request, the signature covers what the handler is given.
  #[tokio::test]
  async fn test_connect_signature_covers_the_body_read() {
    let uri = Uri::from_static("/ws");
    let connect = |version: Version, signed: &Signed| {
      let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri.clone())
        .version(version);
      for (header, value) in signed.headers().iter() {
        request = request.header(header, value);
      }
      request.body(Body::from(BODY)).unwrap()
    };
    let authenticated = |version: Version, signed: Signed| {
      let request = connect(version, &signed);
      let uri = uri.clone();
      async move {
        let (req, body) =
          read_signed_request_body(&KEYED, READ_IP, request).await?;
        extract_request_authentication(
          &KEYED,
          req.method(),
          &uri,
          req.headers(),
          &body,
        )
      }
    };
    let empty = || sign(&Method::CONNECT, &uri, now_ms(), b"");
    let with_body = || sign(&Method::CONNECT, &uri, now_ms(), BODY);
    // Over HTTP/2 the body is the tunnel: signed as empty.
    assert!(matches!(
      authenticated(Version::HTTP_2, empty()).await,
      Ok(Some(RequestAuthentication::PublicKey(_)))
    ));
    let err = authenticated(Version::HTTP_2, with_body())
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // Before, the handler gets the body: it is what was signed, or
    // the request is refused.
    for version in [Version::HTTP_10, Version::HTTP_11] {
      let err = authenticated(version, empty()).await.err().unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{version:?}");
      assert!(matches!(
        authenticated(version, with_body()).await,
        Ok(Some(RequestAuthentication::PublicKey(_)))
      ));
    }
  }

  /// The signature of a request which also carries a jwt or an api
  /// key isn't checked: passed on without its body being read.
  #[tokio::test]
  async fn test_read_signed_request_body_with_other_credentials() {
    // Whatever the timestamp.
    for timestamp in [Some(now_ms()), Some(0), None] {
      let mut with_jwt = signed_request(timestamp, BODY);
      with_jwt
        .headers_mut()
        .insert(AUTHORIZATION, HeaderValue::from_static("Bearer x"));
      let mut with_api_key = signed_request(timestamp, BODY);
      with_api_key
        .headers_mut()
        .insert(API_KEY_HEADER, HeaderValue::from_static("K"));
      for (case, req) in
        [("jwt", with_jwt), ("api key", with_api_key)]
      {
        let (req, body) =
          read_signed_request_body(&KEYED, READ_IP, req)
            .await
            .unwrap_or_else(|e| panic!("{case}: {:#}", e.error));
        assert!(body.body().is_empty(), "{case} {timestamp:?}");
        // Left for the handler.
        let (_, handler_body) = read_request_body(req).await.unwrap();
        assert_eq!(handler_body, BODY, "{case} {timestamp:?}");
      }
    }
  }

  /// A signed request which can't verify is refused before its body
  /// is read, never passed on without it: the signature would then
  /// be checked against an empty body if a later timestamp check
  /// passed, while the handler gets the unread one.
  #[tokio::test]
  async fn test_read_signed_request_body_refuses_unverifiable() {
    let tolerance = KEYED.timestamp_tolerance_ms as i64;
    // Eg. a client whose clock runs ahead, which a later check
    // would find within the tolerance.
    let early = now_ms() + tolerance + 500;
    let mut connect = signed_request(Some(early), BODY);
    *connect.method_mut() = Method::CONNECT;
    let with_header = |header: &'static str, value: &str| {
      let mut request = signed_request(Some(now_ms()), BODY);
      request
        .headers_mut()
        .insert(header, HeaderValue::from_str(value).unwrap());
      request
    };
    let without_header = |header: &'static str| {
      let mut request = signed_request(Some(now_ms()), BODY);
      request.headers_mut().remove(header).unwrap();
      request
    };
    let x25519_key =
      mogh_pki::EncodedKeyPair::generate(PkiKind::Mutual)
        .unwrap()
        .public
        .into_inner();
    let cases = [
      ("missing timestamp", signed_request(None, BODY)),
      ("early timestamp", signed_request(Some(early), BODY)),
      (
        "stale timestamp",
        signed_request(Some(now_ms() - 60_000), BODY),
      ),
      (
        "early empty body",
        signed_request(Some(early), b"".as_slice()),
      ),
      ("early connect", connect),
      (
        "garbage timestamp",
        with_header(API_TIMESTAMP_HEADER, "garbage"),
      ),
      // What a client from before 7.0 sends.
      ("missing public key", without_header(API_PUBLIC_KEY_HEADER)),
      ("missing nonce", without_header(API_NONCE_HEADER)),
      (
        "garbage public key",
        with_header(API_PUBLIC_KEY_HEADER, "nope"),
      ),
      (
        "x25519 public key",
        with_header(API_PUBLIC_KEY_HEADER, &x25519_key),
      ),
      ("short nonce", with_header(API_NONCE_HEADER, "short")),
      (
        "garbage nonce",
        with_header(API_NONCE_HEADER, "0123456789abcdef 0123456789"),
      ),
      // Signed for another server, or for none.
      ("missing host", without_header(API_HOST_HEADER)),
      (
        "another host",
        with_header(API_HOST_HEADER, "other.example.com"),
      ),
      (
        "no host",
        with_header(API_HOST_HEADER, "https://example.com"),
      ),
      // No signature in form.
      ("short signature", with_header(API_SIGNATURE_HEADER, "AAAA")),
      (
        "garbage signature",
        with_header(API_SIGNATURE_HEADER, &"!".repeat(88)),
      ),
    ];
    for (case, req) in cases {
      let err = read_signed_request_body(&KEYED, READ_IP, req)
        .await
        .err()
        .unwrap_or_else(|| panic!("{case}"));
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{case}");
    }
    // What each of them changes is what they are refused for: the
    // request they are made from is read, and so is one with a
    // header set to what it already holds.
    let (_, body) = read_signed_request_body(
      &KEYED,
      READ_IP,
      signed_request(Some(now_ms()), BODY),
    )
    .await
    .unwrap();
    assert_eq!(body.body(), BODY);
    let (_, body) = read_signed_request_body(
      &KEYED,
      READ_IP,
      with_header(API_HOST_HEADER, HOST),
    )
    .await
    .unwrap();
    assert_eq!(body.body(), BODY);

    // Without signing keys enabled, whatever the timestamp.
    for timestamp in [Some(now_ms()), None] {
      let err = read_signed_request_body(
        &TestAuth,
        READ_IP,
        signed_request(timestamp, BODY),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
      assert_eq!(
        err.error.to_string(),
        "Signing keys are not enabled"
      );
    }
  }

  #[test]
  fn test_check_request_timestamp_boundaries() {
    let now = 1_700_000_000_000;
    let tolerance = KEYED.timestamp_tolerance_ms as i64;
    let check = |timestamp: i64| {
      let mut headers = HeaderMap::new();
      headers.insert(
        API_TIMESTAMP_HEADER,
        HeaderValue::from_str(&timestamp.to_string()).unwrap(),
      );
      check_request_timestamp(&KEYED, &headers, now)
    };
    for timestamp in [now, now - tolerance, now + tolerance] {
      assert_eq!(check(timestamp).unwrap(), timestamp);
    }
    for timestamp in [now - tolerance - 1, now + tolerance + 1] {
      let err = check(timestamp).unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{timestamp}");
    }

    let refused = |timestamp: &str| {
      let mut headers = HeaderMap::new();
      headers.insert(
        API_TIMESTAMP_HEADER,
        HeaderValue::from_str(timestamp).unwrap(),
      );
      let err =
        check_request_timestamp(&KEYED, &headers, now).unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{timestamp}");
      err.error.to_string()
    };
    // A time, far from now: the difference doesn't overflow.
    for timestamp in ["0", "1", "9223372036854775807"] {
      let message = refused(timestamp);
      assert!(
        message.starts_with(SIGNED_AT_ANOTHER_TIME),
        "{timestamp}: {message}"
      );
    }
    assert_eq!(
      refused("0"),
      format!(
        "{SIGNED_AT_ANOTHER_TIME}: X-API-TIMESTAMP is {now}ms from it, 1000ms are tolerated"
      )
    );
    // No time in the one form it has: digits, as a number prints.
    for timestamp in [
      "",
      "-1",
      "+1700000000000",
      "01700000000000",
      "00",
      "1700000000000.0",
      "1.7e12",
      "0x18bcfe56800",
      " 1700000000000",
      "1700000000000 ",
      "1_700_000_000_000",
      // One more than fits.
      "9223372036854775808",
      "99999999999999999999999999999999999999",
    ] {
      assert_eq!(
        refused(timestamp),
        "X-API-TIMESTAMP is not a unix timestamp in milliseconds",
        "{timestamp:?}"
      );
    }
  }

  #[tokio::test]
  async fn test_read_signed_request_body_is_limited() {
    // axum's default body limit, 2 MB.
    let large = vec![b'a'; 2 * 1024 * 1024 + 1];
    let err = read_signed_request_body(
      &KEYED,
      READ_IP,
      signed_request(Some(now_ms()), large.clone()),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    // Not read without a signature, the handler decides.
    let (_, body) = read_signed_request_body(
      &KEYED,
      READ_IP,
      unsigned_request(large),
    )
    .await
    .unwrap();
    assert!(body.body().is_empty());
  }

  /// [read_signed_request_body] for `auth` behind the router's
  /// `route_limit`, as a handler sees it. Answers OK when the body
  /// was read, else with the status of the error.
  async fn read_behind_route_limit(
    auth: KeyedAuth,
    route_limit: axum::extract::DefaultBodyLimit,
    req: Request,
  ) -> StatusCode {
    use axum::handler::Handler as _;
    let handler = (move |req: Request| async move {
      match read_signed_request_body(&auth, READ_IP, req).await {
        Ok(_) => StatusCode::OK,
        Err(e) => e.status,
      }
    })
    .layer(route_limit);
    handler.call(req, ()).await.status()
  }

  #[tokio::test]
  async fn test_read_signed_request_body_has_its_own_limit() {
    let limited = KeyedAuth {
      signed_body_limit: 64,
      ..KEYED
    };
    let (_, body) = read_signed_request_body(
      &limited,
      READ_IP,
      signed_request(Some(now_ms()), vec![b'a'; 64]),
    )
    .await
    .unwrap();
    assert_eq!(body.body().len(), 64);
    let err = read_signed_request_body(
      &limited,
      READ_IP,
      signed_request(Some(now_ms()), vec![b'a'; 65]),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
  }

  /// A router which raises or disables its body limit (eg. for
  /// uploads) doesn't raise how much of an unauthenticated signed
  /// request is read, and one which lowers it still applies.
  #[tokio::test]
  async fn test_read_signed_request_body_limit_is_the_smaller() {
    use axum::extract::DefaultBodyLimit;
    const MB: usize = 1024 * 1024;
    let raised = KeyedAuth {
      signed_body_limit: 4 * MB,
      ..KEYED
    };
    let cases = [
      // The default limit (2 MB), whatever the router's.
      (KEYED, DefaultBodyLimit::disable(), 2 * MB, StatusCode::OK),
      (
        KEYED,
        DefaultBodyLimit::disable(),
        2 * MB + 1,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
      (
        KEYED,
        DefaultBodyLimit::max(64 * MB),
        2 * MB + 1,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
      // Raised for signed requests too.
      (raised, DefaultBodyLimit::disable(), 3 * MB, StatusCode::OK),
      (
        raised,
        DefaultBodyLimit::disable(),
        4 * MB + 1,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
      // A router's lower limit applies.
      (raised, DefaultBodyLimit::max(64), 64, StatusCode::OK),
      (
        raised,
        DefaultBodyLimit::max(64),
        65,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
      (
        KEYED,
        DefaultBodyLimit::max(64),
        65,
        StatusCode::PAYLOAD_TOO_LARGE,
      ),
    ];
    for (i, (auth, route_limit, len, expected)) in
      cases.into_iter().enumerate()
    {
      let status = read_behind_route_limit(
        auth,
        route_limit,
        signed_request(Some(now_ms()), vec![b'a'; len]),
      )
      .await;
      assert_eq!(status, expected, "case {i}: {len} bytes");
    }
    // Unsigned requests are left to the handler.
    let status = read_behind_route_limit(
      KEYED,
      DefaultBodyLimit::disable(),
      unsigned_request(vec![b'a'; 3 * MB]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Without a DefaultBodyLimit, axum's 2 MB default still applies:
    // raising only the knob doesn't get a signed body past it.
    for (len, expected) in [
      (2 * MB, StatusCode::OK),
      (2 * MB + 1, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
      let status = match read_signed_request_body(
        &raised,
        READ_IP,
        signed_request(Some(now_ms()), vec![b'a'; len]),
      )
      .await
      {
        Ok(_) => StatusCode::OK,
        Err(e) => e.status,
      };
      assert_eq!(status, expected, "no route limit: {len} bytes");
    }
  }

  /// [KeyedAuth] as [authenticate_request] makes it ([AuthImpl::new]),
  /// with a tolerance short enough for a test to wait it out. Shares
  /// the limiter of [KeyedAuth].
  struct ServedAuth(KeyedAuth);

  const SERVED_TOLERANCE_MS: u64 = 200;

  /// Long enough for a body sent a few tolerances late.
  const SERVED_BODY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(1_500);

  impl AuthImpl for ServedAuth {
    fn new() -> Self {
      ServedAuth(KeyedAuth {
        timestamp_tolerance_ms: SERVED_TOLERANCE_MS,
        signed_body_timeout: SERVED_BODY_TIMEOUT,
        ..KEYED
      })
    }
    fn host(&self) -> &str {
      self.0.host()
    }
    fn extra_hosts(&self) -> &[String] {
      self.0.extra_hosts()
    }
    fn signing_keys_enabled(&self) -> bool {
      self.0.signing_keys_enabled()
    }
    fn signing_key_timestamp_tolerance_ms(&self) -> u64 {
      self.0.signing_key_timestamp_tolerance_ms()
    }
    fn signed_request_body_timeout(&self) -> std::time::Duration {
      self.0.signed_request_body_timeout()
    }
    fn general_rate_limiter(&self) -> &mogh_rate_limit::RateLimiter {
      self.0.general_rate_limiter()
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      self.0.get_user(user_id)
    }
    fn handle_request_authentication(
      &self,
      auth: RequestAuthentication,
      ip: IpAddr,
      require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      self.0.handle_request_authentication(
        auth,
        ip,
        require_user_enabled,
        req,
      )
    }
    fn jwt_provider(&self) -> &JwtProvider {
      self.0.jwt_provider()
    }
  }

  /// Serves [authenticate_request] for [ServedAuth] in front of a
  /// `POST /read` handler which echoes the body.
  async fn serve_authenticated() -> std::net::SocketAddr {
    serve_for::<ServedAuth>().await
  }

  /// Serves the auth server of `I` in front of handlers which echo
  /// the body: `POST /read` behind [authenticate_request], as an
  /// app's api is, `POST /manage` behind the middleware of the auth
  /// management api, and `POST /stacked` behind two
  /// [authenticate_request].
  async fn serve_for<I: AuthImpl>() -> std::net::SocketAddr {
    async fn echo(body: Bytes) -> Bytes {
      body
    }
    let authenticated =
      || axum::middleware::from_fn(authenticate_request::<I, false>);
    let router = axum::Router::new()
      .route("/read", axum::routing::post(echo))
      .layer(authenticated())
      .merge(
        axum::Router::new()
          .route("/manage", axum::routing::post(echo))
          .layer(axum::middleware::from_fn(
            crate::api::manage::middleware::attach_user::<I>,
          )),
      )
      .merge(
        axum::Router::new()
          .route("/stacked", axum::routing::post(echo))
          .layer(authenticated())
          .layer(authenticated()),
      );
    serve_router(router).await
  }

  /// Serves `router` on a port of its own.
  async fn serve_router(
    router: axum::Router,
  ) -> std::net::SocketAddr {
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
      axum::serve(
        listener,
        router.into_make_service_with_connect_info::<
          std::net::SocketAddr,
        >(),
      )
      .await
      .unwrap()
    });
    address
  }

  /// Sends `POST /read` with [BODY] from `client_ip` (the loopback
  /// peer is a trusted proxy by default) signed for `host` at
  /// `timestamp`, by hand: the headers right away, the body after
  /// `body_after`, or never with `None`. Returns the response status
  /// and body.
  ///
  /// The request goes to the address the server listens on, which is
  /// what its Host header says (as behind a proxy which rewrites it):
  /// the server takes the signed host, not that one.
  async fn send_signed(
    address: std::net::SocketAddr,
    client_ip: &str,
    host: &str,
    timestamp: i64,
    body_after: Option<std::time::Duration>,
  ) -> (StatusCode, Vec<u8>) {
    let uri = Uri::from_static("/read");
    let signed = sign_for(host, &Method::POST, &uri, timestamp, BODY);
    let body = match body_after {
      Some(after) => SendBody::After(after),
      None => SendBody::Never,
    };
    send_request(address, client_ip, "/read", &signed, body).await
  }

  /// How [send_request] sends the body, once the headers are out.
  enum SendBody {
    /// All of it, after this long.
    After(std::time::Duration),
    /// A byte at a time, this long apart.
    Dripped(std::time::Duration),
    Never,
  }

  /// Sends `POST {path}` with [BODY] and the headers of `signed`
  /// from `client_ip`, by hand. Returns the response status and
  /// body.
  async fn send_request(
    address: std::net::SocketAddr,
    client_ip: &str,
    path: &str,
    signed: &Signed,
    body: SendBody,
  ) -> (StatusCode, Vec<u8>) {
    send_request_with(address, client_ip, path, signed, body, "")
      .await
  }

  /// [send_request] with more headers: `also` holds their lines,
  /// each ending in `\r\n`.
  async fn send_request_with(
    address: std::net::SocketAddr,
    client_ip: &str,
    path: &str,
    signed: &Signed,
    body: SendBody,
    also: &str,
  ) -> (StatusCode, Vec<u8>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let Signed {
      public_key,
      host,
      timestamp,
      nonce,
      signature,
    } = signed;
    let head = format!(
      "POST {path} HTTP/1.1\r\nhost: {address}\r\nconnection: close\r\ncontent-length: {}\r\nx-forwarded-for: {client_ip}\r\n{also}{API_PUBLIC_KEY_HEADER}: {public_key}\r\n{API_HOST_HEADER}: {host}\r\n{API_TIMESTAMP_HEADER}: {timestamp}\r\n{API_NONCE_HEADER}: {nonce}\r\n{API_SIGNATURE_HEADER}: {signature}\r\n\r\n",
      BODY.len()
    );
    let stream =
      tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut read, mut write) = stream.into_split();
    write.write_all(head.as_bytes()).await.unwrap();
    // The body goes out beside the answer being read: a server
    // which answers before all of it arrived closes the connection,
    // and the rest is not written anymore.
    let sending = tokio::spawn(async move {
      match body {
        SendBody::After(after) => {
          tokio::time::sleep(after).await;
          let _ = write.write_all(BODY).await;
        }
        SendBody::Dripped(apart) => {
          for byte in BODY {
            tokio::time::sleep(apart).await;
            if write.write_all(&[*byte]).await.is_err() {
              break;
            }
          }
        }
        SendBody::Never => {}
      }
      // Kept open until the answer is read.
      write
    });
    let response = async {
      // The response head, then as much body as it announces.
      let mut response = Vec::new();
      loop {
        let head_end = response
          .windows(4)
          .position(|window| window == b"\r\n\r\n");
        if let Some(head_end) = head_end {
          let head = String::from_utf8_lossy(&response[..head_end])
            .to_lowercase();
          let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map(|length| length.trim().parse::<usize>().unwrap())
            .unwrap_or_default();
          let body_start = head_end + 4;
          if response.len() >= body_start + length {
            let status = StatusCode::from_bytes(&response[9..12])
              .unwrap_or_else(|_| panic!("{head}"));
            let body =
              response[body_start..body_start + length].to_vec();
            return (status, body);
          }
        }
        let read = read.read_buf(&mut response).await.unwrap();
        assert_ne!(read, 0, "closed without a response");
      }
    };
    // Refusals don't wait for a body which never arrives.
    let response = tokio::time::timeout(
      std::time::Duration::from_secs(5),
      response,
    )
    .await
    .expect("no response, the server waited for the body");
    sending.abort();
    response
  }

  /// The timestamp is checked when the headers arrive, the signature
  /// is verified against it once the body has: the time the body takes
  /// doesn't count against the tolerance.
  #[tokio::test]
  async fn test_authenticate_request_body_arriving_late() {
    let address = serve_authenticated().await;
    let tolerance = std::time::Duration::from_millis(
      ServedAuth::new().signing_key_timestamp_tolerance_ms(),
    );
    let timestamp = now_ms();
    let (status, body) = send_signed(
      address,
      "203.0.113.53",
      HOST,
      timestamp,
      Some(tolerance * 3),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, BODY);
    // Checked now, the timestamp is stale.
    let signed = sign(
      &Method::POST,
      &Uri::from_static("/read"),
      timestamp,
      BODY,
    );
    let err = extract_request_public_key(
      &ServedAuth::new(),
      &Method::POST,
      &Uri::from_static("/read"),
      &signed.headers(),
      BODY,
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// Behind two middlewares of the auth server the body is read
  /// once, its timestamp checked once when the headers arrived: the
  /// inner middleware takes a body which arrived after the tolerance
  /// (within the body timeout) as the outer one does.
  #[tokio::test]
  async fn test_stacked_middlewares_check_the_timestamp_once() {
    let address = serve_authenticated().await;
    let tolerance = std::time::Duration::from_millis(
      ServedAuth::new().signing_key_timestamp_tolerance_ms(),
    );
    let signed = sign(
      &Method::POST,
      &Uri::from_static("/stacked"),
      now_ms(),
      BODY,
    );
    let (status, body) = send_request(
      address,
      "203.0.113.84",
      "/stacked",
      &signed,
      SendBody::After(tolerance * 3),
    )
    .await;
    assert_eq!(
      status,
      StatusCode::OK,
      "{}",
      String::from_utf8_lossy(&body)
    );
    assert_eq!(body, BODY);
    // A request signed at another time is still refused, before its
    // body is read.
    let stale = sign(
      &Method::POST,
      &Uri::from_static("/stacked"),
      now_ms() - 10_000,
      BODY,
    );
    let (status, _) = send_request(
      address,
      "203.0.113.85",
      "/stacked",
      &stale,
      SendBody::Never,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
  }

  /// Through the middleware: a request signed for a host of the
  /// server is authenticated whatever its Host header says, and one
  /// signed for another server is refused.
  #[tokio::test]
  async fn test_authenticate_request_is_bound_to_the_signed_host() {
    let address = serve_authenticated().await;
    let body = Some(std::time::Duration::ZERO);
    for host in [HOST, EXTRA_HOST] {
      let (status, echoed) =
        send_signed(address, "203.0.113.57", host, now_ms(), body)
          .await;
      assert_eq!(status, StatusCode::OK, "{host}");
      assert_eq!(echoed, BODY, "{host}");
    }
    // Another server, also the one the request actually went to
    // (what its Host header says): the server isn't configured as
    // it, and says so without waiting for the body. Such a refusal
    // costs the client none of its attempts: any number gets the
    // same answer (the limiter of KeyedAuth allows 2 failures).
    for host in
      [String::from("other.example.com"), address.to_string()]
    {
      for _ in 0..4 {
        let (status, answer) =
          send_signed(address, "203.0.113.58", &host, now_ms(), None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{host}");
        let answer = String::from_utf8(answer).unwrap();
        assert!(
          answer.contains(SIGNED_FOR_ANOTHER_HOST)
            && answer.contains(&format!("'{host}'")),
          "{host}: {answer}"
        );
      }
    }
    let (status, _) =
      send_signed(address, "203.0.113.58", HOST, now_ms(), body)
        .await;
    assert_eq!(status, StatusCode::OK);
  }

  /// A stale timestamp in the headers is refused right away, without
  /// waiting for the body.
  #[tokio::test]
  async fn test_authenticate_request_stale_timestamp_body_not_read() {
    let address = serve_authenticated().await;
    // It costs the client none of its attempts: any number gets the
    // same answer (the limiter of KeyedAuth allows 2 failures).
    for _ in 0..4 {
      let stale = now_ms() - 2 * SERVED_TOLERANCE_MS as i64;
      let (status, answer) =
        send_signed(address, "203.0.113.54", HOST, stale, None).await;
      assert_eq!(status, StatusCode::UNAUTHORIZED);
      // The client is told it is the time, not its key.
      let answer = String::from_utf8(answer).unwrap();
      assert!(answer.contains(SIGNED_AT_ANOTHER_TIME), "{answer}");
    }
    // Signed anew, it gets through.
    let (status, _) = send_signed(
      address,
      "203.0.113.54",
      HOST,
      now_ms(),
      Some(std::time::Duration::ZERO),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
  }

  /// The timestamp is checked before the body arrives, so the body
  /// has its own time to arrive in. A request doesn't get accepted
  /// however long after it was signed: its headers sent in time, its
  /// body held back.
  #[tokio::test]
  async fn test_authenticate_request_body_never_arriving() {
    let address = serve_authenticated().await;
    let started = std::time::Instant::now();
    let (status, answer) =
      send_signed(address, "203.0.113.59", HOST, now_ms(), None)
        .await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() >= SERVED_BODY_TIMEOUT);
    let answer = String::from_utf8(answer).unwrap();
    assert!(
      answer
        .contains("The body of the signed request did not arrive"),
      "{answer}"
    );
    // Nor one which arrives after that.
    let (status, _) = send_signed(
      address,
      "203.0.113.59",
      HOST,
      now_ms(),
      Some(SERVED_BODY_TIMEOUT * 2),
    )
    .await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    // One which arrives in time is not affected.
    let (status, _) = send_signed(
      address,
      "203.0.113.59",
      HOST,
      now_ms(),
      Some(std::time::Duration::ZERO),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
  }

  /// The time the body has is for all of it: one which keeps
  /// arriving, a byte at a time, is not waited for any longer than
  /// one which doesn't arrive at all.
  #[tokio::test]
  async fn test_authenticate_request_body_arriving_in_pieces() {
    let address = serve_authenticated().await;
    let send = |apart: std::time::Duration| async move {
      let uri = Uri::from_static("/read");
      let signed = sign(&Method::POST, &uri, now_ms(), BODY);
      let started = std::time::Instant::now();
      let (status, _) = send_request(
        address,
        "203.0.113.60",
        "/read",
        &signed,
        SendBody::Dripped(apart),
      )
      .await;
      (status, started.elapsed())
    };
    // All of it within the time: taken.
    let quick = SERVED_BODY_TIMEOUT / (BODY.len() as u32 * 4);
    let (status, _) = send(quick).await;
    assert_eq!(status, StatusCode::OK);
    // Every piece well within it, all of them not: refused once the
    // time is up, not when the last piece would have come.
    let slow = SERVED_BODY_TIMEOUT / 8;
    assert!(slow * BODY.len() as u32 > SERVED_BODY_TIMEOUT * 2);
    let (status, took) = send(slow).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert!(took >= SERVED_BODY_TIMEOUT, "{took:?}");
    assert!(took < SERVED_BODY_TIMEOUT * 2, "{took:?}");
  }

  /// A client the general rate limiter has locked out is refused
  /// before its body is read, even with a current timestamp.
  #[tokio::test]
  async fn test_authenticate_request_locked_out_body_not_read() {
    let address = serve_authenticated().await;
    let client_ip = "203.0.113.55";
    let uri = Uri::from_static("/read");
    let invalid = invalid_signature(&uri);
    // The limiter of KeyedAuth allows 2 failures.
    for _ in 0..2 {
      let err = extract_request_authentication_rate_limited(
        &KEYED,
        client_ip.parse().unwrap(),
        &Method::POST,
        &uri,
        &invalid,
        &unchecked_body(BODY),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) =
      send_signed(address, client_ip, HOST, now_ms(), None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // Another client gets through.
    let (status, _) = send_signed(
      address,
      "203.0.113.56",
      HOST,
      now_ms(),
      Some(std::time::Duration::ZERO),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
  }

  /// An app which refuses replays: it remembers the signatures it
  /// accepted ([AuthImpl::accept_signed_request]). Every key is one
  /// of its user's, bar the ones it is told not to know.
  struct ReplayAuth;

  static ACCEPTED: std::sync::Mutex<Vec<AcceptedSignature>> =
    std::sync::Mutex::new(Vec::new());
  /// Public keys [ReplayAuth] doesn't know.
  static UNKNOWN_KEYS: std::sync::Mutex<Vec<String>> =
    std::sync::Mutex::new(Vec::new());
  /// Public keys of [ReplayAuth]'s disabled user.
  static DISABLED_KEYS: std::sync::Mutex<Vec<String>> =
    std::sync::Mutex::new(Vec::new());
  /// The requests which got to a handler of [serve_replay].
  static HANDLED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

  struct ReplayUser {
    enabled: bool,
  }

  impl AuthUserImpl for ReplayUser {
    fn id(&self) -> &str {
      if self.enabled {
        "replay-user"
      } else {
        "disabled-user"
      }
    }
    fn username(&self) -> &str {
      "replay"
    }
    fn is_enabled(&self) -> bool {
      self.enabled
    }
  }

  impl AuthImpl for ReplayAuth {
    fn new() -> Self {
      ReplayAuth
    }
    fn host(&self) -> &str {
      KEYED.host()
    }
    fn signing_keys_enabled(&self) -> bool {
      true
    }
    /// Of its own: three refusals lock a client out.
    fn general_rate_limiter(&self) -> &mogh_rate_limit::RateLimiter {
      static LIMITER: std::sync::LazyLock<
        std::sync::Arc<mogh_rate_limit::RateLimiter>,
      > = std::sync::LazyLock::new(|| {
        mogh_rate_limit::RateLimiter::new(
          false,
          3,
          std::time::Duration::from_secs(60),
        )
      });
      &LIMITER
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      Box::pin(async move {
        Ok(Box::new(ReplayUser {
          enabled: user_id != "disabled-user",
        }) as crate::user::BoxAuthUser)
      })
    }
    fn get_signing_key(
      &self,
      public_key: String,
    ) -> DynFuture<mogh_error::Result<crate::api_key::BoxAuthApiKey>>
    {
      Box::pin(async move {
        if UNKNOWN_KEYS.lock().unwrap().contains(&public_key) {
          return Err(
            anyhow!("Invalid client credentials")
              .status_code(StatusCode::UNAUTHORIZED),
          );
        }
        let disabled =
          DISABLED_KEYS.lock().unwrap().contains(&public_key);
        let user_id = if disabled {
          "disabled-user"
        } else {
          "replay-user"
        };
        Ok(Box::new(crate::api_key::AuthApiKey {
          user_id: String::from(user_id),
          cidr_whitelist: Vec::new(),
        }) as crate::api_key::BoxAuthApiKey)
      })
    }
    /// As an app does: the signer is looked up.
    fn handle_request_authentication(
      &self,
      auth: RequestAuthentication,
      ip: IpAddr,
      _require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      Box::pin(async move {
        get_user_from_request_authentication(&ReplayAuth, auth, ip)
          .await?;
        Ok(req)
      })
    }
    fn accept_signed_request(
      &self,
      accepted: AcceptedSignature,
    ) -> DynFuture<mogh_error::Result<()>> {
      Box::pin(async move {
        let mut seen = ACCEPTED.lock().unwrap();
        if seen
          .iter()
          .any(|seen| seen.signature == accepted.signature)
        {
          return Err(
            anyhow!("Invalid client credentials")
              .status_code(StatusCode::UNAUTHORIZED),
          );
        }
        seen.push(accepted);
        Ok(())
      })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      TestAuth.jwt_provider()
    }
  }

  /// Serves [ReplayAuth] in front of handlers which echo the body
  /// and count themselves ([HANDLED]): `POST /read` as an app's api,
  /// `POST /manage` as the auth management api, and `POST /stacked`
  /// behind two middlewares of the auth server.
  async fn serve_replay() -> std::net::SocketAddr {
    async fn handle(body: Bytes) -> Bytes {
      HANDLED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
      body
    }
    let authenticated = || {
      axum::middleware::from_fn(
        authenticate_request::<ReplayAuth, false>,
      )
    };
    let router = axum::Router::new()
      .route("/read", axum::routing::post(handle))
      .layer(authenticated())
      .merge(
        axum::Router::new()
          .route("/manage", axum::routing::post(handle))
          .layer(axum::middleware::from_fn(
            crate::api::manage::middleware::attach_user::<ReplayAuth>,
          )),
      )
      .merge(
        axum::Router::new()
          .route("/stacked", axum::routing::post(handle))
          .layer(authenticated())
          .layer(authenticated()),
      );
    serve_router(router).await
  }

  /// A signed request which authenticated is handed to the app right
  /// before it is handled, once, with the headers it was signed
  /// with: on an app's own api, on the auth management api, and
  /// where two middlewares sit on a route. An app which remembers
  /// them refuses the second copy of a request, which is then not
  /// handled, and what it refuses counts against the client. What
  /// doesn't authenticate never gets to the app.
  #[tokio::test]
  async fn test_accept_signed_request_refuses_a_replay_on_every_api()
  {
    use std::sync::atomic::Ordering::SeqCst;

    let address = serve_replay().await;
    let now = std::time::Duration::ZERO;
    let accepted = || ACCEPTED.lock().unwrap().len();
    let send = |client_ip: &'static str,
                path: &'static str,
                signed: Signed| async move {
      send_request(
        address,
        client_ip,
        path,
        &signed,
        SendBody::After(now),
      )
      .await
      .0
    };
    let signed_for = |path: &'static str| {
      sign(&Method::POST, &Uri::from_static(path), now_ms(), BODY)
    };

    for (path, client_ip) in [
      ("/read", "203.0.113.61"),
      ("/manage", "203.0.113.62"),
      ("/stacked", "203.0.113.63"),
    ] {
      let signed = signed_for(path);
      let before = (accepted(), HANDLED.load(SeqCst));
      let status = send(client_ip, path, signed.clone()).await;
      assert_eq!(status, StatusCode::OK, "{path}");
      // The app was asked once, and given what the request was
      // signed with. Then the request was handled.
      assert_eq!(accepted(), before.0 + 1, "{path}");
      assert_eq!(HANDLED.load(SeqCst), before.1 + 1, "{path}");
      assert_eq!(
        ACCEPTED.lock().unwrap().last().cloned(),
        Some(AcceptedSignature {
          public_key: signed.public_key.clone(),
          host: signed.host.clone(),
          timestamp: signed.timestamp.parse().unwrap(),
          nonce: signed.nonce.clone(),
          signature: signed.signature.clone(),
        }),
        "{path}"
      );
      // The same request once more: refused, and not handled.
      let status = send(client_ip, path, signed).await;
      assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
      assert_eq!(accepted(), before.0 + 1, "{path}");
      assert_eq!(HANDLED.load(SeqCst), before.1 + 1, "{path}");
    }

    // What doesn't authenticate never gets to the app (which would
    // remember a signature for nothing, or instead of a real one).
    let before = (accepted(), HANDLED.load(SeqCst));
    // A signature which doesn't verify.
    let forged = Signed {
      signature: signed_for("/read").signature,
      ..signed_for("/read")
    };
    let status = send("203.0.113.64", "/read", forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A key the app doesn't know, on either api.
    for (path, client_ip) in
      [("/read", "203.0.113.65"), ("/manage", "203.0.113.66")]
    {
      let signed = signed_for(path);
      UNKNOWN_KEYS.lock().unwrap().push(signed.public_key.clone());
      let status = send(client_ip, path, signed).await;
      assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }
    // A disabled user, whom the management api refuses.
    let signed = signed_for("/manage");
    DISABLED_KEYS
      .lock()
      .unwrap()
      .push(signed.public_key.clone());
    let status = send("203.0.113.67", "/manage", signed).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!((accepted(), HANDLED.load(SeqCst)), before);

    // A request which authenticates with other credentials is
    // handled, and its signature headers (which nobody verified)
    // are not the app's to remember.
    let jwt =
      TestAuth.jwt_provider().encode_sub("replay-user").unwrap();
    for path in ["/read", "/manage"] {
      let (status, _) = send_request_with(
        address,
        "203.0.113.68",
        path,
        &signed_for(path),
        SendBody::After(now),
        &format!("authorization: Bearer {}\r\n", jwt.jwt),
      )
      .await;
      assert_eq!(status, StatusCode::OK, "{path}");
    }
    assert_eq!(accepted(), before.0);
    assert_eq!(HANDLED.load(SeqCst), before.1 + 2);

    // Refusals count against the client: two replays and a forgery
    // lock it out, also with a request signed anew.
    let client_ip = "203.0.113.69";
    let signed = signed_for("/read");
    assert_eq!(
      send(client_ip, "/read", signed.clone()).await,
      StatusCode::OK
    );
    for _ in 0..2 {
      assert_eq!(
        send(client_ip, "/read", signed.clone()).await,
        StatusCode::UNAUTHORIZED
      );
    }
    let forged = Signed {
      signature: signed_for("/read").signature,
      ..signed_for("/read")
    };
    assert_eq!(
      send(client_ip, "/read", forged).await,
      StatusCode::UNAUTHORIZED
    );
    assert_eq!(
      send(client_ip, "/read", signed_for("/read")).await,
      StatusCode::TOO_MANY_REQUESTS
    );
    // Another client is not.
    assert_eq!(
      send("203.0.113.70", "/read", signed_for("/read")).await,
      StatusCode::OK
    );
  }

  /// A middleware of an app's own built on [authenticate_user], with
  /// a policy of its own: disabled users are refused everything (as
  /// the supporter api does).
  async fn refuse_disabled_users<I: AuthImpl>(
    RequestIp(ip): RequestIp,
    OriginalUri(uri): OriginalUri,
    req: Request,
    next: Next,
  ) -> mogh_error::Result<Response> {
    let auth = I::new();
    let authenticated =
      authenticate_user(&auth, ip, &uri, req).await?;
    if !authenticated.user.is_enabled() {
      return Err(
        anyhow!("User is not enabled")
          .status_code(StatusCode::FORBIDDEN),
      );
    }
    let req = authenticated.finish(&auth).await?;
    Ok(next.run(req).await)
  }

  /// [ReplayAuth], remembering the signatures it accepted apart from
  /// it ([OWN_ACCEPTED]), so the tests of each don't see the other's.
  struct OwnPolicyAuth;

  static OWN_ACCEPTED: std::sync::Mutex<Vec<AcceptedSignature>> =
    std::sync::Mutex::new(Vec::new());

  impl AuthImpl for OwnPolicyAuth {
    fn new() -> Self {
      OwnPolicyAuth
    }
    fn host(&self) -> &str {
      KEYED.host()
    }
    fn signing_keys_enabled(&self) -> bool {
      true
    }
    fn general_rate_limiter(&self) -> &mogh_rate_limit::RateLimiter {
      ReplayAuth.general_rate_limiter()
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      ReplayAuth.get_user(user_id)
    }
    fn get_signing_key(
      &self,
      public_key: String,
    ) -> DynFuture<mogh_error::Result<crate::api_key::BoxAuthApiKey>>
    {
      ReplayAuth.get_signing_key(public_key)
    }
    fn handle_request_authentication(
      &self,
      auth: RequestAuthentication,
      ip: IpAddr,
      require_user_enabled: bool,
      req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      ReplayAuth.handle_request_authentication(
        auth,
        ip,
        require_user_enabled,
        req,
      )
    }
    fn accept_signed_request(
      &self,
      accepted: AcceptedSignature,
    ) -> DynFuture<mogh_error::Result<()>> {
      Box::pin(async move {
        let mut seen = OWN_ACCEPTED.lock().unwrap();
        if seen
          .iter()
          .any(|seen| seen.signature == accepted.signature)
        {
          return Err(
            anyhow!("Invalid client credentials")
              .status_code(StatusCode::UNAUTHORIZED),
          );
        }
        seen.push(accepted);
        Ok(())
      })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      TestAuth.jwt_provider()
    }
  }

  #[test]
  fn test_format_window() {
    assert_eq!(format_window(900), "15 minutes");
    assert_eq!(format_window(90), "90 seconds");
    assert_eq!(format_window(1), "1 seconds");
  }

  /// The error of a request refused for an old login, as clients
  /// recognize it.
  fn assert_reauthentication_required(
    res: mogh_error::Result<()>,
    what: &str,
  ) {
    let err = res.expect_err(what);
    assert_eq!(err.status, StatusCode::FORBIDDEN, "{what}");
    assert!(
      format!("{:#}", err.error)
        .starts_with(REAUTHENTICATION_REQUIRED),
      "{what}: {:#}",
      err.error
    );
  }

  /// A session needs a login within the window (with the clock skew
  /// of the token validation), a credential without a login passes,
  /// and `0` turns the window off.
  #[test]
  fn test_check_login_age() {
    const NOW: u64 = 1_800_000_000;
    const WINDOW: u64 = 15 * 60;
    const LEEWAY: u64 = 10;
    for at in [NOW, NOW - 1, NOW - WINDOW, NOW + 1, NOW + LEEWAY] {
      check_login_age(WINDOW, LEEWAY, Some(at), NOW)
        .unwrap_or_else(|_| panic!("refused a login at {at}"));
    }
    for at in [NOW - WINDOW - 1, 0, NOW + LEEWAY + 1, u64::MAX] {
      assert_reauthentication_required(
        check_login_age(WINDOW, LEEWAY, Some(at), NOW),
        &format!("login at {at}"),
      );
    }
    // An api key or signing key.
    check_login_age(WINDOW, LEEWAY, None, NOW).unwrap();
    // Disabled.
    for at in [Some(0), Some(u64::MAX), None] {
      check_login_age(0, LEEWAY, at, NOW).unwrap();
    }
  }

  /// [require_recent_login] holds a session to the app's window,
  /// with its token validation's leeway.
  #[test]
  fn test_require_recent_login() {
    let now = unix_timestamp_ms() / 1_000;
    // The default window: 15 minutes.
    let window = TestAuth.reauthentication_window_secs();
    assert_eq!(window, 15 * 60);
    require_recent_login(&TestAuth, Some(now)).unwrap();
    require_recent_login(&TestAuth, Some(now - window + 60)).unwrap();
    require_recent_login(&TestAuth, None).unwrap();
    let err =
      require_recent_login(&TestAuth, Some(now - window - 60))
        .unwrap_err();
    assert_reauthentication_required(Err(err), "an old login");
    assert_eq!(
      format!(
        "{:#}",
        require_recent_login(&TestAuth, Some(0)).unwrap_err().error
      ),
      format!(
        "{REAUTHENTICATION_REQUIRED}: log in again to continue, this needs a login within the last 15 minutes"
      )
    );
  }

  /// An app api authenticating its own session tokens and two api
  /// keys, the second of which its hook attaches a login of its own
  /// to ([OWN_LOGIN_KEY]).
  struct WriteAuth;

  const WRITE_KEY: &str = "K_write_K";
  const OWN_LOGIN_KEY: &str = "K_own_login_K";
  const WRITE_SECRET: &str = "S_write_S";

  impl AuthImpl for WriteAuth {
    fn new() -> Self {
      WriteAuth
    }
    fn get_user(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<crate::user::BoxAuthUser>> {
      TestAuth.get_user(user_id)
    }
    fn handle_request_authentication(
      &self,
      auth: RequestAuthentication,
      _ip: IpAddr,
      _require_user_enabled: bool,
      mut req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      let authenticated = match auth {
        RequestAuthentication::Jwt(jwt) => {
          get_jwt_user_id(self, &jwt).map(|_| ())
        }
        RequestAuthentication::ApiKey { key, secret }
          if secret == WRITE_SECRET =>
        {
          match key.as_str() {
            WRITE_KEY => Ok(()),
            OWN_LOGIN_KEY => {
              // A login the app knows of: long ago.
              req.extensions_mut().insert(AuthenticatedAt(Some(1)));
              Ok(())
            }
            _ => Err(invalid_client_credentials()),
          }
        }
        _ => Err(invalid_client_credentials()),
      };
      Box::pin(async move { authenticated.map(|()| req) })
    }
    fn jwt_provider(&self) -> &JwtProvider {
      TestAuth.jwt_provider()
    }
  }

  /// An app's handler behind [authenticate_request] gets when the
  /// user logged in, and [require_recent_login] refuses a session
  /// whose login is older than the window, while a fresh session and
  /// an api key (no login) pass.
  #[tokio::test]
  async fn test_app_writes_can_require_a_recent_login() {
    async fn write(
      AuthenticatedAt(authenticated_at): AuthenticatedAt,
    ) -> mogh_error::Result<String> {
      require_recent_login(&WriteAuth, authenticated_at)?;
      Ok(format!("written {authenticated_at:?}"))
    }
    let router = axum::Router::new()
      .route("/write", axum::routing::post(write))
      .layer(axum::middleware::from_fn(
        authenticate_request::<WriteAuth, true>,
      ));
    let address = serve_router(router).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/write");
    let send = |request: reqwest::RequestBuilder| async move {
      let response = request.send().await.unwrap();
      let status = response.status();
      (status, response.text().await.unwrap())
    };
    let provider = WriteAuth.jwt_provider();
    let now = unix_timestamp_ms() / 1_000;

    // A fresh session.
    let jwt = provider.encode_sub("user").unwrap().jwt;
    let login =
      provider.decode_claims(&jwt).unwrap().authenticated_at();
    let (status, body) =
      send(client.post(&url).bearer_auth(&jwt)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, format!("written Some({login})"));

    // A session whose login is older than the window, though its
    // token is new (eg. exchanged from an old provider token).
    let stale = now - WriteAuth.reauthentication_window_secs() - 60;
    let jwt = provider
      .encode_sub_with_auth_time("user", stale)
      .unwrap()
      .jwt;
    let (status, body) =
      send(client.post(&url).bearer_auth(&jwt)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let error: serde_json::Value =
      serde_json::from_str(&body).unwrap();
    assert!(
      error["error"]
        .as_str()
        .unwrap()
        .starts_with(REAUTHENTICATION_REQUIRED),
      "{body}"
    );

    // An api key has no login: it passes.
    let (status, body) = send(
      client
        .post(&url)
        .header(API_KEY_HEADER, WRITE_KEY)
        .header("x-api-secret", WRITE_SECRET),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, "written None");

    // The login a hook attached is kept.
    let (status, body) = send(
      client
        .post(&url)
        .header(API_KEY_HEADER, OWN_LOGIN_KEY)
        .header("x-api-secret", WRITE_SECRET),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
  }

  /// [authenticate_user] and [Authenticated::finish] are the auth
  /// management api's sequence for a middleware of an app's own: the
  /// signer authenticates, the middleware's policy refuses what it
  /// refuses before the app is handed the signature, and the handler
  /// extracts the user and when they logged in.
  #[tokio::test]
  async fn test_authenticate_user_for_a_middleware_of_its_own() {
    async fn whoami(
      UserExtractor(user): UserExtractor,
      AuthenticatedAt(at): AuthenticatedAt,
    ) -> String {
      format!("{} {at:?}", user.id())
    }
    let router = axum::Router::new()
      .route("/own", axum::routing::post(whoami))
      .layer(axum::middleware::from_fn(
        refuse_disabled_users::<OwnPolicyAuth>,
      ));
    let address = serve_router(router).await;
    let now = std::time::Duration::ZERO;
    let accepted = || OWN_ACCEPTED.lock().unwrap().len();
    let signed = || {
      sign(&Method::POST, &Uri::from_static("/own"), now_ms(), BODY)
    };

    // An enabled user's signed request: handled, no login.
    let request = signed();
    let (status, body) = send_request(
      address,
      "203.0.113.81",
      "/own",
      &request,
      SendBody::After(now),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8(body).unwrap(), "replay-user None");
    assert_eq!(accepted(), 1);
    // Its replay is refused by the app.
    let (status, _) = send_request(
      address,
      "203.0.113.81",
      "/own",
      &request,
      SendBody::After(now),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A disabled user is refused by the policy, before the app
    // remembers the signature.
    let request = signed();
    DISABLED_KEYS
      .lock()
      .unwrap()
      .push(request.public_key.clone());
    let (status, _) = send_request(
      address,
      "203.0.113.82",
      "/own",
      &request,
      SendBody::After(now),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(accepted(), 1);

    // A session token: the handler gets when the user logged in.
    let jwt = TestAuth
      .jwt_provider()
      .encode_sub("replay-user")
      .unwrap()
      .jwt;
    let iat =
      TestAuth.jwt_provider().decode_claims(&jwt).unwrap().iat;
    let (status, body) = send_request_with(
      address,
      "203.0.113.83",
      "/own",
      &signed(),
      SendBody::After(now),
      &format!("authorization: Bearer {jwt}\r\n"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
      String::from_utf8(body).unwrap(),
      format!("replay-user Some({iat})")
    );
    assert_eq!(accepted(), 1);
  }
}
