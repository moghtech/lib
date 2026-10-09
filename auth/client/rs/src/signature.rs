//! Authenticating requests with a signing key: instead of sending a
//! secret, the client signs every request with its private key (an
//! Ed25519 key), and the server recognizes it by the public key stored
//! with the signing key (`CreateSigningKey`).
//!
//! A signed request carries five headers (`signed_request_headers`):
//! - [API_PUBLIC_KEY_HEADER]: the public key of the signing key.
//! - [API_HOST_HEADER]: the host of the server the request is signed
//!   for.
//! - [API_TIMESTAMP_HEADER]: the time the signature was made at.
//! - [API_NONCE_HEADER]: a random value, new for every request.
//! - [API_SIGNATURE_HEADER]: the signature over
//!   [SignedRequest::message].
//!
//! The signature covers the host of the server, the request method,
//! path and query, timestamp, nonce and body. It is verified with the
//! public key alone: the server holds nothing which could sign for a
//! client. Within the timestamp tolerance of the server (1 second by
//! default) the headers only authenticate this exact request again,
//! never one with another method, path, query or body, and never at
//! another server: one only accepts a request signed for a host of its
//! own. The other headers of a request (its content type, cookies)
//! are not covered, nor is the scheme of the address.
//!
//! Sign the host as the url the request is sent to has it
//! ([url_host], the server must know itself by it), the method and
//! the body exactly as they are sent, and the path and query as the
//! server receives them (percent encoded, without the scheme and
//! host, including any prefix a proxy in front of the server doesn't
//! strip).
//!
//! So the headers are generated per request, right before it is sent,
//! over its exact path, query and body: unlike a jwt or an api key,
//! they can't be set once as default headers of a client.
//! `request::signed_post` (and `request::signed_manage` for the auth
//! management api) sends a JSON `POST` so, and sends it once more,
//! signed anew, when the server refused its timestamp
//! ([SIGNED_AT_ANOTHER_TIME]). By hand it goes like this:
//!
//! ```ignore
//! let url = reqwest::Url::parse(&format!("{address}/read/GetVersion"))?;
//! let body = serde_json::to_vec(&GetVersion {})?;
//! let mut request = reqwest
//!   .post(url.clone())
//!   .header("content-type", "application/json")
//!   .body(body.clone());
//! for (header, value) in
//!   signed_request_headers_for_url(&private_key, "POST", &url, &body)?
//! {
//!   request = request.header(header, value);
//! }
//! ```
//!
//! `signed_request_headers_for_url` signs the host, path and query of
//! the url the request is sent to. Where a proxy in front of the
//! server changes the path (it strips a prefix), sign the one the
//! server receives with `signed_request_headers`.
//!
//! These take the private key as text, and parse it for every
//! request. A client signing more than once parses it once with
//! `signing_keys` and signs with the `_with_keys` functions
//! (`signed_request_headers_with_keys`,
//! `signed_request_headers_for_url_with_keys`), which the others
//! call: the one implementation of the headers, for app clients to
//! sign with rather than building the headers themselves.

use anyhow::Context as _;
use sha2::Digest as _;

pub const API_SIGNATURE_HEADER: &str = "x-api-signature";
pub const API_TIMESTAMP_HEADER: &str = "x-api-timestamp";
pub const API_PUBLIC_KEY_HEADER: &str = "x-api-public-key";
/// Names the host the request is signed for ([SignedRequest::host]).
/// The server verifies the signature for it, once it is one of the
/// hosts the server is configured with: the address the client
/// reaches the server at tells nothing a signature could rest on
/// (whoever passes a request on to another server sets that too).
pub const API_HOST_HEADER: &str = "x-api-host";
pub const API_NONCE_HEADER: &str = "x-api-nonce";

/// The first line of every [SignedRequest::message]. A signature made
/// with the same key for anything else never verifies as a request,
/// and a later format gets another version.
pub const SIGNED_REQUEST_VERSION: &str = "mogh-signed-request-v1";

/// How the error starts (`401`) which a server answers a request
/// with that is signed for a host ([API_HOST_HEADER]) it is not
/// configured with. The host follows. It is the server which has to
/// change (the address the client uses belongs in its hosts), or the
/// address of the client: no other key would get through, so clients
/// can tell this from a key the server doesn't know.
pub const SIGNED_FOR_ANOTHER_HOST: &str =
  "Signed for a host this server is not configured as";

/// How the error starts (`401`) which a server answers a request
/// with whose [API_TIMESTAMP_HEADER] is further from its clock than
/// it tolerates. The clocks have to agree (or the request took too
/// long to arrive): no other key would get through, and a request
/// signed anew may.
pub const SIGNED_AT_ANOTHER_TIME: &str =
  "Signed at a time too far from the clock of this server";

/// The sha256 of a request body as the signature covers it: lowercase
/// hex. An empty body is the sha256 of empty input.
pub fn body_sha256(body: &[u8]) -> String {
  use std::fmt::Write as _;
  let digest = sha2::Sha256::digest(body);
  let mut hex = String::with_capacity(digest.len() * 2);
  for byte in digest.iter() {
    // Writing to a String can't fail.
    let _ = write!(hex, "{byte:02x}");
  }
  hex
}

/// What a request signature covers. Every field is signed as it is
/// given, and has one form the server accepts ([Self::check]).
#[derive(Debug, Clone, Copy)]
pub struct SignedRequest<'a> {
  /// The host of the server the request is for ([url_host]): its
  /// lowercase `host[:port]`, sent in [API_HOST_HEADER].
  pub host: &'a str,
  /// The request method exactly as it is sent (`POST`): methods are
  /// case sensitive.
  pub method: &'a str,
  /// The path and query the server receives (eg. `/read?x=1`),
  /// never the scheme and host.
  pub path_and_query: &'a str,
  /// Unix milliseconds, sent in [API_TIMESTAMP_HEADER].
  pub timestamp: i64,
  /// A random value which makes every signature unique, sent in
  /// [API_NONCE_HEADER] (`random_nonce`, see [valid_nonce]).
  pub nonce: &'a str,
  /// The request body exactly as sent, empty for none
  /// ([body_sha256]), and for a CONNECT request over HTTP/2 or later
  /// (eg. a websocket), whose body is the tunnel.
  pub body: &'a [u8],
}

impl SignedRequest<'_> {
  /// The message which is signed: one line each, joined by `\n`
  /// without a trailing one.
  ///
  /// ```text
  /// mogh-signed-request-v1
  /// {host}
  /// {method}
  /// {path_and_query}
  /// {timestamp}
  /// {nonce}
  /// {sha256(body) hex}
  /// ```
  pub fn message(&self) -> String {
    format!(
      "{SIGNED_REQUEST_VERSION}\n{}\n{}\n{}\n{}\n{}\n{}",
      self.host,
      self.method,
      self.path_and_query,
      self.timestamp,
      self.nonce,
      body_sha256(self.body),
    )
  }

  /// Whether the request is one a server could accept: a host as
  /// [url_host] gives it ([valid_host]), a method as one is sent (a
  /// token: letters, digits and some punctuation), a path and query
  /// as a server receives them (visible ASCII, starting with `/`,
  /// without a fragment, which is never sent), and a [valid_nonce].
  /// So every field stays on its own line of the message, and what a
  /// client signs by mistake (a url or a key for the host) is an
  /// error here rather than a `401`.
  pub fn check(&self) -> anyhow::Result<()> {
    if !valid_host(self.host) {
      anyhow::bail!(
        "Invalid host to sign the request for, expected the lowercase host[:port] of the server address (eg. example.com)"
      );
    }
    // RFC 9110 5.6.2.
    let token = |value: &str| {
      !value.is_empty()
        && value.bytes().all(|byte| {
          byte.is_ascii_alphanumeric()
            || b"!#$%&'*+-.^_`|~".contains(&byte)
        })
    };
    if !token(self.method) {
      anyhow::bail!(
        "Invalid method to sign the request for, expected it as it is sent (eg. POST)"
      );
    }
    if !self.path_and_query.starts_with('/')
      || !self
        .path_and_query
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'#')
    {
      anyhow::bail!(
        "Invalid path to sign the request for, expected the path and query the server receives (eg. /read?x=1)"
      );
    }
    if !valid_nonce(self.nonce) {
      anyhow::bail!(
        "Invalid nonce, expected 16 to 64 characters of A-Z a-z 0-9 - _"
      );
    }
    Ok(())
  }
}

/// The host a request to `url` (an `http(s)` or `ws(s)` url) is
/// signed for: its lowercase `host[:port]`, without the port when it
/// is the default of the scheme.
///
/// `https://Example.com/auth` is `example.com`,
/// `http://10.0.0.5:9120` is `10.0.0.5:9120`, and `http://[::1]:80`
/// is `[::1]`.
///
/// The server derives the hosts it accepts signatures for the same
/// way, from the origins it is configured with. The host is read by
/// the url standard, which spells some anew: a name outside of ASCII
/// in its punycode form, an IPv4 or IPv6 address in its usual one.
///
/// A url with credentials (`https://user:password@example.com`) is
/// an error, which doesn't repeat them: a client sends those as
/// `Authorization`, which a server takes over the signature.
pub fn url_host(url: &str) -> anyhow::Result<String> {
  let url = reqwest::Url::parse(url.trim())
    .context("Invalid url, expected eg. https://example.com")?;
  url_origin_host(&url)
}

/// [url_host] of a parsed url.
pub(crate) fn url_origin_host(
  url: &reqwest::Url,
) -> anyhow::Result<String> {
  // Of any other scheme the host is not read as a host name (its
  // case, an ip address), and no port is the default.
  if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
    anyhow::bail!(
      "The url is not an http(s) url, expected eg. https://example.com"
    );
  }
  if !url.username().is_empty() || url.password().is_some() {
    anyhow::bail!(
      "The url carries credentials (user:password@), expected eg. https://example.com"
    );
  }
  let host = url
    .host_str()
    .filter(|host| !host.is_empty())
    .context("The url has no host, expected eg. https://example.com")?
    .to_ascii_lowercase();
  let host = match url.port() {
    Some(port) => format!("{host}:{port}"),
    None => host,
  };
  // The url standard takes more for a host than a name or address
  // has (`*.example.com`, a list given as one address): nothing a
  // request is sent to.
  if !valid_host(&host) {
    anyhow::bail!(
      "The host of the url is not a host name or ip address, expected eg. https://example.com"
    );
  }
  Ok(host)
}

/// The longest host: a name of 253 characters, a trailing dot and a
/// port.
const MAX_HOST_LEN: usize = 260;

/// Whether `host` has the form a request is signed for and
/// [API_HOST_HEADER] names: what [url_host] makes of an address, a
/// lowercase `host[:port]`. That is letters, digits, `.`, `-` and
/// `_`, and the `[`, `]` and `:` of an IPv6 address and a port.
pub fn valid_host(host: &str) -> bool {
  (1..=MAX_HOST_LEN).contains(&host.len())
    && host.bytes().all(|byte| {
      byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']')
    })
}

/// Whether the server accepts `nonce`: 16 to 64 characters of
/// `A-Z`, `a-z`, `0-9`, `-` and `_` (hex and base64url both fit).
pub fn valid_nonce(nonce: &str) -> bool {
  (16..=64).contains(&nonce.len())
    && nonce.bytes().all(|byte| {
      byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
    })
}

/// A nonce for [SignedRequest]: 16 random bytes read from the OS
/// random source, as 32 hex characters.
#[cfg(feature = "pki")]
pub fn random_nonce() -> anyhow::Result<String> {
  use rand::TryRng as _;
  use std::fmt::Write as _;

  let mut bytes = [0u8; 16];
  rand::rngs::SysRng
    .try_fill_bytes(&mut bytes)
    .context("Failed to read from the OS random source")?;
  let mut nonce = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    // Writing to a String can't fail.
    let _ = write!(nonce, "{byte:02x}");
  }
  Ok(nonce)
}

/// The signature of `request`: 64 bytes, base64. It is sent in
/// [API_SIGNATURE_HEADER], next to the public key of `private_key`
/// ([API_PUBLIC_KEY_HEADER]) and the host, timestamp and nonce of
/// the request. [signed_request_headers] makes all five.
///
/// - `private_key`: the private key of the signing key, an Ed25519
///   key (pkcs8 base64 or pem).
///
/// A request no server could accept ([SignedRequest::check]) is an
/// error.
#[cfg(feature = "pki")]
pub fn sign_request(
  private_key: &str,
  request: &SignedRequest<'_>,
) -> anyhow::Result<String> {
  request.check()?;
  let keys = signing_keys(private_key)?;
  mogh_pki::signature::sign(
    &keys.private,
    request.message().as_bytes(),
  )
  .context("Failed to sign the request")
}

/// The key pair of the private key of a signing key (an Ed25519 key,
/// pkcs8 base64 or pem), to sign requests with
/// ([signed_request_headers_with_keys]). A client parses it once
/// and keeps the pair, rather than giving the private key to
/// [signed_request_headers] for every request, which parses it and
/// derives the public key each time.
///
/// The path of a key file (or a `file:` spec) is refused: it is no
/// key, and up to 32 bytes of it would be taken as the bytes of a raw
/// key, one anybody can derive from the path. The error doesn't
/// repeat the key.
#[cfg(feature = "pki")]
pub fn signing_keys(
  private_key: &str,
) -> anyhow::Result<mogh_pki::EncodedKeyPair> {
  // Short enough, a path would be taken for the bytes of a raw key
  // and sign as a key nobody meant, which anybody can derive.
  if mogh_pki::looks_like_a_path(private_key) {
    anyhow::bail!(
      "Invalid private key: it looks like the path of a key file (or a `file:` spec), not the key in the file. A raw key which reads like a path is not taken: give the key as pkcs8 (base64 der or pem)"
    );
  }
  mogh_pki::EncodedKeyPair::from_private_key(
    mogh_pki::PkiKind::Signature,
    private_key,
  )
  .context("Invalid private key")
}

/// [signed_request_headers] for a `method` request with `body` sent
/// to `url`: signed for the host of the url ([url_host]) and its path
/// and query, as they are sent. So what is signed can't differ from
/// where the request goes.
///
/// It is the path the server has to receive: where a proxy in front
/// of it changes the path (it strips a prefix), sign the one the
/// server receives with [signed_request_headers] instead.
///
/// [signed_request_headers_for_url_with_keys] takes the key pair
/// parsed once ([signing_keys]).
#[cfg(feature = "pki")]
pub fn signed_request_headers_for_url(
  private_key: &str,
  method: &str,
  url: &reqwest::Url,
  body: &[u8],
) -> anyhow::Result<[(&'static str, String); 5]> {
  signed_request_headers_for_url_with_keys(
    &signing_keys(private_key)?,
    method,
    url,
    body,
  )
}

/// [signed_request_headers_for_url] with the key pair of the private
/// key, parsed once ([signing_keys]).
#[cfg(feature = "pki")]
pub fn signed_request_headers_for_url_with_keys(
  keys: &mogh_pki::EncodedKeyPair,
  method: &str,
  url: &reqwest::Url,
  body: &[u8],
) -> anyhow::Result<[(&'static str, String); 5]> {
  let host = url_origin_host(url)?;
  signed_request_headers_with_keys(
    keys,
    &host,
    method,
    &url_path_and_query(url),
    body,
  )
}

/// The path and query of `url` as a request to it carries them:
/// percent encoded, without the fragment.
pub fn url_path_and_query(url: &reqwest::Url) -> String {
  match url.query() {
    Some(query) => format!("{}?{query}", url.path()),
    None => url.path().to_string(),
  }
}

/// The headers authenticating a request made right now to the server
/// at `host` ([url_host] of its address, never the address itself),
/// see [SignedRequest] for the other arguments and [sign_request] for
/// the private key. [signed_request_headers_for_url] takes both the
/// host and the path from the url of the request.
///
/// The server only accepts the signature for about a second by default
/// (`AuthImpl::signing_key_timestamp_tolerance_ms`), so create them right
/// before sending, and keep the clock of the client synchronized.
///
/// It parses the private key (and derives its public key) on every
/// call: a client signing more than once parses it once with
/// [signing_keys] and signs with [signed_request_headers_with_keys].
#[cfg(feature = "pki")]
pub fn signed_request_headers(
  private_key: &str,
  host: &str,
  method: &str,
  path_and_query: &str,
  body: &[u8],
) -> anyhow::Result<[(&'static str, String); 5]> {
  signed_request_headers_with_keys(
    &signing_keys(private_key)?,
    host,
    method,
    path_and_query,
    body,
  )
}

/// [signed_request_headers] with the key pair of the private key,
/// parsed once ([signing_keys]): the five headers of a request made
/// now, a new timestamp and nonce every call. This is the one
/// implementation of the signed request headers, which the other
/// functions call: an app client signing its own requests calls it
/// (or [signed_request_headers_for_url_with_keys]) rather than
/// building the headers itself, so it signs as the server verifies.
///
/// A pair of another algorithm (an X25519 key) is an error.
#[cfg(feature = "pki")]
pub fn signed_request_headers_with_keys(
  keys: &mogh_pki::EncodedKeyPair,
  host: &str,
  method: &str,
  path_and_query: &str,
  body: &[u8],
) -> anyhow::Result<[(&'static str, String); 5]> {
  let timestamp = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .context("Failed to get system timestamp")?
    .as_millis() as i64;
  let nonce = random_nonce()?;
  let request = SignedRequest {
    host,
    method,
    path_and_query,
    timestamp,
    nonce: &nonce,
    body,
  };
  request.check()?;
  let signature = mogh_pki::signature::sign(
    &keys.private,
    request.message().as_bytes(),
  )
  .context("Failed to sign the request")?;
  Ok([
    (API_PUBLIC_KEY_HEADER, keys.public.as_str().to_string()),
    (API_HOST_HEADER, host.to_string()),
    (API_TIMESTAMP_HEADER, timestamp.to_string()),
    (API_NONCE_HEADER, nonce),
    (API_SIGNATURE_HEADER, signature),
  ])
}

#[cfg(test)]
mod tests {
  use super::*;

  /// sha256 of empty input.
  const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  const NONCE: &str = "0123456789abcdef0123456789abcdef";

  fn request<'a>(
    method: &'a str,
    path_and_query: &'a str,
    body: &'a [u8],
  ) -> SignedRequest<'a> {
    SignedRequest {
      host: "example.com",
      method,
      path_and_query,
      timestamp: 1234,
      nonce: NONCE,
      body,
    }
  }

  #[test]
  fn test_message_format_is_stable() {
    // The server builds the same string to verify the signature.
    assert_eq!(
      request("POST", "/auth/manage?x=1", b"").message(),
      format!(
        "mogh-signed-request-v1\nexample.com\nPOST\n/auth/manage?x=1\n1234\n{NONCE}\n{EMPTY_SHA256}"
      )
    );
    assert_eq!(
      request("POST", "/read", b"{}").message(),
      format!(
        "mogh-signed-request-v1\nexample.com\nPOST\n/read\n1234\n{NONCE}\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
      )
    );
    // Every field is signed as it is given: methods are case
    // sensitive, and the host has one form.
    assert_ne!(
      request("post", "/read", b"{}").message(),
      request("POST", "/read", b"{}").message(),
    );
    assert_ne!(
      SignedRequest {
        host: "Example.com",
        ..request("POST", "/read", b"{}")
      }
      .message(),
      request("POST", "/read", b"{}").message(),
    );
    // Every field is its own line.
    assert_eq!(request("GET", "/", b"").message().lines().count(), 7);
  }

  /// What no server could accept is not signed: every field has one
  /// form, and none can hold a line break.
  #[test]
  fn test_signed_request_check() {
    let ok = request("POST", "/read?x=1", b"{}");
    ok.check().unwrap();
    for host in [
      "example.com:8443",
      "10.0.0.5:9120",
      "[::1]:9120",
      "cicada_core",
      "localhost",
    ] {
      SignedRequest { host, ..ok }.check().unwrap();
    }
    let long_host = "a".repeat(261);
    for host in [
      "",
      "Example.com",
      // The address, or a key, in place of the host.
      "https://example.com",
      "example.com/auth",
      "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=",
      "example.com\nPOST",
      "example.com ",
      "*.example.com",
      "a.example.com,b.example.com",
      "exämple.com",
      long_host.as_str(),
    ] {
      assert!(
        SignedRequest { host, ..ok }.check().is_err(),
        "{host:?}"
      );
    }
    // A method is signed as it is sent, whatever its case.
    for method in ["GET", "post", "CONNECT", "M-SEARCH"] {
      SignedRequest { method, ..ok }.check().unwrap();
    }
    for method in [
      "",
      "POST\n/write",
      "PO ST",
      "PÖST",
      // Nothing a request can be sent with.
      "POST/",
      "GET,POST",
      "P(ST",
      "POST:",
    ] {
      assert!(
        SignedRequest { method, ..ok }.check().is_err(),
        "{method:?}"
      );
    }
    for path_and_query in ["/", "/read", "/a%20b?x=%7B1%7D&y=[2]"] {
      SignedRequest {
        path_and_query,
        ..ok
      }
      .check()
      .unwrap();
    }
    for path_and_query in [
      "",
      "read",
      "https://example.com/read",
      "/read\n1",
      "/re ad",
      "/reäd",
      // A fragment is never sent: the server receives another path.
      "/read#x",
      "/read?x=1#y",
    ] {
      assert!(
        SignedRequest {
          path_and_query,
          ..ok
        }
        .check()
        .is_err(),
        "{path_and_query:?}"
      );
    }
    assert!(
      SignedRequest {
        nonce: "short",
        ..ok
      }
      .check()
      .is_err()
    );
  }

  #[test]
  fn test_body_sha256() {
    assert_eq!(body_sha256(b""), EMPTY_SHA256);
    assert_eq!(
      body_sha256(br#"{"type":"GetUserId","params":{}}"#),
      "1063e6f54ccbb0c3e238533021c0952c1cd6c646f177a3bd44b396d640d8a0d8"
    );
  }

  #[test]
  fn test_url_host() {
    for (url, host) in [
      ("https://example.com", "example.com"),
      ("https://example.com/", "example.com"),
      ("https://Example.COM/auth?x=1#y", "example.com"),
      // The default port of the scheme is left out, as in the Host
      // header.
      ("https://example.com:443", "example.com"),
      ("http://example.com:80/", "example.com"),
      ("wss://example.com:443/ws", "example.com"),
      ("ws://example.com:80/ws", "example.com"),
      // Any other port is part of the host.
      ("https://example.com:8443", "example.com:8443"),
      ("http://example.com:443", "example.com:443"),
      ("https://example.com:80", "example.com:80"),
      ("http://localhost:9120", "localhost:9120"),
      ("http://10.0.0.5:9120/api", "10.0.0.5:9120"),
      ("http://[::1]:9120", "[::1]:9120"),
      ("http://[::1]:80", "[::1]"),
      ("  https://example.com\n", "example.com"),
      // The url standard spells these anew.
      ("https://exämple.com", "xn--exmple-cua.com"),
      ("http://127.1:9120", "127.0.0.1:9120"),
      ("http://[0:0:0:0:0:0:0:1]:9120", "[::1]:9120"),
      ("http://cicada_core:9120", "cicada_core:9120"),
      ("https://example.com.", "example.com."),
    ] {
      let signed_for = url_host(url).unwrap();
      assert_eq!(signed_for, host, "{url}");
      assert!(valid_host(&signed_for), "{url}");
    }
    // Without a scheme there is no telling the host from it, and only
    // an http(s) url has a host a request is made to.
    for url in [
      "",
      "example.com",
      "example.com:9120",
      "localhost:9120",
      "/auth",
      "https://",
      "file:///etc/hosts",
      "ftp://example.com",
      "foo://example.com:80",
      // More than a name or an address.
      "https://*.example.com",
      "https://a.example.com,https://b.example.com",
    ] {
      assert!(url_host(url).is_err(), "{url}");
    }
    // Credentials are no part of an address a request is signed for
    // (a client would send them as Authorization, which a server
    // takes over the signature), and the error doesn't repeat them.
    for url in [
      "https://user:hunter2@example.com",
      "https://hunter2@example.com",
      "https://:hunter2@example.com/auth",
    ] {
      let err = format!("{:#}", url_host(url).unwrap_err());
      assert!(err.contains("carries credentials"), "{url}: {err}");
      assert!(!err.contains("hunter2"), "{url}: {err}");
    }
  }

  /// The path and query as the request line carries them.
  #[test]
  fn test_url_path_and_query() {
    for (url, path_and_query) in [
      ("https://example.com", "/"),
      ("https://example.com/", "/"),
      ("https://example.com/read", "/read"),
      ("https://example.com/read?x=1", "/read?x=1"),
      (
        "https://example.com:8443/auth/manage?x=1&y=2",
        "/auth/manage?x=1&y=2",
      ),
      // The fragment stays with the client.
      ("https://example.com/read?x=1#y", "/read?x=1"),
      ("https://example.com/read#y", "/read"),
      // An empty query is one.
      ("https://example.com/read?", "/read?"),
      // Percent encoded as it is sent.
      ("https://example.com/a b?x=ä z", "/a%20b?x=%C3%A4%20z"),
      ("https://example.com/a/../b/./c", "/b/c"),
      ("wss://example.com/ws?token=1", "/ws?token=1"),
    ] {
      let parsed = reqwest::Url::parse(url).unwrap();
      let signed = url_path_and_query(&parsed);
      assert_eq!(signed, path_and_query, "{url}");
      // What a server would be given for it.
      SignedRequest {
        path_and_query: &signed,
        ..request("GET", "/", b"")
      }
      .check()
      .unwrap_or_else(|e| panic!("{url}: {e:#}"));
    }
  }

  #[test]
  fn test_valid_nonce() {
    for nonce in [
      NONCE,
      "0123456789abcdef",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ-_abcdefghijklmnopqrstuvwxyz0123456789",
    ] {
      assert!(valid_nonce(nonce), "{nonce}");
    }
    let too_long = "a".repeat(65);
    for nonce in [
      "",
      "0123456789abcde",
      too_long.as_str(),
      "0123456789abcdef\n",
      "0123456789abcde|",
      "0123456789abcde ",
      "0123456789abcde=",
      "0123456789abcdé",
    ] {
      assert!(!valid_nonce(nonce), "{nonce:?}");
    }
  }

  #[cfg(feature = "pki")]
  #[test]
  fn test_signature_is_verified_by_the_public_key() {
    use mogh_pki::{EncodedKeyPair, PkiKind};

    let client =
      EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    let body = br#"{"type":"ListTrustedIssuers","params":{}}"#;
    let signed = request("POST", "/read", body);
    let signature = sign_request(client.private(), &signed).unwrap();

    let verify = |public_key: &mogh_pki::SpkiPublicKey,
                  request: SignedRequest<'_>| {
      mogh_pki::signature::verify(
        public_key,
        request.message().as_bytes(),
        &signature,
      )
    };

    // The server needs the public key of the client, nothing else.
    verify(&client.public, signed).unwrap();
    // Not valid for another request, or for another server.
    for other in [
      request("POST", "/write", body),
      request("GET", "/read", body),
      SignedRequest {
        timestamp: 1235,
        ..signed
      },
      SignedRequest {
        nonce: "fedcba9876543210fedcba9876543210",
        ..signed
      },
      SignedRequest {
        host: "other.example.com",
        ..signed
      },
      SignedRequest {
        host: "example.com:8443",
        ..signed
      },
      // Another body on the same method and path.
      request(
        "POST",
        "/read",
        br#"{"type":"CreateTrustedIssuer","params":{}}"#,
      ),
      request("POST", "/read", b""),
    ] {
      assert!(verify(&client.public, other).is_err(), "{other:?}");
    }
    // Nor as the request of another key.
    let other = EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    assert!(verify(&other.public, signed).is_err());

    // The same request signs the same, only the nonce (and
    // timestamp) make two signatures differ.
    assert_eq!(
      sign_request(client.private(), &signed).unwrap(),
      signature
    );
  }

  /// A request signed with the example key of RFC 8410: any other
  /// implementation of the signature has to come out the same, as
  /// `openssl pkeyutl -sign -rawin` over the message does.
  #[cfg(feature = "pki")]
  #[test]
  fn test_signature_vector() {
    let private_key = "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";
    let request = SignedRequest {
      host: "example.com",
      method: "POST",
      path_and_query: "/read?x=1",
      timestamp: 1718000000000,
      nonce: NONCE,
      body: br#"{"type":"GetUserId","params":{}}"#,
    };
    assert_eq!(
      request.message(),
      "mogh-signed-request-v1\nexample.com\nPOST\n/read?x=1\n1718000000000\n0123456789abcdef0123456789abcdef\n1063e6f54ccbb0c3e238533021c0952c1cd6c646f177a3bd44b396d640d8a0d8"
    );
    let signature = "Njr3/bBJ/8KlrrnfSauEu0CQZg8NvcK1WIeNqfC6kXri2ZHm3whO7Z8JINSNeknfgE4kFv9gfJbt4bu9TW1kAw==";
    assert_eq!(
      sign_request(private_key, &request).unwrap(),
      signature
    );
    mogh_pki::signature::verify(
      &mogh_pki::SpkiPublicKey::from(String::from(
        "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=",
      )),
      request.message().as_bytes(),
      signature,
    )
    .unwrap();
  }

  #[cfg(feature = "pki")]
  #[test]
  fn test_signed_request_headers() {
    use mogh_pki::{EncodedKeyPair, PkiKind, SpkiPublicKey};

    let client =
      EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    let headers = || {
      signed_request_headers(
        client.private(),
        "example.com",
        "POST",
        "/read",
        b"{}",
      )
      .unwrap()
    };
    let [
      (public_key_header, public_key),
      (host_header, host),
      (timestamp_header, timestamp),
      (nonce_header, nonce),
      (signature_header, signature),
    ] = headers();
    assert_eq!(public_key_header, "x-api-public-key");
    assert_eq!(host_header, "x-api-host");
    assert_eq!(host, "example.com");
    assert_eq!(timestamp_header, "x-api-timestamp");
    assert_eq!(nonce_header, "x-api-nonce");
    assert_eq!(signature_header, "x-api-signature");
    assert_eq!(public_key, client.public());
    let timestamp = timestamp.parse::<i64>().unwrap();
    assert!(timestamp > 1_700_000_000_000);
    assert!(valid_nonce(&nonce));
    assert_eq!(nonce.len(), 32);

    // They verify as the request they were made for.
    mogh_pki::signature::verify(
      &SpkiPublicKey::from(public_key),
      SignedRequest {
        host: "example.com",
        method: "POST",
        path_and_query: "/read",
        timestamp,
        nonce: &nonce,
        body: b"{}",
      }
      .message()
      .as_bytes(),
      &signature,
    )
    .unwrap();

    // Every call has its own nonce, and so its own signature, also
    // within the same millisecond.
    let [_, _, _, (_, other_nonce), (_, other_signature)] = headers();
    assert_ne!(other_nonce, nonce);
    assert_ne!(other_signature, signature);
  }

  /// The key pair parsed once signs as the private key does, and is
  /// what every other signing function signs with.
  #[cfg(feature = "pki")]
  #[test]
  fn test_signed_request_headers_with_keys() {
    use mogh_pki::{EncodedKeyPair, PkiKind, SpkiPublicKey};

    let client =
      EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    let keys = signing_keys(client.private()).unwrap();
    assert_eq!(keys.public.as_str(), client.public());

    let verify = |headers: [(&'static str, String); 5],
                  host: &str,
                  path_and_query: &str| {
      let [
        (API_PUBLIC_KEY_HEADER, public_key),
        (API_HOST_HEADER, signed_host),
        (API_TIMESTAMP_HEADER, timestamp),
        (API_NONCE_HEADER, nonce),
        (API_SIGNATURE_HEADER, signature),
      ] = headers
      else {
        panic!("The headers are not the five in their order");
      };
      assert_eq!(public_key, client.public());
      assert_eq!(signed_host, host);
      mogh_pki::signature::verify(
        &SpkiPublicKey::from(public_key),
        SignedRequest {
          host,
          method: "POST",
          path_and_query,
          timestamp: timestamp.parse().unwrap(),
          nonce: &nonce,
          body: b"{}",
        }
        .message()
        .as_bytes(),
        &signature,
      )
      .unwrap();
    };
    verify(
      signed_request_headers_with_keys(
        &keys,
        "example.com",
        "POST",
        "/read",
        b"{}",
      )
      .unwrap(),
      "example.com",
      "/read",
    );
    let url =
      reqwest::Url::parse("https://Example.com/auth/manage?x=1")
        .unwrap();
    verify(
      signed_request_headers_for_url_with_keys(
        &keys, "POST", &url, b"{}",
      )
      .unwrap(),
      "example.com",
      "/auth/manage?x=1",
    );

    // A pair of another algorithm is an error, not a panic.
    let x25519 = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
    assert!(
      signed_request_headers_with_keys(
        &x25519,
        "example.com",
        "POST",
        "/read",
        b"",
      )
      .is_err()
    );
    // What no server could accept is not signed.
    assert!(
      signed_request_headers_with_keys(
        &keys,
        "https://example.com",
        "POST",
        "/read",
        b"",
      )
      .is_err()
    );
    // No key file path is taken for a key.
    let Err(err) = signing_keys("file:/keys/signing.key") else {
      panic!("A key file path was taken for a key");
    };
    assert!(format!("{err:#}").contains("path of a key file"));
  }

  /// Signed for where the request goes: the host, path and query of
  /// its url.
  #[cfg(feature = "pki")]
  #[test]
  fn test_signed_request_headers_for_url() {
    use mogh_pki::{EncodedKeyPair, PkiKind, SpkiPublicKey};

    let client =
      EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    for (url, host, path_and_query) in [
      ("https://Example.com/read", "example.com", "/read"),
      (
        "http://10.0.0.5:9120/auth/manage?x=1#top",
        "10.0.0.5:9120",
        "/auth/manage?x=1",
      ),
      ("https://example.com:443", "example.com", "/"),
      ("wss://example.com/ws?x=a b", "example.com", "/ws?x=a%20b"),
    ] {
      let url = reqwest::Url::parse(url).unwrap();
      let [
        (_, public_key),
        (_, signed_host),
        (_, timestamp),
        (_, nonce),
        (_, signature),
      ] = signed_request_headers_for_url(
        client.private(),
        "POST",
        &url,
        b"{}",
      )
      .unwrap();
      assert_eq!(signed_host, host, "{url}");
      mogh_pki::signature::verify(
        &SpkiPublicKey::from(public_key),
        SignedRequest {
          host,
          method: "POST",
          path_and_query,
          timestamp: timestamp.parse().unwrap(),
          nonce: &nonce,
          body: b"{}",
        }
        .message()
        .as_bytes(),
        &signature,
      )
      .unwrap_or_else(|e| panic!("{url}: {e:#}"));
    }
    // No url a signed request is sent to.
    for url in [
      "ftp://example.com/read",
      "https://user:hunter2@example.com/read",
      "file:///etc/hosts",
    ] {
      let parsed = reqwest::Url::parse(url).unwrap();
      let err = signed_request_headers_for_url(
        client.private(),
        "POST",
        &parsed,
        b"",
      )
      .unwrap_err();
      assert!(!format!("{err:#}").contains("hunter2"), "{err:#}");
    }
  }

  /// Invalid keys are an error, not a panic.
  #[cfg(feature = "pki")]
  #[test]
  fn test_signed_request_headers_invalid_keys() {
    use mogh_pki::{EncodedKeyPair, PkiKind};

    let client =
      EncodedKeyPair::generate(PkiKind::Signature).unwrap();
    let headers = |private_key: &str| {
      signed_request_headers(
        private_key,
        "example.com",
        "POST",
        "/read",
        b"",
      )
    };
    headers(client.private()).unwrap();

    // Note that up to 32 bytes are taken as a raw key, so these are
    // longer.
    let invalid_base64 = "!".repeat(64);
    for private_key in [
      "",
      invalid_base64.as_str(),
      "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
      // A public key given as the private key.
      client.public(),
    ] {
      assert!(headers(private_key).is_err(), "{private_key:?}");
      assert!(
        sign_request(private_key, &request("POST", "/read", b""))
          .is_err(),
        "{private_key:?}"
      );
    }

    // An X25519 key, as signing keys were before 7.0: the error says
    // which key is needed.
    let x25519 = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
    let err = headers(x25519.private()).unwrap_err();
    assert!(format!("{err:#}").contains("Ed25519"), "{err:#}");

    // A request the server would refuse is not signed: a nonce it
    // doesn't take, or the address (or what the argument was before
    // 7.0, the server public key) in place of the host.
    let short_nonce = SignedRequest {
      nonce: "short",
      ..request("POST", "/read", b"")
    };
    assert!(sign_request(client.private(), &short_nonce).is_err());
    for host in ["https://example.com", client.public()] {
      assert!(
        signed_request_headers(
          client.private(),
          host,
          "POST",
          "/read",
          b""
        )
        .is_err(),
        "{host}"
      );
    }

    // The path of a key file is no key, however short (32 characters
    // or fewer would be read as the bytes of a raw key, one anybody
    // can derive from the path).
    for private_key in [
      "file:/keys/signing.key",
      " file:key",
      "File:/keys/signing.key",
      "/run/secrets/signing.key",
      "./signing.key",
      "~/.config/app/signing.key",
    ] {
      let err = headers(private_key).unwrap_err();
      assert!(
        format!("{err:#}").contains("path of a key file"),
        "{private_key}: {err:#}"
      );
      assert!(
        !format!("{err:#}").contains(private_key.trim()),
        "{err:#}"
      );
      assert!(
        sign_request(private_key, &request("POST", "/read", b""))
          .is_err(),
        "{private_key}"
      );
    }
  }
}
