//! The outbound http of the server: to login providers (OIDC, Google,
//! Github), to the issuers of workload tokens (discovery, key sets),
//! and to the clusters reviewing them. Every client is built, and every
//! response read, here: a change to how (a timeout, a CA, a cap, error
//! handling) reaches all of them.

use std::{
  collections::HashSet,
  sync::{Mutex, OnceLock},
  time::Duration,
};

use anyhow::anyhow;
use mogh_logger::redact_url_credentials;
use tracing::warn;

use crate::provider::CONNECT_TIMEOUT;

/// The user agent of the server's own requests, where no app user
/// agent is given (key sets, token reviews, Github).
pub(crate) const USER_AGENT: &str =
  concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// The start of every client of the server, which the sites extend
/// (eg. the review client with its CA):
///
/// - Gives up on a request after `timeout`, and on connecting after
///   [CONNECT_TIMEOUT] (or `timeout`, when shorter).
/// - Follows no redirect: a token request carries client credentials
///   and a PKCE verifier, a review the reviewer credential and a live
///   token, a key set fetch decides which keys are trusted. A redirect
///   would send them on, or let another server answer.
/// - Sends `user_agent`.
///
/// TLS peers are verified against the system roots (`SSL_CERT_FILE` /
/// `SSL_CERT_DIR` included), unless the site sets its own.
pub(crate) fn client_builder(
  timeout: Duration,
  user_agent: &str,
) -> reqwest::ClientBuilder {
  reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(timeout)
    .connect_timeout(CONNECT_TIMEOUT.min(timeout))
    .user_agent(user_agent)
}

/// Reads the body of `response`, at most `max` bytes, whatever the
/// server sends: one declaring more up front is refused unread, and
/// one sending more is refused once it did, never truncated.
///
/// The errors don't name the request url: reqwest's own would, with
/// anything in its query.
pub(crate) async fn read_capped(
  mut response: reqwest::Response,
  max: usize,
) -> anyhow::Result<Vec<u8>> {
  let too_large =
    || anyhow!("The response is larger than {max} bytes");
  if response
    .content_length()
    .is_some_and(|length| length > max as u64)
  {
    return Err(too_large());
  }
  let mut body = Vec::new();
  while let Some(chunk) = response
    .chunk()
    .await
    .map_err(reqwest::Error::without_url)?
  {
    if body.len() + chunk.len() > max {
      return Err(too_large());
    }
    body.extend_from_slice(&chunk);
  }
  Ok(body)
}

/// Whether `url` is plain `http://`: whatever the server sends there,
/// or gets back, crosses the network unencrypted and unauthenticated.
/// It stays accepted (loopback setups and tests rely on it), with a
/// warning ([warn_plain_http]).
pub(crate) fn is_plain_http(url: &str) -> bool {
  reqwest::Url::parse(url.trim())
    .is_ok_and(|url| url.scheme() == "http")
}

/// What a plain http url belongs to, see [warn_plain_http].
pub(crate) enum UrlOwner<'a> {
  Provider { id: &'a str, name: &'a str },
  Issuer { id: &'a str, name: &'a str },
}

/// Logs a warning that the `field` url of `owner` is plain `http://`,
/// and what anyone on the path can do (`exposes`, eg. "read the
/// reviewer credential"). Nothing when it isn't.
///
/// `once`: the urls listed on every login or exchange are warned about
/// once in the life of the process (for each owner, field and url).
/// Otherwise (an admin storing it) every time, which counts as that
/// once.
///
/// The url is logged without userinfo, and with its query masked
/// ([redact_url_credentials]).
pub(crate) fn warn_plain_http(
  owner: UrlOwner,
  field: &str,
  url: &str,
  exposes: &str,
  once: bool,
) {
  if !is_plain_http(url) {
    return;
  }
  let (is_issuer, id, name) = match owner {
    UrlOwner::Provider { id, name } => (false, id, name),
    UrlOwner::Issuer { id, name } => (true, id, name),
  };
  let first =
    first_warning(format!("{is_issuer}\n{id}\n{field}\n{url}"));
  if once && !first {
    return;
  }
  let url = redact_url_credentials(url);
  if is_issuer {
    warn!(
      issuer_id = id,
      issuer = name,
      field,
      url,
      "Trusted issuer is reached over plain http, unencrypted: anyone \
       on the path can {exposes}. Use https"
    );
  } else {
    warn!(
      provider_id = id,
      provider = name,
      field,
      url,
      "External login provider is reached over plain http, \
       unencrypted: anyone on the path can {exposes}. Use https"
    );
  }
}

/// Whether this is the first warning about `key` in the process.
fn first_warning(key: String) -> bool {
  static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
  WARNED
    .get_or_init(Default::default)
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .insert(key)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_is_plain_http() {
    for url in
      ["http://10.0.0.1:6443", " http://idp.local/ ", "HTTP://x"]
    {
      assert!(is_plain_http(url), "{url}");
    }
    for url in ["https://10.0.0.1:6443", "", "not a url", "ftp://x"] {
      assert!(!is_plain_http(url), "{url}");
    }
  }

  #[test]
  fn test_first_warning() {
    assert!(first_warning(String::from("first-warning-test")));
    assert!(!first_warning(String::from("first-warning-test")));
    assert!(first_warning(String::from("first-warning-test-2")));
  }

  #[tokio::test]
  async fn test_read_capped() {
    let [declared, endless] =
      crate::provider::oversized_servers().await;
    let client = client_builder(Duration::from_secs(5), USER_AGENT)
      .build()
      .unwrap();
    for url in [declared, endless] {
      let response = client.get(&url).send().await.unwrap();
      let err = tokio::time::timeout(
        Duration::from_secs(5),
        read_capped(response, 1024),
      )
      .await
      .expect("the read must stop at the limit")
      .unwrap_err();
      assert_eq!(
        format!("{err:#}"),
        "The response is larger than 1024 bytes"
      );
    }

    // Up to the cap is read whole.
    let exact = crate::provider::answering_server(
      axum::http::StatusCode::OK,
      "a".repeat(1024),
    )
    .await;
    let response = client.get(&exact).send().await.unwrap();
    assert_eq!(
      read_capped(response, 1024).await.unwrap().len(),
      1024
    );
  }

  /// No redirect is followed, and the user agent is sent.
  #[tokio::test]
  async fn test_client_builder() {
    use axum::{Router, http::HeaderMap, routing::get};
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address =
      format!("http://{}", listener.local_addr().unwrap());
    let router = Router::new()
      .route(
        "/redirect",
        get(|| async { axum::response::Redirect::to("/agent") }),
      )
      .route(
        "/agent",
        get(|headers: HeaderMap| async move {
          headers
            .get("user-agent")
            .and_then(|agent| agent.to_str().ok())
            .unwrap_or_default()
            .to_string()
        }),
      );
    tokio::spawn(async move { axum::serve(listener, router).await });

    let client =
      client_builder(Duration::from_secs(5), "test-agent/1")
        .build()
        .unwrap();
    let response = client
      .get(format!("{address}/redirect"))
      .send()
      .await
      .unwrap();
    assert!(response.status().is_redirection());
    let agent = client
      .get(format!("{address}/agent"))
      .send()
      .await
      .unwrap()
      .text()
      .await
      .unwrap();
    assert_eq!(agent, "test-agent/1");
  }
}
