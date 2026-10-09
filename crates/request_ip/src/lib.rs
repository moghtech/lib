//! This library includes an axum extractor for client ip, [RequestIp],
//! as well as functions to help with extracting the client ip from requests.
//!
//! # Trusted proxies
//!
//! Forwarding headers (`X-Forwarded-For`, `X-Real-IP`) are only
//! believed when the connecting socket peer is a [TrustedProxies]
//! member, since anything else could have written them itself.
//! `X-Forwarded-For` is walked from the right (the entry appended by
//! the nearest proxy), skipping trusted proxy hops, and the first
//! untrusted address is the client. Entries further left were
//! written by untrusted parties and are ignored. `X-Real-IP` is
//! only read when `X-Forwarded-For` has no entries, and is walked
//! the same way (a proxy which adds its own line after one the
//! client sent is the nearest, so its line wins, except under
//! [TrustedProxies::All], where the first line is used).
//!
//! The [RequestIp] extractor reads the [TrustedProxies] policy from
//! the request extensions (add it with [TrustedProxies::layer]),
//! falling back to [TrustedProxies::default] (private ranges).
//!
//! # What the trusted proxy must do
//!
//! Every trusted proxy must **append to (or overwrite)
//! `X-Forwarded-For`**, not only set `X-Real-IP`. A proxy passes
//! headers it does not set through untouched, and `X-Forwarded-For`
//! takes precedence over `X-Real-IP`. So behind a proxy which only
//! sets `X-Real-IP`, a client sending its own `X-Forwarded-For`
//! chooses its ip, which passes CIDR whitelists and dodges per ip
//! rate limits. For nginx:
//!
//! ```nginx
//! proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
//! proxy_set_header X-Real-IP $remote_addr;
//! ```
//!
//! Caddy and Traefik set `X-Forwarded-For` by default.
//!
//! # Narrowing the default
//!
//! The default ([TrustedProxies::private]) trusts every loopback and
//! private peer. That is only safe when every such peer is a proxy
//! which sets `X-Forwarded-For`. Any path which makes public clients
//! arrive from a private address lets them choose their ip, eg:
//!
//! - Docker's userland `docker-proxy` (IPv6 clients of a port
//!   published to an IPv4-only network arrive from the bridge
//!   gateway, eg `172.17.0.1`).
//! - Rootless Docker / Podman port forwarding, and Docker Desktop.
//! - A Kubernetes Service with `externalTrafficPolicy: Cluster`
//!   (SNAT to a node ip).
//! - Other hosts / containers on the private network or VPN which
//!   can reach the app directly.
//!
//! In those setups use [TrustedProxies::None] (`["none"]`) when
//! nothing is in front of the app, or list the exact proxy
//! address(es), eg `["172.18.0.5"]` with the proxy container given
//! a static ip. Listing the whole container network is not enough:
//! it includes the gateway the forwarded traffic arrives from.
//!
//! # A list which misses the proxy
//!
//! When the trusted proxies miss the real proxy (a list naming
//! another address, `none` behind a proxy, a proxy outside the
//! private ranges of the default), its forwarding headers are
//! ignored and every client is seen as the proxy: they all share one
//! rate limit budget, and match ip whitelists as the proxy's ip. The
//! first request from a peer which is not trusted but sends
//! `X-Forwarded-For` / `X-Real-IP` is logged as a warning, once per
//! process, naming the peer and the trusted proxies. A client
//! sending the headers itself triggers it too.
//!
//! The [cidr] module provides CIDR set parsing and matching,
//! also used to restrict requests by source ip.

use std::{
  net::{IpAddr, SocketAddr},
  sync::{LazyLock, Once},
};

use anyhow::{Context as _, anyhow};
use axum::{
  Extension,
  extract::{ConnectInfo, FromRequestParts},
  http::{Extensions, HeaderMap, StatusCode},
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};

pub mod cidr;

pub use cidr::CidrSet;

/// Which socket peers are trusted to set the client ip
/// through `X-Forwarded-For` / `X-Real-IP` headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedProxies {
  /// Never trust forwarding headers.
  /// The client ip is always the socket peer.
  None,
  /// Trust forwarding headers only when the socket peer
  /// is within one of the networks.
  Cidrs(CidrSet),
  /// Trust forwarding headers from any peer, and every
  /// `X-Forwarded-For` hop, so the **leftmost** entry is the
  /// client (legacy behavior).
  ///
  /// ⚠️ Only safe when the server is unreachable except through
  /// proxies which **replace** any client-sent `X-Forwarded-For`,
  /// eg the Caddy and Traefik defaults. Behind a proxy which
  /// **appends** (nginx `$proxy_add_x_forwarded_for`, HAProxy
  /// `option forwardfor`, AWS ALB append mode) the leftmost entry
  /// is whatever the client sent, so clients choose their ip.
  /// Likewise behind a proxy which adds its own `X-Real-IP` line
  /// rather than replacing a client-sent one (eg HAProxy
  /// `http-request add-header`), as the first line is used.
  /// List the proxy addresses / networks ([Self::Cidrs]) instead.
  All,
}

impl Default for TrustedProxies {
  /// Trusts loopback and private (RFC 1918 / ULA) peers
  /// ([Self::private]), which covers a reverse proxy on the same
  /// host or container network.
  ///
  /// ⚠️ Any private peer is believed, not only the proxy. When
  /// public clients can reach the app from a private address (a
  /// published port through Docker's userland proxy, rootless
  /// Docker / Podman, Docker Desktop, Kubernetes SNAT, or hosts
  /// on the same network / VPN), they choose their own ip. Narrow
  /// it to the exact proxy address, or [Self::None] when nothing
  /// is in front of the app. See the
  /// [crate docs](crate#narrowing-the-default).
  fn default() -> Self {
    Self::private()
  }
}

/// Loopback and private (RFC 1918 / ULA) ranges,
/// the `private` keyword of [TrustedProxies::from_config].
pub const PRIVATE_RANGES: [&str; 6] = [
  "127.0.0.0/8",
  "::1",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "fc00::/7",
];

static DEFAULT_TRUSTED_PROXIES: LazyLock<TrustedProxies> =
  LazyLock::new(TrustedProxies::default);

impl TrustedProxies {
  /// Loopback and private (RFC 1918 / ULA) ranges ([PRIVATE_RANGES]).
  ///
  /// ⚠️ Believes every private peer, see the caveat on
  /// [TrustedProxies::default].
  pub fn private() -> Self {
    Self::Cidrs(
      CidrSet::parse(PRIVATE_RANGES)
        .expect("private ranges are valid"),
    )
  }

  /// Build the policy from a config list, for piping an app's
  /// `trusted_proxies` / internal CIDR config through.
  ///
  /// - Empty: [Self::private] (the default, see its caveat on
  ///   [TrustedProxies::default]).
  /// - `all` (alone): [Self::All], only safe behind proxies which
  ///   replace (not append to) `X-Forwarded-For`.
  /// - `none` (alone): [Self::None], for an app reached directly.
  /// - Otherwise the CIDR ranges / ips given, where the keyword
  ///   `private` expands to [PRIVATE_RANGES] (eg
  ///   `["private", "203.0.113.10"]`).
  ///
  /// Keywords are case-insensitive. `all` / `none` combined with
  /// any other entry is an error rather than a guess.
  pub fn from_config<I>(entries: I) -> anyhow::Result<Self>
  where
    I: IntoIterator,
    I::Item: AsRef<str>,
  {
    let mut cidrs: Vec<String> = Vec::new();
    let mut all = false;
    let mut none = false;
    let mut count = 0;
    for entry in entries {
      let entry = entry.as_ref().trim();
      if entry.is_empty() {
        continue;
      }
      count += 1;
      match entry.to_ascii_lowercase().as_str() {
        "all" => all = true,
        "none" => none = true,
        "private" => {
          cidrs.extend(PRIVATE_RANGES.iter().map(|s| s.to_string()))
        }
        _ => cidrs.push(entry.to_string()),
      }
    }
    if (all || none) && count > 1 {
      return Err(anyhow!(
        "Trusted proxies 'all' / 'none' cannot be combined with other entries"
      ));
    }
    if all {
      return Ok(Self::All);
    }
    if none {
      return Ok(Self::None);
    }
    if cidrs.is_empty() {
      return Ok(Self::private());
    }
    Self::parse(&cidrs)
  }

  /// The policy attached to the request (by [TrustedProxies::layer],
  /// eg through `mogh_server::serve_app`), or the default.
  pub fn from_extensions(extensions: &Extensions) -> &TrustedProxies {
    extensions
      .get::<TrustedProxies>()
      .unwrap_or(&DEFAULT_TRUSTED_PROXIES)
  }

  /// Parse trusted proxy CIDR ranges / ip addresses.
  /// Empty means no proxies are trusted ([Self::None]).
  pub fn parse<I>(entries: I) -> anyhow::Result<Self>
  where
    I: IntoIterator,
    I::Item: AsRef<str>,
  {
    let set = CidrSet::parse(entries)?;
    Ok(if set.is_empty() {
      Self::None
    } else {
      Self::Cidrs(set)
    })
  }

  /// Whether the ip is a trusted proxy.
  pub fn trusts(&self, ip: IpAddr) -> bool {
    match self {
      Self::None => false,
      Self::Cidrs(set) => set.contains(ip),
      Self::All => true,
    }
  }

  /// Axum layer which attaches this policy to every request,
  /// for use by the [RequestIp] extractor.
  pub fn layer(self) -> Extension<Self> {
    Extension(self)
  }
}

/// Extract the client IP, believing forwarding headers only
/// when the socket peer is in the request's [TrustedProxies]
/// (default: [TrustedProxies::private]). See [get_client_ip].
///
/// Requires the app to be served with
/// `into_make_service_with_connect_info::<SocketAddr>()`
/// unless the policy is [TrustedProxies::All].
pub struct RequestIp(pub IpAddr);

impl From<RequestIp> for IpAddr {
  fn from(value: RequestIp) -> Self {
    value.0
  }
}

impl From<IpAddr> for RequestIp {
  fn from(value: IpAddr) -> Self {
    RequestIp(value)
  }
}

impl<S: Send + Sync> FromRequestParts<S> for RequestIp {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut axum::http::request::Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    get_ip_from_headers_and_extensions(
      &parts.headers,
      &parts.extensions,
      TrustedProxies::from_extensions(&parts.extensions),
    )
    .map(RequestIp)
  }
}

/// [get_client_ip] with the socket peer taken from the
/// `ConnectInfo<SocketAddr>` request extension.
pub fn get_ip_from_headers_and_extensions(
  headers: &HeaderMap,
  extensions: &Extensions,
  trusted_proxies: &TrustedProxies,
) -> mogh_error::Result<IpAddr> {
  let peer = extensions
    .get::<ConnectInfo<SocketAddr>>()
    .map(|info| info.0.ip());
  get_client_ip(headers, peer, trusted_proxies)
}

/// Determine the client ip from the socket `peer` and
/// forwarding headers, according to `trusted_proxies`:
///
/// 1. If the peer is not a trusted proxy, the peer is the client
///    and headers are ignored.
/// 2. Otherwise `X-Forwarded-For` is walked right to left (across
///    all header instances, the last one being the nearest), and
///    the first entry which is not a trusted proxy is the client.
///    If every entry is trusted, the leftmost is used.
/// 3. Otherwise, when `X-Forwarded-For` has no entries, `X-Real-IP`
///    is walked the same way. A proxy which adds its own
///    `X-Real-IP` line after a client-sent one is nearer, so its
///    line wins rather than the first (except under
///    [TrustedProxies::All], where the first line is used).
/// 4. Otherwise the peer is the client.
///
/// ⚠️ A client-sent `X-Forwarded-For` which a trusted proxy passes
/// through takes precedence over the proxy's `X-Real-IP`, so the
/// proxy must append to (or overwrite) `X-Forwarded-For`, see the
/// [crate docs](crate#what-the-trusted-proxy-must-do).
///
/// The first request from a peer which is not trusted but sends
/// forwarding headers is logged as a warning (once per process),
/// naming the peer and the trusted proxies: when the peer is the
/// reverse proxy, every client is seen as the proxy, see the
/// [crate docs](crate#a-list-which-misses-the-proxy). The headers
/// are ignored all the same.
///
/// Errors with `401 Unauthorized` when the peer is unknown (no
/// `ConnectInfo`, ie the app is not served with
/// `into_make_service_with_connect_info`) and the policy is not
/// [TrustedProxies::All], or when a header value from a trusted
/// proxy is malformed (not valid UTF-8, or an entry which must be
/// examined is not an ip). Under [TrustedProxies::All], malformed
/// values and entries are skipped instead, matching the legacy
/// behavior of only reading the leftmost entry.
pub fn get_client_ip(
  headers: &HeaderMap,
  peer: Option<IpAddr>,
  trusted_proxies: &TrustedProxies,
) -> mogh_error::Result<IpAddr> {
  client_ip(
    headers,
    peer,
    trusted_proxies,
    &IGNORED_FORWARDING_LOGGED,
  )
}

/// Whether ignored forwarding headers were logged, see
/// [log_ignored_forwarding].
static IGNORED_FORWARDING_LOGGED: Once = Once::new();

/// [get_client_ip], logging ignored forwarding headers once per
/// `logged`.
fn client_ip(
  headers: &HeaderMap,
  peer: Option<IpAddr>,
  trusted_proxies: &TrustedProxies,
  logged: &Once,
) -> mogh_error::Result<IpAddr> {
  let peer = peer.map(|ip| ip.to_canonical());

  let peer_trusted = match (trusted_proxies, peer) {
    (TrustedProxies::All, _) => true,
    // The peer cannot be verified, so its headers cannot be trusted.
    (_, None) => false,
    (trusted, Some(peer)) => trusted.trusts(peer),
  };

  if !peer_trusted {
    if let Some(peer) = peer
      && (headers.contains_key("x-forwarded-for")
        || headers.contains_key("x-real-ip"))
    {
      log_ignored_forwarding(logged, peer, trusted_proxies);
    }
    return peer
      .context("No socket peer address available for the request (serve the app with 'into_make_service_with_connect_info', eg via mogh_server::serve_app), and forwarding headers cannot be trusted without one.")
      .status_code(StatusCode::UNAUTHORIZED);
  }

  // Under `All` malformed header values / entries are skipped,
  // otherwise they fail closed: a trusted proxy sent something
  // which cannot be attributed, so nothing left of it is either.
  let lenient = matches!(trusted_proxies, TrustedProxies::All);

  // X-Real-IP is only a fallback for proxies which don't
  // set X-Forwarded-For.
  for (name, label) in [
    ("x-forwarded-for", "X-Forwarded-For"),
    ("x-real-ip", "X-Real-IP"),
  ] {
    if let Some(ip) = walk_forwarding_header(
      headers,
      name,
      label,
      trusted_proxies,
      lenient,
    )? {
      return Ok(ip);
    }
  }

  peer
    .context("No socket peer address available for the request, and no forwarding headers were sent.")
    .status_code(StatusCode::UNAUTHORIZED)
}

/// Logs, once per `logged`, that the forwarding headers of a request
/// from `peer`, which is not a trusted proxy, were ignored.
///
/// They are rightly ignored when a client sent them itself. But when
/// `peer` is the reverse proxy, the trusted proxies miss it (a list
/// naming another address, `none` behind a proxy, a proxy outside
/// the private ranges of the default) and every client is seen as
/// the proxy: all of them share one rate limit budget, and match ip
/// whitelists as the proxy's ip. Nothing else would tell. Once per
/// process is enough to notice, and keeps clients sending the
/// headers themselves from filling the log. The header values are
/// not logged: a client chose them.
fn log_ignored_forwarding(
  logged: &Once,
  peer: IpAddr,
  trusted_proxies: &TrustedProxies,
) {
  logged.call_once(|| {
    let trusted = match trusted_proxies {
      TrustedProxies::None => String::from("none"),
      TrustedProxies::All => String::from("all"),
      TrustedProxies::Cidrs(set) => set
        .networks()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", "),
    };
    tracing::warn!(
      "Ignored the X-Forwarded-For / X-Real-IP headers of a request from {peer}, which is not a trusted proxy (trusted_proxies: {trusted}). If {peer} is a reverse proxy in front of this server, add its address to trusted_proxies: until then every client is seen as {peer}, sharing one rate limit budget and matching ip whitelists as the proxy. Logged once"
    );
  });
}

/// Walk a forwarding header from the nearest hop back to the
/// client, across possibly multiple header instances (each a comma
/// separated list, the last instance added by the nearest proxy).
/// Returns the first entry which is not a trusted proxy, else the
/// leftmost entry, or `None` when the header has no entries.
fn walk_forwarding_header(
  headers: &HeaderMap,
  name: &str,
  label: &str,
  trusted_proxies: &TrustedProxies,
  lenient: bool,
) -> mogh_error::Result<Option<IpAddr>> {
  let mut leftmost = None;
  for value in headers.get_all(name).iter().rev() {
    let value = match value.to_str() {
      Ok(value) => value,
      Err(_) if lenient => continue,
      Err(_) => {
        return Err(
          anyhow!("{label} header is not valid UTF-8")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }
    };
    for entry in value.split(',').map(str::trim).rev() {
      if entry.is_empty() {
        continue;
      }
      let ip = match parse_forwarded_ip(entry) {
        Ok(ip) => ip,
        Err(_) if lenient => continue,
        Err(e) => return Err(e),
      };
      if !trusted_proxies.trusts(ip) {
        return Ok(Some(ip));
      }
      leftmost = Some(ip);
    }
  }
  Ok(leftmost)
}

/// Parse a forwarding header entry as an ip, tolerating
/// a port suffix (`1.2.3.4:5678`, `[::1]:5678`) which
/// some proxies include.
fn parse_forwarded_ip(entry: &str) -> mogh_error::Result<IpAddr> {
  if let Ok(ip) = entry.parse::<IpAddr>() {
    return Ok(ip.to_canonical());
  }
  if let Ok(addr) = entry.parse::<SocketAddr>() {
    return Ok(addr.ip().to_canonical());
  }
  Err(
    anyhow!("Invalid ip address '{entry}' in forwarding header")
      .status_code(StatusCode::UNAUTHORIZED),
  )
}

#[cfg(test)]
mod tests {
  use axum::http::HeaderValue;

  use super::*;

  fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
  }

  fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
      headers.append(*name, HeaderValue::from_str(value).unwrap());
    }
    headers
  }

  fn proxies(entries: &[&str]) -> TrustedProxies {
    TrustedProxies::parse(entries).unwrap()
  }

  const PROXY: &str = "10.0.0.1";
  const CLIENT: &str = "203.0.113.7";

  #[test]
  fn untrusted_peer_ignores_headers() {
    // Client connects directly and claims to be someone else.
    let h = headers(&[
      ("x-forwarded-for", "1.1.1.1"),
      ("x-real-ip", "2.2.2.2"),
    ]);
    let trusted = proxies(&["10.0.0.0/8"]);
    assert_eq!(
      get_client_ip(&h, Some(ip(CLIENT)), &trusted).unwrap(),
      ip(CLIENT)
    );
    assert_eq!(
      get_client_ip(&h, Some(ip(CLIENT)), &TrustedProxies::None)
        .unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn trusted_peer_uses_last_untrusted_forwarded_for() {
    let trusted = proxies(&["10.0.0.0/8"]);
    // Client injected a spoofed entry, proxy appended the real one.
    let h = headers(&[("x-forwarded-for", "1.1.1.1, 203.0.113.7")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Two trusted proxy hops after the client.
    let h = headers(&[(
      "x-forwarded-for",
      "1.1.1.1, 203.0.113.7, 10.0.0.2",
    )]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Spread over multiple header instances.
    let h = headers(&[
      ("x-forwarded-for", "1.1.1.1"),
      ("x-forwarded-for", "203.0.113.7, 10.0.0.2"),
    ]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn all_hops_trusted_uses_leftmost() {
    let trusted = proxies(&["10.0.0.0/8"]);
    let h = headers(&[("x-forwarded-for", "10.0.0.5, 10.0.0.2")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip("10.0.0.5")
    );
  }

  #[test]
  fn trusted_peer_falls_back_to_real_ip_then_peer() {
    let trusted = proxies(&["10.0.0.0/8"]);
    let h = headers(&[("x-real-ip", " 203.0.113.7 ")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Empty forwarding headers fall through.
    let h = headers(&[("x-forwarded-for", " , "), ("x-real-ip", "")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(PROXY)
    );
    assert_eq!(
      get_client_ip(&HeaderMap::new(), Some(ip(PROXY)), &trusted)
        .unwrap(),
      ip(PROXY)
    );
  }

  #[test]
  fn real_ip_instances_are_walked_from_the_nearest() {
    let trusted = proxies(&["10.0.0.0/8"]);
    // The client sent its own line and the proxy added the real
    // one after it (eg HAProxy `http-request add-header`).
    let h =
      headers(&[("x-real-ip", "10.9.9.9"), ("x-real-ip", CLIENT)]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // The same, merged into one comma separated line.
    let h = headers(&[("x-real-ip", "10.9.9.9, 203.0.113.7")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Two proxies each adding a line, the nearer one is trusted.
    let h =
      headers(&[("x-real-ip", CLIENT), ("x-real-ip", "10.0.0.2")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Every line from a trusted hop: the leftmost.
    let h = headers(&[
      ("x-real-ip", "10.0.0.5"),
      ("x-real-ip", "10.0.0.2"),
    ]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip("10.0.0.5")
    );
    // A malformed line which must be examined fails closed.
    let h =
      headers(&[("x-real-ip", CLIENT), ("x-real-ip", "unknown")]);
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn forwarded_for_takes_precedence_over_real_ip() {
    let trusted = proxies(&["10.0.0.0/8"]);
    // A proxy which only sets X-Real-IP passes the client's own
    // X-Forwarded-For through, which wins. Documented: the proxy
    // must append to (or overwrite) X-Forwarded-For.
    let h = headers(&[
      ("x-forwarded-for", "10.0.0.7"),
      ("x-real-ip", CLIENT),
    ]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip("10.0.0.7")
    );
    // Once the proxy appends to X-Forwarded-For, the client's
    // entry is never examined.
    let h = headers(&[
      ("x-forwarded-for", "10.0.0.7, 203.0.113.7"),
      ("x-real-ip", CLIENT),
    ]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn unknown_peer_is_unauthorized_unless_all_trusted() {
    let h = headers(&[("x-forwarded-for", CLIENT)]);
    let err =
      get_client_ip(&h, None, &proxies(&["10.0.0.0/8"])).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let err =
      get_client_ip(&h, None, &TrustedProxies::None).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // Legacy behavior: headers believed without a peer.
    assert_eq!(
      get_client_ip(&h, None, &TrustedProxies::All).unwrap(),
      ip(CLIENT)
    );
    let err =
      get_client_ip(&HeaderMap::new(), None, &TrustedProxies::All)
        .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn all_trusted_takes_leftmost_forwarded_for() {
    let h = headers(&[("x-forwarded-for", "1.2.3.4, 10.0.0.1")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip("1.2.3.4")
    );
    // Behind a public proxy which appends, the leftmost entry is
    // the client's own claim (documented on `All`) ...
    let public_proxy = Some(ip("198.51.100.50"));
    let h = headers(&[("x-forwarded-for", "10.0.0.1, 203.0.113.7")]);
    assert_eq!(
      get_client_ip(&h, public_proxy, &TrustedProxies::All).unwrap(),
      ip("10.0.0.1")
    );
    // ... while listing the proxy address takes the entry it added.
    assert_eq!(
      get_client_ip(&h, public_proxy, &proxies(&["198.51.100.50"]))
        .unwrap(),
      ip(CLIENT)
    );
    // X-Real-IP lines likewise: the first one (legacy).
    let h =
      headers(&[("x-real-ip", "1.2.3.4"), ("x-real-ip", CLIENT)]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip("1.2.3.4")
    );
  }

  #[test]
  fn malformed_header_from_trusted_peer_fails_closed() {
    let trusted = proxies(&["10.0.0.0/8"]);
    // Not valid UTF-8: must not fall through to the peer address,
    // which would satisfy an "internal only" whitelist.
    let mut h = HeaderMap::new();
    h.append(
      "x-forwarded-for",
      HeaderValue::from_bytes(b"\xff, 203.0.113.7").unwrap(),
    );
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let mut h = HeaderMap::new();
    h.append("x-real-ip", HeaderValue::from_bytes(b"\xff").unwrap());
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // From an untrusted peer the headers are simply ignored.
    assert_eq!(
      get_client_ip(&h, Some(ip(CLIENT)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Under `All` malformed values are skipped.
    let mut h = HeaderMap::new();
    h.append(
      "x-forwarded-for",
      HeaderValue::from_bytes(b"\xff").unwrap(),
    );
    h.append("x-forwarded-for", HeaderValue::from_static(CLIENT));
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn all_skips_unparseable_entries() {
    // Legacy leniency: proxies like Apache may emit 'unknown'.
    let h = headers(&[("x-forwarded-for", "203.0.113.7, unknown")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip(CLIENT)
    );
    let h = headers(&[("x-forwarded-for", "unknown")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip(PROXY)
    );
    let h = headers(&[("x-real-ip", "unknown")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &TrustedProxies::All)
        .unwrap(),
      ip(PROXY)
    );
  }

  #[test]
  fn invalid_examined_entry_is_unauthorized() {
    let trusted = proxies(&["10.0.0.0/8"]);
    let h = headers(&[("x-forwarded-for", "not-an-ip")]);
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let h = headers(&[("x-forwarded-for", "203.0.113.7, unknown")]);
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let h = headers(&[("x-real-ip", "not-an-ip")]);
    let err =
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    // A garbage entry left of the real client is never examined.
    let h = headers(&[("x-forwarded-for", "garbage, 203.0.113.7")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    // Garbage from an untrusted peer is ignored entirely.
    let h = headers(&[("x-forwarded-for", "garbage")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(CLIENT)), &trusted).unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn ports_and_mapped_ipv6_are_tolerated() {
    let trusted = proxies(&["10.0.0.0/8"]);
    let h = headers(&[("x-forwarded-for", "203.0.113.7:4567")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip(CLIENT)
    );
    let h = headers(&[("x-forwarded-for", "[2001:db8::1]:4567")]);
    assert_eq!(
      get_client_ip(&h, Some(ip(PROXY)), &trusted).unwrap(),
      ip("2001:db8::1")
    );
    // Dual-stack socket reports the proxy as ipv4-mapped ipv6.
    let h = headers(&[("x-forwarded-for", CLIENT)]);
    assert_eq!(
      get_client_ip(&h, Some(ip("::ffff:10.0.0.1")), &trusted)
        .unwrap(),
      ip(CLIENT)
    );
    // Mapped client addresses are canonicalized.
    assert_eq!(
      get_client_ip(
        &HeaderMap::new(),
        Some(ip("::ffff:203.0.113.7")),
        &trusted
      )
      .unwrap(),
      ip(CLIENT)
    );
  }

  #[test]
  fn default_policy_trusts_private_ranges_only() {
    let trusted = TrustedProxies::default();
    for peer in [
      "127.0.0.1",
      "::1",
      "10.1.1.1",
      "172.16.0.1",
      "192.168.1.1",
      "fd12::1",
    ] {
      assert!(trusted.trusts(ip(peer)), "{peer}");
    }
    for peer in ["8.8.8.8", "172.32.0.1", "2001:db8::1", "100.64.0.1"]
    {
      assert!(!trusted.trusts(ip(peer)), "{peer}");
    }
    assert_eq!(
      TrustedProxies::parse(Vec::<String>::new()).unwrap(),
      TrustedProxies::None
    );
    assert!(TrustedProxies::parse(["garbage"]).is_err());
  }

  #[test]
  fn default_policy_believes_any_private_peer() {
    // A public client published through Docker's userland proxy
    // arrives from the bridge gateway, so the default believes the
    // header it sent (documented on `TrustedProxies::default`).
    let gateway = Some(ip("172.17.0.1"));
    let h = headers(&[("x-forwarded-for", "10.0.0.7")]);
    assert_eq!(
      get_client_ip(&h, gateway, &TrustedProxies::default()).unwrap(),
      ip("10.0.0.7")
    );
    // Narrowed to the proxy container's address it is not, while
    // the proxy itself still is.
    let narrowed =
      TrustedProxies::from_config(["172.18.0.5"]).unwrap();
    assert_eq!(
      get_client_ip(&h, gateway, &narrowed).unwrap(),
      ip("172.17.0.1")
    );
    assert_eq!(
      get_client_ip(&h, Some(ip("172.18.0.5")), &narrowed).unwrap(),
      ip("10.0.0.7")
    );
    // Nothing in front of the app: never believed.
    assert_eq!(
      get_client_ip(&h, gateway, &TrustedProxies::None).unwrap(),
      ip("172.17.0.1")
    );
  }

  #[test]
  fn from_config_keywords_and_cidrs() {
    assert_eq!(
      TrustedProxies::from_config(Vec::<String>::new()).unwrap(),
      TrustedProxies::private()
    );
    assert_eq!(
      TrustedProxies::from_config(["", " "]).unwrap(),
      TrustedProxies::private()
    );
    assert_eq!(
      TrustedProxies::from_config(["ALL"]).unwrap(),
      TrustedProxies::All
    );
    assert_eq!(
      TrustedProxies::from_config(["none"]).unwrap(),
      TrustedProxies::None
    );
    assert!(
      TrustedProxies::from_config(["none", "10.0.0.0/8"]).is_err()
    );
    assert!(TrustedProxies::from_config(["none", "all"]).is_err());
    assert!(
      TrustedProxies::from_config(["all", "10.0.0.0/8"]).is_err()
    );
    assert!(TrustedProxies::from_config(["garbage", "all"]).is_err());
    assert!(TrustedProxies::from_config(["garbage"]).is_err());
    let mixed =
      TrustedProxies::from_config(["Private", "203.0.113.10"])
        .unwrap();
    assert!(mixed.trusts(ip("10.1.1.1")));
    assert!(mixed.trusts(ip("203.0.113.10")));
    assert!(!mixed.trusts(ip("203.0.113.11")));
    let only =
      TrustedProxies::from_config(["203.0.113.0/24"]).unwrap();
    assert!(only.trusts(ip("203.0.113.10")));
    assert!(!only.trusts(ip("10.1.1.1")));
  }

  #[test]
  fn from_extensions_falls_back_to_default() {
    assert_eq!(
      TrustedProxies::from_extensions(&Extensions::new()),
      &TrustedProxies::private()
    );
    let mut extensions = Extensions::new();
    extensions.insert(TrustedProxies::None);
    assert_eq!(
      TrustedProxies::from_extensions(&extensions),
      &TrustedProxies::None
    );
  }

  #[test]
  fn extensions_socket_addr_is_peer() {
    let mut extensions = Extensions::new();
    extensions.insert(ConnectInfo::<SocketAddr>(
      "203.0.113.7:1234".parse().unwrap(),
    ));
    let h = headers(&[("x-forwarded-for", "1.1.1.1")]);
    // Public peer: headers ignored.
    assert_eq!(
      get_ip_from_headers_and_extensions(
        &h,
        &extensions,
        &TrustedProxies::default()
      )
      .unwrap(),
      ip(CLIENT)
    );
    let err = get_ip_from_headers_and_extensions(
      &HeaderMap::new(),
      &Extensions::new(),
      &TrustedProxies::default(),
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  /// A writer the log lines are captured into.
  #[derive(Clone, Default)]
  struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

  impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
      self.0.lock().unwrap().extend_from_slice(buf);
      Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
      Ok(())
    }
  }

  impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Captured {
      self.clone()
    }
  }

  /// Forwarding headers from a peer which is not a trusted proxy are
  /// ignored, as before, and the first such request is logged: when
  /// the peer is the reverse proxy, the trusted proxies miss it and
  /// every client is seen as the proxy, which nothing else tells.
  /// Once (per process), naming the peer and the trusted proxies,
  /// never the header values a client chose.
  #[test]
  fn ignored_forwarding_headers_are_logged_once() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
      .with_writer(captured.clone())
      .with_ansi(false)
      .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let log = || {
      String::from_utf8(captured.0.lock().unwrap().clone()).unwrap()
    };

    // Komodo behind nginx at 172.18.0.7, configured with another
    // address.
    let trusted = proxies(&["172.18.0.5"]);
    let nginx = ip("172.18.0.7");
    let logged = Once::new();
    // Nothing to log: no headers, a trusted peer, no peer.
    let forwarded = headers(&[("x-forwarded-for", "203.0.113.7")]);
    for (headers, peer) in [
      (HeaderMap::new(), Some(nginx)),
      (forwarded.clone(), Some(ip("172.18.0.5"))),
      (forwarded.clone(), None),
    ] {
      let _ = client_ip(&headers, peer, &trusted, &logged);
    }
    assert_eq!(log(), "");

    for (name, value) in [
      ("x-forwarded-for", "203.0.113.7"),
      ("x-real-ip", "198.51.100.9"),
    ] {
      let headers = headers(&[(name, value)]);
      // Ignored, as before.
      assert_eq!(
        client_ip(&headers, Some(nginx), &trusted, &logged).unwrap(),
        nginx
      );
    }
    assert_eq!(
      client_ip(
        &forwarded,
        Some(ip("203.0.113.50")),
        &TrustedProxies::None,
        &logged
      )
      .unwrap(),
      ip("203.0.113.50")
    );
    let log = log();
    let lines = log.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "{log}");
    assert!(lines[0].contains("WARN"), "{log}");
    assert!(lines[0].contains("172.18.0.7"), "{log}");
    assert!(
      lines[0].contains("trusted_proxies: 172.18.0.5/32"),
      "{log}"
    );
    for value in ["203.0.113.7", "198.51.100.9", "203.0.113.50"] {
      assert!(!log.contains(value), "{log}");
    }

    // `none` names itself, the default its ranges.
    for (trusted, named) in [
      (TrustedProxies::None, "trusted_proxies: none"),
      (
        TrustedProxies::default(),
        "trusted_proxies: 127.0.0.0/8, ::1/128, 10.0.0.0/8",
      ),
    ] {
      let captured = Captured::default();
      let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
      let _guard = tracing::subscriber::set_default(subscriber);
      let _ = client_ip(
        &forwarded,
        Some(ip("203.0.113.50")),
        &trusted,
        &Once::new(),
      );
      let log = String::from_utf8(captured.0.lock().unwrap().clone())
        .unwrap();
      assert!(log.contains(named), "{log}");
    }
  }

  #[tokio::test]
  async fn request_ip_extractor() {
    // Private peer with default policy: headers believed.
    let request = axum::http::Request::builder()
      .uri("/")
      .header("x-forwarded-for", CLIENT)
      .extension(ConnectInfo::<SocketAddr>(
        "10.0.0.1:1234".parse().unwrap(),
      ))
      .body(())
      .unwrap();
    let (mut parts, _) = request.into_parts();
    let RequestIp(extracted) =
      RequestIp::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(extracted, ip(CLIENT));

    // Policy from extension overrides the default.
    let request = axum::http::Request::builder()
      .uri("/")
      .header("x-forwarded-for", CLIENT)
      .extension(ConnectInfo::<SocketAddr>(
        "10.0.0.1:1234".parse().unwrap(),
      ))
      .extension(TrustedProxies::None)
      .body(())
      .unwrap();
    let (mut parts, _) = request.into_parts();
    let RequestIp(extracted) =
      RequestIp::from_request_parts(&mut parts, &())
        .await
        .unwrap();
    assert_eq!(extracted, ip("10.0.0.1"));

    // Conversions
    assert_eq!(IpAddr::from(RequestIp(ip(CLIENT))), ip(CLIENT));
    assert_eq!(RequestIp::from(ip("::1")).0, ip("::1"));
  }
}
