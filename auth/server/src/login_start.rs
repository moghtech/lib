//! Limits how many external logins (and links) each client can
//! start, and how many login sessions each user can begin.
//!
//! Starting an external login (`/{oidc|github|google}/login`,
//! `/external/{slug}/login`) needs no credentials, and creates a
//! login session holding its state until the provider's callback.
//! Session stores are bounded: `mogh_server`'s in memory store drops
//! the sessions closest to expiry once it is full, which is where a
//! flood of login starts would push out the logins of real users (at
//! the provider, or waiting for their second factor). So each client
//! ip (IPv6 per `/64`) can start [LoginStartLimiter::client_limit]
//! logins at once, then one more every `window / limit`: a token
//! bucket, refilled evenly over the window. The `/64`s of an IPv6
//! `/48` also share a bucket of [IPV6_SITE_MULTIPLIER] times that,
//! as one client may hold a whole `/48` (or a `/56`), which would
//! otherwise be 65,536 clients.
//!
//! The link routes (`.../link`) count too, though they create no
//! session: they continue the one `BeginExternalLoginLink` created.
//!
//! These routes are plain GETs, which any web page can make a browser
//! send (eg. as an image), from the browser's ip. Such a request
//! can't start a login anyways, only a navigation to the route can,
//! so a browser request which isn't one ([embedded_request]) is
//! refused (`403`) before it counts or starts anything: other sites
//! can't use up the allowance of the ip their visitors share.
//!
//! The auth management requests which create a login session
//! (beginning a link, or a passkey / TOTP enrollment) are for logged
//! in users only, so they are limited per user instead:
//! [LoginStartLimiter::user_limit] at once, refilled over the same
//! window.
//!
//! A refused start is `429 Too Many Requests` with `Retry-After`. The
//! external login routes send it to the login page like their other
//! failures, when the app configures one
//! ([AuthImpl::external_login_error_redirect][crate::AuthImpl::external_login_error_redirect]).

use std::{
  collections::HashMap,
  hash::Hash,
  net::{IpAddr, Ipv6Addr},
  sync::{Mutex, MutexGuard, PoisonError},
  time::{Duration, Instant},
};

use anyhow::anyhow;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use mogh_error::AddStatusCodeError as _;

/// The IPv6 prefix a client is counted by: a single client
/// usually controls a whole `/64`.
const IPV6_PREFIX_LEN: u32 = 64;

/// The IPv6 prefix whose clients also share a bucket: a site (or
/// a server) is commonly delegated a `/48` or a `/56`.
const IPV6_SITE_PREFIX_LEN: u32 = 48;

/// How many times [LoginStartLimiter::client_limit] an IPv6 `/48`
/// can start. With the defaults, a `/48` can start 480 logins at
/// once plus 8 per second.
pub const IPV6_SITE_MULTIPLIER: u32 = 16;

/// The limits of starting external logins per client, and login
/// sessions per user. See the [module](self).
///
/// Built once, eg. in a static, and returned by
/// [AuthImpl::login_start_limiter][crate::AuthImpl::login_start_limiter].
pub struct LoginStartLimiter {
  clients: StartLimiter<BucketKey>,
  users: StartLimiter<String>,
}

impl Default for LoginStartLimiter {
  /// [Self::DEFAULT_CLIENT_LIMIT] and [Self::DEFAULT_USER_LIMIT]
  /// over [Self::DEFAULT_WINDOW].
  fn default() -> LoginStartLimiter {
    LoginStartLimiter::new(
      Self::DEFAULT_CLIENT_LIMIT,
      Self::DEFAULT_USER_LIMIT,
      Self::DEFAULT_WINDOW,
    )
  }
}

impl LoginStartLimiter {
  /// How many external logins a client can start at once by
  /// default: plenty for a person (or an office behind one NAT)
  /// logging in, retrying or switching accounts.
  pub const DEFAULT_CLIENT_LIMIT: u32 = 30;

  /// How many login sessions a user can begin at once by default:
  /// plenty for retrying an enrollment.
  pub const DEFAULT_USER_LIMIT: u32 = 10;

  /// The default window the allowances refill over: by default one
  /// more login start every 2 seconds, and one more session of a
  /// user every 6.
  pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

  /// The most clients, and users, tracked. Beyond it, those whose
  /// allowance is full again are dropped first, then those closest
  /// to it, which start over with a full allowance: memory stays
  /// bounded however many addresses a flood comes from.
  pub const MAX_TRACKED: usize = 100_000;

  /// `client_limit` external login (or link) starts per client ip
  /// (IPv6 per `/64`, and [IPV6_SITE_MULTIPLIER] times that per
  /// `/48`) and `user_limit` login sessions per user at once, each
  /// refilled evenly over `window`. A limit of `0`, or a zero
  /// `window`, disables it.
  pub fn new(
    client_limit: u32,
    user_limit: u32,
    window: Duration,
  ) -> LoginStartLimiter {
    LoginStartLimiter {
      clients: StartLimiter::new(
        client_limit,
        window,
        Self::MAX_TRACKED,
      ),
      users: StartLimiter::new(user_limit, window, Self::MAX_TRACKED),
    }
  }

  /// Nothing is limited.
  pub fn disabled() -> LoginStartLimiter {
    LoginStartLimiter::new(0, 0, Duration::ZERO)
  }

  /// How many external logins a client can start at once.
  pub fn client_limit(&self) -> u32 {
    self.clients.limit
  }

  /// How many login sessions a user can begin at once.
  pub fn user_limit(&self) -> u32 {
    self.users.limit
  }

  /// The window the allowances refill over.
  pub fn window(&self) -> Duration {
    self.clients.window
  }

  /// Takes one external login (or link) start of the client at `ip`,
  /// or refuses it with `429 Too Many Requests` and `Retry-After`.
  pub fn take_client_start(
    &self,
    ip: IpAddr,
  ) -> mogh_error::Result<()> {
    self
      .clients
      .take_at(ip, Instant::now())
      .map_err(|retry_in| {
        too_many(
          "Too many logins started from this address.",
          retry_in,
        )
      })
  }

  /// Takes one login session of the user `user_id` (a link, or a
  /// passkey / TOTP enrollment, begun), or refuses it with `429 Too
  /// Many Requests` and `Retry-After`.
  pub fn take_user_start(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<()> {
    self
      .users
      .take_key_at(user_id.to_string(), Instant::now())
      .map_err(|retry_in| {
        too_many(
          "Too many links or 2FA enrollments started.",
          retry_in,
        )
      })
  }
}

/// Whether a browser sent the request for anything but navigating to
/// it (`Sec-Fetch-Mode` other than `navigate`, eg. an image or
/// `fetch`), or navigating a frame of another page (`Sec-Fetch-Dest`
/// other than `document`), unless the request comes from the app's
/// own origin (`Sec-Fetch-Site`). Only a navigation can complete a
/// login, so such a request is another site (or an ad) sending it
/// from the browser of its visitor.
///
/// Browsers send these headers to https origins (and localhost). Over
/// plain http, or from other clients, requests are never refused here.
pub fn embedded_request(headers: &HeaderMap) -> bool {
  let get = |name: &str| {
    headers.get(name).and_then(|value| value.to_str().ok())
  };
  match get("sec-fetch-site") {
    // Not a browser, or one which doesn't tell.
    None => return false,
    // The app itself, or the user (typed url, bookmark).
    Some("same-origin" | "none") => return false,
    // `same-site` too: another app on a sibling subdomain.
    Some(_) => {}
  }
  get("sec-fetch-mode").is_some_and(|mode| mode != "navigate")
    || get("sec-fetch-dest").is_some_and(|dest| dest != "document")
}

/// The refusal of an [embedded_request], starting nothing.
pub(crate) fn embedded_refused() -> mogh_error::Error {
  anyhow!(
    "A login can only be started by opening this page, not from within another site"
  )
  .status_code(StatusCode::FORBIDDEN)
}

/// The whole seconds to wait, rounded up, at least one.
fn retry_secs(retry_in: Duration) -> u64 {
  (retry_in.as_secs() + u64::from(retry_in.subsec_nanos() > 0)).max(1)
}

/// `429 Too Many Requests` saying `what`, with `Retry-After`.
fn too_many(what: &str, retry_in: Duration) -> mogh_error::Error {
  let secs = retry_secs(retry_in);
  anyhow!("{what} Try again in {secs} seconds.")
    .status_code(StatusCode::TOO_MANY_REQUESTS)
    .header(header::RETRY_AFTER, HeaderValue::from(secs))
}

/// A bucket: the network address and prefix length of a client (an
/// IPv4 address, or an IPv6 `/64`), or of the IPv6 `/48` of clients.
type BucketKey = (IpAddr, u32);

/// A token bucket per client (`K`): `limit` starts at once, refilled
/// evenly over `window`. For ips ([BucketKey]), also one per IPv6
/// `/48` of [IPV6_SITE_MULTIPLIER] times that. A start takes from
/// each bucket of the client. Holds at most `max_clients` buckets.
struct StartLimiter<K> {
  /// `0` disables the limiter.
  limit: u32,
  window: Duration,
  max_clients: usize,
  /// When each bucket is full again. Buckets
  /// which are full are the same as absent.
  clients: Mutex<HashMap<K, Instant>>,
}

impl StartLimiter<BucketKey> {
  /// Takes one start for the client at `ip`, or returns how long
  /// until it can start the next one.
  fn take_at(
    &self,
    ip: IpAddr,
    now: Instant,
  ) -> Result<(), Duration> {
    self.take_buckets_at(buckets(ip, self.limit), now)
  }
}

impl StartLimiter<String> {
  /// Takes one start for the client `key` (a user id), or returns
  /// how long until it can start the next one.
  fn take_key_at(
    &self,
    key: String,
    now: Instant,
  ) -> Result<(), Duration> {
    self.take_buckets_at([(key, self.limit)], now)
  }
}

impl<K: Clone + Eq + Hash> StartLimiter<K> {
  fn new(limit: u32, window: Duration, max_clients: usize) -> Self {
    StartLimiter {
      limit,
      window,
      max_clients: max_clients.max(1),
      clients: Default::default(),
    }
  }

  fn enabled(&self) -> bool {
    self.limit != 0 && !self.window.is_zero()
  }

  fn clients(&self) -> MutexGuard<'_, HashMap<K, Instant>> {
    // Nothing panics while holding the lock, and the
    // buckets stay valid even if something did.
    self.clients.lock().unwrap_or_else(PoisonError::into_inner)
  }

  /// Takes one start from each of the client's `buckets` (key, and
  /// its limit), or returns how long until it can start the next one.
  fn take_buckets_at(
    &self,
    buckets: impl IntoIterator<Item = (K, u32)>,
    now: Instant,
  ) -> Result<(), Duration> {
    if !self.enabled() {
      return Ok(());
    }
    let mut clients = self.clients();
    // Each bucket must have room, before any is taken from: a start
    // one bucket refuses uses up nothing.
    let mut takes = Vec::with_capacity(2);
    let mut wait = Duration::ZERO;
    for (key, limit) in buckets {
      // How much of the bucket one start uses.
      let cost = self.window / limit;
      let full_at = clients
        .get(&key)
        .copied()
        .filter(|full_at| *full_at > now)
        .unwrap_or(now);
      // The bucket holds `window`: a start which would need
      // more than that is refused until enough refilled.
      let next = full_at + cost;
      let needed = next.duration_since(now);
      if needed > self.window {
        wait = wait.max(needed - self.window);
      }
      takes.push((key, next));
    }
    if !wait.is_zero() {
      return Err(wait);
    }
    for (key, next) in takes {
      if !clients.contains_key(&key)
        && clients.len() >= self.max_clients
      {
        self.make_room(&mut clients, now);
      }
      clients.insert(key, next);
    }
    Ok(())
  }

  /// Makes room for a new client on the full map: drops the clients
  /// whose bucket is full again, then those closest to it (the least
  /// limited) down to 90% of the maximum. A batch at a time keeps
  /// the cost per new client low. Those evicted start over with a
  /// full bucket, which only happens once more clients started
  /// logins recently than the map holds: memory stays bounded however
  /// many addresses a flood comes from, and the session store is
  /// bounded on its own.
  fn make_room(
    &self,
    clients: &mut HashMap<K, Instant>,
    now: Instant,
  ) {
    clients.retain(|_, full_at| *full_at > now);
    let target = self.max_clients - (self.max_clients / 10).max(1);
    let excess = clients.len().saturating_sub(target);
    if excess == 0 {
      return;
    }
    let mut by_full_at = clients
      .iter()
      .map(|(key, full_at)| (*full_at, key.clone()))
      .collect::<Vec<_>>();
    if excess < by_full_at.len() {
      by_full_at
        .select_nth_unstable_by_key(excess - 1, |(full_at, _)| {
          *full_at
        });
    }
    for (_, key) in &by_full_at[..excess] {
      clients.remove(key);
    }
  }
}

/// IPv4 addresses (IPv4-mapped IPv6 ones included) count as they
/// are, IPv6 addresses by their `/64`.
fn client_key(ip: IpAddr) -> IpAddr {
  match ip.to_canonical() {
    IpAddr::V4(ip) => IpAddr::V4(ip),
    IpAddr::V6(ip) => IpAddr::V6(ipv6_prefix(ip, IPV6_PREFIX_LEN)),
  }
}

fn ipv6_prefix(ip: Ipv6Addr, len: u32) -> Ipv6Addr {
  let mask = u128::MAX << (128 - len);
  Ipv6Addr::from_bits(ip.to_bits() & mask)
}

/// The buckets a start from `ip` takes from, with their limit: the
/// client's, and for IPv6 its `/48`'s.
fn buckets(ip: IpAddr, limit: u32) -> Vec<(BucketKey, u32)> {
  match client_key(ip) {
    IpAddr::V4(ip) => vec![((IpAddr::V4(ip), 32), limit)],
    IpAddr::V6(ip) => vec![
      ((IpAddr::V6(ip), IPV6_PREFIX_LEN), limit),
      (
        (
          IpAddr::V6(ipv6_prefix(ip, IPV6_SITE_PREFIX_LEN)),
          IPV6_SITE_PREFIX_LEN,
        ),
        limit.saturating_mul(IPV6_SITE_MULTIPLIER),
      ),
    ],
  }
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;

  use super::*;

  const SECS_60: Duration = Duration::from_secs(60);
  const A: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
  const B: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));

  fn v6(ip: &str) -> IpAddr {
    ip.parse().unwrap()
  }

  fn ip_limiter(
    limit: u32,
    window: Duration,
    max_clients: usize,
  ) -> StartLimiter<BucketKey> {
    StartLimiter::new(limit, window, max_clients)
  }

  /// Each user has their own bucket.
  #[test]
  fn session_starts_are_limited_per_user() {
    let limiter = StartLimiter::<String>::new(
      LoginStartLimiter::DEFAULT_USER_LIMIT,
      SECS_60,
      100,
    );
    let now = Instant::now();
    let user = |id: &str| String::from(id);
    for _ in 0..LoginStartLimiter::DEFAULT_USER_LIMIT {
      limiter.take_key_at(user("a"), now).unwrap();
    }
    assert_eq!(
      limiter.take_key_at(user("a"), now),
      Err(Duration::from_secs(6))
    );
    limiter.take_key_at(user("b"), now).unwrap();
    limiter
      .take_key_at(user("a"), now + Duration::from_secs(6))
      .unwrap();
    let disabled = StartLimiter::<String>::new(0, SECS_60, 100);
    assert!(!disabled.enabled());
    for _ in 0..100 {
      disabled.take_key_at(user("a"), now).unwrap();
    }
  }

  #[test]
  fn clients_are_keyed_by_ipv4_or_ipv6_64() {
    assert_eq!(client_key(A), A);
    // IPv4-mapped IPv6 is the IPv4 client.
    assert_eq!(client_key(v6("::ffff:203.0.113.1")), A);
    assert_eq!(
      client_key(v6("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
      v6("2001:db8:1:2::")
    );
    assert_eq!(
      client_key(v6("2001:db8:1:2::1")),
      client_key(v6("2001:db8:1:2:ffff::"))
    );
    assert_ne!(
      client_key(v6("2001:db8:1:2::1")),
      client_key(v6("2001:db8:1:3::1"))
    );
  }

  #[test]
  fn a_burst_of_limit_starts_then_one_per_refill() {
    let limiter = ip_limiter(30, SECS_60, 100);
    let now = Instant::now();
    for _ in 0..30 {
      limiter.take_at(A, now).unwrap();
    }
    // The 31st waits for one start to refill (60s / 30).
    assert_eq!(limiter.take_at(A, now), Err(Duration::from_secs(2)));
    assert_eq!(
      limiter.take_at(A, now + Duration::from_secs(1)),
      Err(Duration::from_secs(1))
    );
    // Refused starts use up nothing.
    limiter.take_at(A, now + Duration::from_secs(2)).unwrap();
    assert!(
      limiter.take_at(A, now + Duration::from_secs(2)).is_err()
    );
    // Other clients have their own bucket.
    limiter.take_at(B, now).unwrap();
    // After a whole window the bucket is full again.
    let later = now + Duration::from_secs(62);
    for _ in 0..30 {
      limiter.take_at(A, later).unwrap();
    }
    assert!(limiter.take_at(A, later).is_err());
  }

  /// The addresses of one IPv6 `/64` share a bucket.
  #[test]
  fn ipv6_clients_share_their_64() {
    let limiter = ip_limiter(2, SECS_60, 100);
    let now = Instant::now();
    limiter.take_at(v6("2001:db8::1"), now).unwrap();
    limiter.take_at(v6("2001:db8::2"), now).unwrap();
    assert!(limiter.take_at(v6("2001:db8::ffff:3"), now).is_err());
    limiter.take_at(v6("2001:db8:0:1::1"), now).unwrap();
  }

  /// The `/64`s of a `/48` share a bucket of 16 times the limit,
  /// on top of their own.
  #[test]
  fn ipv6_48s_share_a_larger_bucket() {
    let limiter = ip_limiter(2, SECS_60, 1000);
    let now = Instant::now();
    let in_48 = |i: u16| v6(&format!("2001:db8:1:{i:x}::1"));
    for i in 0..16 {
      limiter.take_at(in_48(i), now).unwrap();
      limiter.take_at(in_48(i), now).unwrap();
      // Each /64 has its own limit.
      assert!(limiter.take_at(in_48(i), now).is_err());
    }
    // The /48 used its 32: another /64 in it waits for a refill
    // (60s / 32), others don't.
    assert_eq!(limiter.take_at(in_48(16), now), Err(SECS_60 / 32));
    limiter.take_at(v6("2001:db8:2::1"), now).unwrap();
    // IPv4 clients only have their own.
    for i in 0..100u32 {
      let ip = IpAddr::V4(Ipv4Addr::from_bits(0x0a00_0000 + i));
      limiter.take_at(ip, now).unwrap();
    }
  }

  /// A start the `/48` refuses uses up nothing of the `/64`'s
  /// bucket, and the other way around.
  #[test]
  fn refused_starts_take_from_no_bucket() {
    let limiter = ip_limiter(1, SECS_60, 1000);
    let now = Instant::now();
    limiter.take_at(v6("2001:db8::1"), now).unwrap();
    // The /64 refuses: its /48 keeps 15 of 16.
    for _ in 0..10 {
      assert!(limiter.take_at(v6("2001:db8::1"), now).is_err());
    }
    for i in 1..16u16 {
      limiter
        .take_at(v6(&format!("2001:db8:0:{i:x}::1")), now)
        .unwrap();
    }
    assert!(limiter.take_at(v6("2001:db8:0:ff::1"), now).is_err());
  }

  #[test]
  fn zero_disables() {
    let now = Instant::now();
    for limiter in [
      ip_limiter(0, SECS_60, 100),
      ip_limiter(30, Duration::ZERO, 100),
    ] {
      for _ in 0..1000 {
        limiter.take_at(A, now).unwrap();
      }
      assert!(limiter.clients().is_empty());
    }
    let disabled = LoginStartLimiter::disabled();
    for _ in 0..1000 {
      disabled.take_client_start(A).unwrap();
      disabled.take_user_start("user").unwrap();
    }
  }

  /// The map never holds more than `max_clients`: clients whose
  /// bucket is full again go first, then those closest to it.
  #[test]
  fn clients_are_bounded_evicting_the_least_limited() {
    let limiter = ip_limiter(3, SECS_60, 10);
    let now = Instant::now();
    // A client which used its whole bucket, at the start.
    for _ in 0..3 {
      limiter.take_at(A, now).unwrap();
    }
    let client = |i: u32| IpAddr::V4(Ipv4Addr::from_bits(i));
    for i in 1..=100u32 {
      let at = now + Duration::from_millis(u64::from(i));
      limiter.take_at(client(i), at).unwrap();
      assert!(limiter.clients().len() <= 10, "{i}");
    }
    // The most limited client is still limited.
    assert!(
      limiter
        .take_at(A, now + Duration::from_millis(200))
        .is_err()
    );
    // The most recent clients are kept, the earliest were evicted.
    let clients = limiter.clients();
    assert!(clients.contains_key(&(client(100), 32)));
    assert!(!clients.contains_key(&(client(1), 32)));
    drop(clients);

    // Once their buckets are full again, they are dropped first.
    let later = now + SECS_60 * 2;
    for i in 1000..1009u32 {
      limiter.take_at(client(i), later).unwrap();
    }
    assert!(limiter.clients().len() <= 10);
    assert!(!limiter.clients().contains_key(&(A, 32)));
  }

  /// The refusals are `429` with `Retry-After` in whole seconds,
  /// rounded up.
  #[test]
  fn refused_starts_answer_429_with_retry_after() {
    let limiter = LoginStartLimiter::new(1, 1, SECS_60);
    limiter.take_client_start(A).unwrap();
    let err = limiter.take_client_start(A).unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after =
      &err.headers.as_ref().unwrap()[header::RETRY_AFTER];
    let secs = retry_after.to_str().unwrap().parse::<u64>().unwrap();
    assert!((59..=60).contains(&secs), "{secs}");
    assert_eq!(
      err.error.to_string(),
      format!(
        "Too many logins started from this address. Try again in {secs} seconds."
      )
    );
    // Users have their own buckets, apart from the clients'.
    limiter.take_user_start("user").unwrap();
    let err = limiter.take_user_start("user").unwrap_err();
    assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(err.error.to_string().starts_with("Too many links"));
    limiter.take_user_start("other").unwrap();

    assert_eq!(retry_secs(Duration::from_secs(3)), 3);
    assert_eq!(retry_secs(Duration::from_millis(1500)), 2);
    assert_eq!(retry_secs(Duration::ZERO), 1);
  }

  /// Browser requests which aren't a navigation to the route (eg.
  /// an image on another site) are refused, others go through.
  #[test]
  fn embedded_requests_are_recognized() {
    let request = |headers: &[(&'static str, &'static str)]| {
      let mut map = HeaderMap::new();
      for (name, value) in headers {
        map.insert(*name, HeaderValue::from_static(value));
      }
      embedded_request(&map)
    };
    // Not a browser, or one not sending them (plain http).
    assert!(!request(&[]));
    // Clicking login in the app, or opening a bookmark.
    for site in ["same-origin", "none"] {
      assert!(!request(&[
        ("sec-fetch-site", site),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
      ]));
    }
    // The app navigating a frame it is shown in.
    assert!(!request(&[
      ("sec-fetch-site", "same-origin"),
      ("sec-fetch-mode", "navigate"),
      ("sec-fetch-dest", "iframe"),
    ]));
    // A link from another site, or the UI dev server.
    for site in ["cross-site", "same-site"] {
      assert!(!request(&[
        ("sec-fetch-site", site),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
      ]));
    }
    // Another site loading it as an image, with fetch, or in a frame.
    for (mode, dest) in [
      ("no-cors", "image"),
      ("cors", "empty"),
      ("no-cors", "script"),
      ("navigate", "iframe"),
    ] {
      for site in ["cross-site", "same-site"] {
        assert!(
          request(&[
            ("sec-fetch-site", site),
            ("sec-fetch-mode", mode),
            ("sec-fetch-dest", dest),
          ]),
          "{site} {mode} {dest}"
        );
      }
    }
    assert_eq!(embedded_refused().status, StatusCode::FORBIDDEN);
  }
}
