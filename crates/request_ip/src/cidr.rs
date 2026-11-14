//! CIDR set parsing and matching, used for source ip whitelists
//! and for the set of [trusted proxies][crate::TrustedProxies].
//!
//! Entries may be given in CIDR notation (`10.0.0.0/8`, `fd00::/8`)
//! or as a bare ip address (`10.0.0.1`, `::1`), which matches
//! only that address.
//!
//! ⚠️ A whitelist is only as trustworthy as the request ip.
//! See [TrustedProxies][crate::TrustedProxies] for how forwarding
//! headers are validated before being believed.

use std::net::IpAddr;

use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use ipnet::IpNet;
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};

/// A parsed set of CIDR networks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CidrSet(Vec<IpNet>);

impl CidrSet {
  /// Parse the entries. Entries may be in CIDR notation
  /// or bare ip addresses, and surrounding whitespace is ignored.
  ///
  /// Errors if any entry is invalid.
  pub fn parse<I>(entries: I) -> anyhow::Result<Self>
  where
    I: IntoIterator,
    I::Item: AsRef<str>,
  {
    entries
      .into_iter()
      .map(|entry| parse_cidr(entry.as_ref()))
      .collect::<anyhow::Result<Vec<_>>>()
      .map(CidrSet)
  }

  /// The parsed networks, IPv4-mapped IPv6 ones in their IPv4 form
  /// (see [parse_cidr]).
  pub fn networks(&self) -> &[IpNet] {
    &self.0
  }

  /// Whether the set has no entries.
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }

  /// Whether the ip is within any network in the set.
  /// Always false when the set is empty.
  ///
  /// IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are matched
  /// as their IPv4 form, so a `1.2.3.4/32` entry matches a client
  /// connecting over a dual-stack socket.
  pub fn contains(&self, ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    self.0.iter().any(|net| net.contains(&ip))
  }
}

/// Collects networks parsed elsewhere, canonicalized as
/// [parse_cidr] does: an IPv4-mapped IPv6 network
/// (`::ffff:10.0.0.0/104`) is kept in its IPv4 form, as
/// [CidrSet::contains] matches canonicalized ips and an IPv6
/// network never contains an IPv4 address.
impl FromIterator<IpNet> for CidrSet {
  fn from_iter<T: IntoIterator<Item = IpNet>>(iter: T) -> Self {
    CidrSet(iter.into_iter().map(canonicalize_net).collect())
  }
}

/// Parse a single whitelist entry, in CIDR notation
/// or as a bare ip address (single host network).
///
/// IPv4-mapped IPv6 entries (`::ffff:1.2.3.4`, `::ffff:0:0/96`)
/// are canonicalized to IPv4, matching how ips are checked.
pub fn parse_cidr(entry: &str) -> anyhow::Result<IpNet> {
  let entry = entry.trim();
  if entry.is_empty() {
    return Err(anyhow!("CIDR whitelist entry cannot be empty"));
  }
  let net = if let Ok(net) = entry.parse::<IpNet>() {
    net
  } else {
    entry.parse::<IpAddr>().map(IpNet::from).with_context(|| {
      format!("Invalid CIDR whitelist entry '{entry}'")
    })?
  };
  Ok(canonicalize_net(net))
}

/// Converts an IPv4-mapped IPv6 network (within `::ffff:0:0/96`)
/// to its IPv4 form, so it matches canonicalized ips.
fn canonicalize_net(net: IpNet) -> IpNet {
  if let IpNet::V6(v6) = net
    && v6.prefix_len() >= 96
    && let Some(v4) = v6.addr().to_ipv4_mapped()
    && let Ok(v4) = ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96)
  {
    return IpNet::V4(v4);
  }
  net
}

/// Validate every entry of a whitelist can be parsed,
/// for example when accepting a whitelist from user input.
pub fn validate_cidr_whitelist<I>(entries: I) -> anyhow::Result<()>
where
  I: IntoIterator,
  I::Item: AsRef<str>,
{
  CidrSet::parse(entries).map(|_| ())
}

/// Ensure the request ip is allowed by the whitelist,
/// returning `403 Forbidden` if it is not.
///
/// An empty whitelist allows all ips. A whitelist containing an
/// invalid entry fails closed, returning `500 Internal Server Error`,
/// since the intended restriction cannot be evaluated.
pub fn check_cidr_whitelist<I>(
  ip: IpAddr,
  whitelist: I,
) -> mogh_error::Result<()>
where
  I: IntoIterator,
  I::Item: AsRef<str>,
{
  let whitelist = CidrSet::parse(whitelist)
    .context("Failed to parse CIDR whitelist")
    .status_code(StatusCode::INTERNAL_SERVER_ERROR)?;
  if whitelist.is_empty() || whitelist.contains(ip) {
    Ok(())
  } else {
    Err(
      anyhow!("Request from ip {ip} is not in the CIDR whitelist")
        .status_code(StatusCode::FORBIDDEN),
    )
  }
}

/// Whether the source ip whitelist `new` lets in an address `stored`
/// does not, as [check_cidr_whitelist] applies them: eg. to ask for a
/// recent login before a credential's whitelist is widened.
///
/// - An empty whitelist lets in every address: emptying a non-empty
///   one widens it, and a whitelist replacing an empty one never
///   does.
/// - Otherwise an entry of `new` (a CIDR range or a bare ip) which no
///   entry of `stored` contains widens it. Both sides are read with
///   [parse_cidr], so an IPv4-mapped entry is the IPv4 network it
///   matches at request time: `::ffff:0:0/96` is `0.0.0.0/0`, which
///   `::/0` does not contain (an IPv4 client never matches an IPv6
///   network).
/// - An entry of `new` which doesn't parse widens it (a write refuses
///   it anyway). A `stored` whitelist with an entry which doesn't
///   parse lets nothing in ([check_cidr_whitelist] fails closed on
///   it), so every `new` one widens it.
///
/// Each new entry is judged against the stored entries one by one: a
/// range only several stored entries cover together (`10.0.0.0/8`
/// over `10.0.0.0/9` and `10.128.0.0/9`) counts as widening. It errs
/// that way only, never calling a widening none.
pub fn whitelist_widened<S, N>(stored: &[S], new: &[N]) -> bool
where
  S: AsRef<str>,
  N: AsRef<str>,
{
  if new.is_empty() {
    return !stored.is_empty();
  }
  if stored.is_empty() {
    return false;
  }
  let Ok(stored) = CidrSet::parse(stored) else {
    return true;
  };
  new.iter().any(|entry| match parse_cidr(entry.as_ref()) {
    Ok(net) => {
      !stored.networks().iter().any(|range| range.contains(&net))
    }
    Err(_) => true,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
  }

  #[test]
  fn parses_cidr_and_bare_ips() {
    let whitelist = CidrSet::parse([
      "10.0.0.0/8",
      " 192.168.1.5 ",
      "fd00::/8",
      "::1",
    ])
    .unwrap();
    assert_eq!(whitelist.networks().len(), 4);
    assert_eq!(whitelist.networks()[1].prefix_len(), 32);
    assert_eq!(whitelist.networks()[3].prefix_len(), 128);
  }

  #[test]
  fn rejects_invalid_entries() {
    assert!(parse_cidr("").is_err());
    assert!(parse_cidr("   ").is_err());
    assert!(parse_cidr("not-an-ip").is_err());
    assert!(parse_cidr("10.0.0.0/33").is_err());
    assert!(parse_cidr("10.0.0/8").is_err());
    assert!(CidrSet::parse(["10.0.0.0/8", "garbage"]).is_err());
    assert!(
      validate_cidr_whitelist(["10.0.0.0/8", "garbage"]).is_err()
    );
    assert!(validate_cidr_whitelist(["10.0.0.0/8", "::1"]).is_ok());
    assert!(validate_cidr_whitelist(Vec::<String>::new()).is_ok());
  }

  #[test]
  fn empty_set_contains_nothing_but_empty_whitelist_allows_all() {
    let set = CidrSet::parse(Vec::<String>::new()).unwrap();
    assert!(set.is_empty());
    assert!(!set.contains(ip("1.2.3.4")));
    assert!(!set.contains(ip("::1")));
    assert!(
      check_cidr_whitelist(ip("1.2.3.4"), &[] as &[String]).is_ok()
    );
    assert!(
      check_cidr_whitelist(ip("::1"), &[] as &[String]).is_ok()
    );
  }

  #[test]
  fn matches_networks_and_hosts() {
    let whitelist =
      CidrSet::parse(["10.0.0.0/8", "192.168.1.5", "fd00::/8"])
        .unwrap();
    assert!(whitelist.contains(ip("10.1.2.3")));
    assert!(whitelist.contains(ip("192.168.1.5")));
    assert!(whitelist.contains(ip("fd00::1")));
    assert!(!whitelist.contains(ip("11.0.0.1")));
    assert!(!whitelist.contains(ip("192.168.1.6")));
    assert!(!whitelist.contains(ip("fe80::1")));
  }

  #[test]
  fn host_bits_in_entry_do_not_matter() {
    // 10.1.2.3/8 still describes the 10.0.0.0/8 network.
    let whitelist = CidrSet::parse(["10.1.2.3/8"]).unwrap();
    assert!(whitelist.contains(ip("10.200.0.1")));
    assert!(!whitelist.contains(ip("11.0.0.1")));
  }

  #[test]
  fn ipv4_mapped_ipv6_matches_ipv4_entries() {
    let whitelist = CidrSet::parse(["1.2.3.4"]).unwrap();
    assert!(whitelist.contains(ip("::ffff:1.2.3.4")));
    assert!(!whitelist.contains(ip("::ffff:1.2.3.5")));
  }

  #[test]
  fn ipv4_mapped_ipv6_entries_match_ipv4_ips() {
    let whitelist =
      CidrSet::parse(["::ffff:192.168.1.10", "::ffff:10.0.0.0/104"])
        .unwrap();
    assert!(whitelist.contains(ip("192.168.1.10")));
    assert!(whitelist.contains(ip("::ffff:192.168.1.10")));
    assert!(whitelist.contains(ip("10.5.5.5")));
    assert!(!whitelist.contains(ip("192.168.1.11")));
    assert_eq!(
      whitelist.networks()[1],
      "10.0.0.0/8".parse::<IpNet>().unwrap()
    );
    // A v6 prefix shorter than 96 bits is kept as v6.
    let wide = CidrSet::parse(["::ffff:0:0/64"]).unwrap();
    assert!(matches!(wide.networks()[0], IpNet::V6(_)));
  }

  /// Networks collected into a set (pre-parsed elsewhere) are
  /// canonicalized as parsed entries are: an `IpNet::V6` never
  /// contains an IPv4 address, so a mapped network kept as given
  /// matched no client at all, plain or mapped.
  #[test]
  fn collected_ipv4_mapped_networks_match_ipv4_ips() {
    let entries =
      ["::ffff:10.0.0.0/104", "::ffff:192.168.1.10", "fd00::/8"];
    let collected = entries
      .iter()
      .map(|entry| {
        entry
          .parse::<IpNet>()
          .unwrap_or_else(|_| IpNet::from(ip(entry)))
      })
      .collect::<CidrSet>();
    assert!(collected.contains(ip("10.1.2.3")));
    assert!(collected.contains(ip("::ffff:10.1.2.3")));
    assert!(collected.contains(ip("192.168.1.10")));
    assert!(!collected.contains(ip("192.168.1.11")));
    assert!(collected.contains(ip("fd00::1")));
    // The same set parsing the entries gives.
    assert_eq!(collected, CidrSet::parse(entries).unwrap());
    // So trusted as proxies the same way.
    let proxies = crate::TrustedProxies::Cidrs(collected);
    assert!(proxies.trusts(ip("10.0.0.1")));
    assert!(proxies.trusts(ip("::ffff:10.0.0.1")));
  }

  /// Addresses of both families, plain and IPv4-mapped, in and
  /// around the ranges the widening tests use.
  const SAMPLE_IPS: [&str; 16] = [
    "10.0.0.1",
    "10.1.2.3",
    "10.200.0.1",
    "11.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "192.168.1.2",
    "1.2.3.4",
    "::ffff:10.1.2.3",
    "::ffff:1.2.3.4",
    "::1",
    "fd00::1",
    "fe80::1",
    "2001:db8::1",
    "::",
    "::ffff:0:1",
  ];

  /// [whitelist_widened], checked against [check_cidr_whitelist]: a
  /// list called no widening lets in none of the sample addresses
  /// the stored one doesn't (an expected widening must let one in).
  fn widened(stored: &[&str], new: &[&str]) -> bool {
    let widened = whitelist_widened(stored, new);
    let allowed = |list: &[&str], ip: IpAddr| {
      check_cidr_whitelist(ip, list).is_ok()
    };
    for sample in SAMPLE_IPS {
      let ip = ip(sample);
      if !widened {
        assert!(
          !allowed(new, ip) || allowed(stored, ip),
          "{stored:?} -> {new:?} lets in {sample}, called no widening"
        );
      }
    }
    widened
  }

  /// The cases of the apps' own copies (Komodo's credential.rs,
  /// Cicada's api/write/mod.rs), which this replaces.
  #[test]
  fn whitelists_widen_when_they_let_more_in() {
    let stored = ["10.0.0.0/8", "192.168.1.1"];
    // Emptied: every address. From every address, any list
    // narrows.
    assert!(widened(&stored, &[]));
    assert!(widened(&["10.0.0.0/8"], &[]));
    assert!(!widened(&[], &["10.0.0.0/8"]));
    assert!(!widened(&[], &[]));
    // Narrower, equal, reordered: nothing new gets in.
    assert!(!widened(&stored, &["10.1.0.0/16"]));
    assert!(!widened(&stored, &["10.1.2.3"]));
    assert!(!widened(&stored, &["192.168.1.1", "10.0.0.0/8"]));
    assert!(!widened(&stored, &["192.168.1.1/32"]));
    assert!(!widened(&["10.0.0.0/8"], &["10.1.0.0/16", "10.2.3.4"]));
    assert!(!widened(&["10.0.0.1"], &["10.0.0.1"]));
    assert!(!widened(&["10.0.0.0/8", "fd00::/8"], &["fd00::1"]));
    assert!(!widened(&[" 10.0.0.0/8 "], &["10.1.2.3 "]));
    // A wider range, an address outside, a host of another family.
    assert!(widened(&stored, &["10.0.0.0/7"]));
    assert!(widened(&["10.1.0.0/16"], &["10.0.0.0/8"]));
    assert!(widened(&stored, &["192.168.1.2"]));
    assert!(widened(&stored, &["::1"]));
    assert!(widened(&stored, &["10.0.0.0/8", "172.16.0.0/12"]));
    assert!(widened(&["10.0.0.0/8"], &["10.0.0.0/8", "192.168.1.1"]));
    // What doesn't parse counts as widening.
    assert!(widened(&stored, &["nope"]));
    assert!(widened(&["10.0.0.0/8"], &["not an ip"]));
    assert!(widened(&stored, &[""]));
    // Covered only by two stored ranges together: widening (the
    // safe way to err).
    assert!(widened(
      &["10.0.0.0/9", "10.128.0.0/9"],
      &["10.0.0.0/8"]
    ));
    // As the apps hold them: `Vec<String>`s.
    let stored = vec![String::from("10.0.0.0/8")];
    let new = vec![String::from("10.1.2.3")];
    assert!(!whitelist_widened(&stored, &new));
  }

  /// IPv4-mapped entries are the IPv4 networks they match at request
  /// time, on either side.
  #[test]
  fn ipv4_mapped_entries_widen_as_the_ipv4_networks_they_are() {
    // `::/0` lets in IPv6 clients only: the mapped range is every
    // IPv4 client.
    assert!(widened(&["::/0"], &["::/0", "::ffff:0:0/96"]));
    assert!(widened(&["::/0"], &["::ffff:1.2.3.4"]));
    assert!(widened(&["::/64"], &["::ffff:10.0.0.0/104"]));
    // Within the stored IPv4 network, mapped or not.
    assert!(!widened(&["::ffff:10.0.0.0/104"], &["10.1.2.3"]));
    assert!(!widened(&["10.0.0.0/8"], &["::ffff:10.1.0.0/112"]));
    assert!(!widened(&["0.0.0.0/0"], &["::ffff:0:0/96"]));
    assert!(!widened(&["::ffff:0:0/96"], &["1.2.3.4", "10.0.0.0/8"]));
    // IPv6 networks stay IPv6 (and let in no IPv4 client).
    assert!(!widened(&["::/0"], &["::/64", "fd00::/8"]));
    assert!(widened(&["0.0.0.0/0"], &["::/0"]));
  }

  /// A stored whitelist with an entry which doesn't parse lets
  /// nothing in (check_cidr_whitelist fails closed), so every new
  /// whitelist widens it.
  #[test]
  fn an_unparsable_stored_whitelist_lets_nothing_in() {
    let stored = ["10.0.0.0/8", "garbage"];
    assert!(widened(&stored, &["10.1.0.0/16"]));
    assert!(widened(&stored, &["10.0.0.0/8"]));
    assert!(widened(&stored, &[]));
    assert!(check_cidr_whitelist(ip("10.1.2.3"), stored).is_err());
  }

  #[test]
  fn check_returns_forbidden_when_not_allowed() {
    let whitelist = vec!["10.0.0.0/8".to_string()];
    assert!(check_cidr_whitelist(ip("10.5.5.5"), &whitelist).is_ok());
    let err =
      check_cidr_whitelist(ip("8.8.8.8"), &whitelist).unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
  }

  #[test]
  fn check_fails_closed_on_invalid_entry() {
    let whitelist =
      vec!["0.0.0.0/0".to_string(), "garbage".to_string()];
    let err =
      check_cidr_whitelist(ip("8.8.8.8"), &whitelist).unwrap_err();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
  }
}
