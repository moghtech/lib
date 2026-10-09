# Mogh Request IP

Axum extractor for client request IP.

Forwarding headers (`X-Forwarded-For`, `X-Real-IP`) are only believed
when the socket peer is a trusted proxy, so clients connecting directly
cannot spoof their ip. `X-Forwarded-For` is walked from the right (the
entry added by the nearest proxy), skipping trusted proxy hops, and the
first untrusted address is the client. `X-Real-IP` is only read when
`X-Forwarded-For` has no entries, and its lines are walked the same way.
The default policy trusts loopback and private ranges.

## What the trusted proxy must do

Every trusted proxy must **append to (or overwrite) `X-Forwarded-For`**,
not only set `X-Real-IP`. Proxies pass headers they don't set through,
and `X-Forwarded-For` takes precedence, so behind a proxy which only sets
`X-Real-IP` a client sending its own `X-Forwarded-For` chooses its ip
(passing CIDR whitelists, dodging per ip rate limits). For nginx:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

Caddy and Traefik set `X-Forwarded-For` by default.

## Narrowing the default

The default (`private`) believes **any** loopback / private peer, not only
the proxy. It is only safe when every such peer is a proxy which sets
`X-Forwarded-For`. Public clients arriving from a private address can
choose their ip, eg:

- Docker's userland `docker-proxy` (IPv6 clients of a port published to an
  IPv4-only network arrive from the bridge gateway, eg `172.17.0.1`).
- Rootless Docker / Podman port forwarding, and Docker Desktop.
- A Kubernetes Service with `externalTrafficPolicy: Cluster` (SNAT).
- Other hosts / containers on the private network or VPN.

Then use `["none"]` when nothing is in front of the app, or list the exact
proxy address (eg `["172.18.0.5"]`, giving the proxy container a static ip).
Listing the whole container network is not enough, it includes the gateway.

`["all"]` trusts every peer and hop, so the **leftmost** `X-Forwarded-For`
entry is the client. Only use it when the app is unreachable except through
proxies which **replace** a client-sent `X-Forwarded-For` (the Caddy and
Traefik defaults). Behind a proxy which appends (nginx
`$proxy_add_x_forwarded_for`, HAProxy `option forwardfor`, AWS ALB) the
leftmost entry is whatever the client sent. Likewise behind a proxy which
adds its own `X-Real-IP` line rather than replacing a client-sent one (eg
HAProxy `http-request add-header`), since the first line is used. List the
proxy address instead.

## A list which misses the proxy

When the trusted proxies miss the real proxy (a list naming another
address, `["none"]` behind a proxy, a proxy outside the private ranges of
the default), its forwarding headers are ignored and every client is seen
as the proxy: they all share one rate limit budget, and match ip whitelists
as the proxy's ip. The first request from a peer which is not trusted but
sends `X-Forwarded-For` / `X-Real-IP` is logged as a warning, once per
process, naming the peer and the trusted proxies (never the header values).
A client sending the headers itself triggers it too.

## Usage

```rust
use mogh_request_ip::{RequestIp, TrustedProxies};

// Use as axum extractor
async fn auth_request(
  RequestIp(ip): RequestIp,
  req: Request
) -> mogh_error::Result<String> {
  println!("Client IP: {ip:?}");
  Ok(ip.to_string())
}

// Configure which proxies are trusted, and serve
// with connect info so the socket peer is known.
// `from_config` also takes the `private` / `none` / `all` keywords.
let app = Router::new()
  .route("/", get(auth_request))
  .layer(TrustedProxies::from_config(["172.18.0.5"])?.layer())
  .into_make_service_with_connect_info::<SocketAddr>();
```
```rust
// Restrict requests to a CIDR whitelist. Entries may be
// CIDR ranges or bare ips, and an empty whitelist allows all.
// IPv4-mapped IPv6 entries and ips (`::ffff:10.0.0.0/104`,
// `::ffff:10.1.2.3`) match as their IPv4 form, also in a
// `CidrSet` collected from `IpNet`s parsed elsewhere.
use mogh_request_ip::cidr::check_cidr_whitelist;

async fn restricted_request(
  RequestIp(ip): RequestIp,
) -> mogh_error::Result<()> {
  let whitelist = ["10.0.0.0/8".to_string(), "::1".to_string()];
  // Returns 403 Forbidden if the ip is not whitelisted.
  check_cidr_whitelist(ip, &whitelist)
}
```

## Since 3.0

- Built on `mogh_error` 2.0: `get_client_ip`,
  `get_ip_from_headers_and_extensions`, `cidr::check_cidr_whitelist` and
  the `RequestIp` rejection are `mogh_error` 2.0 types, so an app upgrades
  both together.
- A `CidrSet` collected from `IpNet`s canonicalizes IPv4-mapped networks,
  as parsed entries are.
- The first request from a peer which is not trusted but sends forwarding
  headers is logged (once per process), see above.
