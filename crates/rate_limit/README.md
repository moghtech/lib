# Mogh Rate Limit

Add configurable rate limiting to fallible async requests.

Only failed attempts count: refusals which may be wrong guesses (see
[below](#a-refusal-which-is-not-a-guess)). A failed attempt returns its own
error (status and headers included) with a `FailedAttempt` context noting the
attempts left, displayed as
`Invalid login credentials | You have 2 attempts remaining`. The original
error stays in the chain, so `error.downcast_ref::<T>()` still finds its
types. Once the attempts are used up, requests from the client are refused
with `429 Too Many Requests` until the window passes.

```rust
use mogh_rate_limit::{RateLimiter, WithFailureRateLimit};

// 5 failed attempts per client every 15 minutes.
let limiter = RateLimiter::new(false, 5, Duration::from_secs(15 * 60));

// Guessable secrets (passwords, TOTP codes): strict.
login(body)
  .with_strict_failure_rate_limit_using_ip(&limiter, &ip)
  .await?;

// Parallel requests with unguessable credentials: best effort.
authenticate(headers)
  .with_failure_rate_limit_using_ip(&limiter, &ip)
  .await?;
```

## Strict or best effort

- `with_strict_failure_rate_limit_using_ip` counts the attempts in flight
  against the budget, so no more than `max_attempts` attempts from a client
  can fail within the window, however many it sends at once. Attempts in flight never cause a refusal, only recorded failures
  do: once they use up the budget, every attempt is refused with `429`, as
  with best effort. While the remaining attempts are all reserved by
  attempts in flight, the next one waits for one of them to finish (a
  success gives its reservation back without using up an attempt). No more
  than `max_attempts` attempts per client run at the same time. Use it for
  secrets which can be guessed.
- `with_failure_rate_limit_using_ip` only counts the failures recorded so
  far. It never holds a request back, but a burst of
  attempts sent at the same time all run before any of them is recorded, so
  it does **not** bound a burst. Use it where requests legitimately run in
  parallel and the credentials can't be guessed, like checking the api key
  or JWT of every authenticated request.

Both share the budget of a client on the same `RateLimiter`.

## A refusal which is not a guess

Only an error which may be a wrong guess counts. These are returned as they
are (no note), cost the client nothing, and give back the reservation of a
strict attempt, like a success:

- An error marked `uncounted` (`mogh_error::Error::uncounted`, checked with
  `is_uncounted`): a refusal of something authentic, which no guess could
  change, like an expired token which verified, or a session the user ended.
  Counting those would lock out every client still holding one (all the tabs
  and devices of a user who logged out everywhere, behind one NAT) without
  any guessing.
- A server error (5xx): the server failed, not the guess. Counting it would
  keep every client refused for a window after a database outage.

So a refusal of a guess must be a client error (`401 Unauthorized`). An error
converted with `?` without a `status_code` is a `500`, which is not counted.

```rust
// Counted: the password may have been guessed.
return Err(anyhow!("Invalid credentials").status_code(StatusCode::UNAUTHORIZED));
// Not counted: the session is authentic, the user ended it.
return Err(
  anyhow!("Session ended")
    .status_code(StatusCode::UNAUTHORIZED)
    .uncounted(),
);
```

## Clients

Attempts are counted per IPv4 address, and per IPv6 `/64` prefix: an IPv6
host usually controls a whole `/64`, and could otherwise use a fresh address
for every attempt. The clients sharing a `/64` share a budget, the way the
users behind one IPv4 address (NAT) do. IPv4-mapped IPv6 addresses count as
their IPv4 address. Change the prefix with `RateLimiter::builder`:

```rust
let limiter = RateLimiter::builder(5, Duration::from_secs(15 * 60))
  // Coarser, for clients assigned a /56. Or 128 for one budget per address.
  .ipv6_prefix_len(56)
  .build();
```

The client address is the caller's to give. In an axum app, pass the one
`mogh_request_ip::RequestIp` resolved (forwarding headers are believed only
from the trusted proxies the server was configured with), so the limiter
counts the same client as everything else handling the request.

## Keyed limiters

A `KeyedRateLimiter<K>` counts per client and key: a client's failures for one
key (eg. the resource a webhook is for) use up only its budget for that key,
while its attempts for other keys keep theirs. Everything else works as on a
`RateLimiter` (which is the keyed limiter of a single key, `()`): the client is
its ip (IPv4 address / IPv6 prefix), strict or best effort, the window, the
bounded memory (each client counted once per key).

```rust
use mogh_rate_limit::{KeyedRateLimiter, WithFailureRateLimit};

// 5 failed attempts per client and resource every 15 seconds.
static WEBHOOK_LIMITER: LazyLock<Arc<KeyedRateLimiter<String>>> =
  LazyLock::new(|| KeyedRateLimiter::new(false, 5, Duration::from_secs(15)));

verify_webhook_signature(&resource, &body)
  .with_strict_failure_rate_limit_using_ip_and_key(
    &WEBHOOK_LIMITER,
    &ip,
    resource.id.clone(),
  )
  .await?;
```

A key is anything `Hash + Eq + Clone + Send + Sync + 'static` (an id, a tuple).
A stale webhook (its resource deleted) or a misconfigured one then only blocks
itself, not every other webhook from the same git host. Keying by the resource
alone would let anyone block a resource's webhooks by failing on purpose from
anywhere: the client stays part of the key.

⚠️ A key made from the request (a name in the url) can be made up: each new
one gets a new budget, and an entry in the limiter (up to `max_entries`, then
the oldest are dropped, their failures with them). Key only what is known to
exist, eg. one key for every unknown resource, so made up keys share a budget.

## Memory

Only clients with failures within the window (or strict attempts in flight)
are tracked. A task removes the rest once a minute, and at most
`max_entries` clients (default 100,000) are kept: past that, the clients
whose failures have all left the window are removed, then the ones whose last
failure is the oldest.

## Since 3.1

- `KeyedRateLimiter<K>` and the `_using_ip_and_key` variants, see
  [Keyed limiters](#keyed-limiters). `RateLimiter` is now
  `KeyedRateLimiter<()>` (a type alias, everything it had works as before) and
  `RateLimiterBuilder` takes the key type, `()` by default.

## Since 3.0

- A refusal which is not a guess is not counted, see above: an error marked
  `uncounted` (mogh_error 2.0), or a server error (5xx). 5xx used to count
  (2.2.1), and to get the note with their causes hidden per the detail
  setting; now they come back as they are. Make sure every refusal of a guess
  carries a 4xx status.
- The `_using_headers` variants and the `TrustedProxies` / `get_client_ip`
  re-exports are gone (nothing used them): resolve the client address with
  `mogh_request_ip` (its `RequestIp` extractor) and use the `_using_ip`
  variants. `mogh_rate_limit` no longer depends on `mogh_request_ip`.
