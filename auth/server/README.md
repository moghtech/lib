# Mogh Auth Library

Provides trait-driven server and client implementations for robust application authentication. Compatible with axum.

- Local login with usernames and passwords
- OIDC / social login
- Two factor authentication with webauthn passkey or TOTP code
- JWT token generation and validation utilities
- Request rate limiting by IP for brute force mitigation (implement
  `general_rate_limiter`, it is off by default)
- Typescript types / client to layer with app-specific typescript client.

## Usage (Server)

Implement the necessary traits and mount the router.

### Implement AuthUserImpl

```rust
use mogh_auth_server::passkey::Passkey;

pub struct AuthUser(UserRecord);

impl mogh_auth_server::user::AuthUserImpl for AuthUser {
  fn id(&self) -> &str {
    &self.0.id
  }

  fn username(&self) -> &str {
    &self.0.username
  }

  fn hashed_password(&self) -> Option<&str> {
    if self.0.password.is_empty() {
      None
    } else {
      Some(&self.0.password)
    }
  }

  fn passkey(&self) -> Option<Passkey> {
    self.0.passkey.clone()
  }

  fn totp_secret(&self) -> Option<&str> {
    if self.0.totp_secret.is_empty() {
      None
    } else {
      Some(&self.0.totp_secret)
    }
  }

  /// Stored by `update_user_stored_totp`, required for recovery code logins.
  fn hashed_totp_recovery_codes(&self) -> &[String] {
    &self.0.hashed_totp_recovery_codes
  }

  /// ⚠️ The default is `true`: users enrolled in 2FA skip it when logging in
  /// through a login provider (and `POST /token`). Store it per user,
  /// defaulting to `false`, so their second factor protects every login.
  fn external_skip_2fa(&self) -> bool {
    self.0.external_skip_2fa
  }

  /// Disabled users are refused the auth management API (all but `GetUserId`).
  fn is_enabled(&self) -> bool {
    self.0.enabled
  }

  /// Admins can manage the login providers and trusted issuers over the API,
  /// which amounts to full control of the app (eg. repointing a provider
  /// logs its new issuer in as the linked users). With separate super
  /// admins, return `enabled && super_admin` here, as Komodo and Cicada do.
  fn is_admin(&self) -> bool {
    self.0.admin
  }

  fn is_workload(&self) -> bool {
    self.0.workload.is_some()
  }

  fn cidr_whitelist(&self) -> &[String] {
    &self.0.cidr_whitelist
  }

  /// The ids of the linked login providers. With them the server refuses to
  /// remove the user's only way to log in (`UnlinkLocalLogin` without a
  /// linked provider, `UnlinkExternalLogin` of the only one without a
  /// password). The default `None` checks nothing.
  fn external_login_provider_ids(&self) -> Option<&[String]> {
    Some(&self.0.linked_provider_ids)
  }
}
```

### Implement AuthImpl

`example/server/src/auth.rs` implements all of it against a database. The
essentials:

```rust
pub struct AppAuthImpl;

impl mogh_auth_server::AuthImpl for AppAuthImpl {
  /// Called for every request, keep it cheap.
  fn new() -> Self {
    Self
  }

  fn app_name(&self) -> &'static str {
    "AppName"
  }

  /// The origin the app is reached at, eg. `https://example.com`. The path
  /// the auth router is nested at is `path()`, "/auth" by default.
  fn host(&self) -> &str {
    &core_config().host
  }

  fn post_link_redirect(&self) -> &str {
    static POST_LINK_REDIRECT: LazyLock<String> =
      LazyLock::new(|| format!("{}/profile", core_config().host));
    &POST_LINK_REDIRECT
  }

  fn get_user(
    &self,
    user_id: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<BoxAuthUser>> {
    Box::pin(async move {
      Ok(Box::new(AuthUser(get_user(&user_id).await?)) as BoxAuthUser)
    })
  }

  /// Authenticates the requests of the app's own API
  /// (`middleware::authenticate_request::<AppAuthImpl, REQUIRE_USER_ENABLED>`).
  fn handle_request_authentication(
    &self,
    auth: RequestAuthentication,
    ip: IpAddr,
    require_user_enabled: bool,
    mut req: Request,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<Request>> {
    Box::pin(async move {
      // Verifies the credentials, and enforces the api key
      // and the user cidr whitelists.
      let user = get_user_from_request_authentication(
        &AppAuthImpl,
        auth,
        ip,
      )
      .await?;
      let user = get_user(user.id()).await?;
      if require_user_enabled && !user.enabled {
        return Err(
          anyhow!("User is not enabled")
            .status_code(StatusCode::FORBIDDEN),
        );
      }
      req.extensions_mut().insert(user);
      Ok(req)
    })
  }

  fn no_users_exist(
    &self,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<bool>> {
    Box::pin(async { no_users_exist().await.map_err(Into::into) })
  }

  fn locked_usernames(&self) -> &'static [String] {
    &core_config().lock_login_credentials_for
  }

  /// Names the app keeps for itself, refused to sign ups (local and
  /// external) and renames after `validate_username`. Not at login: a
  /// user who had one before keeps logging in with it.
  fn validate_new_username(&self, username: &str) -> mogh_error::Result<()> {
    if RESERVED_USERNAMES.contains(&username) {
      return Err(anyhow!("Username is reserved").status_code(StatusCode::BAD_REQUEST));
    }
    Ok(())
  }

  fn registration_disabled(&self) -> bool {
    core_config().disable_user_registration
  }

  // =========
  // = STATE =
  // =========

  fn jwt_provider(&self) -> &JwtProvider {
    static JWT_PROVIDER: LazyLock<JwtProvider> = LazyLock::new(|| {
      // At least 32 random bytes, shared by all instances of the app.
      // Forced in `main` before serving, so a refused secret stops the
      // app at startup rather than the first request needing it.
      JwtProvider::try_new(core_config().jwt_secret.as_bytes(), JWT_TTL_MS)
        .expect("[FATAL] Invalid 'jwt_secret'")
        .with_iss(core_config().host.clone())
        .with_aud("AppName")
    });
    &JWT_PROVIDER
  }

  fn passkey_provider(&self) -> Option<&PasskeyProvider> {
    static PASSKEY_PROVIDER: LazyLock<Option<PasskeyProvider>> =
      LazyLock::new(|| {
        PasskeyProvider::new(&core_config().host)
          .inspect_err(|e| {
            warn!("Invalid 'host' for passkey provider | {e:#}")
          })
          .ok()
      });
    PASSKEY_PROVIDER.as_ref()
  }

  /// ⚠️ Without this nothing is rate limited, see "Rate limiting" below.
  fn general_rate_limiter(&self) -> &RateLimiter {
    static GENERAL_RATE_LIMITER: LazyLock<Arc<RateLimiter>> =
      LazyLock::new(|| RateLimiter::new(false, 10, Duration::from_secs(60)));
    &GENERAL_RATE_LIMITER
  }

  // ==============
  // = LOCAL AUTH =
  // ==============

  fn local_auth_enabled(&self) -> bool {
    core_config().local_auth
  }

  fn sign_up_local_user(
    &self,
    username: String,
    hashed_password: String,
    no_users_exist: bool,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<String>> {
    Box::pin(async move {
      sign_up_local_user(
        username,
        hashed_password,
        no_users_exist || core_config().enable_new_users,
      )
      .await
      .map_err(Into::into)
    })
  }

  fn find_user_with_username(
    &self,
    username: String,
  ) -> mogh_auth_server::DynFuture<
    mogh_error::Result<Option<BoxAuthUser>>,
  > {
    Box::pin(async move {
      let user = find_user_with_username(username)
        .await?
        .map(|user| Box::new(AuthUser(user)) as BoxAuthUser);
      Ok(user)
    })
  }

  fn update_user_username(
    &self,
    user_id: String,
    username: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      update_user_username(&user_id, username).await.map_err(Into::into)
    })
  }

  fn update_user_password(
    &self,
    user_id: String,
    hashed_password: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      update_user_password(&user_id, hashed_password)
        .await
        .map_err(Into::into)
    })
  }

  // ==================
  // = EXTERNAL LOGIN =
  // ==================

  /// Providers from the app config file / env. Read only in the API.
  /// The reserved ids (`oidc`, `github`, `google`) keep the original
  /// callback paths, eg. `/auth/oidc/callback`.
  fn static_external_providers(&self) -> Vec<ExternalLoginProvider> {
    let config = core_config();
    vec![ExternalLoginProvider {
      id: ExternalLoginKind::Oidc.reserved_id().to_string(),
      name: String::from("OIDC"),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Oidc(config.oidc.clone()),
    }]
  }

  /// Providers stored in the database, managed by admins over the API
  /// (`ListExternalLoginProviders`, `CreateExternalLoginProvider`, ...).
  /// The config includes the client secret, encrypt it at rest.
  /// Called by unauthenticated requests, serve it from a cache.
  fn list_external_providers(
    &self,
  ) -> mogh_auth_server::DynFuture<
    mogh_error::Result<Vec<ExternalLoginProvider>>,
  > {
    Box::pin(async move {
      list_stored_login_providers().await.map_err(Into::into)
    })
  }

  // create_external_provider, update_external_provider,
  // delete_external_provider (which also removes the links to it)

  /// ⚠️ External user ids are only unique per provider,
  /// always match on both the provider id and the external id.
  fn find_user_with_external_login(
    &self,
    provider_id: String,
    external_id: String,
  ) -> mogh_auth_server::DynFuture<
    mogh_error::Result<Option<BoxAuthUser>>,
  > {
    Box::pin(async move {
      let user =
        find_user_with_external_login(&provider_id, &external_id)
          .await?
          .map(|user| Box::new(AuthUser(user)) as BoxAuthUser);
      Ok(user)
    })
  }

  // sign_up_external_user, sync_external_user, link_external_login,
  // unlink_external_login, unlink_local_login

  // =======
  // = 2FA =
  // =======

  // update_user_stored_passkey, remove_user_stored_totp,
  // update_user_external_skip_2fa

  fn update_user_stored_totp(
    &self,
    user_id: String,
    encoded_secret: String,
    hashed_recovery_codes: Vec<String>,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // Store the recovery codes too, `hashed_totp_recovery_codes`
      // returns them for recovery code logins.
      update_user_totp(&user_id, encoded_secret, hashed_recovery_codes)
        .await
        .map_err(Into::into)
    })
  }

  /// A recovery code was used, it can't be used again. ⚠️ Remove it only if
  /// it is still there, in one conditional statement, and fail if it wasn't:
  /// another login used it, maybe on another instance. The server serializes
  /// the recovery code logins of a user within one instance only.
  fn remove_totp_recovery_code(
    &self,
    user_id: String,
    hashed_code: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // eg. UPDATE ... WHERE id = ? AND <codes contain the hash>
      if remove_user_recovery_code_if_present(&user_id, &hashed_code).await? {
        Ok(())
      } else {
        Err(
          anyhow!("Invalid recovery code")
            .status_code(StatusCode::UNAUTHORIZED),
        )
      }
    })
  }

  // ============
  // = API KEYS =
  // ============

  // create_api_key, delete_api_key

  /// The server verifies the secret against the hash (a key which doesn't
  /// exist costing as much, so the timing doesn't tell), refuses expired keys
  /// after it (`get_api_key`), and finds the owner of a key to delete it
  /// (`get_api_key_owner_id`) with this. Find expired keys too.
  fn find_api_key(
    &self,
    key: String,
  ) -> mogh_auth_server::DynFuture<mogh_error::Result<Option<StoredApiKey>>> {
    Box::pin(async move {
      let api_key = find_api_key(&key).await?.map(|key| StoredApiKey {
        user_id: key.user_id,
        hashed_secret: key.hashed_secret,
        // unix milliseconds, 0 for never
        expires: key.expires,
        cidr_whitelist: key.cidr_whitelist,
      });
      Ok(api_key)
    })
  }

  // signing keys: signing_keys_enabled (and extra_hosts, for more hosts
  // than `host`), create_signing_key (public keys unique across all
  // users), find_signing_key (expired keys too, as find_api_key),
  // delete_signing_key
}
```

`CreateApiKey` / `CreateSigningKey` take an `expires` (unix milliseconds, `0`
for never) and a `cidr_whitelist` (trimmed, empty and repeated entries dropped,
at most `validations::MAX_CIDR_WHITELIST_ENTRIES` = 64, else `400`, then
`AuthImpl::validate_cidr_whitelist`), which the server passes to
`create_api_key` / `create_signing_key`. That is
`validations::normalize_cidr_whitelist(&auth, whitelist)`: normalize the
whitelists the app sets itself (a user's, a device's) with it too, so they
follow the same rules.
The defaults of `get_api_key` and `get_signing_key` refuse an expired key with
`401 Invalid client credentials` (an api key after its secret verified, so the
timing doesn't tell), and `get_api_key_owner_id` still finds it for
`DeleteApiKey`. A key which doesn't exist gets the same `401` right away,
without a bcrypt: key ids are random, listed by the UIs and logged at creation,
so whether one exists is no secret, and only a request naming a real key costs
the server a bcrypt (made up keys can't spend the budget of the real ones). An app with checks of its own (eg. keys which can be disabled)
overrides `get_api_key` / `get_signing_key`: it finds the key, authenticates it
with `middleware::verify_api_key` / `middleware::verify_signing_key` (which
verify the secret and refuse expired keys), then refuses what it refuses with
the same `401`. ⚠️ An override which doesn't use them checks the secret and the
expiry itself, the server checks them nowhere else.

An app which mints api keys outside the management api (eg. a CLI writing one
to the app's database directly) makes them with
`api_key::generate_api_key_parts(auth.api_key_secret_length(),
auth.api_secret_bcrypt_cost())`: the key and the bcrypt hash of the secret to
store as `create_api_key` stores them, and the secret to show once. It runs
bcrypt on the calling thread.

### Nest the router

Requires Session middleware layer on or outide the auth api router.

```rust
struct MemorySessionConfig;

impl mogh_server::session::SessionConfig for MemorySessionConfig {
  fn host(&self) -> &str {
    &core_config().host
  }
  fn host_env_field(&self) -> &str {
    "APP_HOST"
  }
}

axum::Router::new()
  .nest("/auth", mogh_auth_server::api::router::<AppAuthImpl>())
  .layer(mogh_server::session::memory_session_layer(MemorySessionConfig))
```

### Rate limiting

⚠️ **Nothing is limited by client ip unless the app implements
`AuthImpl::general_rate_limiter`.** The default is a disabled limiter (a warning
is logged once when it is used), so password and api key guesses are
unlimited:

```rust
fn general_rate_limiter(&self) -> &RateLimiter {
  static LIMITER: LazyLock<Arc<RateLimiter>> =
    LazyLock::new(|| RateLimiter::new(false, 10, Duration::from_secs(60)));
  &LIMITER
}
```

- It counts failed authentication by client ip (IPv6 clients per /64): invalid
  tokens, api keys and signatures presented to `authenticate_request` and the
  management api, second factors, external logins and token exchanges. Local
  logins too, unless `local_login_rate_limiter` gives them their own, and
  `/token` exchanges unless `token_exchange_rate_limiter` does.
- The login steps checking a secret which can be guessed (`LoginLocalUser`,
  `CompleteTotpLogin`, `CompleteTotpRecoveryLogin`, `CompletePasskeyLogin`)
  count strictly, so a burst of concurrent attempts can't go past the limit
  either.
- Failed TOTP and recovery codes are also capped per user, whatever the ip
  limiter (the disabled default included), the session or the client ip:
  `MAX_SECOND_FACTOR_FAILURES` (10) per `SECOND_FACTOR_FAILURE_WINDOW`
  (15 minutes), then `429 Too Many Requests` (`api::login::totp`). Only a client
  which passed the first factor can send codes, but whoever holds it can keep
  the user's second factor locked this way: the user or an admin then changes
  the password, or unlinks the external login. A first factor's codes are only
  accepted for 10 minutes after it passed, so the ones passed before the change
  stop at most 10 minutes after it, and the user's codes are accepted again
  once their failures leave the window (at most 25 minutes after the change).
  The count is kept in process memory, so each instance of a replicated app
  allows this many, and a restart starts over.
- Requests without any credentials are never counted, nor are refusals which
  are not guesses: an authentic token which only expired, an `Authorization`
  header of another scheme than `Bearer` (eg. a proxy's basic auth, refused
  `401 Unsupported authorization scheme`), and server errors. An app marks its
  own such refusals in `handle_request_authentication` /
  `get_user_id_from_request_authentication` with `mogh_error::Error::uncounted`
  (a session it ended, a workload user out of sync with its rule): every tab or
  device still sending such a token, often behind one ip, would otherwise lock
  that ip out of logging in.
- The client ip is taken from forwarding headers only when the request comes
  from a trusted proxy (`mogh_server`'s `trusted_proxies`, private ranges by
  default).

### Login starts

Starting an external login needs no credentials, and holds a login session
until the provider's callback. A session store is bounded (`mogh_server`'s in
memory store drops the sessions closest to expiry once it holds
`max_sessions`), so a flood of login starts would push the logins of real users
out of it: logins at the provider, second factors waiting to be typed in. So
`AuthImpl::login_start_limiter` limits, on by default:

- the external login and link starts (`/{slug}/login`, `/{slug}/link`) of each
  client ip: 30 at once, then one more every 2 seconds (refilled evenly over a
  minute). IPv6 clients count per `/64`, and the `/64`s of a `/48` share 16
  times that on top. The link routes create no session, but continue the one
  `BeginExternalLoginLink` created;
- the management requests which begin a login session (`BeginExternalLoginLink`,
  `BeginPasskeyEnrollment`, `BeginTotpEnrollment`) of each user: 10 at once,
  refilled over the same minute.

A refused start is `429 Too Many Requests` with `Retry-After`, which the login
routes send to the login page like their other failures (see [Failed external
logins](#failed-external-logins)). Keep the client limit well below what the
session store holds. A browser request for a login route which isn't a
navigation to it (`Sec-Fetch-Mode` / `Sec-Fetch-Dest`, eg. an image of another
site) can't start a login anyways, and is refused with `403` before it counts,
so other sites can't use up the allowance of their visitors' ip.

```rust
fn login_start_limiter(&self) -> &LoginStartLimiter {
  static LIMITER: LazyLock<LoginStartLimiter> = LazyLock::new(|| {
    // Per client, per user, refilled over the window.
    // `LoginStartLimiter::disabled()` turns both off.
    LoginStartLimiter::new(30, 10, Duration::from_secs(60))
  });
  &LIMITER
}
```

### Login sessions

- Passwords are hashed with bcrypt, which only uses their first 72 bytes: sign
  up and `UpdatePassword` refuse longer ones (`validations::MAX_PASSWORD_BYTES`),
  rather than letting two passwords differing after 72 bytes both work.
- bcrypt runs off the async runtime, at most one per available core at a time
  for the logins, sign ups and password changes together (api key secrets have
  a budget of their own). An app which sets passwords itself (an admin creating
  a user with one) hashes them with
  `mogh_auth_server::hash_password(password, auth.local_auth_bcrypt_cost())`,
  which takes its turn on the same budget.
- The session id is cycled when the first factor passes (the password, or an
  external login), and when a link of an external login is begun
  (`BeginExternalLoginLink`), so a session id planted in the browser beforehand
  (eg. a cookie set by a sibling subdomain) can't be used to complete the login,
  or to start the link. The client must keep the cookie of the response (a
  browser `fetch` with `credentials: "include"` does).
- The second factor (passkey, TOTP or recovery code) of a login has to be
  completed within 10 minutes of its first factor, after that the login starts
  over. Requests anybody holding the cookie can send, which find nothing in
  flight on the session (a callback or `/link` without a flow started,
  `ExchangeForJwt` without a login), leave the session unchanged, so they don't
  extend its expiry.
- Each step stored on the session keeps it for the step's whole time, however
  short the session layer's idle expiry (`SessionConfig::expiry_seconds`,
  3 minutes by default): an external login in flight at the provider and a link
  (10 minutes, `Session::MAX_EXTERNAL_LOGIN_AGE` / `MAX_EXTERNAL_LINK_AGE`), the
  second factor (10 minutes), a TOTP or passkey enrollment (10 minutes). The
  session then expires at that time (`Expiry::AtDateTime`) rather than when it
  idled, unless it lives longer already. A login completed at the provider's
  callback is redeemed (`ExchangeForJwt`) within 2 minutes, in that window.
- A TOTP or passkey enrollment (`BeginTotpEnrollment` / `BeginPasskeyEnrollment`)
  can only be confirmed by the user who began it: the management api
  authenticates by the `Authorization` header, not the session cookie.

### Disabled users

Implement `AuthUserImpl::is_enabled` to disable users. Disabled users can still
log in (to see that they are disabled), and are refused the whole auth management
api except `GetUserId`: no api keys, no changes to how they log in, and a disabled
admin no longer manages login providers or trusted issuers. A link of an external
login they began before being disabled is refused as well, when it is started
(`/link`) and when the provider's callback would complete it. Refusing them the
app's own api is `handle_request_authentication`'s `require_user_enabled`.
The user of a workload rule is disabled along with the rule or its issuer
(`sync_workload_users`), and can't exchange tokens while it is.

### App tokens

The tokens issued by `JwtProvider` are standard JWTs: `iat` / `exp` are unix
timestamps in **seconds** (RFC 7519), validated with 10 seconds of clock skew
tolerance. Tokens issued before 4.0 carried milliseconds and are rejected, so
users have to log in once after upgrading. Since 8.0 each token also carries a
random `jti`, so no two are the same (two logins of one user in one second
were); it isn't checked, and tokens without one stay valid.

⚠️ They are signed with the secret the `JwtProvider` is built with: anyone who
knows it, or guesses it offline from any token they got, can issue tokens for
any user. Use a random secret of at least 32 bytes (`openssl rand -base64 48`),
shared by all instances of the app, and build the provider with
`JwtProvider::try_new`, which refuses shorter ones (`JwtProvider::new` logs a
warning). Build it at startup and refuse to start on its error, which names the
minimum and never the secret: a provider built lazily would only fail at the
first request needing it. With an empty secret no token is issued or accepted.
Generating a random secret when none is configured also works, users are then
logged out on restart.

### Reauthentication

Requests of the management API which change how a user can log in (username,
password, 2FA, linked logins, new api keys and signing keys), or how anybody
can (login providers, trusted issuers), are only accepted with a token from a
login in the last 15 minutes, so a token which leaked is not enough to take the
account over for good. Reading, `GetUserId` and deleting api keys or signing
keys are not affected.

```rust
/// Seconds. `0` disables the check for sessions (api keys and signing keys
/// stay refused).
fn reauthentication_window_secs(&self) -> u64 {
  15 * 60
}
```

- Older tokens get `403 Forbidden` with a message starting with
  `mogh_auth_client::api::manage::REAUTHENTICATION_REQUIRED`
  (`isReauthenticationRequired(e)` in the typescript client). The user logs in
  again, including their second factor (a provider login may ask for neither,
  see below), and retries. `mogh_ui` does this on
  its own: it tells the user why and sends them to `/login?backto=<page>`
  (`setOnReauthenticationRequired` to change that).
- Api keys and signing keys are not a login, and are always refused the
  account requests, whatever the window (`0` included): a leaked key must not
  be able to set a
  password, unenroll 2FA or mint a replacement key. The requests which manage
  resources rather than the caller's account — the login providers and
  trusted issuers, whose handlers require an admin — take them, so an admin's
  key can run Terraform against them; whether keys reach the management api
  at all is the app's `get_user_id_from_request_authentication`.
- The time of a login is the `iat` of the `JwtProvider` token it issued, with
  the 10 seconds of clock skew its validation tolerates (instances behind a
  load balancer). Other tokens which `get_user_id_from_request_authentication`
  accepts have no known login and count as api keys: they are refused the
  account requests whatever the window, and may make only the resource
  requests.
- A token from a [token exchange](#token-exchange-rfc-8693) (`/token`, or
  `ExchangeExternalForJwt` without a second factor) counts as a login when the
  provider authenticated the user, not when it was exchanged: the provider
  token's `auth_time`, else its `iat` (the app token's `auth_time` claim,
  `JwtClaims::authenticated_at`). A provider token can be exchanged again until
  it expires, so a leaked old one gets the app but not the account. Exchange a
  freshly issued provider token for these requests. ⚠️ A fresh token is not
  a fresh login: identity providers with single sign-on sessions issue new
  tokens silently, which keep the original `auth_time`. A token without
  `auth_time` (which OIDC only requires when it is requested, eg. with
  `max_age`, and some providers like Google leave out otherwise) counts from
  its `iat` though, so a silently issued or refreshed one does count as a
  fresh login. To get a recent login through token exchange, the client must make
  the provider authenticate the user again, eg. with OIDC `prompt=login` or
  `max_age=0` on the authorization request.
- ⚠️ A browser login through an external provider (OIDC, Google, GitHub:
  `/external/{slug}/login`, also the one a provider user makes to log in
  again) counts as a fresh login at its callback, also when the provider
  answered from its single sign-on session without asking the user for
  anything: the server sends no `prompt=login` / `max_age` and reads no
  `auth_time` there. So for a provider user who logs in without a second
  factor in the app (`external_skip_2fa`, on by default, or none enrolled) the
  window is only as strong as the provider's session: whoever can make their
  browser log in again (script on the app's origin, a browser left unlocked)
  gets a recent login without their credentials. A second factor in the app
  (`external_skip_2fa` off, with one enrolled) is asked at every such login
  and closes it, and so does a provider configured to authenticate the user at
  every login of the app (a short or no SSO session for its client). Local
  logins need the password, token exchange counts from the provider token's
  `auth_time` (above).

#### Gating app writes

The window protects the management API. Requests of the app's own api can mint
or widen lasting access as well: creating a user with admin rights, an api key
for another user, an onboarding key, widening a cidr whitelist, re-enabling a
key. Hold those to the same window for sessions with
`middleware::require_recent_login`, which answers the same `403` (so
`isReauthenticationRequired(e)` recognizes it):

```rust
use mogh_auth_server::middleware::{AuthenticatedAt, require_recent_login};

async fn write_handler(
  Extension(user): Extension<User>,
  AuthenticatedAt(authenticated_at): AuthenticatedAt,
  Json(request): Json<WriteRequest>,
) -> mogh_error::Result<Response> {
  if mints_or_widens_access(&request) {
    require_recent_login(&AppAuthImpl, authenticated_at)?;
  }
  // ...
}
```

- `middleware::authenticate_request` attaches `AuthenticatedAt` to every
  request it authenticates (after `handle_request_authentication`, which may
  attach its own for a token of the app's whose login it knows):
  `Some(login)` for a session token, the same time the management API checks,
  `None` for api keys and signing keys. A middleware of the app's own built on
  `authenticate_user` gets it from `Authenticated::finish`; any other has to
  attach it, or the extractor refuses the request (`401`).
- Api keys and signing keys pass: they are the automation credentials, and what
  they may do in the app's api is the app's call (the management API refuses
  them the account requests). Narrowing access (deleting a key, disabling a
  user, removing whitelist entries) needs no recent login from anybody.
- `0` (`reauthentication_window_secs`) turns the check off for the app's
  requests too.
- `mogh_ui` sends the user to log in again on this `403` for the management
  requests it makes (`useManageAuth`). The app's own write hooks check
  `isReauthenticationRequired(e)` the same way.

### Failed external logins

External logins are browser navigations. By default a failure (registration
disabled, not in an allowed group, denied at the provider, ...) answers with the
JSON error, which the user sees as a blank page of JSON. Configure where to
send them instead:

```rust
fn external_login_error_redirect(&self) -> Option<&str> {
  // https://example.com/login
  Some(&LOGIN_PAGE)
}
```

Failed logins then redirect to `{login page}?login_error=<reason>`, failed links
to `{post_link_redirect}?link_error=<reason>`. A request to a `/link` route
without a link begun on the session (`BeginExternalLoginLink`) is no link, and
fails to the login page. A link is begun for one provider
(`BeginExternalLoginLink { slug }`, the slug of `/external/{slug}/link`), and
the `/link` of another provider refuses it: `/link` is a plain GET any page
can make the browser send, and must not start the link at a provider of that
page's choosing. The link begun on the session is used up by the first `/link`
request, whatever its outcome, and refused once it is older than 10
minutes. Server errors are logged, and the redirect reports them
only as "Login failed, see the server logs for details". Without the redirect,
the JSON error of a server error carries the full trace like every other
`mogh_error` response, unless the app hides it with
`mogh_error::set_server_error_detail`.

An error the provider answers the login with (`?error=` on the callback, RFC
6749 section 4.1.2.1) is only taken once the callback's `state` matched the
login the session started: anybody can send a browser to the callback with an
error of their choosing, which is a "State mismatch". It is reported as "Login
was denied at the provider" (`access_denied`) or "Login was not completed at the
provider", never with its text, and its code is logged (some are configuration
errors, eg. `invalid_scope`).

The `mogh_ui` `useAuthState` hook shows both as a notification. Anybody can
send a user a link to the app with a made up reason, so the reason itself is
only shown after a flow the same tab started through `mogh_ui` (`externalLogin`,
`LoginPage`, `LinkedLogins`) within the last 30 minutes, and a generic message
otherwise. After a failed login `LoginPage` doesn't redirect to the provider on
its own again, which would only fail again, in a loop.

The requests of a callback to the provider (the code exchange, user info) are
given 30 seconds each, 10 of them to connect, and redirects are not followed. A
provider which accepts the connection but never answers fails the login after
that, instead of leaving the callback hanging. Loading its discovery data is
given 15 seconds (see [Workload identity](#workload-identity)). At most 1 MiB of
any of its responses (discovery, keys, token, user info) is read: a larger one
fails the request unread.

The external login routes are plain `GET`s, which any web page a user visits
can send from their browser. Only the failures of a callback which redeems a
code (and the login rules after it) count against the client ip in
`general_rate_limiter`. An unknown provider, or a login or link which was never
started on the session, is refused without counting it, so it can't lock the
ip out. Starting a login or link takes one of the client's [login
starts](#login-starts). A code the provider refuses (expired, used already, made
up: `invalid_grant`), or an ID token which fails verification, is a failure of
the user (`401`, with what the provider reported), for every provider kind;
the provider refusing the app's configuration (`invalid_client`,
`unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, Github's
`incorrect_client_credentials` / `redirect_uri_mismatch`) or not answering is a
server error, which is not counted.

The `redirect` of `/{slug}/login?redirect=` (where the browser lands after the
login) must be on the app's host and at most 2048 characters, otherwise the
login ends at `host`. The login's query (`redeem_ready=true`, `totp=true`,
`passkey=...`) goes before its fragment.

A new external user is signed up with the provider's name for them if it passes
`validate_username` and `validate_new_username`, else with that name reduced to
`[a-zA-Z0-9._@-]` (`John Smith` becomes `John-Smith`), else with a name made
from the provider's slug (`github-x8k2...`). A taken name gets a random suffix,
and has to pass both with it.

### Login records

The server logs every login. For the app's own audit trail, implement
`record_login`: it is called once per login, at the step which grants it (a
local sign up or login once the password, and any second factor, is verified;
an external sign up or login at the provider's callback, or once its second
factor is complete; a token exchange when the token is issued — an
`ExchangeExternalForJwt` can end in a second factor too), after the hooks the
login needed (`sign_up_local_user` / `sign_up_external_user`,
`sync_external_user`, `get_or_create_workload_user`) and immediately before the
session or token is issued. An error fails the login; by then a one-time
credential (a TOTP step, a recovery code) may be consumed, so an app whose
recording can fail should log and continue instead.

The exception to "immediately before": an external login completed at the
provider's callback without a second factor is recorded at the callback, and
its session jwt is only issued when the app redeems it (`ExchangeForJwt`), up
to 2 minutes later, or never when it isn't redeemed. Its `token_expires` is
the callback time plus the ttl, the jwt expires up to 2 minutes after it.

```rust
fn record_login(&self, login: Login) -> DynFuture<mogh_error::Result<()>> {
  // login.user_id, login.username, login.ip,
  // login.second_factor: Option<Passkey | Totp | TotpRecovery>,
  // login.kind: Local | Provider { provider_id, provider_name }
  //   | Workload { issuer_id, issuer_name, rule_id, rule_name }, and
  // login.token_expires: when the issued session jwt or exchanged
  //   token expires (unix seconds) — a workload rule's
  //   `token_ttl_secs` capped at the app ttl, everything else the
  //   app ttl. Stamp it on the record to show how long each
  //   granted credential lives.
  Box::pin(async move { audit(login).await })
}
```

Refused logins (a wrong password, a token no provider accepts) are not
reported: the server rate limits and logs them.

### Credential changes

A user who changes the password (or enrolls a second factor) because a token
of theirs leaked expects that token to stop working. Once `UpdatePassword`,
`ConfirmTotpEnrollment`, `UnenrollTotp`, `ConfirmPasskeyEnrollment`,
`UnenrollPasskey`, `UnlinkLocalLogin` or `UnlinkExternalLogin` stored its
change, the server calls `credentials_changed(user_id, change, kept_jwt)`:
end the user's other sessions there, keeping `kept_jwt` (the session which
made the change). Eg. store a cutoff with the user and refuse older tokens in
`get_user_id_from_request_authentication`, uncounted:

```rust
fn credentials_changed(
  &self,
  user_id: String,
  _change: CredentialChange,
  kept_jwt: Option<String>,
) -> DynFuture<mogh_error::Result<()>> {
  Box::pin(async move {
    // Tokens carry whole seconds: those of this second stay valid,
    // so a login right after the change works.
    let valid_after = unix_timestamp_secs();
    end_sessions(&user_id, valid_after, kept_jwt.map(sha256_hex)).await
  })
}
// In get_user_id_from_request_authentication, for a jwt:
// claims.iat < user.sessions_valid_after && hash(jwt) != user.kept
//   => Err(anyhow!("The session has ended").status_code(401).uncounted())
// and the keys as the default does it:
//   auth => middleware::get_key_user_id(self, auth, ip)
```

The default does nothing (sessions end when their tokens expire). An error of
the hook fails the request after the change was stored, except for
`ConfirmTotpEnrollment`, whose response carries the recovery codes (shown only
once): its error is logged and the codes returned. A passkey login stores the
passkey's new counter with `update_user_passkey_counter` (defaults to
`update_user_stored_passkey`), which is no credential change.
Each token carries a random `jti`, so two logins of one user in the same
second are two tokens, and a kept token keeps no other. Tokens carry whole
seconds: a cutoff at the change's second keeps the tokens issued in it (a
login right after the change works), one at the next second ends them (and
refuses a login right after the change until then).

### Request context

The hooks which write (`create_external_provider`, `update_trusted_issuer`,
`create_api_key`, `update_user_password`, ...) take what they store, not who
asked for it. For the app's audit rows, `mogh_auth_server::request_context()`
returns the request the server is handling when the hook runs:

```rust
fn update_trusted_issuer(
  &self,
  issuer: TrustedIssuer,
) -> DynFuture<mogh_error::Result<()>> {
  // ip: the client ip; method: the request by its wire name
  // ("UpdateTrustedIssuer", "LoginLocalUser", "ExternalCallback",
  // "TokenExchange"); user_id: who it authenticated as (management
  // requests).
  let context = mogh_auth_server::request_context();
  Box::pin(async move { store_and_audit(issuer, context).await })
}
```

- The router scopes it (a tokio task-local) around every request of the auth
  api, and the server carries it into the task it runs a trusted issuer update
  in (the store and the sync, completed even when the request is dropped). A
  task the app spawns doesn't inherit it: read it first. Outside of the
  auth api (the app's own routes, a background
  task, a helper of the server called directly) it is `None`;
  `scope_request_context` gives such code one, eg. in tests.
- `method` is a login or management request's type once its body is read.
  Before (while a management request authenticates, in
  `get_user_id_from_request_authentication`) it is `context::LOGIN` /
  `context::MANAGE`. The external login routes are `ExternalLogin`,
  `ExternalLink` and `ExternalCallback`, `POST /token` is `TokenExchange`.
- `user_id` is set once a management request authenticated (and by
  `middleware::authenticate_user` + `Authenticated::finish`, eg. the supporter
  api). Logins leave it `None`: their hooks take the user as an argument, and
  `record_login` gets the `Login`.
- The server reads no request body for it: the signed request checks (body
  read after the timestamp) stay as they are.

### Signing keys

A signing key is a key pair registered with the user (`CreateSigningKey`,
`DeleteSigningKey`): the server stores its public key, and clients sign each
request with its private key instead of sending a secret. An api key
(`CreateApiKey`) is the key + secret sent as they are (`X-API-KEY` /
`X-API-SECRET`). The keys are Ed25519 keys, and the server verifies a
signature with a public key alone, the one the request names, which the app
then looks up among the stored ones (`get_signing_key`): the server holds no
key of its own for this, and nothing it holds could sign a request for a
client.

Signing keys are off by default, enable them with
`AuthImpl::signing_keys_enabled` (which needs `AuthImpl::host`):

```rust
fn signing_keys_enabled(&self) -> bool {
  true
}

/// More origins than `host` clients reach the app at and sign requests
/// for, eg. an address inside the network.
fn extra_hosts(&self) -> &[String] {
  &core_config().extra_hosts
}
```

Check the origins when the app starts: one a host can't be read from (it has
no scheme) otherwise only shows in the log, and as a `401` to every client
signing for it (a `500`, when no origin is usable).

```rust
let hosts = mogh_auth_server::middleware::check_signed_request_hosts(&auth)?;
info!("Signed request hosts: {hosts:?}");
```

The rust client has the helpers behind its `pki` feature:
`mogh_auth_client::signature::signed_request_headers_for_url` signs a request
for the host, path and query of the url it is sent to.

```rust
let url = reqwest::Url::parse(&format!("{address}/read/GetVersion"))?;
let body = serde_json::to_vec(&GetVersion {})?;
let mut request = reqwest
  .post(url.clone())
  .header("content-type", "application/json")
  .body(body.clone());
for (header, value) in
  signed_request_headers_for_url(&private_key, "POST", &url, &body)?
{
  request = request.header(header, value);
}
```

Where a proxy in front of the server changes the path (it strips a prefix),
sign the path the server receives: `signed_request_headers` takes the host
(`url_host` of the address) and the path and query on their own.

- A signed request carries five headers: `X-API-PUBLIC-KEY` (the public key of
  the signing key, base64 spki der), `X-API-HOST` (the host the request is
  signed for), `X-API-TIMESTAMP` (unix milliseconds), `X-API-NONCE` (a random
  value of 16 to 64 characters of `A-Z a-z 0-9 - _`, new for every request) and
  `X-API-SIGNATURE` (the base64 of the 64 byte Ed25519 signature). Each has one
  form the server accepts and is given once (the timestamp in plain digits, the
  public key as it is stored), so a request has one spelling.
- The signature is over these lines, joined by `\n` without a trailing one:

  ```text
  mogh-signed-request-v1
  {host}
  {method}
  {path_and_query}
  {timestamp}
  {nonce}
  {sha256(body) hex}
  ```

  eg. `example.com`, `GET`, `/api/notes?page=2`, `1718000000000`,
  `0123456789abcdef0123456789abcdef`, `e3b0c442...b855` (no body): the host
  the request is made for (the value of `X-API-HOST`), the method as it is
  sent (methods are case sensitive), the path and query, the timestamp in unix
  milliseconds (the value of `X-API-TIMESTAMP`), the nonce (the value of
  `X-API-NONCE`) and the lowercase hex sha256 of the body (of empty input for
  no body, and for a CONNECT request over HTTP/2 or later, eg. a websocket,
  whose body is the tunnel). Sign the body exactly as sent, and the path and
  query as the server receives them: percent encoded, without scheme, host
  and fragment (it is the same over HTTP/2). So the headers are made for each
  request, they can't be default headers of a client.
- The host is the lowercase `host[:port]` of the address the client uses,
  without the port when it is the default of the scheme
  (`signature::url_host`): `example.com` for `https://example.com`,
  `10.0.0.5:9120` for `http://10.0.0.5:9120`. An address with credentials
  (`https://user:password@example.com`) is refused: a client sends those as
  `Authorization`, which the server takes over the signature. The server
  accepts a request signed for `AuthImpl::host` or one of
  `AuthImpl::extra_hosts` (both origins, like `https://example.com`), and no
  other: the same public key can be registered at another server, and a
  request made for that one is not a request for this one. What the server
  goes by is the host the client signed (`X-API-HOST`, which the signature
  covers), never where the request arrived (its `Host` header): whoever passes
  a request on to another server sets that too. So it doesn't matter what a
  proxy does to that header, but every address clients sign requests for has
  to be `host` or one of `extra_hosts`.
- The host is all that tells one server from another: list origins which are
  this server's alone. Never the address of another server (a request signed
  for it would be accepted here too), and mind names several deployments
  share (a service name used in two networks, `localhost`). The hosts are not
  secret: the answer to a request signed for another host tells whoever asks
  whether a host is one of them.
- A request signed for another host is refused with `401` before its body is
  read. The error starts with `signature::SIGNED_FOR_ANOTHER_HOST` and names
  the host: the client uses an address the server isn't configured with, and
  no other key would get it through. So is one whose timestamp is outside the
  tolerance, with `signature::SIGNED_AT_ANOTHER_TIME`: the clocks differ, or
  the request took too long to arrive. Clients can tell both from a key the
  server doesn't know (`401 Invalid client credentials`), and neither counts
  against the rate limiter.
- The server reads the body of a signed request before authenticating it, up
  to `AuthImpl::signed_request_body_limit` (2 MB by default) and to the router's
  `DefaultBodyLimit` like axum's body extractors (axum's 2 MB default when the
  router sets none), whichever is smaller, else `413 Payload Too Large`. A
  router which raises or disables its limit (eg. for uploads) doesn't raise how
  much of a signed request is buffered before it is authenticated. To accept
  signed bodies over 2 MB, raise both `signed_request_body_limit` and the
  router's `DefaultBodyLimit` (a layer outside of the auth middleware). A signed
  request which can't verify, found out before (signing keys are not enabled,
  the timestamp is outside the tolerance, the host is none of the server's, or
  one of the five headers is missing, given twice or malformed), is refused
  with `401` without its body being read, and so is a client the general rate
  limiter has locked out, with `429`. Anybody can send well formed headers, so
  the body of any other signed request is read (up to the limit), even when its
  signature turns out to be invalid.
- The body has `AuthImpl::signed_request_body_timeout` (30 seconds by default)
  to arrive once the headers have, else `408 Request Timeout`. The timestamp
  is checked when the headers arrive, so this is what keeps a request from
  being accepted long after it was signed (its headers sent in time, its body
  held back). Raise it along with the limit for larger bodies.
- Apps without `AuthImpl::signing_keys_enabled` (the default) answer signed
  requests with `401 Signing keys are not enabled`, and `CreateSigningKey` with
  `400 Signing keys are not enabled` (the storage hooks need no override for
  it). `DeleteSigningKey` still works, for keys stored while they were on.
- The signature is accepted for one second around the server time by default,
  `AuthImpl::signing_key_timestamp_tolerance_ms` raises that for clients without
  synchronized clocks. It is measured when the headers arrive, the time the
  body takes to upload doesn't count against it (the body timeout does;
  behind a proxy which buffers request bodies the headers arrive with the
  body, so the upload counts). A captured request can be replayed while its
  headers arrive before the server time is past its `X-API-TIMESTAMP` plus the
  tolerance: up to twice the tolerance after it was first accepted, for a
  client whose clock runs ahead (the exact same request to the same server, it
  can't carry another body). Always use TLS.
- The server doesn't remember the requests it has seen. An app which wants to
  refuse a replay implements `AuthImpl::accept_signed_request`, which is
  called once for every signed request when it authenticated, right before it
  is handled, on the app's routes behind `authenticate_request` and on the
  auth management api alike (so there, not in `handle_request_authentication`,
  which the management api doesn't call). What it refuses counts against the
  general rate limiter. The nonce makes every signature unique, and a
  signature has one accepted form (canonical base64 of a canonical signature),
  so one seen before is a replay. A request's body has to arrive by its
  `X-API-TIMESTAMP` plus the tolerance plus the body timeout, and the request
  gets to the hook a moment after that at the latest: remember each signature
  until a margin past that time, and refuse one seen before, or one which only
  gets there after the margin (it could be the copy of one forgotten
  already). The margin covers the moment it takes to authenticate the signer,
  and how far the clocks of the app's instances and of the store differ.
  Check and remember in one step, in a store all instances of the app share.
  A middleware of the app's own which needs the user (as the supporter api
  does) uses the management api's sequence: `middleware::authenticate_user`
  (the signed body, the credentials, the user and the cidr whitelists, in
  that order), its own policy on the user, then `Authenticated::finish`, which
  hands the signature to the hook and attaches `UserExtractor` /
  `AuthenticatedAt` for the handlers.

  ```rust
  fn accept_signed_request(
    &self,
    accepted: AcceptedSignature,
  ) -> DynFuture<mogh_error::Result<()>> {
    Box::pin(async move {
      // accepted.signature, accepted.timestamp (unix ms), and the
      // public_key, host and nonce of the request.
      let keep_until = accepted.timestamp
        + TOLERANCE_MS
        + BODY_TIMEOUT_MS
        + MARGIN_MS;
      if now_ms() > keep_until
        || !seen_signatures().insert_new(accepted.signature, keep_until).await?
      {
        return Err(
          anyhow!("Invalid client credentials")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }
      Ok(())
    })
  }
  ```
- The signature covers the request's method, path and query and body, and the
  host it is for: not its other headers (`Content-Type`, cookies), nor the
  scheme of the address (`http://example.com` and `https://example.com` are
  both signed as `example.com`, as are `ws` and `wss`). Where a proxy strips
  a path prefix, two apps under one host are told apart by nothing a
  signature covers: give them hosts of their own.
- A public key given to `CreateSigningKey` can be base64 or pem
  (`openssl pkey -pubout`), anything else is refused, and so is one already
  stored (`409 Conflict`). It must be an Ed25519 key
  (`openssl genpkey -algorithm ed25519`). ⚠️ Public keys are not secret: store
  them unique across all users (eg. a unique index), which also covers two
  requests racing.
- The default `get_signing_key` refuses an expired signing key
  (`401 Invalid client credentials`), the one `find_signing_key` finds, and the
  default `get_signing_key_owner_id` still finds it (`404` for none), so it can
  be deleted. An override of the owner lookup must not go through
  `get_signing_key` (expired keys could never be deleted), and only its `404`
  counts as "not stored" for `CreateSigningKey`.
- Invalid signatures count against the general rate limiter.

Since 7.0 the signature is an Ed25519 signature: a hard switch. Before, it was
one message of a Noise handshake with a key of the server, which whoever held
that key could also make for any client.
- Signing keys are Ed25519 keys now. The X25519 keys stored before are refused
  (`400` by `CreateSigningKey`, `401` in `X-API-PUBLIC-KEY`), and requests
  signed the old way (`X-API-SIGNATURE` / `X-API-TIMESTAMP` only) are refused
  with `401` until the client upgrades and has a new key. Stored X25519 keys
  can still be deleted (`DeleteSigningKey`): remove them, nothing can be signed
  with them anymore.
- `AuthImpl::server_private_key` is gone, the server has no key for this.
  Signing keys are enabled with `AuthImpl::signing_keys_enabled`, and what the
  server key bound a request to before (this server) is now the host in the
  signed message: `AuthImpl::host` and the new `AuthImpl::extra_hosts`.
- The client functions changed with it: `signed_request_headers` takes the
  host (`url_host` of the server address) instead of the server public key and
  returns five headers (`signed_request_headers_for_url` takes the url of the
  request for both the host and the path), `sign_request` takes a
  `SignedRequest`, whose `message` replaces `pki_auth_prologue` (the server
  verifies the same message). The method is signed as it is sent (it was
  uppercased).
- A stale timestamp is answered with `SIGNED_AT_ANOTHER_TIME` (it was the same
  `Invalid client credentials` as an unknown key).
- The body of a signed request has to arrive within
  `AuthImpl::signed_request_body_timeout` (it could take any time), and a body
  sent with a CONNECT request before HTTP/2 is read and verified like any
  other (it was passed on unread, signed as empty).
- `AuthImpl::accept_signed_request` is new: the place to refuse a replay.

Since 5.0 the body is signed: a hard switch, clients signing the 4.x string
(`{METHOD}|{uri}|{timestamp}`, without the body hash) are refused until they
upgrade. 5.0 also renamed "api keys v2" to signing keys: the requests are
`CreateSigningKey` / `DeleteSigningKey` (were `CreateApiKeyV2` /
`DeleteApiKeyV2`, also on the wire), and the `AuthImpl` methods
`create_signing_key`, `get_signing_key`, `get_signing_key_owner_id`,
`delete_signing_key` and `signing_key_timestamp_tolerance_ms` (were
`*_api_key_v2*`).

### Token exchange (RFC 8693)

A client which already holds a token for a user from one of the external
login providers (eg. a CLI, a script, or another app) can exchange it for
an app token at `POST {path}/token`, without sending the user through the browser.

It is off by default, and enabled per provider (OIDC and Google):

```rust
ExternalLoginProvider {
  id: String::from("oidc"),
  name: String::from("OIDC"),
  registration_disabled: false,
  slug: String::new(),
  token_exchange: TokenExchangeConfig {
    enabled: true,
    // Accept tokens the provider issued to these apps,
    // in addition to the client id of the provider.
    audiences: vec![String::from("my-cli-client-id")],
    // Only accept tokens issued in the last 5 minutes (0 = until they expire).
    max_token_age_secs: 300,
  },
  config: ExternalLoginProviderConfig::Oidc(config.oidc.clone()),
}
```

```sh
curl https://app.example.com/auth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d subject_token=$ID_TOKEN
# {"access_token":"<app jwt>","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":86400}

curl https://app.example.com/api/... -H "Authorization: Bearer <app jwt>"
```

Or with the rust client: `mogh_auth_client::request::token_exchange`.

A provider's login and callback urls name it by its **slug**
(`/external/{slug}/login`, `/external/{slug}/callback`): lowercase letters,
digits and single hyphens, unique among all providers, made from the name
unless the create request gives one. Users' links to the provider carry its
id, never the slug, so changing the slug only changes the redirect URI to
register at the provider. Providers stored before slugs existed have an empty
`slug` and keep their id in the urls (`ExternalLoginProvider::slug()`). So do
providers from the app configuration, which under the reserved id of their kind
also keep the original paths (`/oidc/callback`); while such a provider exists,
its id is a slug no stored provider can take.

The same exchange is part of the login api as `ExchangeExternalForJwt { token }`,
for clients already using it (`authClient().login("ExchangeExternalForJwt", { token })`).
It responds like `LoginLocalUser`: either the JWT, or the second factor to
complete with `CompleteTotpLogin` / `CompletePasskeyLogin` on the same session,
so the client has to keep cookies between the requests. `/token` has no way to
continue, and rejects users who need a second factor for external logins.

- Only tokens **signed by the provider** are accepted (ID tokens / JWTs),
  verified against the keys it publishes. The provider is selected by the
  `iss` claim of the token. Opaque access tokens are rejected, they can't
  be tied to an audience.
- The token must be issued to the client id of the provider, or one of
  `audiences`. ⚠️ Tokens the provider issues to every app listed there
  can be used to log in to this app.
- The user must already exist and be linked to the provider.
  The endpoint never signs up users. If several providers share the
  issuer, the first which accepts the token and knows the user decides.
- A captured token can be exchanged by anyone until it expires, and some
  providers issue tokens valid for hours. `max_token_age_secs` limits this
  to the time since the token was issued. Clients should exchange a token
  right after receiving it, and keep the app token.
- The app token counts as a login when the provider authenticated the user
  (the token's `auth_time`, else its `iat`), not at the exchange. An exchanged
  old token is not a recent login for the [reauthentication](#reauthentication)
  window, so it can't change passwords, 2FA or api keys. A token carrying
  `auth_time` which the provider refreshed, or issued from a single sign-on
  session, keeps the original `auth_time`, so it isn't one either. ⚠️ Without
  `auth_time` its `iat` is used, and a token the provider refreshed or
  re-issued without a login counts as a fresh one. OIDC only requires
  `auth_time` when it is requested (eg. with `max_age`), and some providers
  (eg. Google) leave it out otherwise. To get a recent login through the
  exchange, the client must make the provider authenticate the user again (eg.
  OIDC `prompt=login` or `max_age=0`, which also asks for `auth_time`).
- 'allowed_groups' and the user cidr whitelist apply like for a login,
  and `AuthImpl::sync_external_user` is called. Groups can only come
  from the token itself here, there is no user info request.
- Users who need a second factor for external logins are rejected
  by `/token`, and continue with it using `ExchangeExternalForJwt`.
  ⚠️ That is only users for whom `AuthUserImpl::external_skip_2fa` is `false`.
  It defaults to `true`, so without an implementation a provider token alone
  gets an app token for a user enrolled in 2FA.
- Errors use the OAuth format: `{"error":"invalid_grant","error_description":"..."}`.
  A malformed request is `invalid_request`, a token rejected for any reason is
  `invalid_grant` (as for the RFC 7521 / 7523 assertion grants and common token
  services). This deliberately deviates from RFC 8693 section 2.2.2, which
  would report both as `invalid_request`. Except when another login provider
  (or trusted issuer) of the same issuer couldn't be loaded: a token the others
  rejected (signature, audience, expiry, `allowed_groups`) is then `503`
  `temporarily_unavailable`, since that one might have accepted it. It still
  counts against the rate limit as a failed attempt (the caller picks the
  issuer). A token one of them verified whose user is unknown, or which matches
  no rule, stays `invalid_grant`, as does a user one of them accepted who fails
  the login rules. Login providers and trusted issuers of one issuer are ranked
  together: the furthest any of them got is reported.
- Google ID tokens are only accepted with the `iss` `https://accounts.google.com`.
  The scheme-less variant `accounts.google.com` can't be verified.
- The endpoint takes a form, which any web page can make its visitors' browsers
  post (a CORS "simple" request). A request a browser sent from a page of
  another site is refused with `invalid_request` before anything counts against
  the visitor's ip: a `Sec-Fetch-Site` other than `same-origin` / `none`, or
  without it an `Origin` which isn't `host` or one of `extra_hosts`. Otherwise
  any site could fail exchanges on purpose and get everybody behind its
  visitors' ip refused by the rate limiter. RFC 8693 clients send neither
  header. Apps serving the exchange on another surface which takes such bodies
  call `api::token::check_not_cross_site` first (see
  [The exchange on another surface](#the-exchange-on-another-surface)). So
  token exchange needs `AuthImpl::host` implemented (its default panics), as
  external logins and signing keys do.
- Failed exchanges count against `AuthImpl::token_exchange_rate_limiter`, which
  is `general_rate_limiter` unless the app gives it a limiter of its own (see
  the shared runners note of [Workload identity](#workload-identity)).

### Workload identity

Machines can use the same `/token` endpoint: a CI job or Kubernetes service
account exchanges the short lived token its platform issues it for a short
lived app token, so it doesn't need an api key stored as a secret.

Instead of a login provider this uses a `TrustedIssuer`, which only needs
the keys the platform signs with, and rules deciding which tokens are accepted:

```rust
fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
  vec![TrustedIssuer {
    id: String::from("github-actions"),
    name: String::from("Github Actions"),
    enabled: true,
    issuer: String::from("https://token.actions.githubusercontent.com"),
    // Or `JwksUri(url)`, or `Static(jwks_json)` for issuers the server can't
    // reach, like most clusters: `kubectl get --raw /openid/v1/jwks`
    keys: TrustedIssuerKeys::Discovery {},
    // ⚠️ An audience specific to this app, which the workload requests its
    // token for. The platform default is shared with every other service.
    audiences: vec![String::from("https://app.example.com")],
    max_token_age_secs: 300,
    rules: vec![WorkloadRule {
      id: String::from("deploy"),
      name: String::from("Deploy"),
      enabled: true,
      // All have to match, `*` is a wildcard. Prefer ids over names.
      claims: vec![
        WorkloadClaim { claim: "repository_id".into(), pattern: "12345".into() },
        WorkloadClaim { claim: "ref".into(), pattern: "refs/heads/release/*".into() },
      ],
      groups: vec![String::from("deployers")],
      admin: false,
      token_ttl_secs: 900,
    }],
  }]
}
```

Keys which are fetched are cached for 5 minutes. The same goes for the
discovery data of login providers (OIDC 1 minute, Google 1 hour), and both
are loaded the same way, as they are loaded on demand by unauthenticated requests:

- Concurrent requests share one load, eg. a CI matrix starting many jobs at once.
- A load is given 15 seconds, so a hanging server can't block the others waiting on it.
- A failed load is only tried again after 30 seconds. Requests in between
  get `503` right away (`temporarily_unavailable` from `/token`), and the
  reason is logged once per attempt, not by every request.
- While the source can't be reached, what was loaded before stays in use for
  up to an hour after it went out of date, so a short outage doesn't stop every
  login or workload.

Issuers can also be stored by the app and managed by admins over the API
(`ListTrustedIssuers`, `CreateTrustedIssuer`, ...), with the same storage
methods as for login providers (`list_trusted_issuers`, `create_trusted_issuer`, ...).
The names of login providers, issuers and rules are trimmed, at most 100
characters, and refused (`400`) with a control character (Unicode Cc: a tab,
a line break, an escape sequence) inside: they are listed, shown on the login
page and logged. The error doesn't repeat the name.

Each rule has its own user, which the app provides:

```rust
fn get_or_create_workload_user(
  &self,
  identity: WorkloadIdentity,
) -> mogh_auth_server::DynFuture<mogh_error::Result<String>> {
  Box::pin(async move {
    // One user per (issuer_id, rule_id), under a unique key on both.
    // Called concurrently for the same rule (a CI matrix starting):
    // `INSERT ... ON CONFLICT DO NOTHING`, then read the user back.
    create_service_user_if_missing(
      &identity.issuer_id,
      &identity.rule_id,
      &identity.rule_name,
    )
    .await?;
    let user =
      find_service_user(&identity.issuer_id, &identity.rule_id).await?;
    // Apply the groups and admin status every time,
    // they are the full definition of the user.
    set_user_groups(&user.id, identity.groups).await?;
    set_user_admin(&user.id, identity.admin).await?;
    // Created enabled. Leave `enabled` to `sync_workload_users`.
    // `identity.claims` tell which repository / run / service account it was.
    Ok(user.id)
  })
}

/// Called after `update_trusted_issuer` stored an update (and by
/// `sync_all_workload_users`), with every rule of the issuer.
fn sync_workload_users(
  &self,
  issuer_id: String,
  rules: Vec<WorkloadAccess>,
) -> mogh_auth_server::DynFuture<mogh_error::Result<()>> {
  Box::pin(async move {
    // Eg. in one transaction: remove the users of `issuer_id` whose rule
    // isn't in `rules`, and give the others their rule's groups, admin
    // and enabled (`false` while the rule or the issuer is disabled, it
    // overrides the user's own). Rules without a user get none.
    sync_service_users(&issuer_id, &rules).await.map_err(Into::into)
  })
}
```

- That user must report `AuthUserImpl::is_workload`, otherwise the exchange
  is refused. Workload users are refused by the whole auth management API
  (all but `GetUserId`),
  so a workload can't create an api key (or password, 2fa, linked login,
  login provider, ...) which outlives its rule. ⚠️ Apps with their own ways to
  create credentials must refuse workload users there as well.
- ⚠️ `get_or_create_workload_user` is called concurrently for the same rule, and
  has to return the same user to all of them without failing any: keep a unique
  key on (`issuer_id`, `rule_id`), create with an upsert or an insert ignoring
  the conflict and read the user back, and make usernames which can't collide
  (or retry). The library serializes the calls of a rule within one instance
  of the app, not across several. The example app shows it (`example/server`).
- Rules of static issuers need an `id` which is unique within the issuer,
  it identifies the user of the rule. Tokens matching a rule without one
  are refused. Ids of rules managed over the API are generated.
- A rule needs a condition on a claim which identifies the workload (eg. `sub`,
  `repository_id`). Conditions on claims every accepted token has (`iss`,
  `aud`, `exp`, `iat`, `nbf`, `jti`) can only narrow it further: an audience is
  no restriction on a public platform, where anyone can request a token for any
  audience. A claim whose pattern is only `*` restricts nothing either. This is
  best effort, `repo:*` still matches every repository there. The management
  api refuses such rules (and issuers without an audience, or with credentials
  in a url) with `400`; a static issuer of the app configuration which has one
  is skipped, with an error in the log, so it accepts no token and
  `sync_all_workload_users` removes the users of its rules. Apps can check their
  configured issuers with
  `mogh_auth_server::provider::workload::validate_trusted_issuer` when they load
  it.
- An admin user is only accepted if the rule has `admin` set, and a disabled
  user not at all.
- The user cidr whitelist applies. Users requiring a second factor are refused.
- The app token is valid for `token_ttl_secs`, capped at the app default.
- Every exchange is logged with the issuer, rule, subject and matched claims.

**Changing a rule.** The app token of a workload carries the id of the rule's
user only, and the user keeps its id as long as the rule does. Saving an issuer
(`UpdateTrustedIssuer`) syncs the users of its rules (`sync_workload_users`), so
a change reaches the tokens already issued on their next request:

- Disabling a rule or its issuer disables the user: its tokens are refused by
  the app's disabled user check (`require_user_enabled`), and it gets no new
  ones. Enabling it again brings back the same user, and its tokens.
- Changing a rule's `groups` or `admin` applies to the user right away: a
  demoted rule's tokens are no admin anymore.
- Removing a rule, or deleting the issuer, removes the user: its tokens are
  refused.
- ⚠️ Narrowing a rule's `claims` only stops new exchanges of the tokens it no
  longer matches. The app tokens issued before carry no claims, they act as the
  rule's user like those of the workloads still matching. To cut them off,
  disable or delete the rule (a new rule has a new user).
- ⚠️ The synced `enabled` is the state of the rule, and wins over any other way
  the user was disabled: saving the issuer (or `sync_all_workload_users` at
  startup) re-enables a workload user an admin disabled directly while its rule
  and issuer are enabled. Disabling the rule is the way to switch its user off.
  An app with its own per user switch must refuse it for workload users (the
  example app does), or store the rule's `enabled` apart from the switch and
  have `is_enabled` report both. When upgrading an app which had such a switch,
  disable the rules of the workload users it disabled first.

A failed `sync_workload_users` fails `UpdateTrustedIssuer` after the issuer was
stored, which is logged (the update, and a warning that its users weren't
synced). Saving the issuer again syncs again.

Within one instance of the app, exchanges of an issuer wait while it is updated
or deleted and then read the rule again, so an exchange which read it before
never gives the user access the update took away, nor creates the user of a
removed rule. Apps running several instances only get that as far as each one
sees the change right away (the cache of `list_trusted_issuers`), see
`get_or_create_workload_user`.

Static issuers can't be updated over the API. Their changes (a restart with
another configuration) apply to new exchanges, and a rule's `groups` / `admin`
reach its user at its next exchange. Call
`mogh_auth_server::provider::workload::sync_all_workload_users` when the app
starts to apply them to the users right away (disabling and removing the users
of disabled and removed rules). At its end it calls
`AuthImpl::remove_workload_users_except` with every issuer as it is then (and
the ids of its rules): remove the users of the issuers (and rules) which aren't
among them, eg. of an issuer removed from the configuration. The default
removes nothing. Token exchanges wait while it runs, and the issuers are listed
for it once they do, so the user of an issuer (or rule) created meanwhile is
created after it, never removed as one which is gone. That holds within one
instance of the app: an app which creates workload users outside the exchange,
or runs several instances, checks its stored issuers again in the statement
which removes the users (eg. `NOT EXISTS` against them in the `DELETE`). It can
run while the app serves: each issuer is read again under its lock, so an
update made meanwhile isn't undone, and one issuer failing to sync doesn't stop
the others. The example app does both (`example/server`).

⚠️ **Rate limiting and shared runners.** Failed exchanges count against
`AuthImpl::token_exchange_rate_limiter` by client ip, which is
`general_rate_limiter` (the one of failed logins) unless the app gives it a
limiter of its own. Hosted CI runners (eg. Github's) share their ips between many
customers and jobs, so with a strict limit one misconfigured job failing
repeatedly, or anyone else running jobs on the same runners and sending tokens no
rule accepts, can get the ip limited and make your other jobs fail with `429` /
`temporarily_unavailable` for a while (and, with the shared limiter, the logins
from that ip). If workloads come from shared ips, keep the failure limit
generous or separate, make jobs retry an exchange with a delay rather than in a
tight loop, or use self hosted runners with their own ips. Successful exchanges
are never rate limited.

### The exchange on another surface

Apps serving the exchange elsewhere, eg. a Vault compatible `auth/jwt/login`
whose `client_token` is the app token, call what the endpoint calls:

```rust
use mogh_auth_server::api::token::{
  ExchangedLogin, RoleNotFound, TokenExchangeOptions, exchange_token,
  token_exchange_error,
};

let exchanged = exchange_token(
  &auth,
  ip,
  TokenExchangeRequest::id_token(jwt),
  TokenExchangeOptions {
    // Vault's `role`: only log in through the login provider or workload
    // rule with this id or name. A workload token is then matched against
    // that rule alone (not the first matching rule of its issuer), and a
    // role nothing of that name accepts is refused before the exchange
    // has any effect, as `RoleNotFound` (an `invalid_grant`).
    role: Some(String::from("deploy")),
  },
)
.await;

match exchanged {
  Ok(exchanged) => {
    // exchanged.response is what `/token` answers; exchanged.user_id and
    // exchanged.login (the provider, or the issuer + rule) say who it is.
    if let ExchangedLogin::Workload { rule_name, .. } = &exchanged.login {}
  }
  Err(e) => {
    if e.error.downcast_ref::<RoleNotFound>().is_some() {}
    // The OAuth error and status the endpoint would answer with
    let (status, error) = token_exchange_error(&e);
  }
}
```

It is exactly the endpoint's exchange: the failure rate limit by ip included,
the app told about the login through the same hooks.

What it does not do is the endpoint's first check: a request a web browser sent
from a page of another site is refused before anything counts against the
visitor's ip. A surface which reads a body of any content type (Vault clients
send JSON without saying so) takes one any page can post from its visitors'
browsers, so it checks first too, and so does any other unauthenticated
endpoint of the app counting failures by ip (eg. a Vault AppRole login).
`middleware::is_cross_site_browser_request` is the endpoint's check as a
`bool`, to answer in the surface's own format (`api::token::check_not_cross_site`
answers with the endpoint's `invalid_request`):

```rust
use mogh_auth_server::middleware::is_cross_site_browser_request;

async fn vault_jwt_login(
  RequestIp(ip): RequestIp,
  headers: HeaderMap,
  body: Bytes,
) -> Result<Response, VaultError> {
  let auth = AppAuthImpl::new();
  // Before anything is counted: any site could otherwise fail logins on
  // purpose from its visitors' browsers, and get their ip refused.
  if is_cross_site_browser_request(&auth, &headers) {
    return Err(VaultError::new(
      StatusCode::FORBIDDEN,
      "web pages of other sites can't log in",
    ));
  }
  // ...exchange_token(&auth, ip, ..)
}
```

Github Actions:

```yaml
permissions:
  id-token: write
steps:
  - run: |
      ID_TOKEN=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://app.example.com" | jq -r .value)
      APP_TOKEN=$(curl -s https://app.example.com/auth/token \
        -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
        -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
        -d subject_token=$ID_TOKEN | jq -r .access_token)
```

Kubernetes, with a projected service account token for the audience
(`serviceAccountToken: { audience: https://app.example.com, path: token }`),
matching eg. `sub` = `system:serviceaccount:<namespace>:<name>`.
