//! Workload identity: tokens of a [TrustedIssuer] are matched against
//! its [WorkloadRule]s, and the matching rule decides who the workload
//! acts as. See [crate::api::token] for the exchange itself.

use std::{
  collections::HashMap,
  hash::{DefaultHasher, Hash, Hasher as _},
  sync::{Arc, Mutex, OnceLock},
  time::Duration,
};

use anyhow::{Context as _, anyhow};
use mogh_auth_client::config::{
  TrustedIssuer, TrustedIssuerKeys, WorkloadClaim, WorkloadRule,
};
use mogh_logger::redact_url_credentials;
use openidconnect::{IssuerUrl, core::CoreJsonWebKeySet};
use serde_json::{Map, Value};
use tracing::{error, warn};

use crate::{
  AuthImpl,
  provider::{
    external::validate_provider_id,
    load_cache::LoadCache,
    token_exchange::{TokenVerificationKeys, issuers_match},
  },
  validations::validate_public_http_url,
};

/// Fetched keys are reused for 5min, so a rotation at the issuer is picked up.
const FETCHED_KEYS_VALID_FOR: Duration = Duration::from_secs(5 * 60);
/// Nested claims deeper than this are not looked up.
const MAX_CLAIM_PATH_PARTS: usize = 16;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Far larger than any real key set.
pub const MAX_JWKS_LENGTH: usize = 256 * 1024;

pub type Claims = Map<String, Value>;

/// The workload a verified token belongs to, passed to
/// [AuthImpl::get_or_create_workload_user].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WorkloadIdentity {
  /// The id of the [TrustedIssuer] which issued the token.
  pub issuer_id: String,
  /// The id of the matched [WorkloadRule]. Together with
  /// `issuer_id` this identifies the user of the workload:
  /// every token matching the rule acts as the same user.
  pub rule_id: String,
  /// The name of the rule, to name the user after.
  pub rule_name: String,
  /// The app groups the user must have. This is the full
  /// list: groups not on it should be removed from the user.
  pub groups: Vec<String>,
  /// Whether the user must be an admin.
  pub admin: bool,
  /// The verified claims of the token, eg. to record which
  /// repository / run / service account the user was last used by.
  pub claims: Claims,
}

// ============
// = MATCHING =
// ============

/// `*` matches any run of characters (including none),
/// everything else is literal and case sensitive.
pub fn glob_match(pattern: &str, value: &str) -> bool {
  let mut parts = pattern.split('*');
  // Without any '*' the first part is the whole pattern.
  let first = parts.next().unwrap_or_default();
  let Some(mut rest) = value.strip_prefix(first) else {
    return false;
  };
  let mut parts = parts.peekable();
  if parts.peek().is_none() {
    return rest.is_empty();
  }
  while let Some(part) = parts.next() {
    if parts.peek().is_none() {
      // The last part has to end the value.
      return rest.ends_with(part);
    }
    match rest.find(part) {
      Some(index) => rest = &rest[index + part.len()..],
      None => return false,
    }
  }
  true
}

/// Finds the claim at a dotted path. Claim names can contain dots
/// themselves (`kubernetes.io`), so every split of the path is tried,
/// longest names first.
pub fn lookup_claim<'a>(
  claims: &'a Claims,
  path: &str,
) -> Option<&'a Value> {
  fn lookup<'a>(
    claims: &'a Claims,
    parts: &[&str],
  ) -> Option<&'a Value> {
    for split in (1..=parts.len()).rev() {
      let Some(value) = claims.get(&parts[..split].join(".")) else {
        continue;
      };
      if split == parts.len() {
        return Some(value);
      }
      if let Some(found) = value
        .as_object()
        .and_then(|nested| lookup(nested, &parts[split..]))
      {
        return Some(found);
      }
    }
    None
  }
  let parts = path.split('.').collect::<Vec<_>>();
  // Every split is tried at every level, which gets expensive fast.
  if path.is_empty() || parts.len() > MAX_CLAIM_PATH_PARTS {
    return None;
  }
  lookup(claims, &parts)
}

fn claim_matches(claims: &Claims, condition: &WorkloadClaim) -> bool {
  let matches = |value: &Value| match value {
    Value::String(value) => glob_match(&condition.pattern, value),
    Value::Bool(value) => {
      glob_match(&condition.pattern, &value.to_string())
    }
    Value::Number(value) => {
      glob_match(&condition.pattern, &value.to_string())
    }
    _ => false,
  };
  match lookup_claim(claims, &condition.claim) {
    // One of the values of a list, eg. `aud`
    Some(Value::Array(values)) => values.iter().any(matches),
    Some(value) => matches(value),
    // A missing claim never matches, whatever the pattern.
    None => false,
  }
}

/// The first enabled rule the claims meet all conditions of.
/// A rule without conditions never matches.
pub fn match_rule<'a>(
  rules: &'a [WorkloadRule],
  claims: &Claims,
) -> Option<&'a WorkloadRule> {
  rules.iter().find(|rule| {
    rule.enabled
      && !rule.claims.is_empty()
      && rule
        .claims
        .iter()
        .all(|condition| claim_matches(claims, condition))
  })
}

// ========
// = KEYS =
// ========

pub fn parse_jwks(jwks: &str) -> anyhow::Result<CoreJsonWebKeySet> {
  if jwks.len() > MAX_JWKS_LENGTH {
    return Err(anyhow!("Key set is too large"));
  }
  let jwks: CoreJsonWebKeySet = serde_json::from_str(jwks)
    .context("Invalid key set (JWKS) json")?;
  if jwks.keys().is_empty() {
    return Err(anyhow!("Key set (JWKS) has no usable keys"));
  }
  Ok(jwks)
}

fn http_client() -> &'static reqwest::Client {
  static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
  CLIENT.get_or_init(|| {
    reqwest::Client::builder()
      .redirect(reqwest::redirect::Policy::none())
      .timeout(FETCH_TIMEOUT)
      .user_agent(concat!(
        env!("CARGO_PKG_NAME"),
        "/",
        env!("CARGO_PKG_VERSION")
      ))
      .build()
      .expect("Invalid workload identity reqwest client")
  })
}

/// Reads at most [MAX_JWKS_LENGTH], whatever the server sends.
///
/// The management api refuses urls with credentials, but issuers
/// configured elsewhere (static ones, rows stored before) may still
/// carry them, in the userinfo or the query: errors name the url
/// redacted ([redact_url_credentials]), and the http client's own
/// errors, which would repeat it with its query, without it.
async fn fetch_text(url: &str) -> anyhow::Result<String> {
  let shown = redact_url_credentials(url);
  let mut response = http_client()
    .get(url)
    .send()
    .await
    .map_err(reqwest::Error::without_url)
    .with_context(|| format!("Failed to reach {shown}"))?
    .error_for_status()
    .map_err(reqwest::Error::without_url)
    .with_context(|| format!("Request to {shown} failed"))?;
  let too_large = || anyhow!("Response of {shown} is too large");
  if response
    .content_length()
    .is_some_and(|length| length > MAX_JWKS_LENGTH as u64)
  {
    return Err(too_large());
  }
  let mut body = Vec::<u8>::new();
  while let Some(chunk) = response
    .chunk()
    .await
    .map_err(reqwest::Error::without_url)
    .with_context(|| format!("Failed to read response of {shown}"))?
  {
    if body.len() + chunk.len() > MAX_JWKS_LENGTH {
      return Err(too_large());
    }
    body.extend_from_slice(&chunk);
  }
  String::from_utf8(body).with_context(|| {
    format!("Response of {shown} is not valid UTF-8")
  })
}

/// The part of OpenID discovery workload issuers publish. They have
/// no login endpoints, so they are not valid OIDC provider metadata.
#[derive(serde::Deserialize)]
struct IssuerDiscovery {
  issuer: String,
  jwks_uri: String,
}

async fn load_jwks(
  issuer: &TrustedIssuer,
) -> anyhow::Result<CoreJsonWebKeySet> {
  let jwks_uri = match &issuer.keys {
    TrustedIssuerKeys::Static(jwks) => return parse_jwks(jwks),
    TrustedIssuerKeys::JwksUri(url) => url.clone(),
    TrustedIssuerKeys::Discovery {} => {
      let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.issuer.trim_end_matches('/')
      );
      let discovery: IssuerDiscovery =
        serde_json::from_str(&fetch_text(&url).await?)
          .context("Invalid OpenID discovery document")?;
      if !issuers_match(&discovery.issuer, &issuer.issuer) {
        return Err(anyhow!(
          "Discovery document is for another issuer: {}",
          discovery.issuer
        ));
      }
      discovery.jwks_uri
    }
  };
  parse_jwks(&fetch_text(&jwks_uri).await?)
}

/// See [LoadCache] for how concurrent
/// exchanges and outages of the issuer are handled.
fn keys_cache() -> &'static LoadCache<TokenVerificationKeys> {
  static CACHE: OnceLock<LoadCache<TokenVerificationKeys>> =
    OnceLock::new();
  CACHE.get_or_init(Default::default)
}

/// Only what the keys depend on, rule changes don't reload them.
fn keys_fingerprint(issuer: &TrustedIssuer) -> u64 {
  let mut hasher = DefaultHasher::new();
  issuer.issuer.hash(&mut hasher);
  issuer.keys.hash(&mut hasher);
  hasher.finish()
}

/// The keys to verify tokens of the issuer with, cached
/// until its key configuration changes or they are outdated.
pub async fn load_verification_keys(
  issuer: &TrustedIssuer,
) -> anyhow::Result<Arc<TokenVerificationKeys>> {
  // Static keys only change with the configuration
  let valid_for = match issuer.keys {
    TrustedIssuerKeys::Static(_) => None,
    _ => Some(FETCHED_KEYS_VALID_FOR),
  };
  keys_cache()
    .load(&issuer.id, keys_fingerprint(issuer), valid_for, || async {
      Ok(TokenVerificationKeys::new(
        IssuerUrl::new(issuer.issuer.clone())
          .context("Issuer is not a valid url")?,
        load_jwks(issuer).await?,
      ))
    })
    .await
}

pub fn evict_verification_keys(issuer_id: &str) {
  keys_cache().evict(issuer_id);
}

// =========
// = LOCKS =
// =========

type Locks<K, L> = Mutex<HashMap<K, Arc<L>>>;
type RuleLock = tokio::sync::Mutex<()>;
type IssuerLock = tokio::sync::RwLock<()>;
type RemovalLock = tokio::sync::RwLock<()>;

/// Written while [sync_all_workload_users] lists the issuers which
/// are live and the app removes the users of the others
/// ([AuthImpl::remove_workload_users_except]), read by the exchanges
/// while they get or create a user ([hold_off_removal]). One for all
/// issuers: the user created meanwhile may be one of an issuer
/// created after the listing, which no lock of its own could have
/// held off.
fn removal_lock() -> &'static RemovalLock {
  static LOCK: OnceLock<RemovalLock> = OnceLock::new();
  LOCK.get_or_init(Default::default)
}

/// Held by an exchange around [lock_workload_user] and
/// [AuthImpl::get_or_create_workload_user]: waits for the removal of
/// the users of the issuers and rules which are gone at the end of
/// [sync_all_workload_users], and holds it off. A user created after
/// it listed the live issuers (the first exchange of an issuer or rule
/// created meanwhile) would be taken for one of an issuer which is
/// gone.
///
/// Take it first, holding nothing else while it waits, and never
/// wait for another exchange while holding it: the lock is fair, a
/// removal waiting for it holds off the exchanges which come after.
pub(crate) async fn hold_off_removal()
-> tokio::sync::RwLockReadGuard<'static, ()> {
  removal_lock().read().await
}

/// One lock per (issuer id, rule id) with a caller.
fn rule_locks() -> &'static Locks<(String, String), RuleLock> {
  static LOCKS: OnceLock<Locks<(String, String), RuleLock>> =
    OnceLock::new();
  LOCKS.get_or_init(Default::default)
}

/// One lock per issuer id with a caller.
fn issuer_locks() -> &'static Locks<String, IssuerLock> {
  static LOCKS: OnceLock<Locks<String, IssuerLock>> = OnceLock::new();
  LOCKS.get_or_init(Default::default)
}

/// The lock of `key` in `locks`, held until dropped. The last one
/// released takes the lock out of the map.
struct Held<K: Eq + Hash + 'static, L: 'static, G> {
  locks: &'static Locks<K, L>,
  key: K,
  guard: Option<G>,
}

impl<K: Eq + Hash + 'static, L: 'static, G> Drop for Held<K, L, G> {
  fn drop(&mut self) {
    let mut locks =
      self.locks.lock().unwrap_or_else(|e| e.into_inner());
    drop(self.guard.take());
    // Waiting callers hold a clone, which is only taken with the
    // map locked: nobody but the map holding it means nobody waits.
    if locks
      .get(&self.key)
      .is_some_and(|lock| Arc::strong_count(lock) == 1)
    {
      locks.remove(&self.key);
    }
  }
}

async fn hold<K, L, G, F>(
  locks: &'static Locks<K, L>,
  key: K,
  lock: impl FnOnce(Arc<L>) -> F,
) -> Held<K, L, G>
where
  K: Eq + Hash + Clone + 'static,
  L: Default + 'static,
  F: Future<Output = G>,
{
  let shared = locks
    .lock()
    .unwrap_or_else(|e| e.into_inner())
    .entry(key.clone())
    .or_default()
    .clone();
  let guard = lock(shared).await;
  Held {
    locks,
    key,
    guard: Some(guard),
  }
}

/// Held while the app gets or creates the user of a rule, see
/// [lock_workload_user]. Releases the locks when dropped.
pub struct WorkloadUserLock {
  // Released in this order: the rule, then the issuer.
  _rule: Held<
    (String, String),
    RuleLock,
    tokio::sync::OwnedMutexGuard<()>,
  >,
  _issuer:
    Held<String, IssuerLock, tokio::sync::OwnedRwLockReadGuard<()>>,
}

/// Serializes the exchanges of one rule (`issuer_id`, `rule_id`)
/// around [AuthImpl::get_or_create_workload_user]. A CI matrix starts
/// many jobs at once, and without this all their first exchanges ask
/// the app for a user which doesn't exist yet at the same moment,
/// racing to create it. Exchanges of other rules don't wait.
///
/// It also waits for, and holds off, changes to the issuer
/// ([lock_trusted_issuer]): an exchange which reads the rule again
/// once it holds this never gives the user the access the rule had
/// before an update the app finished storing and syncing.
///
/// The exchange takes it once it waited for the removal of the users
/// of issuers and rules which are gone, at the end of
/// [sync_all_workload_users].
///
/// This only covers one instance of the app: apps running several
/// still need a get or create which is safe under concurrency.
pub async fn lock_workload_user(
  issuer_id: &str,
  rule_id: &str,
) -> WorkloadUserLock {
  let issuer = hold(issuer_locks(), issuer_id.to_string(), |lock| {
    lock.read_owned()
  })
  .await;
  let rule = hold(
    rule_locks(),
    (issuer_id.to_string(), rule_id.to_string()),
    |lock| lock.lock_owned(),
  )
  .await;
  WorkloadUserLock {
    _rule: rule,
    _issuer: issuer,
  }
}

/// Held while a trusted issuer is changed, see [lock_trusted_issuer].
/// Releases the lock when dropped.
pub struct TrustedIssuerLock {
  _issuer:
    Held<String, IssuerLock, tokio::sync::OwnedRwLockWriteGuard<()>>,
}

/// Waits until no exchange of the issuer is getting the user of one
/// of its rules ([lock_workload_user]), and holds them off until
/// dropped. The management API holds it while the app stores an
/// update of the issuer and syncs the users of its rules
/// ([AuthImpl::sync_workload_users]), or deletes it.
///
/// This only covers one instance of the app.
pub async fn lock_trusted_issuer(
  issuer_id: &str,
) -> TrustedIssuerLock {
  TrustedIssuerLock {
    _issuer: hold(issuer_locks(), issuer_id.to_string(), |lock| {
      lock.write_owned()
    })
    .await,
  }
}

// ==========
// = ACCESS =
// ==========

/// What the user of a [WorkloadRule] can do, as the rule and its
/// [TrustedIssuer] say now. [AuthImpl::sync_workload_users] applies
/// it to the user of the rule (`issuer_id`, `rule_id`), if it has
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkloadAccess {
  /// The id of the rule.
  pub rule_id: String,
  /// The app groups of the user. This is the full
  /// list: groups not on it should be removed from the user.
  pub groups: Vec<String>,
  /// Whether the user is an admin.
  pub admin: bool,
  /// Whether the user is enabled
  /// ([AuthUserImpl::is_enabled][crate::user::AuthUserImpl::is_enabled]):
  /// the rule and its issuer both are. The tokens a disabled user got
  /// before are refused by the app's disabled user check
  /// (`require_user_enabled`), and it can't exchange tokens.
  ///
  /// ⚠️ It is the state of the rule, and `true` re-enables a user
  /// which was disabled any other way, see
  /// [AuthImpl::sync_workload_users].
  pub enabled: bool,
}

impl WorkloadAccess {
  /// The access of every rule of `issuer`, the rules
  /// [AuthImpl::sync_workload_users] is called with.
  ///
  /// Rules the exchange refuses for their id (static issuers only:
  /// ids of stored issuers are generated) have no usable user: one
  /// without a valid id is left out, so the sync removes any user
  /// with it, and rules sharing an id get one disabled entry, without
  /// groups or admin.
  pub fn of_issuer(issuer: &TrustedIssuer) -> Vec<WorkloadAccess> {
    let mut access = Vec::<WorkloadAccess>::new();
    for rule in &issuer.rules {
      if validate_provider_id(&rule.id).is_err() {
        continue;
      }
      if let Some(shared) =
        access.iter_mut().find(|access| access.rule_id == rule.id)
      {
        shared.groups.clear();
        shared.admin = false;
        shared.enabled = false;
        continue;
      }
      access.push(WorkloadAccess {
        rule_id: rule.id.clone(),
        groups: rule.groups.clone(),
        admin: rule.admin,
        enabled: issuer.enabled && rule.enabled,
      });
    }
    access
  }
}

/// A trusted issuer as it is, and the ids of the rules whose users
/// it keeps, see [AuthImpl::remove_workload_users_except].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LiveIssuer {
  /// The id of the issuer.
  pub issuer_id: String,
  /// The ids of its rules which can have a user
  /// ([WorkloadAccess::of_issuer]).
  pub rule_ids: Vec<String>,
}

impl LiveIssuer {
  fn of(issuer: &TrustedIssuer) -> LiveIssuer {
    LiveIssuer {
      issuer_id: issuer.id.clone(),
      rule_ids: WorkloadAccess::of_issuer(issuer)
        .into_iter()
        .map(|access| access.rule_id)
        .collect(),
    }
  }
}

/// Applies the rules of every trusted issuer, static and stored, to
/// their users with [AuthImpl::sync_workload_users], then removes the
/// users of issuers and rules which are gone with
/// [AuthImpl::remove_workload_users_except].
///
/// Call it when the app starts. Static issuers
/// ([AuthImpl::static_trusted_issuers]) are never updated over the
/// API, so this is how a change to their configuration reaches the
/// users of their rules: a rule disabled or removed there, or given
/// other groups or admin status (which the rule's next exchange
/// would apply as well), and an issuer removed from it (or skipped
/// for its configuration, see [list_trusted_issuers]). Stored issuers
/// are synced on every update already: including them brings users in
/// line which were stored before, eg. by an earlier version.
///
/// It can run while the app serves: each issuer is read again once
/// its lock is held ([lock_trusted_issuer]), so an update of it made
/// meanwhile is not undone with what it was before, and one deleted
/// meanwhile is skipped. An issuer which fails to sync doesn't stop
/// the others: the failures are logged and returned together, after
/// the users of the issuers which are gone have been removed. While
/// the app removes them, exchanges wait before they get or create a
/// user, and the live issuers are listed once they do: the user of
/// an issuer or rule created meanwhile is created after the removal,
/// never taken for one which is gone (within one instance of the
/// app, see [AuthImpl::remove_workload_users_except]).
///
/// ⚠️ It enables the users of every enabled rule of an enabled
/// issuer, also those an admin disabled directly: when upgrading an
/// app which let admins disable workload users, disable their rules
/// before the first start.
pub async fn sync_all_workload_users<I: AuthImpl + ?Sized>(
  auth: &I,
) -> mogh_error::Result<()> {
  let mut failed = Vec::<String>::new();
  for ResolvedIssuer { issuer, .. } in
    list_trusted_issuers(auth).await?
  {
    let _lock = lock_trusted_issuer(&issuer.id).await;
    // As it is now: what was listed may have been updated (and
    // synced) or deleted since.
    let current = match list_trusted_issuers(auth).await {
      Ok(issuers) => issuers
        .into_iter()
        .map(|resolved| resolved.issuer)
        .find(|current| current.id == issuer.id),
      Err(e) => {
        error!(
          issuer_id = issuer.id,
          issuer = issuer.name,
          "Failed to read the trusted issuer to sync its users | {:#}",
          e.error
        );
        failed.push(issuer.name);
        continue;
      }
    };
    let Some(current) = current else {
      continue;
    };
    if let Err(e) = auth
      .sync_workload_users(
        current.id.clone(),
        WorkloadAccess::of_issuer(&current),
      )
      .await
    {
      error!(
        issuer_id = current.id,
        issuer = current.name,
        "Failed to sync the users of the trusted issuer's rules | {:#}",
        e.error
      );
      failed.push(current.name);
    }
  }

  {
    // No exchange gets or creates a user until the app is done
    // removing: one created after the listing (the first exchange
    // of an issuer or rule created meanwhile) would be found by the
    // app, and taken for a user of an issuer which is gone.
    let _removal = removal_lock().write().await;
    // Listed again, so an issuer created meanwhile (whose first
    // exchanges may have created users) isn't taken for one gone.
    let live = list_trusted_issuers(auth)
      .await?
      .iter()
      .map(|resolved| LiveIssuer::of(&resolved.issuer))
      .collect();
    auth.remove_workload_users_except(live).await?;
  }

  if failed.is_empty() {
    Ok(())
  } else {
    Err(
      anyhow!(
        "Failed to sync the users of the trusted issuers {}, see the log",
        failed
          .iter()
          .map(|name| format!("'{name}'"))
          .collect::<Vec<_>>()
          .join(", ")
      )
      .into(),
    )
  }
}

// ==============
// = VALIDATION =
// ==============

const MAX_NAME_LENGTH: usize = 100;
const MAX_AUDIENCES: usize = 16;
/// The most rules an issuer can have.
pub(crate) const MAX_RULES: usize = 64;
const MAX_CLAIMS_PER_RULE: usize = 16;
const MAX_GROUPS_PER_RULE: usize = 64;
const MAX_VALUE_LENGTH: usize = 512;

/// Claims which verification fixes for every token it accepts: the
/// issuer, one of the accepted audiences, and times. A rule matching
/// only these identifies no workload, it accepts every token of the
/// issuer. For a public platform (Github Actions, Gitlab.com) that is
/// anybody's, the audience included: anyone can request a token for
/// any audience there.
const VERIFIED_CLAIMS: [&str; 6] =
  ["iss", "aud", "exp", "iat", "nbf", "jti"];

/// The name of an issuer or rule (`kind`), trimmed: listed, logged,
/// and repeated in the errors about the rule, so a control character
/// (Unicode Cc) inside it is refused (the error doesn't repeat the
/// name).
fn validate_name(kind: &str, name: &str) -> anyhow::Result<String> {
  let name = name.trim();
  if name.is_empty() {
    return Err(anyhow!("{kind} name cannot be empty"));
  }
  if name.chars().count() > MAX_NAME_LENGTH {
    return Err(anyhow!(
      "{kind} name cannot be longer than {MAX_NAME_LENGTH} characters"
    ));
  }
  if name.chars().any(char::is_control) {
    return Err(anyhow!(
      "{kind} name cannot contain control characters"
    ));
  }
  Ok(name.to_string())
}

/// Trimmed, without empty entries or duplicates.
fn clean_list(
  field: &str,
  values: Vec<String>,
  max: usize,
) -> anyhow::Result<Vec<String>> {
  let mut cleaned = Vec::<String>::new();
  for value in values {
    let value = value.trim();
    if value.is_empty() || cleaned.iter().any(|v| v == value) {
      continue;
    }
    if value.len() > MAX_VALUE_LENGTH {
      return Err(anyhow!(
        "'{field}' values cannot be longer than {MAX_VALUE_LENGTH} characters"
      ));
    }
    cleaned.push(value.to_string());
  }
  if cleaned.len() > max {
    return Err(anyhow!("'{field}' accepts at most {max} values"));
  }
  Ok(cleaned)
}

fn validate_rule(
  mut rule: WorkloadRule,
) -> anyhow::Result<WorkloadRule> {
  rule.name = validate_name("Rule", &rule.name)?;
  // Without conditions a rule would accept every token of the issuer.
  if rule.claims.is_empty() {
    return Err(anyhow!(
      "Rule '{}' needs at least one claim to match",
      rule.name
    ));
  }
  if rule.claims.len() > MAX_CLAIMS_PER_RULE {
    return Err(anyhow!(
      "Rule '{}' can match at most {MAX_CLAIMS_PER_RULE} claims",
      rule.name
    ));
  }
  for condition in &mut rule.claims {
    condition.claim = condition.claim.trim().to_string();
    if condition.claim.is_empty() || condition.pattern.is_empty() {
      return Err(anyhow!(
        "Rule '{}' has a claim without a name or a value",
        rule.name
      ));
    }
    if condition.claim.len() > MAX_VALUE_LENGTH
      || condition.pattern.len() > MAX_VALUE_LENGTH
    {
      return Err(anyhow!(
        "Claims of rule '{}' cannot be longer than {MAX_VALUE_LENGTH} characters",
        rule.name
      ));
    }
    // Matches anything, so it restricts nothing.
    if condition.pattern.chars().all(|c| c == '*') {
      return Err(anyhow!(
        "Claim '{}' of rule '{}' matches any value, which doesn't restrict anything",
        condition.claim,
        rule.name
      ));
    }
  }
  // Conditions on these may narrow a rule down further (eg. one of
  // several audiences), but can't be all it takes.
  if rule.claims.iter().all(|condition| {
    VERIFIED_CLAIMS.contains(&condition.claim.as_str())
  }) {
    return Err(anyhow!(
      "Rule '{}' only matches claims every accepted token has (issuer, audience, times), which doesn't restrict anything. Add a claim identifying the workload, eg. 'sub' or 'repository_id'.",
      rule.name
    ));
  }
  rule.groups =
    clean_list("groups", rule.groups, MAX_GROUPS_PER_RULE)?;
  Ok(rule)
}

/// [validate_trusted_issuer], returning the issuer as the management
/// api stores it: names trimmed, lists cleaned.
pub(crate) fn normalize_trusted_issuer(
  mut issuer: TrustedIssuer,
) -> anyhow::Result<TrustedIssuer> {
  issuer.name = validate_name("Issuer", &issuer.name)?;

  issuer.issuer = issuer.issuer.trim().to_string();
  validate_public_http_url("issuer", &issuer.issuer)?;

  issuer.audiences =
    clean_list("audiences", issuer.audiences, MAX_AUDIENCES)?;
  if issuer.audiences.is_empty() {
    return Err(anyhow!(
      "At least one audience is required. Use one specific to this app, eg. its url."
    ));
  }

  if let TrustedIssuerKeys::JwksUri(url) = &issuer.keys {
    validate_public_http_url("keys url", url)?;
  }

  if issuer.rules.len() > MAX_RULES {
    return Err(anyhow!(
      "An issuer can have at most {MAX_RULES} rules"
    ));
  }
  issuer.rules = issuer
    .rules
    .into_iter()
    .map(validate_rule)
    .collect::<anyhow::Result<_>>()?;

  Ok(issuer)
}

/// Checks a trusted issuer the way the management api checks the
/// ones it stores (`CreateTrustedIssuer`, `UpdateTrustedIssuer`): a
/// name, an http(s) issuer url and keys url without credentials, at
/// least one audience, and rules which identify a workload: each
/// matches at least one claim besides those every accepted token has
/// (`iss`, `aud`, `exp`, `iat`, `nbf`, `jti`), and no claim with a
/// pattern of only `*`. On a public platform anyone can get a token
/// for any audience, so a rule matching the audience alone accepts
/// everybody's.
///
/// Rule ids are not checked (the api assigns them, and the exchange
/// refuses a rule without a unique valid one), nor whether a static
/// key set parses (the issuer is unavailable until it does).
///
/// The static issuers of the app ([AuthImpl::static_trusted_issuers])
/// failing it are skipped by [list_trusted_issuers], with an error in
/// the log: they accept no token, and
/// [sync_all_workload_users] removes the users of their rules. Apps
/// can call it when they load their configuration, to refuse such an
/// issuer up front.
pub fn validate_trusted_issuer(
  issuer: &TrustedIssuer,
) -> anyhow::Result<()> {
  normalize_trusted_issuer(issuer.clone()).map(|_| ())
}

// ==============
// = RESOLUTION =
// ==============

/// A [TrustedIssuer] and where it comes from.
pub struct ResolvedIssuer {
  pub issuer: TrustedIssuer,
  /// Whether the issuer comes from [AuthImpl::static_trusted_issuers],
  /// and can't be managed over the API.
  pub is_static: bool,
}

/// Lists all the trusted issuers, static ones first.
/// Issuers with invalid or duplicate ids are skipped, and static
/// issuers which fail [validate_trusted_issuer] (with an error in the
/// log): the management api refuses to store those.
pub async fn list_trusted_issuers<I: AuthImpl + ?Sized>(
  auth: &I,
) -> mogh_error::Result<Vec<ResolvedIssuer>> {
  let stored = auth.list_trusted_issuers().await?;
  let mut issuers = Vec::<ResolvedIssuer>::new();
  let all = auth
    .static_trusted_issuers()
    .into_iter()
    .map(|issuer| (issuer, true))
    .chain(stored.into_iter().map(|issuer| (issuer, false)));
  for (issuer, is_static) in all {
    if let Err(e) = validate_provider_id(&issuer.id) {
      warn!(
        "Skipping trusted issuer '{}' with invalid id '{}' | {e:#}",
        issuer.name, issuer.id
      );
      continue;
    }
    if issuers
      .iter()
      .any(|existing| existing.issuer.id == issuer.id)
    {
      warn!(
        "Skipping trusted issuer '{}' with duplicate id '{}'",
        issuer.name, issuer.id
      );
      continue;
    }
    // Stored ones passed it when they were stored.
    if is_static && let Err(e) = validate_trusted_issuer(&issuer) {
      error!(
        issuer_id = issuer.id,
        issuer = issuer.name,
        "Skipping trusted issuer of the app configuration, which the management api would refuse | {e:#}"
      );
      continue;
    }
    issuers.push(ResolvedIssuer { issuer, is_static });
  }
  Ok(issuers)
}

#[cfg(test)]
mod tests {
  use serde_json::json;

  use super::*;
  use crate::provider::token_exchange::test_tokens::jwks_json;

  fn claims(value: Value) -> Claims {
    value.as_object().unwrap().clone()
  }

  fn condition(claim: &str, pattern: &str) -> WorkloadClaim {
    WorkloadClaim {
      claim: claim.to_string(),
      pattern: pattern.to_string(),
    }
  }

  fn rule(id: &str, conditions: &[(&str, &str)]) -> WorkloadRule {
    WorkloadRule {
      id: id.to_string(),
      name: id.to_string(),
      enabled: true,
      claims: conditions
        .iter()
        .map(|(claim, pattern)| condition(claim, pattern))
        .collect(),
      ..Default::default()
    }
  }

  #[test]
  fn test_glob_match() {
    for (pattern, value, expected) in [
      ("main", "main", true),
      ("main", "main2", false),
      ("main", "amain", false),
      ("", "", true),
      ("", "a", false),
      ("*", "", true),
      ("*", "anything/at all", true),
      ("refs/heads/*", "refs/heads/release/1", true),
      ("refs/heads/*", "refs/tags/v1", false),
      ("refs/heads/*", "refs/heads/", true),
      ("*/main", "refs/heads/main", true),
      ("*/main", "refs/heads/main2", false),
      (
        "repo:org/*:ref:refs/heads/main",
        "repo:org/app:ref:refs/heads/main",
        true,
      ),
      (
        "repo:org/*:ref:refs/heads/main",
        "repo:evil/app:ref:refs/heads/main",
        false,
      ),
      ("a*b*c", "aXbXc", true),
      ("a*b*c", "abc", true),
      ("a*b*c", "acb", false),
      // The parts can't overlap
      ("ab*ba", "aba", false),
      ("ab*ba", "abba", true),
      // Literal, not a regex or a character class
      ("a.c", "abc", false),
      ("a?c", "abc", false),
      ("Main", "main", false),
      // Multibyte values
      ("*ü*", "grüße", true),
      ("grü*e", "grüße", true),
    ] {
      assert_eq!(
        glob_match(pattern, value),
        expected,
        "{pattern} / {value}"
      );
    }
  }

  #[test]
  fn test_lookup_claim_with_dotted_names() {
    let claims = claims(json!({
      "sub": "system:serviceaccount:prod:deployer",
      "kubernetes.io": {
        "namespace": "prod",
        "serviceaccount": { "name": "deployer" },
      },
      "realm_access": { "roles": ["a"] },
      "a.b": "flat",
      "a": { "b": "nested" },
    }));
    assert_eq!(
      lookup_claim(&claims, "kubernetes.io.namespace"),
      Some(&json!("prod"))
    );
    assert_eq!(
      lookup_claim(&claims, "kubernetes.io.serviceaccount.name"),
      Some(&json!("deployer"))
    );
    assert_eq!(
      lookup_claim(&claims, "realm_access.roles"),
      Some(&json!(["a"]))
    );
    // The exact name wins over a nested path
    assert_eq!(lookup_claim(&claims, "a.b"), Some(&json!("flat")));
    for missing in
      ["", "missing", "sub.nested", "kubernetes.io.missing", "."]
    {
      assert_eq!(lookup_claim(&claims, missing), None, "{missing}");
    }
  }

  #[test]
  fn test_match_rule() {
    let claims = claims(json!({
      "sub": "repo:org/app:ref:refs/heads/main",
      "repository_id": 12345,
      "repository_owner_id": "99",
      "ref": "refs/heads/main",
      "aud": ["https://app.example.com", "other"],
      "protected": true,
      "nested": { "object": {} },
    }));
    let matched = |rules: &[WorkloadRule]| {
      match_rule(rules, &claims).map(|rule| rule.id.clone())
    };

    // All conditions have to match
    assert_eq!(
      matched(&[rule(
        "a",
        &[("repository_id", "12345"), ("ref", "refs/heads/*")]
      )]),
      Some("a".to_string())
    );
    assert_eq!(
      matched(&[rule(
        "a",
        &[("repository_id", "12345"), ("ref", "refs/tags/*")]
      )]),
      None
    );
    // Numbers, booleans, and one value of a list
    assert!(
      matched(&[rule("a", &[("protected", "true")])]).is_some()
    );
    assert!(
      matched(&[rule("a", &[("aud", "https://app.example.com")])])
        .is_some()
    );
    // Missing claims and objects never match, not even a wildcard
    assert!(matched(&[rule("a", &[("missing", "*")])]).is_none());
    assert!(matched(&[rule("a", &[("nested", "*")])]).is_none());
    // A rule without conditions would match every token
    assert!(matched(&[rule("a", &[])]).is_none());

    // The first enabled matching rule decides
    let mut disabled = rule("disabled", &[("ref", "*")]);
    disabled.enabled = false;
    assert_eq!(
      matched(&[
        disabled,
        rule("no-match", &[("ref", "refs/tags/*")]),
        rule("first", &[("ref", "refs/heads/main")]),
        rule("second", &[("ref", "*")]),
      ]),
      Some("first".to_string())
    );
  }

  #[test]
  fn test_parse_jwks() {
    assert!(parse_jwks(&jwks_json()).is_ok());
    for invalid in ["", "not json", "{}", r#"{"keys":[]}"#] {
      assert!(parse_jwks(invalid).is_err(), "{invalid}");
    }
    // Keys of unknown types are skipped, leaving none
    assert!(parse_jwks(r#"{"keys":[{"kty":"unknown"}]}"#).is_err());
    assert!(parse_jwks(&" ".repeat(MAX_JWKS_LENGTH + 1)).is_err());
  }

  #[tokio::test]
  async fn test_static_keys_are_cached_until_changed() {
    let mut issuer = TrustedIssuer {
      id: "keys-cache-test".to_string(),
      name: "Test".to_string(),
      enabled: true,
      issuer: "https://issuer.example.com".to_string(),
      keys: TrustedIssuerKeys::Static(jwks_json()),
      audiences: vec!["app".to_string()],
      max_token_age_secs: 0,
      rules: Vec::new(),
    };
    let first = load_verification_keys(&issuer).await.unwrap();
    // Rule changes don't reload the keys
    issuer.rules.push(rule("a", &[("sub", "a")]));
    let second = load_verification_keys(&issuer).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second));

    issuer.issuer = "https://other.example.com".to_string();
    let third = load_verification_keys(&issuer).await.unwrap();
    assert!(!Arc::ptr_eq(&first, &third));

    evict_verification_keys(&issuer.id);
    let fourth = load_verification_keys(&issuer).await.unwrap();
    assert!(!Arc::ptr_eq(&third, &fourth));

    issuer.keys = TrustedIssuerKeys::Static("broken".to_string());
    assert!(load_verification_keys(&issuer).await.is_err());
  }

  /// Serves a discovery document and key set like a workload issuer.
  /// `discovery_issuer` overrides the issuer the document claims to be for.
  async fn serve_issuer(
    discovery_issuer: Option<&'static str>,
  ) -> String {
    use axum::{Json, Router, routing::get};
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address =
      format!("http://{}", listener.local_addr().unwrap());
    let issuer = discovery_issuer
      .map(str::to_string)
      .unwrap_or_else(|| address.clone());
    let jwks_uri = format!("{address}/keys");
    let router = Router::new()
      .route(
        "/.well-known/openid-configuration",
        get(move || async move {
          // No login endpoints, like Github Actions or Kubernetes
          Json(json!({ "issuer": issuer, "jwks_uri": jwks_uri }))
        }),
      )
      .route(
        "/keys",
        get(|| async {
          ([("content-type", "application/json")], jwks_json())
        }),
      )
      .route(
        "/redirect",
        get(|| async { axum::response::Redirect::to("/keys") }),
      );
    tokio::spawn(async move {
      axum::serve(listener, router).await.unwrap();
    });
    address
  }

  fn fetched_issuer(
    id: &str,
    issuer: &str,
    keys: TrustedIssuerKeys,
  ) -> TrustedIssuer {
    TrustedIssuer {
      id: id.to_string(),
      name: "Test".to_string(),
      enabled: true,
      issuer: issuer.to_string(),
      keys,
      audiences: vec!["app".to_string()],
      max_token_age_secs: 0,
      rules: Vec::new(),
    }
  }

  #[tokio::test]
  async fn test_keys_from_discovery_and_url() {
    let address = serve_issuer(None).await;
    let discovery = fetched_issuer(
      "fetch-discovery",
      // Trailing slash tolerant
      &format!("{address}/"),
      TrustedIssuerKeys::Discovery {},
    );
    assert!(load_verification_keys(&discovery).await.is_ok());

    let url = fetched_issuer(
      "fetch-url",
      "https://unreachable.example.com",
      TrustedIssuerKeys::JwksUri(format!("{address}/keys")),
    );
    assert!(load_verification_keys(&url).await.is_ok());
  }

  /// The token endpoint is unauthenticated, requests naming an
  /// unreachable issuer must not each cause another fetch.
  #[tokio::test]
  async fn test_failed_load_is_not_retried_right_away() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static FETCHES: AtomicUsize = AtomicUsize::new(0);

    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address =
      format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new().route(
      "/keys",
      axum::routing::get(|| async {
        FETCHES.fetch_add(1, Ordering::SeqCst);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
      }),
    );
    tokio::spawn(async move {
      axum::serve(listener, router).await.unwrap();
    });

    let issuer = fetched_issuer(
      "fetch-negative-cache",
      &address,
      TrustedIssuerKeys::JwksUri(format!("{address}/keys")),
    );
    for _ in 0..5 {
      assert!(load_verification_keys(&issuer).await.is_err());
    }
    assert_eq!(FETCHES.load(Ordering::SeqCst), 1);

    // A changed configuration is tried right away
    let mut changed = issuer.clone();
    changed.keys =
      TrustedIssuerKeys::JwksUri(format!("{address}/keys?v=2"));
    assert!(load_verification_keys(&changed).await.is_err());
    assert_eq!(FETCHES.load(Ordering::SeqCst), 2);
  }

  #[tokio::test]
  async fn test_oversized_response_is_not_read() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // A content length over the limit is refused before reading
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let declared =
      format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new().route(
      "/keys",
      axum::routing::get(|| async {
        " ".repeat(MAX_JWKS_LENGTH + 1)
      }),
    );
    tokio::spawn(async move {
      axum::serve(listener, router).await.unwrap();
    });

    // A server which doesn't say how much it
    // sends, and keeps sending until the client hangs up.
    let listener =
      tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endless =
      format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
      let (mut socket, _) = listener.accept().await.unwrap();
      let mut request = [0u8; 1024];
      let _ = socket.read(&mut request).await;
      let _ = socket
        .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
        .await;
      let chunk = vec![b' '; 64 * 1024];
      while socket.write_all(&chunk).await.is_ok() {}
    });

    for address in [declared, endless] {
      let err = tokio::time::timeout(
        Duration::from_secs(5),
        fetch_text(&format!("{address}/keys")),
      )
      .await
      .expect("the read must stop at the limit")
      .unwrap_err();
      assert!(format!("{err:#}").contains("too large"), "{err:#}");
    }
  }

  /// Issuers configured outside the management api may still have
  /// credentials in their urls, errors (which get logged) never show them.
  #[tokio::test]
  async fn test_fetch_errors_hide_url_credentials() {
    let address = serve_issuer(None).await;
    let with_credentials =
      address.replace("http://", "http://user:hunter2@");
    // Nothing listens there anymore
    let closed = {
      let listener =
        tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
      format!(
        "http://user:hunter2@{}",
        listener.local_addr().unwrap()
      )
    };
    for (id, issuer, keys) in [
      (
        "fetch-credentials-unreachable",
        closed.clone(),
        TrustedIssuerKeys::JwksUri(format!("{closed}/keys")),
      ),
      (
        "fetch-credentials-missing",
        address.clone(),
        TrustedIssuerKeys::JwksUri(format!(
          "{with_credentials}/missing"
        )),
      ),
      (
        "fetch-credentials-not-keys",
        address.clone(),
        TrustedIssuerKeys::JwksUri(format!(
          "{with_credentials}/.well-known/openid-configuration"
        )),
      ),
      (
        "fetch-credentials-discovery",
        closed.clone(),
        TrustedIssuerKeys::Discovery {},
      ),
    ] {
      let issuer = fetched_issuer(id, &issuer, keys);
      let err = load_verification_keys(&issuer).await.err().unwrap();
      for shown in [format!("{err:#}"), format!("{err:?}")] {
        assert!(!shown.contains("hunter2"), "{id}: {shown}");
      }
    }
    // The apps' marker in place of the userinfo.
    let err =
      fetch_text(&format!("{closed}/keys")).await.unwrap_err();
    assert!(
      format!("{err:#}").contains(&format!(
        "Failed to reach http://{}@",
        mogh_auth_client::config::REDACTED
      )),
      "{err:#}"
    );
    // Nor a key in the query, by the context or by the http
    // client's error under it.
    let unreachable = closed.replace("user:hunter2@", "");
    for url in [
      format!("{unreachable}/keys?token=hunter2"),
      format!("{address}/missing?token=hunter2"),
    ] {
      let err = fetch_text(&url).await.unwrap_err();
      for shown in [format!("{err:#}"), format!("{err:?}")] {
        assert!(!shown.contains("hunter2"), "{url}: {shown}");
        assert!(shown.contains("?##############"), "{url}: {shown}");
      }
    }
  }

  /// Exchanges of one rule get the user one after another, those of
  /// other rules don't wait, and nothing is left behind in the map.
  #[tokio::test]
  async fn test_workload_user_lock() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let holders = Arc::new(AtomicUsize::new(0));
    let max_holders = Arc::new(AtomicUsize::new(0));
    let callers = (0..20)
      .map(|_| {
        let (holders, max_holders) =
          (holders.clone(), max_holders.clone());
        tokio::spawn(async move {
          let _lock =
            lock_workload_user("lock-test", "same-rule").await;
          let now = holders.fetch_add(1, Ordering::SeqCst) + 1;
          max_holders.fetch_max(now, Ordering::SeqCst);
          tokio::time::sleep(Duration::from_millis(5)).await;
          holders.fetch_sub(1, Ordering::SeqCst);
        })
      })
      .collect::<Vec<_>>();
    // Another rule, while the first one is held.
    let other = lock_workload_user("lock-test", "other-rule").await;
    for caller in callers {
      caller.await.unwrap();
    }
    assert_eq!(max_holders.load(Ordering::SeqCst), 1);

    let held = |rule: &str| {
      rule_locks()
        .lock()
        .unwrap()
        .contains_key(&("lock-test".to_string(), rule.to_string()))
    };
    assert!(!held("same-rule"));
    assert!(held("other-rule"));
    drop(other);
    assert!(!held("other-rule"));

    // A caller giving up while waiting doesn't block the next one.
    let first = lock_workload_user("lock-test", "cancelled").await;
    let waiting = tokio::time::timeout(
      Duration::from_millis(20),
      lock_workload_user("lock-test", "cancelled"),
    )
    .await;
    assert!(waiting.is_err());
    drop(first);
    let next = tokio::time::timeout(
      Duration::from_secs(5),
      lock_workload_user("lock-test", "cancelled"),
    )
    .await;
    assert!(next.is_ok());
    drop(next);
    assert!(!held("cancelled"));
    assert!(
      !issuer_locks().lock().unwrap().contains_key("lock-test")
    );
  }

  /// A change of the issuer waits for the exchanges getting a user of
  /// one of its rules, and they wait for it. Other issuers don't.
  #[tokio::test]
  async fn test_trusted_issuer_lock() {
    let waits = |issuer: &'static str, rule: &'static str| async move {
      tokio::time::timeout(
        Duration::from_millis(20),
        lock_workload_user(issuer, rule),
      )
      .await
      .is_err()
    };

    let exchange = lock_workload_user("issuer-lock-test", "a").await;
    let update =
      tokio::spawn(lock_trusted_issuer("issuer-lock-test"));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!update.is_finished());
    drop(exchange);
    let update = tokio::time::timeout(Duration::from_secs(5), update)
      .await
      .expect("the update gets the issuer")
      .unwrap();
    // Every rule of the issuer waits, another issuer doesn't.
    assert!(waits("issuer-lock-test", "a").await);
    assert!(waits("issuer-lock-test", "b").await);
    assert!(!waits("issuer-lock-test-other", "a").await);
    drop(update);
    assert!(!waits("issuer-lock-test", "a").await);
    assert!(
      !issuer_locks()
        .lock()
        .unwrap()
        .contains_key("issuer-lock-test")
    );
  }

  fn issuer_with(
    id: &str,
    enabled: bool,
    rules: Vec<WorkloadRule>,
  ) -> TrustedIssuer {
    TrustedIssuer {
      id: id.to_string(),
      name: id.to_string(),
      enabled,
      issuer: "https://issuer.example.com".to_string(),
      keys: TrustedIssuerKeys::Discovery {},
      audiences: vec!["app".to_string()],
      max_token_age_secs: 0,
      rules,
    }
  }

  #[test]
  fn test_workload_access_of_issuer() {
    let mut issuer = issuer_with(
      "access-test",
      true,
      vec![
        WorkloadRule {
          groups: vec!["deployers".to_string()],
          admin: true,
          ..rule("a", &[("sub", "a")])
        },
        WorkloadRule {
          enabled: false,
          ..rule("b", &[("sub", "b")])
        },
      ],
    );
    let access = WorkloadAccess::of_issuer(&issuer);
    assert_eq!(
      access,
      [
        WorkloadAccess {
          rule_id: "a".to_string(),
          groups: vec!["deployers".to_string()],
          admin: true,
          enabled: true,
        },
        WorkloadAccess {
          rule_id: "b".to_string(),
          groups: Vec::new(),
          admin: false,
          enabled: false,
        },
      ]
    );
    issuer.enabled = false;
    assert!(
      WorkloadAccess::of_issuer(&issuer)
        .iter()
        .all(|access| !access.enabled)
    );
  }

  /// Static issuers are only synced when the app asks for it.
  #[tokio::test]
  async fn test_sync_all_workload_users() {
    #[derive(Default)]
    struct TestAuth {
      synced: Mutex<Vec<(String, Vec<WorkloadAccess>)>>,
    }
    impl AuthImpl for TestAuth {
      fn new() -> Self {
        Self::default()
      }
      fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
        vec![issuer_with(
          "static",
          true,
          vec![WorkloadRule {
            enabled: false,
            ..rule("disabled", &[("sub", "a")])
          }],
        )]
      }
      fn list_trusted_issuers(
        &self,
      ) -> crate::DynFuture<mogh_error::Result<Vec<TrustedIssuer>>>
      {
        let stored = vec![
          issuer_with(
            "stored",
            true,
            vec![rule("deploy", &[("sub", "b")])],
          ),
          // The static one wins.
          issuer_with("static", true, Vec::new()),
        ];
        Box::pin(async move { Ok(stored) })
      }
      fn sync_workload_users(
        &self,
        issuer_id: String,
        rules: Vec<WorkloadAccess>,
      ) -> crate::DynFuture<mogh_error::Result<()>> {
        self.synced.lock().unwrap().push((issuer_id, rules));
        Box::pin(async { Ok(()) })
      }
      crate::test_support::stub_auth_impl!(
        get_user,
        handle_request_authentication,
        jwt_provider
      );
    }

    let auth = TestAuth::default();
    sync_all_workload_users(&auth).await.unwrap();
    let synced = auth.synced.into_inner().unwrap();
    let synced = synced
      .iter()
      .map(|(issuer, rules)| {
        let rules = rules
          .iter()
          .map(|access| (access.rule_id.as_str(), access.enabled))
          .collect::<Vec<_>>();
        (issuer.as_str(), rules)
      })
      .collect::<Vec<_>>();
    assert_eq!(
      synced,
      [
        ("static", vec![("disabled", false)]),
        ("stored", vec![("deploy", true)]),
      ]
    );
  }

  /// While it runs, the app serves: an update of another issuer
  /// (here made by the sync of the first) is synced as it is now,
  /// not as it was listed, and an issuer deleted meanwhile is
  /// skipped. One failing doesn't stop the others. At the end the
  /// app is told which issuers and rules are live, to remove the
  /// users of those which are gone.
  #[tokio::test]
  async fn test_sync_all_reads_each_issuer_under_its_lock() {
    #[derive(Default)]
    struct TestAuth {
      stored: Mutex<Vec<TrustedIssuer>>,
      synced: Mutex<Vec<(String, Vec<WorkloadAccess>)>>,
      live: Mutex<Option<Vec<LiveIssuer>>>,
    }
    impl AuthImpl for TestAuth {
      fn new() -> Self {
        Self::default()
      }
      fn list_trusted_issuers(
        &self,
      ) -> crate::DynFuture<mogh_error::Result<Vec<TrustedIssuer>>>
      {
        let stored = self.stored.lock().unwrap().clone();
        Box::pin(async move { Ok(stored) })
      }
      fn sync_workload_users(
        &self,
        issuer_id: String,
        rules: Vec<WorkloadAccess>,
      ) -> crate::DynFuture<mogh_error::Result<()>> {
        if issuer_id == "sync-all-a" {
          // An admin disables B's rule and deletes C meanwhile.
          let mut stored = self.stored.lock().unwrap();
          stored.retain(|issuer| issuer.id != "sync-all-c");
          for issuer in stored.iter_mut() {
            if issuer.id == "sync-all-b" {
              issuer.rules[0].enabled = false;
            }
          }
        }
        let fails = issuer_id == "sync-all-fails";
        self.synced.lock().unwrap().push((issuer_id, rules));
        Box::pin(async move {
          if fails {
            Err(anyhow!("database unavailable").into())
          } else {
            Ok(())
          }
        })
      }
      fn remove_workload_users_except(
        &self,
        live: Vec<LiveIssuer>,
      ) -> crate::DynFuture<mogh_error::Result<()>> {
        *self.live.lock().unwrap() = Some(live);
        Box::pin(async { Ok(()) })
      }
      crate::test_support::stub_auth_impl!(
        get_user,
        handle_request_authentication,
        jwt_provider
      );
    }

    let auth = TestAuth::default();
    *auth.stored.lock().unwrap() = ["a", "fails", "b", "c"]
      .into_iter()
      .map(|id| {
        issuer_with(
          &format!("sync-all-{id}"),
          true,
          vec![rule(id, &[("sub", id)])],
        )
      })
      .collect();

    let err = sync_all_workload_users(&auth).await.unwrap_err();
    // The one which failed, after all were tried.
    assert!(format!("{:#}", err.error).contains("'sync-all-fails'"));
    let synced = auth.synced.into_inner().unwrap();
    let synced = synced
      .iter()
      .map(|(issuer, rules)| {
        (issuer.as_str(), rules[0].rule_id.as_str(), rules[0].enabled)
      })
      .collect::<Vec<_>>();
    assert_eq!(
      synced,
      [
        ("sync-all-a", "a", true),
        ("sync-all-fails", "fails", true),
        // As updated meanwhile, not as listed.
        ("sync-all-b", "b", false),
        // C was deleted meanwhile, and skipped.
      ]
    );
    // What is live now: C's users go.
    let live = auth.live.into_inner().unwrap().unwrap();
    assert_eq!(
      live,
      ["a", "fails", "b"]
        .into_iter()
        .map(|id| LiveIssuer {
          issuer_id: format!("sync-all-{id}"),
          rule_ids: vec![id.to_string()],
        })
        .collect::<Vec<_>>()
    );
  }

  /// The static issuers of the app are held to what the management
  /// api enforces: one whose rule accepts everybody's tokens (the
  /// audience alone, any value) or which has no audience or a url with
  /// credentials is skipped, with an error in the log. Rule ids and a
  /// static key set are left to the exchange and the key load.
  #[tokio::test]
  async fn test_static_issuers_the_api_would_refuse_are_skipped() {
    fn valid() -> TrustedIssuer {
      issuer_with(
        "valid",
        true,
        vec![rule("deploy", &[("repository_id", "12345")])],
      )
    }
    fn refused() -> Vec<(&'static str, TrustedIssuer)> {
      let with = |id: &str, change: fn(&mut TrustedIssuer)| {
        let mut issuer = valid();
        issuer.id = id.to_string();
        change(&mut issuer);
        issuer
      };
      vec![
        (
          "only matches claims every accepted token has",
          with("audience-only", |issuer| {
            issuer.rules = vec![rule(
              "everybody",
              &[("aud", "https://app.example.com")],
            )]
          }),
        ),
        (
          "matches any value",
          with("any-sub", |issuer| {
            issuer.rules = vec![rule("anything", &[("sub", "*")])]
          }),
        ),
        (
          "at least one claim",
          with("no-claims", |issuer| {
            issuer.rules = vec![rule("none", &[])]
          }),
        ),
        (
          "audience is required",
          with("no-audience", |issuer| issuer.audiences.clear()),
        ),
        (
          "must not carry credentials",
          with("credentials", |issuer| {
            issuer.keys = TrustedIssuerKeys::JwksUri(
              "https://user:hunter2@issuer.example.com/keys"
                .to_string(),
            )
          }),
        ),
      ]
    }
    struct TestAuth;
    impl AuthImpl for TestAuth {
      fn new() -> Self {
        TestAuth
      }
      fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
        std::iter::once(valid())
          .chain(refused().into_iter().map(|(_, issuer)| issuer))
          .collect()
      }
      crate::test_support::stub_auth_impl!(
        get_user,
        handle_request_authentication,
        jwt_provider
      );
    }

    let listed = list_trusted_issuers(&TestAuth)
      .await
      .unwrap()
      .into_iter()
      .map(|resolved| resolved.issuer.id)
      .collect::<Vec<_>>();
    assert_eq!(listed, ["valid"]);

    for (reason, issuer) in refused() {
      let err = validate_trusted_issuer(&issuer).unwrap_err();
      assert!(format!("{err:#}").contains(reason), "{err:#}");
      assert!(!format!("{err:#}").contains("hunter2"), "{err:#}");
    }
    validate_trusted_issuer(&valid()).unwrap();
    let mut left_to_others = valid();
    left_to_others.rules[0].id = String::new();
    left_to_others.keys = TrustedIssuerKeys::Static("broken".into());
    validate_trusted_issuer(&left_to_others).unwrap();
  }

  #[test]
  fn test_lookup_claim_path_depth_is_bounded() {
    let claims = claims(json!({ "a": "value" }));
    let deep = vec!["a"; MAX_CLAIM_PATH_PARTS + 1].join(".");
    assert_eq!(lookup_claim(&claims, &deep), None);
  }

  #[tokio::test]
  async fn test_keys_fetch_failures() {
    // The document must be for the configured issuer, otherwise any
    // server could vouch for the keys of another issuer.
    let address =
      serve_issuer(Some("https://other.example.com")).await;
    let wrong_issuer = fetched_issuer(
      "fetch-wrong-issuer",
      &address,
      TrustedIssuerKeys::Discovery {},
    );
    let err =
      load_verification_keys(&wrong_issuer).await.err().unwrap();
    assert!(format!("{err:#}").contains("another issuer"), "{err:#}");

    for (id, url) in [
      // Redirects are not followed
      ("fetch-redirect", format!("{address}/redirect")),
      ("fetch-missing", format!("{address}/missing")),
      // Not a key set
      (
        "fetch-not-keys",
        format!("{address}/.well-known/openid-configuration"),
      ),
    ] {
      let issuer = fetched_issuer(
        id,
        &address,
        TrustedIssuerKeys::JwksUri(url.clone()),
      );
      assert!(
        load_verification_keys(&issuer).await.is_err(),
        "{url}"
      );
    }
  }
}
