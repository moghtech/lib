//! Management of the trusted issuers (workload identity) stored
//! by the app. Admin only, see [AuthUserImpl::is_admin].

use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::{
  api::manage::{
    CreateTrustedIssuer, DeleteTrustedIssuer,
    DeleteTrustedIssuerResponse, ListTrustedIssuers,
    TrustedIssuerListItem, UpdateTrustedIssuer,
  },
  config::{TrustedIssuer, TrustedIssuerKeys, WorkloadRule},
};
use std::sync::Arc;

use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_resolver::Resolve;
use tracing::{Instrument as _, info, instrument, warn};

use crate::{
  AuthImpl,
  api::manage::ManageArgs,
  provider::{
    external::PROVIDER_ID_LENGTH,
    token_exchange::issuers_match,
    workload::{
      WorkloadAccess, ensure_in_cluster_review,
      evict_verification_keys, list_trusted_issuers,
      lock_trusted_issuer, normalize_trusted_issuer, parse_jwks,
      warn_plain_http_urls,
    },
  },
  rand::random_string,
  user::AuthUserImpl,
  validations::keep_credential,
};

fn bad_request(message: impl std::fmt::Display) -> mogh_error::Error {
  anyhow!("{message}").status_code(StatusCode::BAD_REQUEST)
}

fn reviews_tokens(issuer: &TrustedIssuer) -> bool {
  matches!(issuer.keys, TrustedIssuerKeys::TokenReview(_))
}

/// Refuses (400) a TokenReview issuer naming a `device` when the app
/// has no review devices ([AuthImpl::reviews_through_devices]): the
/// default review refuses every token of such an issuer, so its
/// exchanges could only ever fail.
fn ensure_review_device<I: AuthImpl + ?Sized>(
  auth: &I,
  issuer: &TrustedIssuer,
) -> mogh_error::Result<()> {
  match &issuer.keys {
    TrustedIssuerKeys::TokenReview(config)
      if !config.device.is_empty()
        && !auth.reviews_through_devices() =>
    {
      Err(bad_request(
        "This app has no review devices: review through the cluster \
         api server 'url', or 'in_cluster'",
      ))
    }
    _ => Ok(()),
  }
}

/// Held from [ensure_distinct_review_issuer] until the issuer it
/// checked is stored, so two admins creating or updating issuers at
/// the same time can't both pass the check with issuers which collide.
/// Taken after the issuer's own lock ([lock_trusted_issuer]), never
/// before it, and nothing holding it waits for an issuer's lock.
///
/// This only covers one instance of the app: the exchange refuses to
/// review the tokens of an issuer url which is shared all the same
/// (see `verify_workload_by` in [crate::api::token]).
fn distinct_review_issuer_lock() -> Arc<tokio::sync::Mutex<()>> {
  static LOCK: std::sync::OnceLock<Arc<tokio::sync::Mutex<()>>> =
    std::sync::OnceLock::new();
  LOCK.get_or_init(Default::default).clone()
}

/// Refuses (409) an issuer which, stored as it is, would leave an
/// enabled TokenReview issuer sharing its issuer url (compared with
/// [issuers_match]) with another enabled issuer, static ones and those
/// verifying with keys included.
///
/// The exchange tries every enabled issuer of a token's `iss`, and
/// trying a TokenReview issuer posts the whole token to that issuer's
/// cluster (or review device). Sharing the url, that cluster would
/// receive the live tokens of the other issuer: a captured one acts as
/// the other's workload until it expires, and a compromise of one
/// cluster extends to the workload identities of the other. Issuers
/// verifying with keys check a token locally, and may share a url
/// among themselves (the Kubernetes default issuer url is the same for
/// every cluster).
///
/// It checks the issuer as it would be stored: created, given another
/// `issuer` url or keys, or enabled again. A disabled issuer is never
/// refused, nor is one which collides only with disabled ones.
async fn ensure_distinct_review_issuer<I: AuthImpl + ?Sized>(
  auth: &I,
  issuer: &TrustedIssuer,
) -> mogh_error::Result<()> {
  if !issuer.enabled {
    return Ok(());
  }
  let reviews = reviews_tokens(issuer);
  let Some(other) = list_trusted_issuers(auth)
    .await?
    .into_iter()
    .map(|resolved| resolved.issuer)
    .find(|other| {
      other.id != issuer.id
        && other.enabled
        && issuers_match(&other.issuer, &issuer.issuer)
        && (reviews || reviews_tokens(other))
    })
  else {
    return Ok(());
  };
  let reviewer = if reviews {
    String::from("this issuer's cluster")
  } else {
    format!("the cluster of '{}'", other.name)
  };
  let tokens_of = if reviews {
    format!("'{}'", other.name)
  } else {
    String::from("this issuer")
  };
  Err(
    anyhow!(
      "Trusted issuer '{}' already uses this issuer url. A token \
       review issuer has to be the only enabled issuer of its url: \
       the exchange tries every issuer of a token's url, so \
       {reviewer} would receive the live tokens of {tokens_of} for \
       review. Give each cluster its own issuer url (kube-apiserver \
       --service-account-issuer), or verify both with keys \
       (Discovery, JwksUri or Static) instead",
      other.name
    )
    .status_code(StatusCode::CONFLICT),
  )
}

fn check_admin(user: &dyn AuthUserImpl) -> mogh_error::Result<()> {
  if user.is_admin() {
    Ok(())
  } else {
    Err(
      anyhow!("Only admins can manage trusted issuers")
        .status_code(StatusCode::FORBIDDEN),
    )
  }
}

/// Validates the issuer, and assigns the rule ids: rules keep the id
/// (and with it their user) they had on `existing`, all others get a
/// new random one. An id the caller made up could otherwise be the
/// one of a deleted rule, and take over its user.
fn validate_issuer(
  issuer: TrustedIssuer,
  existing: Option<&TrustedIssuer>,
) -> mogh_error::Result<TrustedIssuer> {
  let mut issuer = normalize_trusted_issuer(issuer)
    .status_code(StatusCode::BAD_REQUEST)?;
  if let TrustedIssuerKeys::Static(jwks) = &issuer.keys {
    parse_jwks(jwks).status_code(StatusCode::BAD_REQUEST)?;
  }

  let mut rules = Vec::<WorkloadRule>::new();
  for mut rule in issuer.rules {
    let keeps_id = existing.is_some_and(|existing| {
      existing.rules.iter().any(|r| r.id == rule.id)
    }) && !rules.iter().any(|r| r.id == rule.id);
    if !keeps_id {
      rule.id = random_string(PROVIDER_ID_LENGTH);
    }
    rules.push(rule);
  }
  issuer.rules = rules;

  Ok(issuer)
}

//

pub async fn list_issuers<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
) -> mogh_error::Result<Vec<TrustedIssuerListItem>> {
  check_admin(user)?;
  let issuers = list_trusted_issuers(auth)
    .await?
    .into_iter()
    .map(|resolved| {
      let mut issuer = resolved.issuer;
      issuer.redact_secrets();
      TrustedIssuerListItem {
        issuer,
        read_only: resolved.is_static,
      }
    })
    .collect();
  Ok(issuers)
}

impl Resolve<ManageArgs> for ListTrustedIssuers {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    list_issuers(auth.as_ref(), user.as_ref().as_ref()).await
  }
}

//

pub async fn create_issuer<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  issuer: TrustedIssuer,
) -> mogh_error::Result<TrustedIssuerListItem> {
  check_admin(user)?;

  let mut issuer = validate_issuer(issuer, None)?;
  ensure_in_cluster_review(&issuer, auth.in_cluster_env().as_ref())?;
  ensure_review_device(auth, &issuer)?;
  // Random ids are never reused, so a new issuer
  // can't inherit the users of a deleted one.
  issuer.id = random_string(PROVIDER_ID_LENGTH);

  let distinct = distinct_review_issuer_lock();
  let distinct = distinct.lock().await;
  ensure_distinct_review_issuer(auth, &issuer).await?;
  auth.create_trusted_issuer(issuer.clone()).await?;
  drop(distinct);

  info!(
    admin_id = user.id(),
    admin = user.username(),
    issuer_id = issuer.id,
    issuer = issuer.name,
    "Trusted issuer created"
  );
  warn_plain_http_urls(&issuer, false);

  issuer.redact_secrets();
  Ok(TrustedIssuerListItem {
    issuer,
    read_only: false,
  })
}

impl Resolve<ManageArgs> for CreateTrustedIssuer {
  #[instrument(
    "CreateTrustedIssuer",
    skip_all,
    fields(user_id = user.id(), username = user.username())
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    create_issuer(auth.as_ref(), user.as_ref().as_ref(), self.into())
      .await
  }
}

//

/// An empty or redacted reviewer credential keeps the stored one
/// ([keep_credential]), like the login providers' client secret. The
/// stored credential is only kept for the url it was entered for: a
/// changed url needs the credential entered again, so it is never
/// sent anywhere else. An issuer naming a `device`, or reviewing
/// in its own cluster, reviews with credentials of its own, so there
/// is nothing to keep.
fn keep_existing_review_token(
  issuer: &mut TrustedIssuer,
  existing: &TrustedIssuer,
) -> mogh_error::Result<()> {
  let TrustedIssuerKeys::TokenReview(config) = &mut issuer.keys
  else {
    return Ok(());
  };
  if !config.device.trim().is_empty() || config.in_cluster {
    // These modes review with their own credentials: nothing kept.
    return Ok(());
  }
  let (stored, stored_url) = match &existing.keys {
    TrustedIssuerKeys::TokenReview(existing) => {
      (existing.token.as_str(), existing.url.as_str())
    }
    _ => ("", ""),
  };
  let url_changed = config.url.trim() != stored_url.trim();
  keep_credential(
    &mut config.token,
    stored,
    url_changed,
    "reviewer credential",
    "cluster api server url",
  )
  .status_code(StatusCode::BAD_REQUEST)
}

/// Finds an issuer which can be managed over the API.
async fn resolve_managed_issuer<I: AuthImpl + ?Sized>(
  auth: &I,
  issuer_id: &str,
) -> mogh_error::Result<TrustedIssuer> {
  let resolved = list_trusted_issuers(auth)
    .await?
    .into_iter()
    .find(|resolved| resolved.issuer.id == issuer_id)
    .with_context(|| {
      format!("No trusted issuer with id '{issuer_id}'")
    })
    .status_code(StatusCode::NOT_FOUND)?;
  if resolved.is_static {
    return Err(bad_request(format!(
      "Issuer '{}' comes from the app configuration and is read only",
      resolved.issuer.name
    )));
  }
  Ok(resolved.issuer)
}

/// Stores the update, then syncs the users of the rules
/// ([AuthImpl::sync_workload_users]): rules demoted or disabled, or
/// of a disabled issuer, reach the tokens already issued. Exchanges
/// of the issuer wait for both ([lock_trusted_issuer]).
///
/// Once stored, the update is audited and the issuer's keys evicted
/// whether or not the sync succeeds: a failed sync fails the request,
/// but the new trust configuration is already in effect.
///
/// The store, the eviction, the audit and the sync run in a task of
/// their own, which holds the issuer's lock: a request dropped
/// meanwhile (the admin's client gone) still completes them. Otherwise
/// the new rules could be stored, and in effect for new exchanges,
/// without their users synced: the tokens already issued would keep
/// the access the rules no longer give, with nothing logged. The task
/// runs in the [request_context][crate::request_context] of the
/// request, and its tracing span.
pub async fn update_issuer<I: AuthImpl + ?Sized>(
  auth: Arc<I>,
  user: &dyn AuthUserImpl,
  issuer: TrustedIssuer,
) -> mogh_error::Result<TrustedIssuerListItem> {
  check_admin(user)?;

  let lock = lock_trusted_issuer(&issuer.id).await;
  let existing =
    resolve_managed_issuer(auth.as_ref(), &issuer.id).await?;
  let mut issuer = issuer;
  keep_existing_review_token(&mut issuer, &existing)?;
  let mut issuer = validate_issuer(issuer, Some(&existing))?;
  ensure_in_cluster_review(&issuer, auth.in_cluster_env().as_ref())?;
  ensure_review_device(auth.as_ref(), &issuer)?;
  issuer.id = existing.id;

  let distinct = distinct_review_issuer_lock().lock_owned().await;
  ensure_distinct_review_issuer(auth.as_ref(), &issuer).await?;

  let admin_id = user.id().to_string();
  let admin = user.username().to_string();
  let update = async move {
    let stored = auth.update_trusted_issuer(issuer.clone()).await;
    drop(distinct);
    stored?;

    evict_verification_keys(&issuer.id);

    info!(
      admin_id,
      admin,
      issuer_id = issuer.id,
      issuer = issuer.name,
      "Trusted issuer updated"
    );
    warn_plain_http_urls(&issuer, false);

    if let Err(e) = auth
      .sync_workload_users(
        issuer.id.clone(),
        WorkloadAccess::of_issuer(&issuer),
      )
      .await
    {
      warn!(
        admin_id,
        admin,
        issuer_id = issuer.id,
        issuer = issuer.name,
        "Trusted issuer was stored, but syncing the users of its rules failed. \
         They may keep their previous access until it is saved again | {:#}",
        e.error
      );
      return Err(e);
    }
    drop(lock);

    let mut issuer = issuer;
    issuer.redact_secrets();
    Ok(TrustedIssuerListItem {
      issuer,
      read_only: false,
    })
  };
  let context = crate::request_context();
  let update = async move {
    match context {
      Some(context) => {
        crate::scope_request_context(context, update).await
      }
      None => update.await,
    }
  };
  tokio::spawn(update.instrument(tracing::Span::current()))
    .await
    .context("Failed to update the trusted issuer")?
}

impl Resolve<ManageArgs> for UpdateTrustedIssuer {
  #[instrument(
    "UpdateTrustedIssuer",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      issuer_id = self.id
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    update_issuer(auth.clone(), user.as_ref().as_ref(), self.into())
      .await
  }
}

//

pub async fn delete_issuer<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  issuer_id: &str,
) -> mogh_error::Result<()> {
  check_admin(user)?;

  // Exchanges of the issuer wait, and then find it gone.
  let lock = lock_trusted_issuer(issuer_id).await;
  let issuer = resolve_managed_issuer(auth, issuer_id).await?;

  auth.delete_trusted_issuer(issuer.id.clone()).await?;
  drop(lock);

  evict_verification_keys(&issuer.id);

  info!(
    admin_id = user.id(),
    admin = user.username(),
    issuer_id = issuer.id,
    issuer = issuer.name,
    "Trusted issuer deleted"
  );

  Ok(())
}

impl Resolve<ManageArgs> for DeleteTrustedIssuer {
  #[instrument(
    "DeleteTrustedIssuer",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      issuer_id = self.id
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    delete_issuer(auth.as_ref(), user.as_ref().as_ref(), &self.id)
      .await?;
    Ok(DeleteTrustedIssuerResponse {})
  }
}

#[cfg(test)]
mod tests {
  use std::sync::{Arc, Mutex};

  use mogh_auth_client::config::{REDACTED, WorkloadClaim};

  use super::*;
  use crate::provider::{
    token_exchange::test_tokens::jwks_json, workload::MAX_RULES,
  };

  struct TestUser {
    admin: bool,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      "user-id"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn is_admin(&self) -> bool {
      self.admin
    }
  }

  const ADMIN: TestUser = TestUser { admin: true };
  const USER: TestUser = TestUser { admin: false };

  /// The calls of sync_workload_users.
  type Synced = Arc<Mutex<Vec<(String, Vec<WorkloadAccess>)>>>;

  /// Cloned, it shares its storage: the server owns one in a task.
  #[derive(Default, Clone)]
  struct TestAuth {
    static_issuers: Vec<TrustedIssuer>,
    stored: Arc<Mutex<Vec<TrustedIssuer>>>,
    synced: Synced,
    sync_fails: bool,
    /// Whether an exchange of the issuer had to wait, for each
    /// call storing, syncing or deleting it.
    exchange_waited: Arc<Mutex<Vec<bool>>>,
    /// How long storing an update takes.
    store_delay: std::time::Duration,
    /// The request context the last sync_workload_users ran in.
    sync_context: Arc<Mutex<Option<crate::RequestContext>>>,
    /// The cluster the server runs in, None outside one. Tests
    /// always answer from here, never from the real environment.
    in_cluster: Option<crate::provider::workload::InClusterEnv>,
    /// [AuthImpl::reviews_through_devices]
    review_devices: bool,
  }

  /// Whether an exchange of a rule of the issuer has to wait.
  async fn exchange_waits(issuer_id: &str) -> bool {
    tokio::time::timeout(
      std::time::Duration::from_millis(20),
      crate::provider::workload::lock_workload_user(
        issuer_id, "rule",
      ),
    )
    .await
    .is_err()
  }

  impl TestAuth {
    fn record_exchange_waits(
      &self,
      issuer_id: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      let waited = self.exchange_waited.clone();
      Box::pin(async move {
        let waits = exchange_waits(&issuer_id).await;
        waited.lock().unwrap().push(waits);
        Ok(())
      })
    }
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::default()
    }

    fn in_cluster_env(
      &self,
    ) -> Option<crate::provider::workload::InClusterEnv> {
      self.in_cluster.clone()
    }

    fn reviews_through_devices(&self) -> bool {
      self.review_devices
    }

    fn static_trusted_issuers(&self) -> Vec<TrustedIssuer> {
      self.static_issuers.clone()
    }

    fn list_trusted_issuers(
      &self,
    ) -> crate::DynFuture<mogh_error::Result<Vec<TrustedIssuer>>>
    {
      let stored = self.stored.lock().unwrap().clone();
      Box::pin(async move { Ok(stored) })
    }

    fn create_trusted_issuer(
      &self,
      issuer: TrustedIssuer,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.stored.lock().unwrap().push(issuer);
      Box::pin(async { Ok(()) })
    }

    fn update_trusted_issuer(
      &self,
      issuer: TrustedIssuer,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      let id = issuer.id.clone();
      let mut stored = self.stored.lock().unwrap();
      let existing =
        stored.iter_mut().find(|i| i.id == issuer.id).unwrap();
      *existing = issuer;
      let delay = self.store_delay;
      let record = self.record_exchange_waits(id);
      Box::pin(async move {
        tokio::time::sleep(delay).await;
        record.await
      })
    }

    fn sync_workload_users(
      &self,
      issuer_id: String,
      rules: Vec<WorkloadAccess>,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      if self.sync_fails {
        return Box::pin(async {
          Err(anyhow!("sync failed").into())
        });
      }
      self.synced.lock().unwrap().push((issuer_id.clone(), rules));
      *self.sync_context.lock().unwrap() = crate::request_context();
      self.record_exchange_waits(issuer_id)
    }

    fn delete_trusted_issuer(
      &self,
      id: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.stored.lock().unwrap().retain(|i| i.id != id);
      self.record_exchange_waits(id)
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }

    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _ip: std::net::IpAddr,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async { Err(anyhow!("not implemented").into()) })
    }

    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for these tests")
    }
  }

  fn rule(id: &str, name: &str) -> WorkloadRule {
    WorkloadRule {
      id: id.to_string(),
      name: name.to_string(),
      enabled: true,
      claims: vec![WorkloadClaim {
        claim: " repository_id ".to_string(),
        pattern: "12345".to_string(),
      }],
      groups: vec![
        " deployers ".into(),
        "".into(),
        "deployers".into(),
      ],
      admin: false,
      token_ttl_secs: 900,
    }
  }

  fn issuer(rules: Vec<WorkloadRule>) -> TrustedIssuer {
    TrustedIssuer {
      id: "made-up-id".to_string(),
      name: "  Github Actions ".to_string(),
      enabled: true,
      issuer: "https://token.actions.githubusercontent.com"
        .to_string(),
      keys: TrustedIssuerKeys::Discovery {},
      audiences: vec![" https://app.example.com ".to_string()],
      max_token_age_secs: 0,
      rules,
    }
  }

  #[tokio::test]
  async fn test_non_admins_are_forbidden() {
    let auth = TestAuth::default();
    let id = create_issuer(&auth, &ADMIN, issuer(Vec::new()))
      .await
      .unwrap()
      .issuer
      .id;
    let mut update = issuer(Vec::new());
    update.id = id.clone();
    let statuses = [
      list_issuers(&auth, &USER).await.unwrap_err().status,
      create_issuer(&auth, &USER, issuer(Vec::new()))
        .await
        .unwrap_err()
        .status,
      update_issuer(Arc::new(auth.clone()), &USER, update)
        .await
        .unwrap_err()
        .status,
      delete_issuer(&auth, &USER, &id).await.unwrap_err().status,
    ];
    assert!(statuses.iter().all(|s| *s == StatusCode::FORBIDDEN));
    assert_eq!(auth.stored.lock().unwrap().len(), 1);
  }

  #[tokio::test]
  async fn test_create_generates_ids_and_cleans_input() {
    let auth = TestAuth::default();
    let item = create_issuer(
      &auth,
      &ADMIN,
      issuer(vec![rule("made-up-rule-id", " Deploy ")]),
    )
    .await
    .unwrap();
    let created = item.issuer;
    assert!(!item.read_only);
    // Ids from the caller are never used
    assert_eq!(created.id.len(), PROVIDER_ID_LENGTH);
    assert_ne!(created.id, "made-up-id");
    assert_eq!(created.rules[0].id.len(), PROVIDER_ID_LENGTH);
    assert_ne!(created.rules[0].id, "made-up-rule-id");

    assert_eq!(created.name, "Github Actions");
    assert_eq!(created.audiences, ["https://app.example.com"]);
    assert_eq!(created.rules[0].name, "Deploy");
    assert_eq!(created.rules[0].claims[0].claim, "repository_id");
    assert_eq!(created.rules[0].groups, ["deployers"]);
    assert_eq!(auth.stored.lock().unwrap()[0], created);
  }

  #[tokio::test]
  async fn test_update_keeps_known_rule_ids_only() {
    let auth = TestAuth::default();
    let created =
      create_issuer(&auth, &ADMIN, issuer(vec![rule("", "Deploy")]))
        .await
        .unwrap()
        .issuer;
    let deploy_id = created.rules[0].id.clone();

    let mut update = created.clone();
    update.rules = vec![
      // Keeps its id, and with it its user
      rule(&deploy_id, "Deploy renamed"),
      // The same id again, an id made up by the caller (which
      // could be the one of a deleted rule), and a new rule
      rule(&deploy_id, "Duplicate"),
      rule("deleted-rule-id", "Made up"),
      rule("", "New"),
    ];
    let updated =
      update_issuer(Arc::new(auth.clone()), &ADMIN, update)
        .await
        .unwrap()
        .issuer;

    assert_eq!(updated.id, created.id);
    assert_eq!(updated.rules[0].id, deploy_id);
    assert_eq!(updated.rules[0].name, "Deploy renamed");
    let mut ids = updated
      .rules
      .iter()
      .map(|r| r.id.clone())
      .collect::<Vec<_>>();
    assert!(!ids.contains(&"deleted-rule-id".to_string()));
    assert!(ids.iter().all(|id| id.len() == PROVIDER_ID_LENGTH));
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 4);
  }

  #[tokio::test]
  async fn test_validation() {
    let auth = TestAuth::default();
    let invalid = |change: fn(&mut TrustedIssuer)| {
      let mut issuer = issuer(vec![rule("", "Deploy")]);
      change(&mut issuer);
      issuer
    };
    for issuer in [
      invalid(|i| i.name = "  ".into()),
      invalid(|i| i.issuer = "not a url".into()),
      invalid(|i| i.issuer = "ftp://issuer.example.com".into()),
      // An audience is what ties the token to this app
      invalid(|i| i.audiences = vec!["  ".into()]),
      invalid(|i| i.keys = TrustedIssuerKeys::JwksUri("nope".into())),
      // Credentials would be stored, listed and logged in plain text
      invalid(|i| {
        i.issuer = "https://user:pass@issuer.example.com".into()
      }),
      invalid(|i| {
        i.issuer = "https://user@issuer.example.com".into()
      }),
      invalid(|i| {
        i.keys = TrustedIssuerKeys::JwksUri(
          "https://user:pass@issuer.example.com/keys".into(),
        )
      }),
      invalid(|i| {
        i.keys = TrustedIssuerKeys::JwksUri(
          "https://:pass@issuer.example.com/keys".into(),
        )
      }),
      invalid(|i| i.keys = TrustedIssuerKeys::Static("{}".into())),
      // A rule accepting every token of the issuer
      invalid(|i| i.rules[0].claims.clear()),
      invalid(|i| i.rules[0].claims[0].pattern = "*".into()),
      invalid(|i| i.rules[0].claims[0].pattern = "**".into()),
      invalid(|i| i.rules[0].claims[0].pattern = String::new()),
      invalid(|i| i.rules[0].claims[0].claim = " ".into()),
      // Every token the issuer has for the audience matches these
      invalid(|i| {
        i.rules[0].claims = vec![WorkloadClaim {
          claim: "aud".into(),
          pattern: "https://app.example.com".into(),
        }]
      }),
      invalid(|i| {
        i.rules[0].claims = vec![
          WorkloadClaim {
            claim: " iss ".into(),
            pattern: "https://token.actions.githubusercontent.com"
              .into(),
          },
          WorkloadClaim {
            claim: "aud".into(),
            pattern: "https://app.example.com".into(),
          },
        ]
      }),
      invalid(|i| {
        i.rules[0].claims = vec![WorkloadClaim {
          claim: "exp".into(),
          pattern: "1*".into(),
        }]
      }),
      invalid(|i| i.rules[0].name = String::new()),
      invalid(|i| {
        i.rules = (0..=MAX_RULES)
          .map(|n| rule("", &format!("r{n}")))
          .collect()
      }),
    ] {
      let err = create_issuer(&auth, &ADMIN, issuer.clone())
        .await
        .unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST, "{issuer:?}");
    }
    assert!(auth.stored.lock().unwrap().is_empty());

    // The error names the field, not the credentials
    let err = create_issuer(
      &auth,
      &ADMIN,
      invalid(|i| {
        i.keys = TrustedIssuerKeys::JwksUri(
          "https://user:hunter2@issuer.example.com/keys".into(),
        )
      }),
    )
    .await
    .unwrap_err();
    let message = format!("{:#}", err.error);
    assert!(
      message.contains("'keys url' must not carry credentials"),
      "{message}"
    );
    assert!(!message.contains("hunter2"), "{message}");

    // Updates are validated the same way
    let created = create_issuer(&auth, &ADMIN, issuer(Vec::new()))
      .await
      .unwrap()
      .issuer;
    let mut update = created.clone();
    update.keys = TrustedIssuerKeys::JwksUri(
      "https://user:pass@issuer.example.com/keys".into(),
    );
    let err = update_issuer(Arc::new(auth.clone()), &ADMIN, update)
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(auth.stored.lock().unwrap()[0].keys, created.keys);
    delete_issuer(&auth, &ADMIN, &created.id).await.unwrap();

    // Narrow wildcards and static keys are fine
    let mut valid = issuer(vec![rule("", "Deploy")]);
    valid.rules[0].claims[0].pattern = "refs/heads/*".into();
    valid.keys = TrustedIssuerKeys::Static(jwks_json());
    assert!(create_issuer(&auth, &ADMIN, valid).await.is_ok());

    // An audience next to a claim identifying the workload is fine
    let mut valid = issuer(vec![rule("", "Deploy")]);
    valid.rules[0].claims.push(WorkloadClaim {
      claim: "aud".into(),
      pattern: "https://app.example.com".into(),
    });
    assert!(create_issuer(&auth, &ADMIN, valid).await.is_ok());
  }

  /// Issuer and rule names refuse control characters (Unicode Cc)
  /// at create and update, the error not repeating the name.
  #[tokio::test]
  async fn test_names_refuse_control_characters() {
    let auth = TestAuth::default();
    let created = create_issuer(&auth, &ADMIN, issuer(Vec::new()))
      .await
      .unwrap()
      .issuer;
    for name in
      ["CI\tjobs", "CI\njobs", "CI\u{1b}jobs", "CI\u{85}jobs"]
    {
      let mut issuer_named = issuer(vec![rule("", "Deploy")]);
      issuer_named.name = name.into();
      let mut rule_named = issuer(vec![rule("", name)]);
      rule_named.name = "Rules".into();
      for (what, candidate) in
        [("Issuer", issuer_named), ("Rule", rule_named)]
      {
        let mut update = candidate.clone();
        update.id = created.id.clone();
        for err in [
          create_issuer(&auth, &ADMIN, candidate).await.unwrap_err(),
          update_issuer(Arc::new(auth.clone()), &ADMIN, update)
            .await
            .unwrap_err(),
        ] {
          assert_eq!(err.status, StatusCode::BAD_REQUEST, "{name:?}");
          assert_eq!(
            format!("{:#}", err.error),
            format!("{what} name cannot contain control characters")
          );
        }
      }
    }
    let stored = auth.stored.lock().unwrap().clone();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].name, created.name);
    drop(stored);
    // Validated as the api validates (static issuers too).
    let mut named = issuer(vec![rule("", "Deploy")]);
    named.name = "CI\tjobs".into();
    assert!(
      crate::provider::workload::validate_trusted_issuer(&named)
        .is_err()
    );
    named.name = "  CI jobs (prod)  ".into();
    crate::provider::workload::validate_trusted_issuer(&named)
      .unwrap();
  }

  #[tokio::test]
  async fn test_static_issuers_are_read_only() {
    let mut static_issuer = issuer(Vec::new());
    static_issuer.id = "github".to_string();
    let auth = TestAuth {
      static_issuers: vec![static_issuer.clone()],
      ..Default::default()
    };
    let listed = list_issuers(&auth, &ADMIN).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].read_only);

    let err =
      update_issuer(Arc::new(auth.clone()), &ADMIN, static_issuer)
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    let err =
      delete_issuer(&auth, &ADMIN, "github").await.unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    let err =
      delete_issuer(&auth, &ADMIN, "unknown").await.unwrap_err();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
  }

  /// The rules kept by an update keep their user, which gets what
  /// the rule says now right away: tokens issued before carry only
  /// the user id, and would keep the old access otherwise.
  #[tokio::test]
  async fn test_update_syncs_the_users_of_the_rules() {
    let auth = TestAuth::default();
    let admin_rule = WorkloadRule {
      admin: true,
      ..rule("", "Infra")
    };
    let created = create_issuer(
      &auth,
      &ADMIN,
      issuer(vec![admin_rule, rule("", "Deploy"), rule("", "Docs")]),
    )
    .await
    .unwrap()
    .issuer;
    // A new issuer's rules have no users yet.
    assert!(auth.synced.lock().unwrap().is_empty());
    let [infra, deploy, docs] =
      [0, 1, 2].map(|i| created.rules[i].clone());

    // Demote Infra, disable Deploy, drop Docs, add one.
    let mut update = created.clone();
    update.rules = vec![
      WorkloadRule {
        admin: false,
        groups: vec!["readers".into()],
        ..infra.clone()
      },
      WorkloadRule {
        enabled: false,
        ..deploy.clone()
      },
      rule("", "New"),
    ];
    let updated =
      update_issuer(Arc::new(auth.clone()), &ADMIN, update)
        .await
        .unwrap()
        .issuer;
    let access = |rule_id: &str, groups: &[&str], admin, enabled| {
      WorkloadAccess {
        rule_id: rule_id.to_string(),
        groups: groups.iter().map(|g| g.to_string()).collect(),
        admin,
        enabled,
      }
    };
    let synced = auth.synced.lock().unwrap().clone();
    assert_eq!(
      synced,
      [(
        created.id.clone(),
        vec![
          access(&infra.id, &["readers"], false, true),
          access(&deploy.id, &["deployers"], false, false),
          access(&updated.rules[2].id, &["deployers"], false, true),
        ]
      )]
    );
    // Docs isn't among them, so its user is removed.
    assert!(
      synced[0].1.iter().all(|access| access.rule_id != docs.id)
    );

    // Disabling the issuer disables every rule's user,
    // enabling it again brings them back.
    for enabled in [false, true] {
      let update = TrustedIssuer {
        enabled,
        ..updated.clone()
      };
      update_issuer(Arc::new(auth.clone()), &ADMIN, update)
        .await
        .unwrap();
      let synced = auth.synced.lock().unwrap().pop().unwrap().1;
      assert_eq!(
        synced.iter().map(|a| a.enabled).collect::<Vec<_>>(),
        [enabled, false, enabled]
      );
    }
  }

  /// An event logged with an `issuer_id`.
  #[derive(Clone, Debug)]
  struct IssuerEvent {
    level: tracing::Level,
    issuer_id: String,
    message: String,
    /// The `url` field, if any.
    url: Option<String>,
  }

  /// Records the events logged with an `issuer_id`, by every test.
  #[derive(Clone, Default)]
  struct Events(Arc<Mutex<Vec<IssuerEvent>>>);

  impl Events {
    /// The events logged about the issuer. The subscriber is the
    /// global default: callsites which other tests register while a
    /// scoped one is set only ask theirs, and would stay off.
    fn of_issuer(issuer_id: &str) -> Vec<IssuerEvent> {
      static EVENTS: std::sync::OnceLock<Events> =
        std::sync::OnceLock::new();
      let events = EVENTS.get_or_init(|| {
        let events = Events::default();
        tracing::subscriber::set_global_default(events.clone())
          .expect("no other global subscriber in the tests");
        // Those registered by others while it was set.
        tracing::callsite::rebuild_interest_cache();
        events
      });
      events
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.issuer_id == issuer_id)
        .cloned()
        .collect()
    }
  }

  impl tracing::Subscriber for Events {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
      true
    }
    fn new_span(
      &self,
      _: &tracing::span::Attributes<'_>,
    ) -> tracing::span::Id {
      tracing::span::Id::from_u64(1)
    }
    fn record(
      &self,
      _: &tracing::span::Id,
      _: &tracing::span::Record<'_>,
    ) {
    }
    fn record_follows_from(
      &self,
      _: &tracing::span::Id,
      _: &tracing::span::Id,
    ) {
    }
    fn event(&self, event: &tracing::Event<'_>) {
      #[derive(Default)]
      struct Fields {
        issuer_id: Option<String>,
        message: String,
        url: Option<String>,
      }
      impl tracing::field::Visit for Fields {
        fn record_str(
          &mut self,
          field: &tracing::field::Field,
          value: &str,
        ) {
          match field.name() {
            "issuer_id" => self.issuer_id = Some(value.to_string()),
            "url" => self.url = Some(value.to_string()),
            _ => {}
          }
        }
        fn record_debug(
          &mut self,
          field: &tracing::field::Field,
          value: &dyn std::fmt::Debug,
        ) {
          if field.name() == "message" {
            self.message = format!("{value:?}");
          }
        }
      }
      let mut fields = Fields::default();
      event.record(&mut fields);
      let Some(issuer_id) = fields.issuer_id else {
        return;
      };
      self.0.lock().unwrap().push(IssuerEvent {
        level: *event.metadata().level(),
        issuer_id,
        message: fields.message,
        url: fields.url,
      });
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
  }

  /// A failed sync fails the request, but the update is stored and
  /// in effect: it is audited, and the old keys are evicted.
  /// A request dropped while its update is stored (the admin's client
  /// gone) doesn't leave the new rules in effect but unapplied to the
  /// users they had: the update runs to its end, the users synced, the
  /// issuer unlocked, in the request's context.
  #[tokio::test]
  async fn test_a_dropped_update_still_syncs() {
    let auth = TestAuth {
      store_delay: std::time::Duration::from_millis(200),
      ..Default::default()
    };
    let created =
      create_issuer(&auth, &ADMIN, issuer(vec![rule("", "Deploy")]))
        .await
        .unwrap()
        .issuer;
    let update = TrustedIssuer {
      enabled: false,
      ..created.clone()
    };
    let context = crate::RequestContext::new(
      "10.1.2.3".parse().unwrap(),
      "UpdateTrustedIssuer",
      Some(String::from("user-id")),
    );

    let res = crate::scope_request_context(
      context.clone(),
      tokio::time::timeout(
        std::time::Duration::from_millis(50),
        update_issuer(Arc::new(auth.clone()), &ADMIN, update),
      ),
    )
    .await;
    assert!(res.is_err(), "the update finished before the drop");
    assert!(auth.synced.lock().unwrap().is_empty());

    // It completes all the same (the budget is generous: the store
    // takes 200 ms, and the suite runs under load).
    for _ in 0..500 {
      if !auth.synced.lock().unwrap().is_empty() {
        break;
      }
      tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let synced = auth.synced.lock().unwrap().clone();
    assert_eq!(synced.len(), 1);
    assert_eq!(synced[0].0, created.id);
    assert!(synced[0].1.iter().all(|access| !access.enabled));
    assert!(!auth.stored.lock().unwrap()[0].enabled);
    // In the request's context, and unlocked once done.
    assert_eq!(
      auth.sync_context.lock().unwrap().clone(),
      Some(context)
    );
    assert!(!exchange_waits(&created.id).await);
  }

  #[tokio::test]
  async fn test_failed_sync_fails_the_update() {
    use crate::provider::workload::load_verification_keys;

    Events::of_issuer("");
    let mut auth = TestAuth::default();
    let created = create_issuer(
      &auth,
      &ADMIN,
      TrustedIssuer {
        keys: TrustedIssuerKeys::Static(jwks_json()),
        ..issuer(vec![rule("", "Deploy")])
      },
    )
    .await
    .unwrap()
    .issuer;
    let keys = load_verification_keys(&created).await.unwrap();
    auth.sync_fails = true;

    let err =
      update_issuer(Arc::new(auth.clone()), &ADMIN, created.clone())
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);

    let events = Events::of_issuer(&created.id);
    assert!(
      events.iter().any(|event| {
        event.level == tracing::Level::INFO
          && event.message == "Trusted issuer updated"
      }),
      "{events:?}"
    );
    assert!(
      events.iter().any(|event| {
        event.level == tracing::Level::WARN
          && event
            .message
            .contains("syncing the users of its rules failed")
          && event.message.contains("sync failed")
      }),
      "{events:?}"
    );
    let reloaded = load_verification_keys(&created).await.unwrap();
    assert!(!Arc::ptr_eq(&keys, &reloaded));
  }

  /// Exchanges of the issuer's rules wait while the app stores an
  /// update and syncs the users, or deletes the issuer.
  #[tokio::test]
  async fn test_exchanges_wait_for_updates_and_deletion() {
    let auth = TestAuth::default();
    let created =
      create_issuer(&auth, &ADMIN, issuer(vec![rule("", "Deploy")]))
        .await
        .unwrap()
        .issuer;
    update_issuer(Arc::new(auth.clone()), &ADMIN, created.clone())
      .await
      .unwrap();
    delete_issuer(&auth, &ADMIN, &created.id).await.unwrap();
    // Store, sync, delete
    assert_eq!(*auth.exchange_waited.lock().unwrap(), [true; 3]);
    // And not after.
    assert!(!exchange_waits(&created.id).await);
  }

  #[test]
  fn test_workload_access_of_static_rules_without_usable_ids() {
    let mut static_issuer = issuer(vec![
      rule("deploy", "Deploy"),
      rule("", "No id"),
      rule("invalid id", "Invalid id"),
      WorkloadRule {
        admin: true,
        ..rule("shared", "Shared")
      },
      WorkloadRule {
        admin: true,
        ..rule("shared", "Shared again")
      },
    ]);
    static_issuer.id = "static".to_string();
    let access = WorkloadAccess::of_issuer(&static_issuer);
    assert_eq!(access.len(), 2);
    assert_eq!(access[0].rule_id, "deploy");
    assert!(access[0].enabled);
    // Their exchanges are refused, and so is their user.
    assert_eq!(access[1].rule_id, "shared");
    assert!(!access[1].enabled && !access[1].admin);
    assert!(access[1].groups.is_empty());
  }

  #[tokio::test]
  async fn test_delete() {
    let auth = TestAuth::default();
    let id = create_issuer(&auth, &ADMIN, issuer(Vec::new()))
      .await
      .unwrap()
      .issuer
      .id;
    delete_issuer(&auth, &ADMIN, &id).await.unwrap();
    assert!(auth.stored.lock().unwrap().is_empty());
  }

  use mogh_auth_client::config::TokenReviewConfig;

  fn review_issuer(url: &str, token: &str) -> TrustedIssuer {
    let mut issuer = issuer(vec![WorkloadRule {
      id: String::new(),
      name: "Pods".to_string(),
      enabled: true,
      claims: vec![WorkloadClaim {
        claim: "sub".to_string(),
        pattern: "system:serviceaccount:ns:*".to_string(),
      }],
      groups: vec!["pods".to_string()],
      admin: false,
      token_ttl_secs: 0,
    }]);
    issuer.issuer =
      "https://kubernetes.default.svc.cluster.local".to_string();
    issuer.keys = TrustedIssuerKeys::TokenReview(TokenReviewConfig {
      url: url.to_string(),
      ca: String::new(),
      token: token.to_string(),
      device: String::new(),
      in_cluster: false,
    });
    issuer
  }

  fn in_cluster_issuer() -> TrustedIssuer {
    let mut issuer = review_issuer("", "");
    issuer.keys = TrustedIssuerKeys::TokenReview(TokenReviewConfig {
      in_cluster: true,
      ..Default::default()
    });
    issuer
  }

  /// A TestAuth running inside a mock cluster: the api server is
  /// `url`, the mounted token lives in the returned directory.
  fn in_cluster_auth(url: &str) -> (TestAuth, std::path::PathBuf) {
    let dir = std::env::temp_dir()
      .join(format!("in-cluster-{}", random_string(12)));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("token"), "mounted-reviewer").unwrap();
    let auth = TestAuth {
      in_cluster: Some(crate::provider::workload::InClusterEnv {
        url: url.to_string(),
        token_path: dir.join("token"),
        ca_path: dir.join("ca.crt"),
      }),
      ..Default::default()
    };
    (auth, dir)
  }

  fn stored_review_token(auth: &TestAuth) -> String {
    let stored = auth.stored.lock().unwrap();
    match &stored[0].keys {
      TrustedIssuerKeys::TokenReview(config) => config.token.clone(),
      _ => unreachable!(),
    }
  }

  #[tokio::test]
  async fn test_review_credential_is_redacted_and_kept() {
    let auth = TestAuth::default();
    let created = create_issuer(
      &auth,
      &ADMIN,
      review_issuer("https://10.0.0.1:6443", "reviewer-secret"),
    )
    .await
    .unwrap()
    .issuer;

    // Stored in full, never shown again
    assert_eq!(created.keys.review_token(), Some(REDACTED));
    assert_eq!(stored_review_token(&auth), "reviewer-secret");
    let listed = list_issuers(&auth, &ADMIN).await.unwrap();
    assert_eq!(listed[0].issuer.keys.review_token(), Some(REDACTED));

    // An empty or redacted credential keeps the stored one
    for kept in ["", REDACTED] {
      let mut update = review_issuer("https://10.0.0.1:6443", kept);
      update.id = created.id.clone();
      let updated =
        update_issuer(Arc::new(auth.clone()), &ADMIN, update)
          .await
          .unwrap()
          .issuer;
      assert_eq!(updated.keys.review_token(), Some(REDACTED));
      assert_eq!(stored_review_token(&auth), "reviewer-secret");
    }

    // A new credential replaces it
    let mut update =
      review_issuer("https://10.0.0.1:6443", "new-secret");
    update.id = created.id.clone();
    update_issuer(Arc::new(auth.clone()), &ADMIN, update)
      .await
      .unwrap();
    assert_eq!(stored_review_token(&auth), "new-secret");

    // A changed url needs the credential entered again
    let mut update = review_issuer("https://10.0.0.2:6443", "");
    update.id = created.id.clone();
    let error = update_issuer(Arc::new(auth.clone()), &ADMIN, update)
      .await
      .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert!(
      format!("{:#}", error.error)
        .contains("enter the reviewer credential again"),
      "{:#}",
      error.error
    );
    assert_eq!(stored_review_token(&auth), "new-secret");

    // With the credential, the new url is fine
    let mut update =
      review_issuer("https://10.0.0.2:6443", "third-secret");
    update.id = created.id.clone();
    update_issuer(Arc::new(auth.clone()), &ADMIN, update)
      .await
      .unwrap();
    assert_eq!(stored_review_token(&auth), "third-secret");
  }

  #[tokio::test]
  async fn test_review_validation() {
    let auth = TestAuth::default();
    for (what, issuer) in [
      ("neither url nor device", review_issuer("", "")),
      ("url without a credential", {
        review_issuer("https://10.0.0.1:6443", "")
      }),
      ("a redacted credential on create", {
        review_issuer("https://10.0.0.1:6443", REDACTED)
      }),
      ("url and device", {
        let mut issuer =
          review_issuer("https://10.0.0.1:6443", "reviewer");
        if let TrustedIssuerKeys::TokenReview(config) =
          &mut issuer.keys
        {
          config.device = "dev_123".to_string();
        }
        issuer
      }),
    ] {
      let error =
        create_issuer(&auth, &ADMIN, issuer).await.unwrap_err();
      assert_eq!(error.status, StatusCode::BAD_REQUEST, "{what}");
    }
    assert!(auth.stored.lock().unwrap().is_empty());

    // A device reviews with its own credentials: the stale ones
    // of the form are dropped
    let device_issuer = || {
      let mut issuer = review_issuer("", "stale");
      if let TrustedIssuerKeys::TokenReview(config) = &mut issuer.keys
      {
        config.device = "dev_123".to_string();
        config.ca = "stale".to_string();
      }
      issuer
    };
    let auth = TestAuth {
      review_devices: true,
      ..Default::default()
    };
    create_issuer(&auth, &ADMIN, device_issuer()).await.unwrap();
    let stored = auth.stored.lock().unwrap();
    let TrustedIssuerKeys::TokenReview(config) = &stored[0].keys
    else {
      unreachable!()
    };
    assert_eq!(config.device, "dev_123");
    assert!(config.token.is_empty());
    assert!(config.ca.is_empty());
  }

  /// An app without review devices (the default) refuses an issuer
  /// naming one, created or updated: the default review could only
  /// refuse its every token.
  #[tokio::test]
  async fn test_review_device_needs_an_app_with_devices() {
    let auth = TestAuth::default();
    let mut device_issuer = review_issuer("", "");
    if let TrustedIssuerKeys::TokenReview(config) =
      &mut device_issuer.keys
    {
      config.device = "dev_123".to_string();
    }
    let error = create_issuer(&auth, &ADMIN, device_issuer.clone())
      .await
      .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert!(
      format!("{:#}", error.error)
        .contains("This app has no review devices"),
      "{:#}",
      error.error
    );
    assert!(auth.stored.lock().unwrap().is_empty());

    let created = create_issuer(
      &auth,
      &ADMIN,
      review_issuer("https://10.0.0.1:6443", "reviewer-secret"),
    )
    .await
    .unwrap()
    .issuer;
    let mut update = device_issuer;
    update.id = created.id.clone();
    let error = update_issuer(Arc::new(auth.clone()), &ADMIN, update)
      .await
      .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert_eq!(stored_review_token(&auth), "reviewer-secret");
  }

  #[tokio::test]
  async fn test_review_exchange() {
    use crate::{
      api::token::verify_workload_token,
      provider::{
        token_exchange::test_tokens::TestToken,
        workload::test_reviews::{
          authenticated, rejected, serve_cluster,
        },
      },
    };
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let mint = || {
      let mut token =
        TestToken::new(openidconnect::EmptyAdditionalClaims {});
      token.issuer =
        "https://kubernetes.default.svc.cluster.local".to_string();
      token.subject = "system:serviceaccount:ns:app".to_string();
      token.audiences = vec!["https://app.example.com".to_string()];
      token.mint()
    };

    // The cluster authenticates the token: the rule matches
    let (address, requests) = serve_cluster(
      201,
      authenticated("system:serviceaccount:ns:app"),
    )
    .await;
    let auth = TestAuth::default();
    create_issuer(
      &auth,
      &ADMIN,
      review_issuer(&address, "reviewer-secret"),
    )
    .await
    .unwrap();
    let verified =
      verify_workload_token(&auth, ip, &mint(), |_, _| true)
        .await
        .unwrap();
    assert_eq!(verified.rule.name, "Pods");
    assert_eq!(
      verified.claims["sub"],
      "system:serviceaccount:ns:app"
    );
    // The review carried the issuer's audiences and credential
    let (bearer, body) = requests.lock().unwrap()[0].clone();
    assert_eq!(bearer, "reviewer-secret");
    assert_eq!(
      body["spec"]["audiences"],
      serde_json::json!(["https://app.example.com"])
    );

    // The cluster rejects the token: a 400 describing it
    let (address, _) =
      serve_cluster(201, rejected("token has expired")).await;
    let auth = TestAuth::default();
    create_issuer(
      &auth,
      &ADMIN,
      review_issuer(&address, "reviewer-secret"),
    )
    .await
    .unwrap();
    let error =
      verify_workload_token(&auth, ip, &mint(), |_, _| true)
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert!(
      format!("{:#}", error.error).contains("token has expired"),
      "{:#}",
      error.error
    );

    // The cluster cannot be asked: the issuer is unavailable
    let auth = TestAuth::default();
    create_issuer(
      &auth,
      &ADMIN,
      review_issuer("http://127.0.0.1:1", "reviewer-secret"),
    )
    .await
    .unwrap();
    let error =
      verify_workload_token(&auth, ip, &mint(), |_, _| true)
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
  }

  /// The exchange is unauthenticated: a token failing the checks
  /// which need no key (expiry, audience, age) never reaches the
  /// cluster, and a cluster failing reviews is asked once, not by
  /// every request.
  #[tokio::test]
  async fn test_reviews_spare_the_cluster() {
    use crate::{
      api::token::verify_workload_token,
      provider::{
        token_exchange::test_tokens::TestToken,
        workload::test_reviews::{authenticated, serve_cluster},
      },
    };
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let token = || {
      let mut token =
        TestToken::new(openidconnect::EmptyAdditionalClaims {});
      token.issuer =
        "https://kubernetes.default.svc.cluster.local".to_string();
      token.subject = "system:serviceaccount:ns:app".to_string();
      token.audiences = vec!["https://app.example.com".to_string()];
      token
    };

    let (address, requests) = serve_cluster(
      201,
      authenticated("system:serviceaccount:ns:app"),
    )
    .await;
    let auth = TestAuth::default();
    let mut issuer = review_issuer(&address, "reviewer-secret");
    issuer.max_token_age_secs = 600;
    create_issuer(&auth, &ADMIN, issuer).await.unwrap();
    for (what, token) in [
      ("expired", {
        let mut token = token();
        token.expires_in = chrono::Duration::minutes(-5);
        token.issued_ago = chrono::Duration::minutes(10);
        token
      }),
      ("another audience", {
        let mut token = token();
        token.audiences = vec!["https://other.example.com".into()];
        token
      }),
      ("too old", {
        let mut token = token();
        token.expires_in = chrono::Duration::hours(1);
        token.issued_ago = chrono::Duration::hours(1);
        token
      }),
    ] {
      let error =
        verify_workload_token(&auth, ip, &token.mint(), |_, _| true)
          .await
          .unwrap_err();
      assert_eq!(error.status, StatusCode::BAD_REQUEST, "{what}");
    }
    assert!(requests.lock().unwrap().is_empty());
    // A token passing them is reviewed.
    verify_workload_token(&auth, ip, &token().mint(), |_, _| true)
      .await
      .unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);

    // The cluster fails every review (the reviewer credential
    // refused): asked once, the next requests are unavailable
    // without a review.
    let (address, requests) =
      serve_cluster(401, serde_json::json!({"message": "no"})).await;
    let auth = TestAuth::default();
    create_issuer(&auth, &ADMIN, review_issuer(&address, "revoked"))
      .await
      .unwrap();
    for _ in 0..3 {
      let error =
        verify_workload_token(&auth, ip, &token().mint(), |_, _| {
          true
        })
        .await
        .unwrap_err();
      assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    }
    assert_eq!(requests.lock().unwrap().len(), 1);
    // Saving the issuer (a new credential) tries again right away.
    let created = auth.stored.lock().unwrap()[0].clone();
    let mut update = review_issuer(&address, "renewed");
    update.id = created.id;
    update_issuer(Arc::new(auth.clone()), &ADMIN, update)
      .await
      .unwrap();
    verify_workload_token(&auth, ip, &token().mint(), |_, _| true)
      .await
      .unwrap_err();
    assert_eq!(requests.lock().unwrap().len(), 2);
  }

  #[tokio::test]
  async fn test_in_cluster_review_needs_a_cluster() {
    // Outside a cluster the configuration is refused up front.
    let auth = TestAuth::default();
    let error = create_issuer(&auth, &ADMIN, in_cluster_issuer())
      .await
      .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert!(
      format!("{:#}", error.error)
        .contains("running in a Kubernetes cluster"),
      "{:#}",
      error.error
    );

    // So is a service account which is not mounted.
    let (auth, dir) = in_cluster_auth("https://unused");
    std::fs::remove_file(dir.join("token")).unwrap();
    let error = create_issuer(&auth, &ADMIN, in_cluster_issuer())
      .await
      .unwrap_err();
    assert_eq!(error.status, StatusCode::BAD_REQUEST);
    assert!(
      format!("{:#}", error.error)
        .contains("automountServiceAccountToken"),
      "{:#}",
      error.error
    );
    std::fs::remove_dir_all(&dir).ok();
  }

  #[tokio::test]
  async fn test_in_cluster_review_stores_no_credential() {
    let (auth, dir) = in_cluster_auth("https://unused");

    // A credential pasted along anyway is dropped, not stored.
    let mut issuer = in_cluster_issuer();
    if let TrustedIssuerKeys::TokenReview(config) = &mut issuer.keys {
      config.token = "pasted-by-mistake".to_string();
    }
    let created =
      create_issuer(&auth, &ADMIN, issuer).await.unwrap().issuer;
    assert_eq!(created.keys.review_token(), Some(""));
    assert_eq!(stored_review_token(&auth), "");
    std::fs::remove_dir_all(&dir).ok();
  }

  #[tokio::test]
  async fn test_switch_to_in_cluster_drops_the_credential() {
    let (auth, dir) = in_cluster_auth("https://unused");
    let created = create_issuer(
      &auth,
      &ADMIN,
      review_issuer("https://10.0.0.1:6443", "reviewer-secret"),
    )
    .await
    .unwrap()
    .issuer;
    assert_eq!(stored_review_token(&auth), "reviewer-secret");

    // The switch needs no credential entry, unlike a url change,
    // and clears the stored one.
    let mut update = in_cluster_issuer();
    update.id = created.id.clone();
    update.rules = created.rules.clone();
    update_issuer(Arc::new(auth.clone()), &ADMIN, update)
      .await
      .unwrap();
    assert_eq!(stored_review_token(&auth), "");
    let stored = auth.stored.lock().unwrap()[0].clone();
    let TrustedIssuerKeys::TokenReview(config) = &stored.keys else {
      unreachable!()
    };
    assert!(config.in_cluster);
    std::fs::remove_dir_all(&dir).ok();
  }

  #[tokio::test]
  async fn test_in_cluster_review_exchange() {
    use crate::{
      api::token::verify_workload_token,
      provider::{
        token_exchange::test_tokens::TestToken,
        workload::test_reviews::{authenticated, serve_cluster},
      },
    };
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let mint = || {
      let mut token =
        TestToken::new(openidconnect::EmptyAdditionalClaims {});
      token.issuer =
        "https://kubernetes.default.svc.cluster.local".to_string();
      token.subject = "system:serviceaccount:ns:app".to_string();
      token.audiences = vec!["https://app.example.com".to_string()];
      token.mint()
    };

    // The server's own mounted credential reviews the token.
    let (address, requests) = serve_cluster(
      201,
      authenticated("system:serviceaccount:ns:app"),
    )
    .await;
    let (auth, dir) = in_cluster_auth(&address);
    create_issuer(&auth, &ADMIN, in_cluster_issuer())
      .await
      .unwrap();
    let verified =
      verify_workload_token(&auth, ip, &mint(), |_, _| true)
        .await
        .unwrap();
    assert_eq!(verified.rule.name, "Pods");
    let (bearer, body) = requests.lock().unwrap()[0].clone();
    assert_eq!(bearer, "mounted-reviewer");
    assert_eq!(
      body["spec"]["audiences"],
      serde_json::json!(["https://app.example.com"])
    );
    std::fs::remove_dir_all(&dir).ok();

    // Stored, but the server no longer runs in a cluster: the
    // issuer is unavailable, never the token's fault.
    let auth = TestAuth::default();
    auth
      .stored
      .lock()
      .unwrap()
      .push(stored_as("icl", in_cluster_issuer()));
    let error =
      verify_workload_token(&auth, ip, &mint(), |_, _| true)
        .await
        .unwrap_err();
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
  }

  /// An issuer verifying with keys, on the url of [review_issuer].
  fn keys_issuer(jwks: String) -> TrustedIssuer {
    let mut issuer = review_issuer("", "");
    issuer.name = "Keys".to_string();
    issuer.keys = TrustedIssuerKeys::Static(jwks);
    issuer
  }

  /// `issuer` as the management api would have stored it, with `id`:
  /// for rows stored before the api refused them.
  fn stored_as(id: &str, issuer: TrustedIssuer) -> TrustedIssuer {
    let mut issuer = validate_issuer(issuer, None).unwrap();
    issuer.id = id.to_string();
    issuer
  }

  fn assert_conflict(error: mogh_error::Error, other: &str) {
    assert_eq!(error.status, StatusCode::CONFLICT);
    let message = format!("{:#}", error.error);
    assert!(
      message.contains(&format!(
        "Trusted issuer '{other}' already uses this issuer url"
      )),
      "{message}"
    );
    assert!(
      message.contains("--service-account-issuer"),
      "{message}"
    );
    assert!(!message.contains("reviewer-secret"), "{message}");
  }

  /// A TokenReview issuer posts every token of its issuer url to its
  /// cluster: it may share the url with no other enabled issuer, of
  /// any kind, created in either order. Issuers verifying with keys
  /// may share one.
  #[tokio::test]
  async fn test_token_review_issuer_url_is_its_own() {
    let review = || {
      let mut issuer =
        review_issuer("https://10.0.0.1:6443", "reviewer-secret");
      issuer.name = "Review".to_string();
      issuer
    };
    let keys = || keys_issuer(jwks_json());
    let other_review = || {
      let mut issuer =
        review_issuer("https://10.0.0.2:6443", "reviewer-secret");
      issuer.name = "Other review".to_string();
      // The same url, written another way.
      issuer.issuer.push('/');
      issuer
    };

    for (first, second, other) in [
      (keys(), review(), "Keys"),
      (review(), keys(), "Review"),
      (review(), other_review(), "Review"),
      (other_review(), review(), "Other review"),
    ] {
      let auth = TestAuth::default();
      create_issuer(&auth, &ADMIN, first).await.unwrap();
      let error =
        create_issuer(&auth, &ADMIN, second).await.unwrap_err();
      assert_conflict(error, other);
      assert_eq!(auth.stored.lock().unwrap().len(), 1);
    }

    // Keys and keys share a url.
    let auth = TestAuth::default();
    create_issuer(&auth, &ADMIN, keys()).await.unwrap();
    let mut discovery = keys();
    discovery.keys = TrustedIssuerKeys::Discovery {};
    let discovery = create_issuer(&auth, &ADMIN, discovery)
      .await
      .unwrap()
      .issuer;

    // Turning one of them into a TokenReview issuer collides.
    let mut update = review();
    update.id = discovery.id.clone();
    let error = update_issuer(Arc::new(auth.clone()), &ADMIN, update)
      .await
      .unwrap_err();
    assert_conflict(error, "Keys");
    assert_eq!(
      auth.stored.lock().unwrap()[1].keys,
      TrustedIssuerKeys::Discovery {}
    );

    // A disabled TokenReview issuer collides with nothing, until it
    // is enabled.
    let disabled = TrustedIssuer {
      enabled: false,
      ..review()
    };
    let disabled =
      create_issuer(&auth, &ADMIN, disabled).await.unwrap().issuer;
    let enable = TrustedIssuer {
      enabled: true,
      id: disabled.id.clone(),
      ..review()
    };
    let error = update_issuer(Arc::new(auth.clone()), &ADMIN, enable)
      .await
      .unwrap_err();
    assert_conflict(error, "Keys");
    assert!(!auth.stored.lock().unwrap()[2].enabled);
    // Nor do disabled ones collide with an enabled one.
    let auth = TestAuth::default();
    create_issuer(
      &auth,
      &ADMIN,
      TrustedIssuer {
        enabled: false,
        ..keys()
      },
    )
    .await
    .unwrap();
    create_issuer(&auth, &ADMIN, review()).await.unwrap();

    // Moving a TokenReview issuer onto a url in use collides.
    let auth = TestAuth::default();
    create_issuer(&auth, &ADMIN, keys()).await.unwrap();
    let elsewhere = TrustedIssuer {
      issuer: "https://cluster-b.example.com".to_string(),
      ..review()
    };
    let elsewhere = create_issuer(&auth, &ADMIN, elsewhere)
      .await
      .unwrap()
      .issuer;
    let mut moved = review();
    moved.id = elsewhere.id.clone();
    let error = update_issuer(Arc::new(auth.clone()), &ADMIN, moved)
      .await
      .unwrap_err();
    assert_conflict(error, "Keys");
    assert_eq!(
      auth.stored.lock().unwrap()[1].issuer,
      "https://cluster-b.example.com"
    );

    // An issuer of the app configuration counts too.
    let auth = TestAuth {
      static_issuers: vec![stored_as("configured", keys())],
      ..Default::default()
    };
    let error =
      create_issuer(&auth, &ADMIN, review()).await.unwrap_err();
    assert_conflict(error, "Keys");
    assert!(auth.stored.lock().unwrap().is_empty());
  }

  /// Issuers which share a url with a TokenReview issuer though (of
  /// the app configuration, or stored before the management api
  /// refused them): the exchange never posts a token to the cluster.
  /// The TokenReview issuer is unavailable, the others verify as ever.
  #[tokio::test]
  async fn test_shared_review_issuer_url_is_never_reviewed() {
    use crate::{
      api::token::verify_workload_token,
      provider::{
        token_exchange::test_tokens::{TestToken, other_jwks_json},
        workload::test_reviews::{authenticated, serve_cluster},
      },
    };
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let mint = || {
      let mut token =
        TestToken::new(openidconnect::EmptyAdditionalClaims {});
      token.issuer =
        "https://kubernetes.default.svc.cluster.local".to_string();
      token.subject = "system:serviceaccount:ns:app".to_string();
      token.audiences = vec!["https://app.example.com".to_string()];
      token.mint()
    };
    let (address, requests) = serve_cluster(
      201,
      authenticated("system:serviceaccount:ns:app"),
    )
    .await;
    let review =
      stored_as("shared-review", review_issuer(&address, "secret"));

    // The keys issuer rejects the token (other keys): unavailable,
    // as the TokenReview issuer could not be asked.
    let rejecting = stored_as(
      "shared-keys-rejecting",
      keys_issuer(other_jwks_json()),
    );
    for stored in [
      vec![review.clone(), rejecting.clone()],
      vec![rejecting.clone(), review.clone()],
    ] {
      let auth = TestAuth::default();
      *auth.stored.lock().unwrap() = stored;
      let error =
        verify_workload_token(&auth, ip, &mint(), |_, _| true)
          .await
          .unwrap_err();
      assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    // The keys issuer verifies the token, listed after the
    // TokenReview issuer, and of the app configuration.
    let accepting =
      stored_as("shared-keys-accepting", keys_issuer(jwks_json()));
    let auth = TestAuth {
      static_issuers: vec![accepting],
      ..Default::default()
    };
    auth.stored.lock().unwrap().push(review.clone());
    let verified =
      verify_workload_token(&auth, ip, &mint(), |_, _| true)
        .await
        .unwrap();
    assert_eq!(verified.issuer.id, "shared-keys-accepting");

    // Even when no rule of the other issuer is admitted.
    let auth = TestAuth::default();
    *auth.stored.lock().unwrap() = vec![rejecting, review.clone()];
    let error =
      verify_workload_token(&auth, ip, &mint(), |issuer, _| {
        issuer.id == "shared-review"
      })
      .await
      .unwrap_err();
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);

    assert!(requests.lock().unwrap().is_empty());

    // Alone on its url, it reviews.
    let auth = TestAuth::default();
    auth.stored.lock().unwrap().push(review);
    verify_workload_token(&auth, ip, &mint(), |_, _| true)
      .await
      .unwrap();
    assert_eq!(requests.lock().unwrap().len(), 1);
  }

  /// An enabled issuer reached over plain http is stored (tests and
  /// loopback setups rely on it), with a warning naming the issuer
  /// and the url (without userinfo or query). Listed, the issuers of
  /// the app configuration (and rows stored before) are warned about
  /// once in the life of the process.
  #[tokio::test]
  async fn test_plain_http_urls_are_warned_about() {
    Events::of_issuer("");
    let plain_http_warnings = |issuer_id: &str| {
      Events::of_issuer(issuer_id)
        .into_iter()
        .filter(|event| {
          event.level == tracing::Level::WARN
            && event.message.contains("plain http")
        })
        .collect::<Vec<_>>()
    };
    let auth = TestAuth::default();
    let create = |change: fn(&mut TrustedIssuer)| {
      let mut issuer = issuer(vec![rule("", "Deploy")]);
      change(&mut issuer);
      create_issuer(&auth, &ADMIN, issuer)
    };

    for (change, warned) in [
      (
        (|i: &mut TrustedIssuer| {
          i.keys = TrustedIssuerKeys::JwksUri(
            "http://keys.example.com/keys?v=2".into(),
          )
        }) as fn(&mut TrustedIssuer),
        Some(("keys url", "the key set")),
      ),
      (
        |i| i.issuer = "http://issuer.example.com".into(),
        Some(("issuer", "the key set")),
      ),
      (
        |i| {
          // Its own issuer url: a TokenReview issuer shares none.
          i.issuer = "https://cluster.example.com".into();
          i.keys =
            TrustedIssuerKeys::TokenReview(TokenReviewConfig {
              url: "http://10.0.0.1:6443".into(),
              token: "reviewer-secret".into(),
              ..Default::default()
            });
        },
        Some(("token review url", "the reviewer credential")),
      ),
      // Static keys are fetched from nowhere.
      (
        |i| {
          i.issuer = "http://issuer.example.com".into();
          i.keys = TrustedIssuerKeys::Static(jwks_json());
        },
        None,
      ),
      // Nothing is sent for a disabled issuer.
      (
        |i| {
          i.enabled = false;
          i.issuer = "http://issuer.example.com".into();
        },
        None,
      ),
      (|_| {}, None),
    ] {
      let created = create(change).await.unwrap().issuer;
      let warnings = plain_http_warnings(&created.id);
      let Some((field, exposed)) = warned else {
        assert!(warnings.is_empty(), "{warnings:?}");
        continue;
      };
      assert_eq!(warnings.len(), 1, "{field}: {warnings:?}");
      assert!(warnings[0].message.contains(exposed), "{warnings:?}");
      let url = warnings[0].url.clone().unwrap();
      assert!(url.starts_with("http://"), "{url}");
      // Listing the stored issuer doesn't repeat it.
      list_issuers(&auth, &ADMIN).await.unwrap();
      assert_eq!(plain_http_warnings(&created.id).len(), 1);
    }

    // An issuer of the app configuration, listed by every exchange:
    // once, the url without userinfo and with the query masked.
    let mut configured = issuer(vec![rule("deploy", "Deploy")]);
    configured.id = "plain-http-configured".into();
    configured.keys = TrustedIssuerKeys::JwksUri(
      "http://keys.example.com/keys?token=hunter2".into(),
    );
    let auth = TestAuth {
      static_issuers: vec![configured],
      ..Default::default()
    };
    for _ in 0..3 {
      list_issuers(&auth, &ADMIN).await.unwrap();
    }
    let warnings = plain_http_warnings("plain-http-configured");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    let url = warnings[0].url.clone().unwrap();
    assert!(!url.contains("hunter2"), "{url}");
    assert!(
      url.starts_with("http://keys.example.com/keys?"),
      "{url}"
    );
  }
}
