//! Storage on sqlite. Everything the app stores goes through here.

use std::{
  str::FromStr as _,
  sync::OnceLock,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, anyhow};
use example_client::entities::{
  ApiKey, ApiKeyKind, LinkedLogin, Note, NoteListItem, User,
  WorkloadLink,
};
use mogh_auth_client::{
  config::{ExternalLoginProvider, TrustedIssuer},
  passkey::Passkey,
};
use mogh_auth_server::provider::workload::WorkloadAccess;
use mogh_supporter::SupporterBranding;
use serde::{Serialize, de::DeserializeOwned};
use sqlx::{
  SqlitePool,
  sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions,
  },
};
use uuid::Uuid;

use crate::{config::core_config, crypto};

static DB: OnceLock<SqlitePool> = OnceLock::new();

pub fn db() -> &'static SqlitePool {
  DB.get().expect("Database used before 'db::init'")
}

/// Opens (creating if missing) the database and applies the migrations.
pub async fn init() -> anyhow::Result<()> {
  let path = &core_config().database_path;
  if let Some(parent) = path.parent()
    && !parent.as_os_str().is_empty()
  {
    std::fs::create_dir_all(parent)
      .with_context(|| format!("Failed to create {parent:?}"))?;
  }
  let options = SqliteConnectOptions::new()
    .filename(path)
    .create_if_missing(true)
    .foreign_keys(true)
    .journal_mode(SqliteJournalMode::Wal);
  let pool = SqlitePoolOptions::new()
    .max_connections(8)
    .connect_with(options)
    .await
    .with_context(|| {
      format!("Failed to open database at {path:?}")
    })?;
  sqlx::migrate!("./migrations")
    .run(&pool)
    .await
    .context("Failed to apply database migrations")?;
  DB.set(pool)
    .map_err(|_| anyhow!("Database initialized more than once"))
}

pub fn unix_timestamp_ms() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_millis() as i64)
    .unwrap_or_default()
}

pub fn new_id() -> String {
  Uuid::new_v4().simple().to_string()
}

fn to_json<T: Serialize>(value: &T) -> anyhow::Result<String> {
  serde_json::to_string(value).context("Failed to serialize to JSON")
}

fn from_json<T: DeserializeOwned>(json: &str) -> anyhow::Result<T> {
  serde_json::from_str(json).context("Invalid JSON on database")
}

// =========
// = USERS =
// =========

#[derive(sqlx::FromRow)]
struct UserRow {
  id: String,
  username: String,
  password: String,
  enabled: bool,
  admin: bool,
  groups: String,
  passkey: String,
  totp_secret: String,
  totp_recovery_codes: String,
  external_skip_2fa: bool,
  cidr_whitelist: String,
  workload_issuer_id: Option<String>,
  workload_rule_id: Option<String>,
  workload_last_subject: String,
  created_at: i64,
  updated_at: i64,
}

#[derive(sqlx::FromRow)]
struct ExternalLoginRow {
  provider_id: String,
  external_id: String,
  avatar_url: Option<String>,
  groups: String,
}

/// The stored user, including the (decrypted) credentials.
/// Convert to [User] before it leaves the server.
#[derive(Clone)]
pub struct DbUser {
  pub id: String,
  pub username: String,
  /// bcrypt hash, empty if the user has no password.
  pub hashed_password: String,
  pub enabled: bool,
  pub admin: bool,
  /// The groups assigned in the app, or by the workload rule.
  pub groups: Vec<String>,
  pub passkey: Option<Passkey>,
  /// Empty if the user isn't enrolled.
  pub totp_secret: String,
  pub hashed_totp_recovery_codes: Vec<String>,
  pub external_skip_2fa: bool,
  pub cidr_whitelist: Vec<String>,
  pub workload: Option<WorkloadLink>,
  pub linked_logins: Vec<LinkedLogin>,
  /// The groups synced from the linked providers.
  pub provider_groups: Vec<String>,
  pub created_at: i64,
  pub updated_at: i64,
}

impl DbUser {
  /// The groups assigned in the app plus the
  /// ones synced from login providers.
  pub fn all_groups(&self) -> Vec<String> {
    let mut groups = self.groups.clone();
    for group in &self.provider_groups {
      if !groups.contains(group) {
        groups.push(group.clone());
      }
    }
    groups.sort();
    groups
  }

  pub fn into_user(self) -> User {
    User {
      groups: self.all_groups(),
      id: self.id,
      username: self.username,
      enabled: self.enabled,
      admin: self.admin,
      has_password: !self.hashed_password.is_empty(),
      totp_enrolled: !self.totp_secret.is_empty(),
      passkey_enrolled: self.passkey.is_some(),
      external_skip_2fa: self.external_skip_2fa,
      linked_logins: self.linked_logins,
      workload: self.workload,
      cidr_whitelist: self.cidr_whitelist,
      created_at: self.created_at,
      updated_at: self.updated_at,
    }
  }
}

async fn hydrate_user(row: UserRow) -> anyhow::Result<DbUser> {
  let logins = sqlx::query_as::<_, ExternalLoginRow>(
    "SELECT provider_id, external_id, avatar_url, groups
     FROM external_logins WHERE user_id = ? ORDER BY provider_id",
  )
  .bind(&row.id)
  .fetch_all(db())
  .await
  .context("Failed to query external logins")?;

  let mut provider_groups = Vec::<String>::new();
  let mut linked_logins = Vec::with_capacity(logins.len());
  for login in logins {
    provider_groups.extend(from_json::<Vec<String>>(&login.groups)?);
    linked_logins.push(LinkedLogin {
      provider_id: login.provider_id,
      external_id: login.external_id,
      avatar_url: login.avatar_url,
    });
  }

  let passkey = if row.passkey.is_empty() {
    None
  } else {
    Some(from_json(&crypto::open(&row.passkey, &row.id)?)?)
  };
  let totp_secret = if row.totp_secret.is_empty() {
    String::new()
  } else {
    crypto::open(&row.totp_secret, &row.id)?
  };
  let workload = match (row.workload_issuer_id, row.workload_rule_id)
  {
    (Some(issuer_id), Some(rule_id)) => Some(WorkloadLink {
      issuer_id,
      rule_id,
      last_subject: row.workload_last_subject,
    }),
    _ => None,
  };

  Ok(DbUser {
    hashed_password: row.password,
    enabled: row.enabled,
    admin: row.admin,
    groups: from_json(&row.groups)?,
    passkey,
    totp_secret,
    hashed_totp_recovery_codes: from_json(&row.totp_recovery_codes)?,
    external_skip_2fa: row.external_skip_2fa,
    cidr_whitelist: from_json(&row.cidr_whitelist)?,
    workload,
    linked_logins,
    provider_groups,
    created_at: row.created_at,
    updated_at: row.updated_at,
    id: row.id,
    username: row.username,
  })
}

pub async fn find_user(id: &str) -> anyhow::Result<Option<DbUser>> {
  let row =
    sqlx::query_as::<_, UserRow>("SELECT * FROM users WHERE id = ?")
      .bind(id)
      .fetch_optional(db())
      .await
      .context("Failed to query user")?;
  match row {
    Some(row) => hydrate_user(row).await.map(Some),
    None => Ok(None),
  }
}

pub async fn find_user_with_username(
  username: &str,
) -> anyhow::Result<Option<DbUser>> {
  let row = sqlx::query_as::<_, UserRow>(
    "SELECT * FROM users WHERE username = ?",
  )
  .bind(username)
  .fetch_optional(db())
  .await
  .context("Failed to query user")?;
  match row {
    Some(row) => hydrate_user(row).await.map(Some),
    None => Ok(None),
  }
}

/// ⚠️ External ids are only unique per provider,
/// so this always matches on both.
pub async fn find_user_with_external_login(
  provider_id: &str,
  external_id: &str,
) -> anyhow::Result<Option<DbUser>> {
  let row = sqlx::query_as::<_, UserRow>(
    "SELECT users.* FROM users
     JOIN external_logins ON external_logins.user_id = users.id
     WHERE external_logins.provider_id = ?
       AND external_logins.external_id = ?",
  )
  .bind(provider_id)
  .bind(external_id)
  .fetch_optional(db())
  .await
  .context("Failed to query user")?;
  match row {
    Some(row) => hydrate_user(row).await.map(Some),
    None => Ok(None),
  }
}

pub async fn find_workload_user(
  issuer_id: &str,
  rule_id: &str,
) -> anyhow::Result<Option<DbUser>> {
  let row = sqlx::query_as::<_, UserRow>(
    "SELECT * FROM users
     WHERE workload_issuer_id = ? AND workload_rule_id = ?",
  )
  .bind(issuer_id)
  .bind(rule_id)
  .fetch_optional(db())
  .await
  .context("Failed to query user")?;
  match row {
    Some(row) => hydrate_user(row).await.map(Some),
    None => Ok(None),
  }
}

pub async fn list_users() -> anyhow::Result<Vec<DbUser>> {
  let rows = sqlx::query_as::<_, UserRow>(
    "SELECT * FROM users ORDER BY created_at, username",
  )
  .fetch_all(db())
  .await
  .context("Failed to query users")?;
  let mut users = Vec::with_capacity(rows.len());
  for row in rows {
    users.push(hydrate_user(row).await?);
  }
  Ok(users)
}

/// Doesn't count workload users, they never sign up.
pub async fn no_users_exist() -> anyhow::Result<bool> {
  let count: i64 = sqlx::query_scalar(
    "SELECT COUNT(*) FROM users WHERE workload_issuer_id IS NULL",
  )
  .fetch_one(db())
  .await
  .context("Failed to count users")?;
  Ok(count == 0)
}

pub struct NewUser {
  pub username: String,
  pub hashed_password: String,
  pub enabled: bool,
  pub admin: bool,
  pub workload: Option<(String, String)>,
}

/// Returns the id of the created user.
pub async fn create_user(user: NewUser) -> anyhow::Result<String> {
  let id = new_id();
  let now = unix_timestamp_ms();
  let (issuer_id, rule_id) = user.workload.unzip();
  sqlx::query(
    "INSERT INTO users
      (id, username, password, enabled, admin,
       workload_issuer_id, workload_rule_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
  )
  .bind(&id)
  .bind(&user.username)
  .bind(&user.hashed_password)
  .bind(user.enabled)
  .bind(user.admin)
  .bind(issuer_id)
  .bind(rule_id)
  .bind(now)
  .bind(now)
  .execute(db())
  .await
  .context("Failed to create user")?;
  Ok(id)
}

/// Inserts the user of a workload rule, unless the rule has a user
/// already, or the username is taken: the insert then does nothing.
/// Returns whether the user was inserted.
///
/// Exchanges of one rule run concurrently (a CI matrix starting), and
/// several of them can find no user and get here. The unique index
/// `users_workload` makes all but one of them do nothing, where a
/// plain insert would fail them.
pub async fn insert_workload_user(
  user: NewUser,
) -> anyhow::Result<bool> {
  let Some((issuer_id, rule_id)) = user.workload else {
    return Err(anyhow!("A workload user needs its issuer and rule"));
  };
  let now = unix_timestamp_ms();
  let res = sqlx::query(
    "INSERT INTO users
      (id, username, password, enabled, admin,
       workload_issuer_id, workload_rule_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT DO NOTHING",
  )
  .bind(new_id())
  .bind(&user.username)
  .bind(&user.hashed_password)
  .bind(user.enabled)
  .bind(user.admin)
  .bind(issuer_id)
  .bind(rule_id)
  .bind(now)
  .bind(now)
  .execute(db())
  .await
  .context("Failed to create workload user")?;
  Ok(res.rows_affected() == 1)
}

/// The columns of a user which can be updated on their own.
pub enum UserUpdate {
  Username(String),
  Password(String),
  Enabled(bool),
  Admin(bool),
  Groups(Vec<String>),
  Passkey(Option<Passkey>),
  Totp {
    secret: String,
    hashed_recovery_codes: Vec<String>,
  },
  ExternalSkip2fa(bool),
  CidrWhitelist(Vec<String>),
  WorkloadLastSubject(String),
}

pub async fn update_user(
  id: &str,
  update: UserUpdate,
) -> anyhow::Result<()> {
  let now = unix_timestamp_ms();
  let query = |column: &str| {
    format!(
      "UPDATE users SET {column} = ?, updated_at = ? WHERE id = ?"
    )
  };
  let res = match update {
    UserUpdate::Username(username) => {
      sqlx::query(sqlx::AssertSqlSafe(query("username")))
        .bind(username)
        .bind(now)
        .bind(id)
        .execute(db())
        .await
    }
    UserUpdate::Password(password) => {
      sqlx::query(sqlx::AssertSqlSafe(query("password")))
        .bind(password)
        .bind(now)
        .bind(id)
        .execute(db())
        .await
    }
    UserUpdate::Enabled(enabled) => {
      sqlx::query(sqlx::AssertSqlSafe(query("enabled")))
        .bind(enabled)
        .bind(now)
        .bind(id)
        .execute(db())
        .await
    }
    UserUpdate::Admin(admin) => {
      sqlx::query(sqlx::AssertSqlSafe(query("admin")))
        .bind(admin)
        .bind(now)
        .bind(id)
        .execute(db())
        .await
    }
    UserUpdate::Groups(groups) => {
      sqlx::query(sqlx::AssertSqlSafe(query("groups")))
        .bind(to_json(&groups)?)
        .bind(now)
        .bind(id)
        .execute(db())
        .await
    }
    UserUpdate::Passkey(passkey) => {
      let passkey = match passkey {
        Some(passkey) => crypto::seal(&to_json(&passkey)?, id)?,
        None => String::new(),
      };
      sqlx::query(sqlx::AssertSqlSafe(query("passkey")))
        .bind(passkey)
        .bind(now)
        .bind(id)
        .execute(db())
        .await
    }
    UserUpdate::Totp {
      secret,
      hashed_recovery_codes,
    } => {
      let secret = if secret.is_empty() {
        String::new()
      } else {
        crypto::seal(&secret, id)?
      };
      sqlx::query(
        "UPDATE users
         SET totp_secret = ?, totp_recovery_codes = ?, updated_at = ?
         WHERE id = ?",
      )
      .bind(secret)
      .bind(to_json(&hashed_recovery_codes)?)
      .bind(now)
      .bind(id)
      .execute(db())
      .await
    }
    UserUpdate::ExternalSkip2fa(skip) => {
      sqlx::query(sqlx::AssertSqlSafe(query("external_skip_2fa")))
        .bind(skip)
        .bind(now)
        .bind(id)
        .execute(db())
        .await
    }
    UserUpdate::CidrWhitelist(cidr_whitelist) => {
      sqlx::query(sqlx::AssertSqlSafe(query("cidr_whitelist")))
        .bind(to_json(&cidr_whitelist)?)
        .bind(now)
        .bind(id)
        .execute(db())
        .await
    }
    UserUpdate::WorkloadLastSubject(subject) => {
      sqlx::query(sqlx::AssertSqlSafe(query("workload_last_subject")))
        .bind(subject)
        .bind(now)
        .bind(id)
        .execute(db())
        .await
    }
  }
  .context("Failed to update user")?;
  if res.rows_affected() == 0 {
    return Err(anyhow!("No user with id {id}"));
  }
  Ok(())
}

pub async fn delete_user(id: &str) -> anyhow::Result<()> {
  sqlx::query("DELETE FROM users WHERE id = ?")
    .bind(id)
    .execute(db())
    .await
    .context("Failed to delete user")?;
  Ok(())
}

/// Brings the users of the workload rules of an issuer in line with
/// `rules`, in one transaction: the users of rules which aren't among
/// them are removed, the others get their rule's groups, admin status
/// and enabled. Rules without a user don't get one.
pub async fn sync_workload_users(
  issuer_id: &str,
  rules: &[WorkloadAccess],
) -> anyhow::Result<()> {
  // Takes the write lock up front: a transaction which only reads
  // at first can't write anymore once another one wrote meanwhile.
  let mut tx = db()
    .begin_with("BEGIN IMMEDIATE")
    .await
    .context("Failed to begin transaction")?;
  let users = sqlx::query_as::<_, (String, Option<String>)>(
    "SELECT id, workload_rule_id FROM users
     WHERE workload_issuer_id = ?",
  )
  .bind(issuer_id)
  .fetch_all(&mut *tx)
  .await
  .context("Failed to query workload users")?;
  let now = unix_timestamp_ms();
  for (id, rule_id) in users {
    let rule = rules
      .iter()
      .find(|rule| rule_id.as_ref() == Some(&rule.rule_id));
    let Some(rule) = rule else {
      sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&id)
        .execute(&mut *tx)
        .await
        .context("Failed to delete workload user")?;
      continue;
    };
    sqlx::query(
      "UPDATE users
       SET groups = ?, admin = ?, enabled = ?, updated_at = ?
       WHERE id = ?",
    )
    .bind(to_json(&rule.groups)?)
    .bind(rule.admin)
    .bind(rule.enabled)
    .bind(now)
    .bind(&id)
    .execute(&mut *tx)
    .await
    .context("Failed to update workload user")?;
  }
  tx.commit().await.context("Failed to commit transaction")
}

/// Removes the workload users of issuers which aren't among
/// `issuer_ids`, eg. of an issuer removed from the config file.
pub async fn delete_workload_users_of_other_issuers(
  issuer_ids: &[String],
) -> anyhow::Result<u64> {
  let mut deleted = 0;
  let users = sqlx::query_as::<_, (String, String)>(
    "SELECT id, workload_issuer_id FROM users
     WHERE workload_issuer_id IS NOT NULL",
  )
  .fetch_all(db())
  .await
  .context("Failed to query workload users")?;
  for (id, issuer_id) in users {
    if !issuer_ids.contains(&issuer_id) {
      delete_user(&id).await?;
      deleted += 1;
    }
  }
  Ok(deleted)
}

// ===================
// = EXTERNAL LOGINS =
// ===================

pub async fn link_external_login(
  user_id: &str,
  provider_id: &str,
  external_id: &str,
  avatar_url: Option<&str>,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO external_logins
      (user_id, provider_id, external_id, avatar_url)
     VALUES (?, ?, ?, ?)",
  )
  .bind(user_id)
  .bind(provider_id)
  .bind(external_id)
  .bind(avatar_url)
  .execute(db())
  .await
  .context("Failed to link external login")?;
  Ok(())
}

pub async fn unlink_external_login(
  user_id: &str,
  provider_id: &str,
) -> anyhow::Result<()> {
  sqlx::query(
    "DELETE FROM external_logins WHERE user_id = ? AND provider_id = ?",
  )
  .bind(user_id)
  .bind(provider_id)
  .execute(db())
  .await
  .context("Failed to unlink external login")?;
  Ok(())
}

/// Replaces only the groups synced from this provider,
/// keeping the ones assigned in the app.
pub async fn set_provider_groups(
  user_id: &str,
  provider_id: &str,
  groups: &[String],
) -> anyhow::Result<()> {
  sqlx::query(
    "UPDATE external_logins SET groups = ?
     WHERE user_id = ? AND provider_id = ?",
  )
  .bind(to_json(&groups)?)
  .bind(user_id)
  .bind(provider_id)
  .execute(db())
  .await
  .context("Failed to update provider groups")?;
  Ok(())
}

// ============
// = API KEYS =
// ============

#[derive(sqlx::FromRow)]
struct ApiKeyRow {
  key: String,
  kind: String,
  secret: String,
  user_id: String,
  name: String,
  expires: i64,
  cidr_whitelist: String,
  created_at: i64,
}

pub struct DbApiKey {
  pub api_key: ApiKey,
  /// bcrypt hash (api keys only, empty for signing keys).
  pub hashed_secret: String,
}

impl DbApiKey {
  pub fn expired(&self) -> bool {
    self.api_key.expires != 0
      && self.api_key.expires <= unix_timestamp_ms()
  }
}

impl TryFrom<ApiKeyRow> for DbApiKey {
  type Error = anyhow::Error;
  fn try_from(row: ApiKeyRow) -> anyhow::Result<DbApiKey> {
    Ok(DbApiKey {
      api_key: ApiKey {
        kind: ApiKeyKind::from_str(&row.kind)
          .context("Invalid api key kind on database")?,
        key: row.key,
        user_id: row.user_id,
        name: row.name,
        expires: row.expires,
        cidr_whitelist: from_json(&row.cidr_whitelist)?,
        created_at: row.created_at,
      },
      hashed_secret: row.secret,
    })
  }
}

pub async fn create_api_key(
  api_key: &ApiKey,
  hashed_secret: &str,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO api_keys
      (key, kind, secret, user_id, name, expires, cidr_whitelist, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  )
  .bind(&api_key.key)
  .bind(api_key.kind.to_string())
  .bind(hashed_secret)
  .bind(&api_key.user_id)
  .bind(&api_key.name)
  .bind(api_key.expires)
  .bind(to_json(&api_key.cidr_whitelist)?)
  .bind(api_key.created_at)
  .execute(db())
  .await
  .context("Failed to create api key")?;
  Ok(())
}

pub async fn find_api_key(
  key: &str,
  kind: ApiKeyKind,
) -> anyhow::Result<Option<DbApiKey>> {
  sqlx::query_as::<_, ApiKeyRow>(
    "SELECT * FROM api_keys WHERE key = ? AND kind = ?",
  )
  .bind(key)
  .bind(kind.to_string())
  .fetch_optional(db())
  .await
  .context("Failed to query api key")?
  .map(DbApiKey::try_from)
  .transpose()
}

pub async fn list_api_keys(
  user_id: &str,
) -> anyhow::Result<Vec<ApiKey>> {
  sqlx::query_as::<_, ApiKeyRow>(
    "SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at",
  )
  .bind(user_id)
  .fetch_all(db())
  .await
  .context("Failed to query api keys")?
  .into_iter()
  .map(|row| DbApiKey::try_from(row).map(|key| key.api_key))
  .collect()
}

pub async fn delete_api_key(
  key: &str,
  kind: ApiKeyKind,
) -> anyhow::Result<()> {
  sqlx::query("DELETE FROM api_keys WHERE key = ? AND kind = ?")
    .bind(key)
    .bind(kind.to_string())
    .execute(db())
    .await
    .context("Failed to delete api key")?;
  Ok(())
}

// ===================
// = LOGIN PROVIDERS =
// ===================

/// The provider includes its client secret, so it is stored encrypted.
pub async fn list_login_providers()
-> anyhow::Result<Vec<ExternalLoginProvider>> {
  sqlx::query_as::<_, (String, String)>(
    "SELECT id, data FROM login_providers ORDER BY created_at",
  )
  .fetch_all(db())
  .await
  .context("Failed to query login providers")?
  .into_iter()
  .map(|(id, data)| from_json(&crypto::open(&data, &id)?))
  .collect()
}

pub async fn create_login_provider(
  provider: &ExternalLoginProvider,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO login_providers (id, data, created_at) VALUES (?, ?, ?)",
  )
  .bind(&provider.id)
  .bind(crypto::seal(&to_json(provider)?, &provider.id)?)
  .bind(unix_timestamp_ms())
  .execute(db())
  .await
  .context("Failed to create login provider")?;
  Ok(())
}

pub async fn update_login_provider(
  provider: &ExternalLoginProvider,
) -> anyhow::Result<()> {
  let res =
    sqlx::query("UPDATE login_providers SET data = ? WHERE id = ?")
      .bind(crypto::seal(&to_json(provider)?, &provider.id)?)
      .bind(&provider.id)
      .execute(db())
      .await
      .context("Failed to update login provider")?;
  if res.rows_affected() == 0 {
    return Err(anyhow!("No login provider with id {}", provider.id));
  }
  Ok(())
}

/// Also removes the links to the provider from all users.
pub async fn delete_login_provider(id: &str) -> anyhow::Result<()> {
  let mut tx =
    db().begin().await.context("Failed to begin transaction")?;
  sqlx::query("DELETE FROM login_providers WHERE id = ?")
    .bind(id)
    .execute(&mut *tx)
    .await
    .context("Failed to delete login provider")?;
  sqlx::query("DELETE FROM external_logins WHERE provider_id = ?")
    .bind(id)
    .execute(&mut *tx)
    .await
    .context("Failed to remove links to login provider")?;
  tx.commit().await.context("Failed to commit transaction")
}

// =================
// = SUPPORTER KEY =
// =================

/// The key an admin set over the supporter api, if any. It holds the
/// instance private key, so it is stored encrypted.
pub async fn load_supporter_key() -> anyhow::Result<Option<String>> {
  sqlx::query_as::<_, (String,)>(
    "SELECT data FROM supporter_key WHERE id = 1",
  )
  .fetch_optional(db())
  .await
  .context("Failed to query supporter key")?
  .map(|(data,)| crypto::open(&data, "supporter_key"))
  .transpose()
}

/// Keeps the key an admin set, or removes it (`None`).
pub async fn store_supporter_key(
  key: Option<&str>,
) -> anyhow::Result<()> {
  match key {
    Some(key) => {
      sqlx::query(
        "INSERT INTO supporter_key (id, data, updated_at) VALUES (1, ?, ?) \
         ON CONFLICT (id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
      )
      .bind(crypto::seal(key, "supporter_key")?)
      .bind(unix_timestamp_ms())
      .execute(db())
      .await
      .context("Failed to store supporter key")?;
    }
    None => {
      sqlx::query("DELETE FROM supporter_key WHERE id = 1")
        .execute(db())
        .await
        .context("Failed to remove supporter key")?;
    }
  }
  Ok(())
}

/// The branding an admin set over the supporter api, if any.
pub async fn load_supporter_branding()
-> anyhow::Result<Option<SupporterBranding>> {
  sqlx::query_as::<_, (String,)>(
    "SELECT data FROM supporter_branding WHERE id = 1",
  )
  .fetch_optional(db())
  .await
  .context("Failed to query supporter branding")?
  .map(|(data,)| from_json(&data))
  .transpose()
}

/// Keeps the branding an admin set, replacing what was kept.
pub async fn store_supporter_branding(
  branding: &SupporterBranding,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO supporter_branding (id, data, updated_at) VALUES (1, ?, ?) \
     ON CONFLICT (id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
  )
  .bind(to_json(branding)?)
  .bind(unix_timestamp_ms())
  .execute(db())
  .await
  .context("Failed to store supporter branding")?;
  Ok(())
}

// ===================
// = TRUSTED ISSUERS =
// ===================

pub async fn list_trusted_issuers()
-> anyhow::Result<Vec<TrustedIssuer>> {
  sqlx::query_scalar::<_, String>(
    "SELECT data FROM trusted_issuers ORDER BY created_at",
  )
  .fetch_all(db())
  .await
  .context("Failed to query trusted issuers")?
  .iter()
  .map(|data| from_json(data))
  .collect()
}

pub async fn create_trusted_issuer(
  issuer: &TrustedIssuer,
) -> anyhow::Result<()> {
  sqlx::query(
    "INSERT INTO trusted_issuers (id, data, created_at) VALUES (?, ?, ?)",
  )
  .bind(&issuer.id)
  .bind(to_json(issuer)?)
  .bind(unix_timestamp_ms())
  .execute(db())
  .await
  .context("Failed to create trusted issuer")?;
  Ok(())
}

pub async fn update_trusted_issuer(
  issuer: &TrustedIssuer,
) -> anyhow::Result<()> {
  let res =
    sqlx::query("UPDATE trusted_issuers SET data = ? WHERE id = ?")
      .bind(to_json(issuer)?)
      .bind(&issuer.id)
      .execute(db())
      .await
      .context("Failed to update trusted issuer")?;
  if res.rows_affected() == 0 {
    return Err(anyhow!("No trusted issuer with id {}", issuer.id));
  }
  Ok(())
}

/// Also removes the users of its rules.
pub async fn delete_trusted_issuer(id: &str) -> anyhow::Result<()> {
  let mut tx =
    db().begin().await.context("Failed to begin transaction")?;
  sqlx::query("DELETE FROM trusted_issuers WHERE id = ?")
    .bind(id)
    .execute(&mut *tx)
    .await
    .context("Failed to delete trusted issuer")?;
  sqlx::query("DELETE FROM users WHERE workload_issuer_id = ?")
    .bind(id)
    .execute(&mut *tx)
    .await
    .context("Failed to delete the users of the trusted issuer")?;
  tx.commit().await.context("Failed to commit transaction")
}

// ========
// = TOTP =
// ========

/// Returns whether the step was fresh, marking it as consumed.
pub async fn consume_totp_step(
  user_id: &str,
  step: u64,
) -> anyhow::Result<bool> {
  let res = sqlx::query(
    "INSERT OR IGNORE INTO totp_steps (user_id, step) VALUES (?, ?)",
  )
  .bind(user_id)
  .bind(step as i64)
  .execute(db())
  .await
  .context("Failed to consume TOTP step")?;
  // Only the most recent steps can still be replayed.
  sqlx::query(
    "DELETE FROM totp_steps WHERE user_id = ? AND step < ?",
  )
  .bind(user_id)
  .bind(step.saturating_sub(10) as i64)
  .execute(db())
  .await
  .context("Failed to clean up TOTP steps")?;
  Ok(res.rows_affected() == 1)
}

/// Removes a used recovery code (its hash) of the user, returning
/// whether it was still there. One conditional statement, so of two
/// logins using the same code at once (on any instance) only one
/// removes it, and removing one code never writes back another which
/// was just removed.
pub async fn remove_totp_recovery_code(
  user_id: &str,
  hashed_code: &str,
) -> anyhow::Result<bool> {
  let res = sqlx::query(
    "UPDATE users
     SET totp_recovery_codes = (
       SELECT json_group_array(code.value)
       FROM json_each(users.totp_recovery_codes) AS code
       WHERE code.value != ?
     ), updated_at = ?
     WHERE id = ? AND EXISTS (
       SELECT 1 FROM json_each(users.totp_recovery_codes) AS code
       WHERE code.value = ?
     )",
  )
  .bind(hashed_code)
  .bind(unix_timestamp_ms())
  .bind(user_id)
  .bind(hashed_code)
  .execute(db())
  .await
  .context("Failed to remove TOTP recovery code")?;
  Ok(res.rows_affected() == 1)
}

// =========
// = NOTES =
// =========

#[derive(sqlx::FromRow)]
struct NoteRow {
  id: String,
  owner_id: String,
  title: String,
  content: String,
  created_at: i64,
  updated_at: i64,
}

impl NoteRow {
  fn open(self) -> anyhow::Result<Note> {
    Ok(Note {
      content: crypto::open(&self.content, &self.id)?,
      id: self.id,
      owner_id: self.owner_id,
      title: self.title,
      created_at: self.created_at,
      updated_at: self.updated_at,
    })
  }
}

pub async fn list_notes(
  owner_id: &str,
  query: &str,
) -> anyhow::Result<Vec<NoteListItem>> {
  let rows = sqlx::query_as::<_, NoteRow>(
    "SELECT * FROM notes
     WHERE owner_id = ? AND instr(lower(title), lower(?)) > 0
     ORDER BY updated_at DESC",
  )
  .bind(owner_id)
  .bind(query)
  .fetch_all(db())
  .await
  .context("Failed to query notes")?;
  Ok(
    rows
      .into_iter()
      .map(|row| NoteListItem {
        id: row.id,
        owner_id: row.owner_id,
        title: row.title,
        created_at: row.created_at,
        updated_at: row.updated_at,
      })
      .collect(),
  )
}

pub async fn find_note(id: &str) -> anyhow::Result<Option<Note>> {
  sqlx::query_as::<_, NoteRow>("SELECT * FROM notes WHERE id = ?")
    .bind(id)
    .fetch_optional(db())
    .await
    .context("Failed to query note")?
    .map(NoteRow::open)
    .transpose()
}

pub async fn create_note(
  owner_id: &str,
  title: &str,
  content: &str,
) -> anyhow::Result<Note> {
  let id = new_id();
  let now = unix_timestamp_ms();
  sqlx::query(
    "INSERT INTO notes (id, owner_id, title, content, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)",
  )
  .bind(&id)
  .bind(owner_id)
  .bind(title)
  .bind(crypto::seal(content, &id)?)
  .bind(now)
  .bind(now)
  .execute(db())
  .await
  .context("Failed to create note")?;
  Ok(Note {
    id,
    owner_id: owner_id.to_string(),
    title: title.to_string(),
    content: content.to_string(),
    created_at: now,
    updated_at: now,
  })
}

pub async fn update_note(note: &Note) -> anyhow::Result<()> {
  sqlx::query(
    "UPDATE notes SET title = ?, content = ?, updated_at = ? WHERE id = ?",
  )
  .bind(&note.title)
  .bind(crypto::seal(&note.content, &note.id)?)
  .bind(note.updated_at)
  .bind(&note.id)
  .execute(db())
  .await
  .context("Failed to update note")?;
  Ok(())
}

pub async fn delete_note(id: &str) -> anyhow::Result<()> {
  sqlx::query("DELETE FROM notes WHERE id = ?")
    .bind(id)
    .execute(db())
    .await
    .context("Failed to delete note")?;
  Ok(())
}

// =========
// = STATS =
// =========

/// (users, notes, api keys)
pub async fn counts() -> anyhow::Result<(i64, i64, i64)> {
  sqlx::query_as(
    "SELECT
      (SELECT COUNT(*) FROM users),
      (SELECT COUNT(*) FROM notes),
      (SELECT COUNT(*) FROM api_keys)",
  )
  .fetch_one(db())
  .await
  .context("Failed to query counts")
}
