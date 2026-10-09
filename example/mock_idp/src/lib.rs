//! # Mock identity provider
//!
//! A minimal OIDC provider (discovery, key set, authorization code flow
//! with PKCE, user info) which can also mint arbitrary signed tokens,
//! to test external login, token exchange and workload identity against.
//!
//! ⚠️ For tests only. The signing keys are committed to this
//! repository, and everybody is logged in without being asked.

use std::{
  collections::HashMap,
  net::SocketAddr,
  sync::{Arc, Mutex},
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use axum::{
  Form, Json, Router,
  extract::{Query, State},
  http::{HeaderMap, StatusCode, header},
  response::{Html, IntoResponse, Redirect, Response},
  routing::{get, post},
};
use data_encoding::{BASE64, BASE64URL_NOPAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openidconnect::{
  JsonWebKeyId, PrivateSigningKey as _,
  core::{CoreJsonWebKeySet, CoreRsaPrivateSigningKey},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

/// The key the provider publishes.
const KEY_A: &str = include_str!("../../../auth/test_keys/rsa_a.pem");
/// A key the provider doesn't publish, to test rejected signatures.
const KEY_B: &str = include_str!("../../../auth/test_keys/rsa_b.pem");
const KEY_ID: &str = "test-key";

pub const DEFAULT_CLIENT_ID: &str = "example-client-id";
pub const DEFAULT_CLIENT_SECRET: &str = "example-client-secret";

/// A user who can log in at the provider.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdpUser {
  /// The subject (`sub`), which identifies the user.
  pub sub: String,
  #[serde(default)]
  pub preferred_username: Option<String>,
  #[serde(default)]
  pub email: Option<String>,
  #[serde(default)]
  pub picture: Option<String>,
  /// Put on the `groups` claim.
  #[serde(default)]
  pub groups: Option<Vec<String>>,
  /// Only put the groups in the user info, not in the id token.
  #[serde(default)]
  pub groups_in_user_info_only: bool,
}

/// Which key a token is signed with.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub enum Signer {
  /// The key the provider publishes.
  #[default]
  Provider,
  /// A key the provider doesn't publish.
  Other,
}

/// A token to mint, with any claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintToken {
  /// Defaults to the issuer of the provider.
  #[serde(default)]
  pub iss: Option<String>,
  pub sub: String,
  pub aud: Vec<String>,
  /// Seconds until the token expires. Negative for an expired token.
  #[serde(default = "default_expires_in")]
  pub expires_in: i64,
  /// Seconds since the token was issued.
  #[serde(default)]
  pub issued_ago: i64,
  #[serde(default)]
  pub signer: Signer,
  /// Any other claims.
  #[serde(default)]
  pub claims: Map<String, Value>,
}

fn default_expires_in() -> i64 {
  300
}

impl Default for MintToken {
  fn default() -> Self {
    Self {
      iss: None,
      sub: String::new(),
      aud: Vec::new(),
      expires_in: default_expires_in(),
      issued_ago: 0,
      signer: Signer::default(),
      claims: Map::new(),
    }
  }
}

struct PendingCode {
  sub: String,
  nonce: Option<String>,
  client_id: String,
  redirect_uri: String,
  code_challenge: Option<String>,
}

#[derive(Default)]
struct Inner {
  users: HashMap<String, IdpUser>,
  /// Log this user in without showing the user selection.
  auto_user: Option<String>,
  codes: HashMap<String, PendingCode>,
  /// access token -> sub
  access_tokens: HashMap<String, String>,
  /// How often the key set was fetched.
  jwks_requests: u64,
}

#[derive(Clone)]
pub struct MockIdp {
  /// The issuer url, where the provider is reachable at.
  pub issuer: String,
  pub client_id: String,
  pub client_secret: String,
  inner: Arc<Mutex<Inner>>,
}

impl MockIdp {
  /// Binds `127.0.0.1:port` (0 picks a free port) and serves in the background.
  pub async fn spawn(port: u16) -> anyhow::Result<MockIdp> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((
      [127, 0, 0, 1],
      port,
    )))
    .await
    .context("Failed to bind mock idp")?;
    let port = listener.local_addr()?.port();
    let idp = MockIdp {
      issuer: format!("http://127.0.0.1:{port}"),
      client_id: DEFAULT_CLIENT_ID.to_string(),
      client_secret: DEFAULT_CLIENT_SECRET.to_string(),
      inner: Default::default(),
    };
    let app = idp.router();
    tokio::spawn(async move {
      if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Mock idp stopped | {e:#}");
      }
    });
    Ok(idp)
  }

  pub fn router(&self) -> Router {
    Router::new()
      .route("/.well-known/openid-configuration", get(discovery))
      .route("/jwks", get(jwks))
      .route("/authorize", get(authorize))
      .route("/token", post(token))
      .route("/userinfo", get(userinfo))
      .route("/control/users", post(control_upsert_user))
      .route("/control/auto_user", post(control_auto_user))
      .route("/control/mint", post(control_mint))
      .with_state(self.clone())
  }

  pub fn upsert_user(&self, user: IdpUser) {
    self.lock().users.insert(user.sub.clone(), user);
  }

  /// The user `/authorize` logs in right away.
  /// With `None` it shows a page to select the user.
  pub fn set_auto_user(&self, sub: Option<&str>) {
    self.lock().auto_user = sub.map(str::to_string);
  }

  pub fn jwks_requests(&self) -> u64 {
    self.lock().jwks_requests
  }

  /// The key set the provider publishes, as JSON.
  pub fn jwks_json(&self) -> String {
    jwks_json()
  }

  pub fn mint(&self, token: MintToken) -> String {
    let now = unix_timestamp();
    let mut claims = token.claims;
    claims.insert(
      "iss".into(),
      json!(token.iss.unwrap_or_else(|| self.issuer.clone())),
    );
    claims.insert("sub".into(), json!(token.sub));
    claims.insert("aud".into(), json!(token.aud));
    claims.insert("iat".into(), json!(now - token.issued_ago));
    claims.insert("exp".into(), json!(now + token.expires_in));
    sign(&claims, token.signer)
  }

  /// An id token for the user, as the provider
  /// would issue it to `aud` during a login.
  pub fn mint_id_token(&self, sub: &str, aud: &str) -> String {
    let user =
      self.lock().users.get(sub).cloned().unwrap_or(IdpUser {
        sub: sub.to_string(),
        ..Default::default()
      });
    self.mint(MintToken {
      sub: user.sub.clone(),
      aud: vec![aud.to_string()],
      claims: user_claims(&user, true),
      ..Default::default()
    })
  }

  fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
    self.inner.lock().unwrap_or_else(|e| e.into_inner())
  }
}

fn unix_timestamp() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|duration| duration.as_secs() as i64)
    .unwrap_or_default()
}

fn jwks_json() -> String {
  let key = CoreRsaPrivateSigningKey::from_pem(
    KEY_A,
    Some(JsonWebKeyId::new(KEY_ID.to_string())),
  )
  .expect("Invalid test key");
  serde_json::to_string(&CoreJsonWebKeySet::new(vec![
    key.as_verification_key(),
  ]))
  .expect("Failed to serialize key set")
}

fn sign(claims: &Map<String, Value>, signer: Signer) -> String {
  let pem = match signer {
    Signer::Provider => KEY_A,
    Signer::Other => KEY_B,
  };
  let mut header = Header::new(Algorithm::RS256);
  header.kid = Some(KEY_ID.to_string());
  jsonwebtoken::encode(
    &header,
    claims,
    &EncodingKey::from_rsa_pem(pem.as_bytes())
      .expect("Invalid test key"),
  )
  .expect("Failed to sign token")
}

fn user_claims(user: &IdpUser, id_token: bool) -> Map<String, Value> {
  let mut claims = Map::new();
  if let Some(username) = &user.preferred_username {
    claims.insert("preferred_username".into(), json!(username));
  }
  if let Some(email) = &user.email {
    claims.insert("email".into(), json!(email));
    claims.insert("email_verified".into(), json!(true));
  }
  if let Some(picture) = &user.picture {
    claims.insert("picture".into(), json!(picture));
  }
  if let Some(groups) = &user.groups
    && !(id_token && user.groups_in_user_info_only)
  {
    claims.insert("groups".into(), json!(groups));
  }
  claims
}

fn oauth_error(
  status: StatusCode,
  error: &str,
  description: &str,
) -> Response {
  (
    status,
    Json(json!({ "error": error, "error_description": description })),
  )
    .into_response()
}

async fn discovery(State(idp): State<MockIdp>) -> Json<Value> {
  let issuer = &idp.issuer;
  Json(json!({
    "issuer": issuer,
    "authorization_endpoint": format!("{issuer}/authorize"),
    "token_endpoint": format!("{issuer}/token"),
    "userinfo_endpoint": format!("{issuer}/userinfo"),
    "jwks_uri": format!("{issuer}/jwks"),
    "response_types_supported": ["code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "profile", "email", "groups"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    "code_challenge_methods_supported": ["S256"],
  }))
}

async fn jwks(State(idp): State<MockIdp>) -> Response {
  idp.lock().jwks_requests += 1;
  ([(header::CONTENT_TYPE, "application/json")], jwks_json())
    .into_response()
}

#[derive(Deserialize)]
struct AuthorizeQuery {
  client_id: String,
  redirect_uri: String,
  state: Option<String>,
  nonce: Option<String>,
  code_challenge: Option<String>,
  code_challenge_method: Option<String>,
  /// Set by the user selection page.
  user: Option<String>,
  /// Set by the user selection page to deny the login.
  deny: Option<String>,
}

async fn authorize(
  State(idp): State<MockIdp>,
  Query(query): Query<AuthorizeQuery>,
  axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
) -> Response {
  if query.client_id != idp.client_id {
    return oauth_error(
      StatusCode::BAD_REQUEST,
      "invalid_client",
      "Unknown client id",
    );
  }
  if query.code_challenge.is_some()
    && query.code_challenge_method.as_deref() != Some("S256")
  {
    return oauth_error(
      StatusCode::BAD_REQUEST,
      "invalid_request",
      "Only S256 code challenges are supported",
    );
  }

  let redirect = |params: &[(&str, &str)]| {
    let mut url = query.redirect_uri.clone();
    url.push(if url.contains('?') { '&' } else { '?' });
    let mut params = params.to_vec();
    if let Some(state) = &query.state {
      params.push(("state", state));
    }
    url.push_str(
      &params
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&"),
    );
    Redirect::to(&url).into_response()
  };

  if query.deny.is_some() {
    return redirect(&[("error", "access_denied")]);
  }

  let mut inner = idp.lock();
  let Some(sub) = query.user.clone().or(inner.auto_user.clone())
  else {
    // Let the person pick who to log in as.
    let raw_query = raw_query.unwrap_or_default();
    let mut users = inner.users.values().collect::<Vec<_>>();
    users.sort_by(|a, b| a.sub.cmp(&b.sub));
    let links = users
      .iter()
      .map(|user| {
        format!(
          r#"<li><a data-testid="idp-user-{sub}" href="/authorize?{raw_query}&user={sub}">Log in as {name} ({sub})</a></li>"#,
          sub = urlencode(&user.sub),
          name = user.preferred_username.as_deref().unwrap_or(&user.sub),
        )
      })
      .collect::<String>();
    return Html(format!(
      r#"<!DOCTYPE html><html><body><h1>Mock Identity Provider</h1><ul>{links}<li><a data-testid="idp-deny" href="/authorize?{raw_query}&deny=true">Deny</a></li></ul></body></html>"#
    ))
    .into_response();
  };

  if !inner.users.contains_key(&sub) {
    return oauth_error(
      StatusCode::BAD_REQUEST,
      "invalid_request",
      "Unknown user",
    );
  }

  let code = uuid::Uuid::new_v4().simple().to_string();
  inner.codes.insert(
    code.clone(),
    PendingCode {
      sub,
      nonce: query.nonce.clone(),
      client_id: query.client_id.clone(),
      redirect_uri: query.redirect_uri.clone(),
      code_challenge: query.code_challenge.clone(),
    },
  );
  drop(inner);

  redirect(&[("code", &code)])
}

fn urlencode(value: &str) -> String {
  value
    .bytes()
    .map(|byte| match byte {
      b'A'..=b'Z'
      | b'a'..=b'z'
      | b'0'..=b'9'
      | b'-'
      | b'_'
      | b'.'
      | b'~' => (byte as char).to_string(),
      _ => format!("%{byte:02X}"),
    })
    .collect()
}

#[derive(Deserialize)]
struct TokenForm {
  grant_type: String,
  code: Option<String>,
  redirect_uri: Option<String>,
  code_verifier: Option<String>,
  client_id: Option<String>,
  client_secret: Option<String>,
}

/// The client credentials from basic auth, else from the form.
fn client_credentials(
  headers: &HeaderMap,
  form: &TokenForm,
) -> Option<(String, String)> {
  if let Some(basic) = headers
    .get(header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.strip_prefix("Basic "))
  {
    let decoded = BASE64.decode(basic.as_bytes()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    return Some((percent_decode(id), percent_decode(secret)));
  }
  Some((form.client_id.clone()?, form.client_secret.clone()?))
}

fn percent_decode(value: &str) -> String {
  let bytes = value.as_bytes();
  let mut out = Vec::with_capacity(bytes.len());
  let mut i = 0;
  while i < bytes.len() {
    if bytes[i] == b'%'
      && let Some(hex) = value.get(i + 1..i + 3)
      && let Ok(byte) = u8::from_str_radix(hex, 16)
    {
      out.push(byte);
      i += 3;
      continue;
    }
    out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
    i += 1;
  }
  String::from_utf8_lossy(&out).to_string()
}

async fn token(
  State(idp): State<MockIdp>,
  headers: HeaderMap,
  Form(form): Form<TokenForm>,
) -> Response {
  if form.grant_type != "authorization_code" {
    return oauth_error(
      StatusCode::BAD_REQUEST,
      "unsupported_grant_type",
      "Only authorization_code is supported",
    );
  }
  match client_credentials(&headers, &form) {
    Some((id, secret))
      if id == idp.client_id && secret == idp.client_secret => {}
    _ => {
      return oauth_error(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "Invalid client credentials",
      );
    }
  }
  let mut inner = idp.lock();
  // A code only works once.
  let Some(pending) =
    form.code.as_ref().and_then(|code| inner.codes.remove(code))
  else {
    return oauth_error(
      StatusCode::BAD_REQUEST,
      "invalid_grant",
      "Unknown code",
    );
  };
  if form.redirect_uri.as_deref() != Some(&pending.redirect_uri) {
    return oauth_error(
      StatusCode::BAD_REQUEST,
      "invalid_grant",
      "The redirect uri doesn't match the authorization request",
    );
  }
  if let Some(challenge) = &pending.code_challenge {
    let verified =
      form.code_verifier.as_ref().is_some_and(|verifier| {
        &BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()))
          == challenge
      });
    if !verified {
      return oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "PKCE verification failed",
      );
    }
  }
  let Some(user) = inner.users.get(&pending.sub).cloned() else {
    return oauth_error(
      StatusCode::BAD_REQUEST,
      "invalid_grant",
      "Unknown user",
    );
  };
  let access_token = uuid::Uuid::new_v4().simple().to_string();
  inner
    .access_tokens
    .insert(access_token.clone(), user.sub.clone());
  drop(inner);

  let mut claims = user_claims(&user, true);
  if let Some(nonce) = pending.nonce {
    claims.insert("nonce".into(), json!(nonce));
  }
  let id_token = idp.mint(MintToken {
    sub: user.sub,
    aud: vec![pending.client_id],
    claims,
    ..Default::default()
  });

  (
    [(header::CACHE_CONTROL, "no-store")],
    Json(json!({
      "access_token": access_token,
      "token_type": "Bearer",
      "expires_in": 300,
      "id_token": id_token,
    })),
  )
    .into_response()
}

async fn userinfo(
  State(idp): State<MockIdp>,
  headers: HeaderMap,
) -> Response {
  let inner = idp.lock();
  let user = headers
    .get(header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| value.strip_prefix("Bearer "))
    .and_then(|token| inner.access_tokens.get(token))
    .and_then(|sub| inner.users.get(sub));
  let Some(user) = user else {
    return oauth_error(
      StatusCode::UNAUTHORIZED,
      "invalid_token",
      "Unknown access token",
    );
  };
  let mut claims = user_claims(user, false);
  claims.insert("sub".into(), json!(user.sub));
  Json(claims).into_response()
}

async fn control_upsert_user(
  State(idp): State<MockIdp>,
  Json(user): Json<IdpUser>,
) -> StatusCode {
  idp.upsert_user(user);
  StatusCode::OK
}

#[derive(Deserialize)]
struct AutoUser {
  sub: Option<String>,
}

async fn control_auto_user(
  State(idp): State<MockIdp>,
  Json(AutoUser { sub }): Json<AutoUser>,
) -> StatusCode {
  idp.set_auto_user(sub.as_deref());
  StatusCode::OK
}

async fn control_mint(
  State(idp): State<MockIdp>,
  Json(token): Json<MintToken>,
) -> Json<Value> {
  Json(json!({ "token": idp.mint(token) }))
}
