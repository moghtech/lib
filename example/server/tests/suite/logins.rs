//! Login records: the example appends every login the auth server
//! completes to its `logins` table (`AuthImpl::record_login`). The
//! server calls the hook once per login, at the step which grants it:
//! a local sign up or login, its second factor, a provider's
//! callback (not the redeem after it), a token exchange. What is
//! refused, or only half done, records nothing.

use example_client::{
  ClientAuth,
  auth::{
    api::{
      login::{
        CompleteTotpLogin, ExchangeForJwt, JwtOrTwoFactor,
        LoginLocalUser,
      },
      manage::{
        BeginTotpEnrollment, ConfirmTotpEnrollment,
        CreateTrustedIssuer,
      },
      token::{TOKEN_TYPE_ID_TOKEN, TOKEN_TYPE_JWT},
    },
    config::{TrustedIssuerKeys, WorkloadClaim, WorkloadRule},
  },
};
use example_mock_idp::MintToken;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::common::*;

/// A row of the `logins` table.
#[derive(Debug)]
struct LoginRow {
  user_id: String,
  username: String,
  /// The JSON `LoginKind`.
  kind: Value,
  second_factor: String,
  token_expires: i64,
}

/// The logins the app recorded, in order.
async fn logins(app: &TestApp) -> Vec<LoginRow> {
  let pool = sqlx::SqlitePool::connect_with(
    sqlx::sqlite::SqliteConnectOptions::new()
      .filename(app.path("data/example.db")),
  )
  .await
  .unwrap();
  let rows: Vec<(String, String, String, String, i64)> =
    sqlx::query_as(
      "SELECT user_id, username, kind, second_factor, token_expires
       FROM logins ORDER BY created_at, rowid",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
  pool.close().await;
  rows
    .into_iter()
    .map(|(user_id, username, kind, second_factor, token_expires)| {
      LoginRow {
        user_id,
        username,
        kind: serde_json::from_str(&kind).unwrap(),
        second_factor,
        token_expires,
      }
    })
    .collect()
}

/// The kind of a login row: `Local`, `Provider` or `Workload`.
fn kind_of(row: &LoginRow) -> &str {
  match &row.kind {
    Value::String(kind) => kind,
    Value::Object(kind) => kind.keys().next().unwrap(),
    other => panic!("Not a LoginKind: {other}"),
  }
}

const AUDIENCE: &str = "https://example-app.test";

#[tokio::test]
async fn every_login_is_recorded_once() {
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    config: json!({ "oidc_token_exchange": { "enabled": true } }),
    ..Default::default()
  })
  .await;
  let now_secs = || (unix_timestamp_ms() / 1000) as i64;

  // A local sign up logs the user in.
  let admin = app.sign_up("admin").await;
  let admin_id = get_user(&admin).await.id;
  let rows = logins(&app).await;
  assert_eq!(rows.len(), 1, "{rows:?}");
  assert_eq!(kind_of(&rows[0]), "Local");
  assert_eq!(rows[0].user_id, admin_id);
  assert_eq!(rows[0].username, "admin");
  assert_eq!(rows[0].second_factor, "");
  // The session's expiry: the app's 24h ttl.
  assert!(
    (rows[0].token_expires - now_secs() - 24 * 60 * 60).abs() < 60,
    "{rows:?}"
  );

  // A local login. A wrong password records nothing.
  app.log_in("admin").await;
  let res = app
    .client()
    .login(LoginLocalUser {
      username: "admin".into(),
      password: "wrong-password".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  assert_eq!(logins(&app).await.len(), 2);

  // The workload issuer, while the sign up's login is recent.
  admin
    .manage(CreateTrustedIssuer {
      name: "Mock CI".into(),
      enabled: true,
      issuer: app.idp.issuer.clone(),
      keys: TrustedIssuerKeys::Discovery {},
      audiences: vec![AUDIENCE.into()],
      max_token_age_secs: 300,
      rules: vec![WorkloadRule {
        id: String::new(),
        name: "Deploy".into(),
        enabled: true,
        claims: vec![WorkloadClaim {
          claim: "repository_id".into(),
          pattern: "12345".into(),
        }],
        groups: Vec::new(),
        admin: false,
        token_ttl_secs: 900,
      }],
    })
    .await
    .unwrap();

  // With TOTP, the password alone is no login: the code completes
  // it. A wrong code records nothing either.
  let enrollment =
    admin.manage(BeginTotpEnrollment {}).await.unwrap();
  let totp = totp_from_uri(&enrollment.uri);
  admin
    .manage(ConfirmTotpEnrollment {
      code: totp.generate_current().to_string(),
    })
    .await
    .unwrap();
  let client = app.client();
  let res = client
    .login(LoginLocalUser {
      username: "admin".into(),
      password: PASSWORD.into(),
    })
    .await
    .unwrap();
  assert!(matches!(res, JwtOrTwoFactor::Totp {}), "{res:?}");
  let res = client
    .login(CompleteTotpLogin {
      code: "000000".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  assert_eq!(logins(&app).await.len(), 2);
  client
    .login(CompleteTotpLogin {
      // The next step's: the current one confirmed the enrollment.
      code: totp
        .generate(unix_timestamp_ms() / 1000 + 30)
        .to_string(),
    })
    .await
    .unwrap();
  let rows = logins(&app).await;
  assert_eq!(rows.len(), 3, "{rows:?}");
  assert_eq!(kind_of(&rows[2]), "Local");
  assert_eq!(rows[2].user_id, admin_id);
  assert_eq!(rows[2].second_factor, "totp");

  // A provider login is recorded at the callback, its redeem is no
  // other login.
  app.add_idp_user("alice", &["example-users"]);
  app.idp.set_auto_user(Some("alice-sub"));
  let alice = app.client();
  let landed = follow_external_flow(
    &alice,
    &format!("{}/auth/oidc/login", app.address),
  )
  .await;
  assert_eq!(landed.query(), Some("redeem_ready=true"), "{landed}");
  let rows = logins(&app).await;
  assert_eq!(rows.len(), 4, "{rows:?}");
  let jwt = alice.login(ExchangeForJwt {}).await.unwrap().jwt;
  let alice_id =
    get_user(&alice.with_auth(ClientAuth::Jwt(jwt))).await.id;
  assert_eq!(logins(&app).await.len(), 4);
  assert_eq!(kind_of(&rows[3]), "Provider");
  assert_eq!(rows[3].kind["Provider"]["provider_id"], "oidc");
  assert_eq!(rows[3].user_id, alice_id);
  assert_eq!(rows[3].username, "alice");

  // A token exchange of the provider's token. A refused one (another
  // audience) records nothing.
  let token = app.idp.mint_id_token("alice-sub", "another-client");
  let (status, _) = app
    .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);
  assert_eq!(logins(&app).await.len(), 4);
  let token = app.idp.mint_id_token("alice-sub", &app.idp.client_id);
  app
    .token_exchange(&token, TOKEN_TYPE_ID_TOKEN)
    .await
    .unwrap();
  let rows = logins(&app).await;
  assert_eq!(rows.len(), 5, "{rows:?}");
  assert_eq!(kind_of(&rows[4]), "Provider");
  assert_eq!(rows[4].user_id, alice_id);

  // A workload's token exchange, its rule's ttl the token's.
  let ci_token = |repository_id: &str| {
    app.idp.mint(MintToken {
      sub: "repo:my-org/my-repo:ref:refs/heads/main".into(),
      aud: vec![AUDIENCE.into()],
      claims: json!({ "repository_id": repository_id })
        .as_object()
        .unwrap()
        .clone(),
      ..Default::default()
    })
  };
  let (status, _) = app
    .token_exchange(&ci_token("99999"), TOKEN_TYPE_JWT)
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);
  assert_eq!(logins(&app).await.len(), 5);
  app
    .token_exchange(&ci_token("12345"), TOKEN_TYPE_JWT)
    .await
    .unwrap();
  let rows = logins(&app).await;
  assert_eq!(rows.len(), 6, "{rows:?}");
  assert_eq!(kind_of(&rows[5]), "Workload");
  assert_eq!(rows[5].kind["Workload"]["rule_name"], "Deploy");
  assert_eq!(rows[5].username, "workload-deploy");
  assert_eq!(rows[5].second_factor, "");
  assert!(
    (rows[5].token_expires - now_secs() - 900).abs() < 60,
    "{rows:?}"
  );
}
