//! External login with OIDC against the mock identity provider:
//! signup, login, groups, linking, second factor and the callback checks.

use example_client::{
  ClientAuth, ExampleClient,
  auth::api::{
    login::{CompleteTotpLogin, ExchangeForJwt, GetLoginOptions},
    manage::{
      BeginExternalLoginLink, BeginTotpEnrollment,
      ConfirmTotpEnrollment, CreateExternalLoginProvider,
      UnlinkExternalLogin, UnlinkLocalLogin, UpdateExternalSkip2fa,
    },
  },
  auth::config::{
    ExternalLoginKind, ExternalLoginProviderConfig, OidcConfig,
  },
};
use example_mock_idp::IdpUser;
use reqwest::StatusCode;
use serde_json::json;

use crate::{common::*, reauth::assert_reauthentication_required};

fn oidc_app_options(oidc: serde_json::Value) -> TestAppOptions {
  TestAppOptions {
    static_oidc: true,
    config: json!({ "oidc": oidc }),
    ..Default::default()
  }
}

/// Goes through the browser redirects of an OIDC login as `idp_user`.
/// Returns the client holding the session, and the url it landed on.
async fn browser_login(
  app: &TestApp,
  idp_user: &str,
) -> (ExampleClient, reqwest::Url) {
  app.idp.set_auto_user(Some(&format!("{idp_user}-sub")));
  let client = app.client();
  let landed = follow_external_flow(
    &client,
    &format!("{}/auth/oidc/login", app.address),
  )
  .await;
  (client, landed)
}

/// A full OIDC login, up to the app token.
async fn oidc_login(app: &TestApp, idp_user: &str) -> ExampleClient {
  let (client, landed) = browser_login(app, idp_user).await;
  assert_eq!(landed.query(), Some("redeem_ready=true"), "{landed}");
  let jwt = client.login(ExchangeForJwt {}).await.unwrap().jwt;
  client.with_auth(ClientAuth::Jwt(jwt))
}

/// A login which is expected to fail: the browser is sent back
/// to the login page of the app, with the reason.
async fn failed_browser_login(
  app: &TestApp,
  idp_user: &str,
) -> String {
  let (_, landed) = browser_login(app, idp_user).await;
  assert_eq!(landed.path(), "/login", "{landed}");
  external_error(&landed, "login_error")
}

#[tokio::test]
async fn sign_up_and_log_in_with_oidc() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);

  let options = app.client().login(GetLoginOptions {}).await.unwrap();
  assert_eq!(options.providers.len(), 1);
  assert_eq!(options.providers[0].id, "oidc");
  assert_eq!(options.providers[0].kind, ExternalLoginKind::Oidc);

  let alice = oidc_login(&app, "alice").await;
  let user = get_user(&alice).await;
  assert_eq!(user.username, "alice");
  // The first user is the admin.
  assert!(user.admin && user.enabled && !user.has_password);
  assert_eq!(user.linked_logins.len(), 1);
  assert_eq!(user.linked_logins[0].provider_id, "oidc");
  assert_eq!(user.linked_logins[0].external_id, "alice-sub");

  // Logging in again finds the same user.
  let again = oidc_login(&app, "alice").await;
  assert_eq!(get_user(&again).await.id, user.id);

  // The exchange only works once per login.
  let res = again.login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  // And never without one.
  let res = app.client().login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

/// The token redeemed for an external login counts as a login from
/// the provider's callback, not from the redeem: a login left on the
/// session (eg. by whoever got into the user's identity provider
/// account) is not a fresh one when it is redeemed later. It can't
/// be kept for long either: past `Session::MAX_COMPLETED_LOGIN_AGE`
/// (2 minutes, the session unit tests cover it) it is refused.
#[tokio::test]
async fn a_late_redeem_is_not_a_recent_login() {
  const WINDOW_SECS: u64 = 2;
  let app = TestApp::spawn_with(TestAppOptions {
    env: vec![(
      "EXAMPLE_REAUTHENTICATION_WINDOW_SECONDS".into(),
      WINDOW_SECS.to_string(),
    )],
    ..oidc_app_options(json!({}))
  })
  .await;
  app.add_idp_user("alice", &[]);

  // Redeemed right away, as the app does: a recent login.
  let alice = oidc_login(&app, "alice").await;
  alice.manage(BeginTotpEnrollment {}).await.unwrap();

  let (client, landed) = browser_login(&app, "alice").await;
  assert_eq!(landed.query(), Some("redeem_ready=true"), "{landed}");
  tokio::time::sleep(std::time::Duration::from_secs(WINDOW_SECS + 2))
    .await;
  let jwt = client.login(ExchangeForJwt {}).await.unwrap().jwt;
  let late = client.with_auth(ClientAuth::Jwt(jwt));
  assert_reauthentication_required(
    late.manage(BeginTotpEnrollment {}).await,
    "BeginTotpEnrollment",
  );
  // The token is good for everything else.
  assert_eq!(get_user(&late).await.username, "alice");
}

#[tokio::test]
async fn taken_usernames_get_a_suffix() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.sign_up("alice").await;
  app.add_idp_user("alice", &[]);
  let alice = oidc_login(&app, "alice").await;
  let user = get_user(&alice).await;
  assert!(user.username.starts_with("alice-"), "{}", user.username);
  assert!(!user.admin);
}

/// External sign ups are held to the app's username rule.
#[tokio::test]
async fn usernames_follow_the_username_rule() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.idp.upsert_user(IdpUser {
    sub: "alice-sub".into(),
    preferred_username: Some("Alice Smith".into()),
    ..Default::default()
  });
  let alice = oidc_login(&app, "alice").await;
  assert_eq!(get_user(&alice).await.username, "Alice-Smith");
}

#[tokio::test]
async fn redirects_back_to_the_app_only() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  app.idp.set_auto_user(Some("alice-sub"));

  for (redirect, expected) in [
    (
      format!("{}/notes?tab=1", app.address),
      format!("{}/notes?tab=1&redeem_ready=true", app.address),
    ),
    (
      "/notes".to_string(),
      format!("{}/notes?redeem_ready=true", app.address),
    ),
    // Open redirects fall back to the app.
    (
      "https://evil.example/steal".to_string(),
      format!("{}?redeem_ready=true", app.address),
    ),
    (
      "//evil.example".to_string(),
      format!("{}?redeem_ready=true", app.address),
    ),
    // The app reads the query, which goes before the fragment.
    (
      "/notes#tab".to_string(),
      format!("{}/notes?redeem_ready=true#tab", app.address),
    ),
    // Stored on the session by an unauthenticated request:
    // one which is too long is dropped.
    (
      format!("/{}", "a".repeat(10 * 1024)),
      format!("{}?redeem_ready=true", app.address),
    ),
  ] {
    let client = app.client();
    let landed = follow_external_flow(
      &client,
      &format!(
        "{}/auth/oidc/login?redirect={}",
        app.address,
        urlencode(&redirect)
      ),
    )
    .await;
    assert_eq!(
      landed,
      reqwest::Url::parse(&expected).unwrap(),
      "{redirect}"
    );
  }
}

fn urlencode(value: &str) -> String {
  reqwest::Url::parse_with_params("http://x", [("v", value)])
    .unwrap()
    .query()
    .unwrap()
    .trim_start_matches("v=")
    .to_string()
}

#[tokio::test]
async fn registration_can_be_disabled() {
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    config: json!({ "disable_user_registration": true }),
    ..Default::default()
  })
  .await;
  app.add_idp_user("alice", &[]);
  app.add_idp_user("bob", &[]);
  // The first user can always sign up.
  oidc_login(&app, "alice").await;

  let error = failed_browser_login(&app, "bob").await;
  assert!(error.contains("registration is disabled"), "{error}");
  // Existing users still log in.
  oidc_login(&app, "alice").await;
}

#[tokio::test]
async fn groups_are_synced_on_every_login() {
  let app = TestApp::spawn_with(oidc_app_options(json!({
    "groups_claim": "groups",
    "admin_groups": ["example-admins"],
  })))
  .await;
  app.sign_up("local-admin").await;
  app.add_idp_user("alice", &["example-users", "example-admins"]);

  let alice = oidc_login(&app, "alice").await;
  let user = get_user(&alice).await;
  assert_eq!(user.groups, ["example-admins", "example-users"]);
  assert!(user.admin, "Members of an admin group are admins");

  // Removed from the admins at the provider.
  app.add_idp_user("alice", &["example-users"]);
  let alice = oidc_login(&app, "alice").await;
  let user = get_user(&alice).await;
  assert_eq!(user.groups, ["example-users"]);
  assert!(!user.admin);
}

#[tokio::test]
async fn groups_can_come_from_the_user_info() {
  let app = TestApp::spawn_with(oidc_app_options(json!({
    "groups_claim": "groups",
  })))
  .await;
  app.idp.upsert_user(IdpUser {
    sub: "alice-sub".into(),
    preferred_username: Some("alice".into()),
    groups: Some(vec!["from-user-info".into()]),
    groups_in_user_info_only: true,
    ..Default::default()
  });
  let alice = oidc_login(&app, "alice").await;
  assert_eq!(get_user(&alice).await.groups, ["from-user-info"]);
}

#[tokio::test]
async fn allowed_groups_gate_the_login() {
  let app = TestApp::spawn_with(oidc_app_options(json!({
    "allowed_groups": ["example-users"],
  })))
  .await;
  app.add_idp_user("alice", &["example-users"]);
  app.add_idp_user("mallory", &["other"]);
  app.idp.upsert_user(IdpUser {
    sub: "nogroups-sub".into(),
    preferred_username: Some("nogroups".into()),
    ..Default::default()
  });

  oidc_login(&app, "alice").await;
  for user in ["mallory", "nogroups"] {
    let error = failed_browser_login(&app, user).await;
    assert!(
      error.to_lowercase().contains("group"),
      "{user}: {error}"
    );
  }
  // Nobody was signed up by the refused logins.
  let users = alice_users(&app).await;
  assert_eq!(users, ["alice"]);

  // Losing the group locks an existing user out as well.
  app.add_idp_user("alice", &["other"]);
  let error = failed_browser_login(&app, "alice").await;
  assert!(error.to_lowercase().contains("group"), "{error}");
}

async fn alice_users(app: &TestApp) -> Vec<String> {
  app.add_idp_user("alice", &["example-users"]);
  let alice = oidc_login(app, "alice").await;
  alice
    .read(example_client::api::read::ListUsers {})
    .await
    .unwrap()
    .into_iter()
    .map(|user| user.username)
    .collect()
}

#[tokio::test]
async fn link_and_unlink_a_login() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  app.add_idp_user("bob", &[]);
  let admin = app.sign_up("admin").await;
  let admin_id = get_user(&admin).await.id;

  // Linking needs the signed in user to begin it on the session.
  // Without that the request is no link: it fails to the login page.
  let link_url = format!("{}/auth/external/oidc/link", app.address);
  let landed = follow_external_flow(&admin, &link_url).await;
  assert_eq!(landed.path(), "/login");
  let error = external_error(&landed, "login_error");
  assert!(error.contains("not been initiated"), "{error}");

  app.idp.set_auto_user(Some("alice-sub"));
  admin
    .manage(BeginExternalLoginLink {
      slug: "oidc".into(),
    })
    .await
    .unwrap();
  let landed = follow_external_flow(&admin, &link_url).await;
  assert_eq!(landed.path(), "/profile");
  let user = get_user(&admin).await;
  assert_eq!(user.linked_logins.len(), 1);
  assert_eq!(user.linked_logins[0].external_id, "alice-sub");

  // Now alice logs in as the existing user.
  let alice = oidc_login(&app, "alice").await;
  assert_eq!(get_user(&alice).await.id, admin_id);

  // The same login can't be linked to somebody else.
  let other = app.sign_up("other").await;
  other
    .manage(BeginExternalLoginLink {
      slug: "oidc".into(),
    })
    .await
    .unwrap();
  // Back where logins are linked, with the reason.
  let landed = follow_external_flow(&other, &link_url).await;
  assert_eq!(landed.path(), "/profile");
  let error = external_error(&landed, "link_error");
  assert!(error.contains("already linked"), "{error}");
  assert!(get_user(&other).await.linked_logins.is_empty());

  // With a password and a linked login, either can be removed.
  admin
    .manage(UnlinkExternalLogin {
      provider_id: "oidc".into(),
    })
    .await
    .unwrap();
  assert!(get_user(&admin).await.linked_logins.is_empty());
  // Alice is a new user now.
  let alice = oidc_login(&app, "alice").await;
  assert_ne!(get_user(&alice).await.id, admin_id);

  // Provider ids are checked before they reach storage.
  let res = admin
    .manage(UnlinkExternalLogin {
      provider_id: "../etc".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);

  // The last way to log in can't be removed: the admin's password,
  // alice's only linked login (she has no password).
  let res = admin.manage(UnlinkLocalLogin {}).await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
  assert!(get_user(&admin).await.has_password);
  let res = alice
    .manage(UnlinkExternalLogin {
      provider_id: "oidc".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
  assert_eq!(get_user(&alice).await.linked_logins.len(), 1);
}

#[tokio::test]
async fn external_login_can_require_the_second_factor() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  let alice = oidc_login(&app, "alice").await;

  let enrollment =
    alice.manage(BeginTotpEnrollment {}).await.unwrap();
  let totp = totp_from_uri(&enrollment.uri);
  alice
    .manage(ConfirmTotpEnrollment {
      code: totp.generate_current().to_string(),
    })
    .await
    .unwrap();

  // The provider is trusted with the second factor by default in this app.
  assert!(!get_user(&alice).await.external_skip_2fa);
  let (client, landed) = browser_login(&app, "alice").await;
  assert_eq!(landed.query(), Some("totp=true"));
  // The session isn't authenticated yet.
  let res = client.login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  let jwt = client
    .login(CompleteTotpLogin {
      code: totp
        .generate(unix_timestamp_ms() / 1000 + 30)
        .to_string(),
    })
    .await
    .unwrap()
    .jwt;
  get_user(&client.with_auth(ClientAuth::Jwt(jwt))).await;

  alice
    .manage(UpdateExternalSkip2fa {
      external_skip_2fa: true,
    })
    .await
    .unwrap();
  oidc_login(&app, "alice").await;
}

#[tokio::test]
async fn callback_is_bound_to_the_session_which_started_the_login() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  app.idp.set_auto_user(Some("alice-sub"));

  // The victim starts a login, the attacker gets hold of the callback url.
  let victim = app.client();
  let res = victim
    .reqwest
    .get(format!("{}/auth/oidc/login", app.address))
    .send()
    .await
    .unwrap();
  let authorize_url = res.headers()["location"].to_str().unwrap();
  let res = victim.reqwest.get(authorize_url).send().await.unwrap();
  let callback_url =
    res.headers()["location"].to_str().unwrap().to_string();
  assert!(callback_url.contains("/auth/oidc/callback"));

  // Another session can't complete it.
  let attacker = app.client();
  let landed = follow_external_flow(&attacker, &callback_url).await;
  let error = external_error(&landed, "login_error");
  assert!(error.contains("not been initiated"), "{error}");
  // The attacker's session didn't get authenticated by it.
  let res = attacker.login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);

  // Neither can a callback with another state (CSRF).
  let mut forged = reqwest::Url::parse(&callback_url).unwrap();
  let pairs = forged
    .query_pairs()
    .map(|(key, value)| {
      let value = if key == "state" {
        "forged".to_string()
      } else {
        value.to_string()
      };
      (key.to_string(), value)
    })
    .collect::<Vec<_>>();
  forged.query_pairs_mut().clear().extend_pairs(pairs);
  let landed = follow_external_flow(&victim, forged.as_str()).await;
  let error = external_error(&landed, "login_error");
  assert!(error.contains("State mismatch"), "{error}");

  // The failed attempt used up the login, it has to be started again.
  let landed = follow_external_flow(&victim, &callback_url).await;
  external_error(&landed, "login_error");
  let res = victim.login(ExchangeForJwt {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  // Nobody got signed up along the way.
  assert!(
    app
      .sign_up("first")
      .await
      .read(example_client::api::read::ListUsers {})
      .await
      .unwrap()
      .len()
      == 1
  );
}

/// Starts a login (or link) at `url` up to the provider's page, and
/// returns the state the provider answers it with.
async fn state_at_provider(
  client: &ExampleClient,
  url: &str,
) -> String {
  let res = client.reqwest.get(url).send().await.unwrap();
  let authorize =
    reqwest::Url::parse(res.headers()["location"].to_str().unwrap())
      .unwrap();
  authorize
    .query_pairs()
    .find(|(key, _)| key == "state")
    .map(|(_, state)| state.to_string())
    .expect("No state on the authorize url")
}

#[tokio::test]
async fn denied_login_and_unknown_providers() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  let client = app.client();
  let login_url = format!("{}/auth/oidc/login", app.address);

  // The user denies the login at the provider, which answers with
  // the error and the state of the login.
  let state = state_at_provider(&client, &login_url).await;
  let landed = follow_external_flow(
    &client,
    &format!(
      "{}/auth/oidc/callback?error=access_denied&state={state}",
      app.address
    ),
  )
  .await;
  assert_eq!(landed.path(), "/login");
  let error = external_error(&landed, "login_error");
  assert_eq!(error, "Login was denied at the provider");

  // Anybody can send the browser to the callback with an error of
  // their choosing, shown as the server's reason. Without the state
  // of the login it is no answer of the provider.
  state_at_provider(&client, &login_url).await;
  let landed = follow_external_flow(
    &client,
    &format!(
      "{}/auth/oidc/callback?error=Your%20account%20is%20locked&state=forged",
      app.address
    ),
  )
  .await;
  let error = external_error(&landed, "login_error");
  assert!(error.contains("State mismatch"), "{error}");
  assert!(!error.contains("locked"), "{error}");
  // Whatever the provider's error says, the user is told only
  // that the login didn't complete.
  let state = state_at_provider(&client, &login_url).await;
  let landed = follow_external_flow(
    &client,
    &format!(
      "{}/auth/oidc/callback?error=Your%20account%20is%20locked&state={state}",
      app.address
    ),
  )
  .await;
  let error = external_error(&landed, "login_error");
  assert_eq!(error, "Login was not completed at the provider");

  for path in [
    "/auth/external/unknown/login",
    "/auth/github/login",
    "/auth/google/login",
  ] {
    let landed = follow_external_flow(
      &client,
      &format!("{}{path}", app.address),
    )
    .await;
    assert_eq!(landed.path(), "/login", "{path}");
    external_error(&landed, "login_error");
  }
}

#[tokio::test]
async fn failures_are_json_errors_without_the_redirect() {
  // What apps get which don't configure a page to send failures to.
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    config: json!({
      "login_error_redirect": false,
      "disable_user_registration": true,
    }),
    ..Default::default()
  })
  .await;
  app.add_idp_user("alice", &[]);
  app.add_idp_user("bob", &[]);
  oidc_login(&app, "alice").await;

  app.idp.set_auto_user(Some("bob-sub"));
  let client = app.client();
  let mut url = format!("{}/auth/oidc/login", app.address);
  let res = loop {
    let res = client.reqwest.get(&url).send().await.unwrap();
    if !res.status().is_redirection() {
      break res;
    }
    url = res.headers()["location"].to_str().unwrap().to_string();
  };
  assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
  let body: serde_json::Value = res.json().await.unwrap();
  assert!(
    body["error"]
      .as_str()
      .unwrap()
      .contains("registration is disabled"),
    "{body}"
  );

  let res = client
    .reqwest
    .get(format!("{}/auth/external/unknown/login", app.address))
    .send()
    .await
    .unwrap();
  assert!(res.status().is_client_error(), "{}", res.status());
}

#[tokio::test]
async fn unreachable_provider_fails_without_taking_the_app_down() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({
      "oidc": {
        "enabled": true,
        // Nothing listens here.
        "provider": "http://127.0.0.1:9",
        "client_id": "id",
        "client_secret": "secret",
      }
    }),
    ..Default::default()
  })
  .await;
  let landed = follow_external_flow(
    &app.client(),
    &format!("{}/auth/oidc/login", app.address),
  )
  .await;
  // Server errors are only reported as such, the reason is in the log.
  let error = external_error(&landed, "login_error");
  assert!(error.contains("Login failed"), "{error}");
  assert!(!landed.as_str().contains("127.0.0.1%3A9"), "{landed}");
  assert!(app.logs().contains("127.0.0.1:9"));
  // Local login is unaffected.
  app.sign_up("admin").await;
}

/// The link begun on the session is used up by the first link
/// request, even a failed one: it can't be completed later.
#[tokio::test]
async fn a_failed_link_uses_up_the_begun_link() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  app.idp.set_auto_user(Some("alice-sub"));
  let admin = app.sign_up("admin").await;

  admin
    .manage(BeginExternalLoginLink {
      slug: "oidc".into(),
    })
    .await
    .unwrap();
  let landed = follow_external_flow(
    &admin,
    &format!("{}/auth/external/unknown/link", app.address),
  )
  .await;
  assert_eq!(landed.path(), "/profile");
  external_error(&landed, "link_error");

  let landed = follow_external_flow(
    &admin,
    &format!("{}/auth/external/oidc/link", app.address),
  )
  .await;
  let error = external_error(&landed, "login_error");
  assert!(error.contains("not been initiated"), "{error}");
  assert!(get_user(&admin).await.linked_logins.is_empty());
}

/// A link is begun for the provider the user chose: `/link` of
/// another provider refuses it, and uses it up. A page the user visits
/// in the meantime can't start it at a provider of its choosing (where
/// the browser may be logged in as somebody else).
#[tokio::test]
async fn a_link_is_bound_to_the_provider_it_was_begun_for() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  app.idp.set_auto_user(Some("alice-sub"));
  let admin = app.sign_up("admin").await;
  // The same identity provider, a second time.
  admin
    .manage(CreateExternalLoginProvider {
      slug: "second".into(),
      name: "Second".into(),
      registration_disabled: false,
      token_exchange: Default::default(),
      config: ExternalLoginProviderConfig::Oidc(OidcConfig {
        enabled: true,
        provider: app.idp.issuer.clone(),
        client_id: app.idp.client_id.clone(),
        client_secret: app.idp.client_secret.clone(),
        ..Default::default()
      }),
    })
    .await
    .unwrap();
  let link_url =
    |slug: &str| format!("{}/auth/external/{slug}/link", app.address);

  // Begun for `oidc`, started at `second`.
  admin
    .manage(BeginExternalLoginLink {
      slug: "oidc".into(),
    })
    .await
    .unwrap();
  let landed =
    follow_external_flow(&admin, &link_url("second")).await;
  assert_eq!(landed.path(), "/profile", "{landed}");
  let error = external_error(&landed, "link_error");
  assert!(error.contains("another login provider"), "{error}");
  // Used up: not even `oidc` takes it anymore.
  let landed = follow_external_flow(&admin, &link_url("oidc")).await;
  let error = external_error(&landed, "login_error");
  assert!(error.contains("not been initiated"), "{error}");
  assert!(get_user(&admin).await.linked_logins.is_empty());

  // Begun for `second`, it links there.
  admin
    .manage(BeginExternalLoginLink {
      slug: "second".into(),
    })
    .await
    .unwrap();
  let landed =
    follow_external_flow(&admin, &link_url("second")).await;
  assert_eq!(landed.path(), "/profile", "{landed}");
  let user = get_user(&admin).await;
  assert_eq!(user.linked_logins.len(), 1);
  assert_eq!(user.linked_logins[0].external_id, "alice-sub");

  // There is no link to begin for a provider which doesn't exist.
  let res = admin
    .manage(BeginExternalLoginLink {
      slug: "unknown".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::NOT_FOUND);
}

/// Beginning a link gives the session a new id, like the first
/// factor of a login: a session planted in the browser beforehand
/// (session fixation) can't start the link, and link the login its
/// holder completes at the provider to the user.
#[tokio::test]
async fn beginning_a_link_gets_a_new_session_id() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  app.add_idp_user("alice", &[]);
  let admin = app.sign_up("admin").await;

  // Without a cookie store: the cookies are set by hand.
  let reqwest = reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .unwrap();
  let get = |url: String, cookie: Option<String>| {
    let request = reqwest.get(url);
    match cookie {
      Some(cookie) => request.header("cookie", cookie),
      None => request,
    }
    .send()
  };
  let location = |res: &reqwest::Response| {
    res.headers()["location"].to_str().unwrap().to_string()
  };

  // A live session of the attacker.
  let res = get(format!("{}/auth/oidc/login", app.address), None)
    .await
    .unwrap();
  assert!(res.status().is_redirection());
  let planted = session_cookie(&res);

  // The victim's browser was made to carry it (eg. by a sibling
  // subdomain), and they begin a link.
  let path = "/auth/manage/BeginExternalLoginLink";
  let res = admin
    .authenticate(
      reqwest
        .post(format!("{}{path}", app.address))
        .header("cookie", &planted)
        .json(&json!({ "slug": "oidc" })),
    )
    .unwrap()
    .send()
    .await
    .unwrap();
  assert!(res.status().is_success(), "{}", res.status());
  let cycled = session_cookie(&res);
  assert_ne!(cycled, planted);

  // The planted session holds no link of the victim.
  let link_url = format!("{}/auth/oidc/link", app.address);
  let res = get(link_url.clone(), Some(planted)).await.unwrap();
  let landed = reqwest::Url::parse(&location(&res)).unwrap();
  assert_eq!(landed.path(), "/login", "{landed}");
  let error = external_error(&landed, "login_error");
  assert!(error.contains("not been initiated"), "{error}");

  // The victim's own cookie starts and completes it.
  app.idp.set_auto_user(Some("alice-sub"));
  let res = get(link_url, Some(cycled.clone())).await.unwrap();
  let authorize = location(&res);
  assert!(authorize.starts_with(&app.idp.issuer), "{authorize}");
  let res = get(authorize, None).await.unwrap();
  let callback = location(&res);
  let res = get(callback, Some(cycled)).await.unwrap();
  assert_eq!(location(&res), format!("{}/profile", app.address));
  let user = get_user(&admin).await;
  assert_eq!(user.linked_logins.len(), 1);
  assert_eq!(user.linked_logins[0].external_id, "alice-sub");
}
/// A link denied at the provider goes back to where links are
/// managed, and uses up the attempt.
#[tokio::test]
async fn denied_link_goes_back_to_the_link_page() {
  let app = TestApp::spawn_with(oidc_app_options(json!({}))).await;
  let admin = app.sign_up("admin").await;
  admin
    .manage(BeginExternalLoginLink {
      slug: "oidc".into(),
    })
    .await
    .unwrap();
  // Up to the provider's login page.
  let state = state_at_provider(
    &admin,
    &format!("{}/auth/oidc/link", app.address),
  )
  .await;

  let callback = format!(
    "{}/auth/oidc/callback?error=access_denied&state={state}",
    app.address
  );
  let landed = follow_external_flow(&admin, &callback).await;
  assert_eq!(landed.path(), "/profile");
  let error = external_error(&landed, "link_error");
  assert_eq!(error, "Login was denied at the provider");

  let landed = follow_external_flow(&admin, &callback).await;
  assert_eq!(landed.path(), "/login");
  let error = external_error(&landed, "login_error");
  assert!(error.contains("not been initiated"), "{error}");
}

/// The external routes are plain GETs, which any web page the user
/// visits can send from their browser. Requests which name an unknown
/// provider, or a flow never started on the session, are refused
/// without counting against the ip: they can't lock it out. Nor can
/// the token exchange, a form any page can make a browser post: a
/// browser's request from another site is refused before it counts.
#[tokio::test]
async fn cross_site_requests_do_not_lock_out_the_ip() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((2, 60)),
    ..oidc_app_options(json!({}))
  })
  .await;
  let admin = app.sign_up("admin").await;
  let client = app.client();
  for _ in 0..3 {
    for path in [
      "/auth/external/unknown/login",
      "/auth/github/login",
      "/auth/external/unknown/link",
      "/auth/oidc/link",
      "/auth/oidc/callback?state=x&code=y",
      "/auth/oidc/callback?error=access_denied",
      "/auth/external/unknown/callback?state=x&code=y",
    ] {
      let landed = follow_external_flow(
        &client,
        &format!("{}{path}", app.address),
      )
      .await;
      let error = external_error(&landed, "login_error");
      assert!(!error.contains("Too many"), "{path}: {error}");
    }
    // What an auto-submitted form of another site sends: a browser
    // with fetch metadata, and one with only the `Origin`.
    for (header, value) in [
      ("sec-fetch-site", "cross-site"),
      ("origin", "https://evil.example"),
    ] {
      let res = client
        .reqwest
        .post(format!("{}/auth/token", app.address))
        .header(header, value)
        .form(&[
          (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
          ),
          ("subject_token", "a.b.c"),
          (
            "subject_token_type",
            "urn:ietf:params:oauth:token-type:id_token",
          ),
        ])
        .send()
        .await
        .unwrap();
      assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{header}");
      let body: serde_json::Value = res.json().await.unwrap();
      assert_eq!(body["error"], "invalid_request", "{body}");
      let description = body["error_description"].as_str().unwrap();
      assert!(!description.contains("attempts"), "{description}");
    }
  }
  // Credentials from the same ip are still accepted.
  get_user(&admin).await;
  app.log_in("admin").await;
  app.add_idp_user("alice", &[]);
  oidc_login(&app, "alice").await;
}
