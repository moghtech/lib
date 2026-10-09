//! The limits on starting login flows: external logins per client
//! ip, so a flood of them can't push the logins of others out of the
//! session store, and the login sessions a user begins.

use example_client::auth::api::{
  login::ExchangeForJwt, manage::BeginTotpEnrollment,
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

/// A client sending login starts without keeping cookies: every
/// start it is allowed creates a session of its own.
fn flood_client() -> reqwest::Client {
  reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .unwrap()
}

/// Alice starts an OIDC login and logs in at the provider, then
/// another client on her ip sends 30 login starts (and requests other
/// sites embed) before her browser comes back to the callback.
/// Returns where her login lands, and how many of the 30 were
/// refused for the start limit.
async fn flood_during_a_login(limit: u32) -> (reqwest::Url, usize) {
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    rate_limit: Some((100, 60)),
    // A small store, which 30 sessions overflow.
    config: json!({
      "auth_login_start_limit": limit,
      "max_sessions": 8,
    }),
    ..Default::default()
  })
  .await;
  app.add_idp_user("alice", &[]);
  app.idp.set_auto_user(Some("alice-sub"));

  // Alice is at the provider.
  let alice = app.client();
  let res = alice
    .reqwest
    .get(format!("{}/auth/oidc/login", app.address))
    .send()
    .await
    .unwrap();
  let authorize = res.headers()["location"].to_str().unwrap();
  let res = alice.reqwest.get(authorize).send().await.unwrap();
  let callback =
    res.headers()["location"].to_str().unwrap().to_string();

  let flood = flood_client();
  // An image of another site: refused before it counts.
  for _ in 0..10 {
    let res = flood
      .get(format!("{}/auth/oidc/login", app.address))
      .header("sec-fetch-site", "cross-site")
      .header("sec-fetch-mode", "no-cors")
      .header("sec-fetch-dest", "image")
      .send()
      .await
      .unwrap();
    let location = res.headers()["location"].to_str().unwrap();
    let error = external_error(
      &reqwest::Url::parse(location).unwrap(),
      "login_error",
    );
    assert!(
      error.contains("not from within another site"),
      "{error}"
    );
    assert!(!sets_session_cookie(&res));
  }
  let mut refused = 0;
  for _ in 0..30 {
    let res = flood
      .get(format!("{}/auth/oidc/login", app.address))
      .send()
      .await
      .unwrap();
    let location = res.headers()["location"].to_str().unwrap();
    if location.starts_with(&app.address) {
      let error = external_error(
        &reqwest::Url::parse(location).unwrap(),
        "login_error",
      );
      assert!(error.contains("Too many logins started"), "{error}");
      assert!(!sets_session_cookie(&res));
      refused += 1;
    } else {
      // Sent to the provider, with a session of its own.
      assert!(location.starts_with(&app.idp.issuer), "{location}");
      assert!(sets_session_cookie(&res));
    }
  }

  let landed = follow_external_flow(&alice, &callback).await;
  if landed.query() == Some("redeem_ready=true") {
    alice.login(ExchangeForJwt {}).await.unwrap();
  }
  (landed, refused)
}

/// The start limit keeps the sessions a client creates few: past it
/// (Alice's start was one of the 3) its starts are refused, and her
/// login completes.
#[tokio::test]
async fn a_flood_of_login_starts_can_not_push_out_a_login() {
  let (landed, refused) = flood_during_a_login(3).await;
  assert_eq!(refused, 28);
  assert_eq!(landed.query(), Some("redeem_ready=true"), "{landed}");
}

/// What the limit is for: without it, the flood's sessions fill the
/// store, which drops the ones closest to expiry, Alice's first.
#[tokio::test]
async fn without_the_start_limit_a_flood_pushes_out_a_login() {
  let (landed, refused) = flood_during_a_login(0).await;
  assert_eq!(refused, 0);
  let error = external_error(&landed, "login_error");
  assert!(error.contains("not been initiated"), "{error}");
}

/// The management requests which begin a login session (a link, a
/// 2fa enrollment) are limited per user: 10 at once.
#[tokio::test]
async fn session_starts_are_limited_per_user() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((100, 60)),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  for _ in 0..10 {
    admin.manage(BeginTotpEnrollment {}).await.unwrap();
  }
  let res = admin.manage(BeginTotpEnrollment {}).await;
  assert_eq!(status_of(res), StatusCode::TOO_MANY_REQUESTS);
  // Other users have their own.
  let other = app.sign_up("other").await;
  other.manage(BeginTotpEnrollment {}).await.unwrap();
  // And the user's other requests aren't limited.
  get_user(&admin).await;
}
