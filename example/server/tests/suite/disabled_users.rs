//! Disabled users are refused the auth management api (all but
//! `GetUserId`), whatever credential they use, so disabling an admin
//! takes away their control of the login providers and trusted issuers.
//! Nor can they complete a link of a login they began before.

use example_client::{
  ClientAuth, ExampleClient,
  api::write::UpdateUserAccess,
  auth::{
    api::manage::{
      BeginExternalLoginLink, CreateApiKey,
      CreateExternalLoginProvider, CreateTrustedIssuer, GetUserId,
      ListTrustedIssuers,
    },
    config::{
      ExternalLoginProviderConfig, OidcConfig, TrustedIssuer,
      TrustedIssuerKeys, WorkloadClaim, WorkloadRule,
    },
  },
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

/// A trusted issuer whose tokens are exchanged for an admin.
fn admin_issuer(app: &TestApp) -> CreateTrustedIssuer {
  CreateTrustedIssuer {
    issuer: TrustedIssuer {
      id: String::new(),
      name: "Admin CI".into(),
      enabled: true,
      issuer: app.idp.issuer.clone(),
      keys: TrustedIssuerKeys::Discovery {},
      audiences: vec!["https://example-app.test".into()],
      max_token_age_secs: 300,
      rules: vec![WorkloadRule {
        id: String::new(),
        name: "Admin".into(),
        enabled: true,
        claims: vec![WorkloadClaim {
          claim: "repository_id".into(),
          pattern: "12345".into(),
        }],
        groups: Vec::new(),
        admin: true,
        token_ttl_secs: 900,
      }],
    },
  }
}

fn oidc_provider(app: &TestApp) -> CreateExternalLoginProvider {
  CreateExternalLoginProvider {
    slug: String::new(),
    name: "Mine".into(),
    registration_disabled: false,
    token_exchange: Default::default(),
    config: ExternalLoginProviderConfig::Oidc(OidcConfig {
      enabled: true,
      provider: app.idp.issuer.clone(),
      client_id: app.idp.client_id.clone(),
      client_secret: app.idp.client_secret.clone(),
      ..Default::default()
    }),
  }
}

async fn set_access(
  admin: &ExampleClient,
  user_id: &str,
  enabled: bool,
  is_admin: bool,
) {
  admin
    .write(UpdateUserAccess {
      user_id: user_id.into(),
      enabled: Some(enabled),
      admin: Some(is_admin),
      groups: None,
    })
    .await
    .unwrap();
}

/// `POST /auth/manage/{variant}`, the type in the path.
async fn manage_variant(
  client: &ExampleClient,
  variant: &str,
  params: serde_json::Value,
) -> StatusCode {
  let path = format!("/auth/manage/{variant}");
  client
    .authenticate(
      client
        .reqwest
        .post(format!("{}{path}", client.address))
        .json(&params),
    )
    .unwrap()
    .send()
    .await
    .unwrap()
    .status()
}

#[tokio::test]
async fn disabled_admin_is_refused_the_management_api() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let other = app.sign_up("other").await;
  let other_id = get_user(&other).await.id;
  set_access(&admin, &other_id, true, true).await;

  // An api key made while enabled.
  let key = other
    .manage(CreateApiKey {
      name: "terraform".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
    })
    .await
    .unwrap();

  set_access(&admin, &other_id, false, true).await;

  // Logging in again, or the api key made before.
  let relogged = app.log_in("other").await;
  let api = relogged.with_auth(ClientAuth::ApiKey {
    key: key.key,
    secret: key.secret,
  });
  for (name, client) in [("jwt", &relogged), ("api key", &api)] {
    // They can still find out who they are.
    assert_eq!(
      client.manage(GetUserId {}).await.unwrap().id,
      other_id
    );
    assert_eq!(
      manage_variant(client, "GetUserId", json!({})).await,
      StatusCode::OK,
      "{name}"
    );

    let res = client.manage(admin_issuer(&app)).await;
    assert_eq!(status_of(res), StatusCode::FORBIDDEN, "{name}");
    let res = client.manage(oidc_provider(&app)).await;
    assert_eq!(status_of(res), StatusCode::FORBIDDEN, "{name}");
    let res = client
      .manage(CreateApiKey {
        name: "another".into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
      })
      .await;
    assert_eq!(status_of(res), StatusCode::FORBIDDEN, "{name}");
    assert_eq!(
      manage_variant(
        client,
        "CreateTrustedIssuer",
        serde_json::to_value(admin_issuer(&app)).unwrap(),
      )
      .await,
      StatusCode::FORBIDDEN,
      "{name}"
    );
  }
  assert!(
    admin
      .manage(ListTrustedIssuers {})
      .await
      .unwrap()
      .is_empty()
  );

  // Enabled again, they can.
  set_access(&admin, &other_id, true, true).await;
  let relogged = app.log_in("other").await;
  relogged.manage(admin_issuer(&app)).await.unwrap();
  assert_eq!(
    admin.manage(ListTrustedIssuers {}).await.unwrap().len(),
    1
  );
}

#[tokio::test]
async fn users_waiting_to_be_enabled_can_only_get_their_id() {
  let app = TestApp::spawn_with(TestAppOptions {
    env: vec![("EXAMPLE_ENABLE_NEW_USERS".into(), "false".into())],
    ..Default::default()
  })
  .await;
  app.sign_up("admin").await;
  let pending = app.sign_up("pending").await;
  // Disabled, the app api refuses them.
  let res = pending.read(example_client::api::read::GetUser {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);

  pending.manage(GetUserId {}).await.unwrap();
  let res = pending
    .manage(CreateApiKey {
      name: "mine".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  assert_eq!(
    manage_variant(&pending, "BeginTotpEnrollment", json!({})).await,
    StatusCode::FORBIDDEN
  );
}

/// A user disabled while linking a login can't complete the link,
/// whether they were disabled before the link was started at
/// `/link`, or before the provider's callback came back.
#[tokio::test]
async fn disabled_users_can_not_complete_a_link() {
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    ..Default::default()
  })
  .await;
  app.add_idp_user("alice", &[]);
  app.idp.set_auto_user(Some("alice-sub"));
  let admin = app.sign_up("admin").await;
  let bob = app.sign_up("bob").await;
  let bob_id = get_user(&bob).await.id;
  let link_url = format!("{}/auth/oidc/link", app.address);

  // Disabled before the link is started.
  bob
    .manage(BeginExternalLoginLink {
      slug: "oidc".into(),
    })
    .await
    .unwrap();
  set_access(&admin, &bob_id, false, false).await;
  let landed = follow_external_flow(&bob, &link_url).await;
  assert_eq!(landed.path(), "/profile", "{landed}");
  let error = external_error(&landed, "link_error");
  assert!(error.contains("not enabled"), "{error}");

  // Disabled while at the provider.
  set_access(&admin, &bob_id, true, false).await;
  bob
    .manage(BeginExternalLoginLink {
      slug: "oidc".into(),
    })
    .await
    .unwrap();
  let location = |res: reqwest::Response| {
    res.headers()["location"].to_str().unwrap().to_string()
  };
  let authorize =
    location(bob.reqwest.get(&link_url).send().await.unwrap());
  assert!(authorize.starts_with(&app.idp.issuer), "{authorize}");
  let callback =
    location(bob.reqwest.get(&authorize).send().await.unwrap());
  set_access(&admin, &bob_id, false, false).await;
  let landed = follow_external_flow(&bob, &callback).await;
  assert_eq!(landed.path(), "/profile", "{landed}");
  let error = external_error(&landed, "link_error");
  assert!(error.contains("not enabled"), "{error}");

  // Nothing was linked: enabled again, bob has no linked login, and
  // the login at the provider is somebody else.
  set_access(&admin, &bob_id, true, false).await;
  assert!(get_user(&bob).await.linked_logins.is_empty());
  let (alice, landed) = {
    let client = app.client();
    let landed = follow_external_flow(
      &client,
      &format!("{}/auth/oidc/login", app.address),
    )
    .await;
    (client, landed)
  };
  assert_eq!(landed.query(), Some("redeem_ready=true"), "{landed}");
  let jwt = alice
    .login(example_client::auth::api::login::ExchangeForJwt {})
    .await
    .unwrap()
    .jwt;
  let alice = alice.with_auth(ClientAuth::Jwt(jwt));
  assert_ne!(get_user(&alice).await.id, bob_id);
}
