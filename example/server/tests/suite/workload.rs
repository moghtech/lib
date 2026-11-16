//! Workload identity: machines exchange the token their platform
//! issues them for a short lived app token at `POST /auth/token`.

use example_client::{
  ClientAuth, ExampleClient,
  api::{
    read::{GetRequestInfo, ListUsers},
    write::{CreateNote, UpdateUserAccess},
  },
  auth::{
    api::{
      manage::{
        CreateApiKey, CreateTrustedIssuer, DeleteTrustedIssuer,
        GetUserId, ListTrustedIssuers, UpdatePassword,
        UpdateTrustedIssuer,
      },
      token::TOKEN_TYPE_JWT,
    },
    config::{
      REDACTED, TokenReviewConfig, TrustedIssuer, TrustedIssuerKeys,
      WorkloadClaim, WorkloadRule,
    },
  },
};
use example_mock_idp::{DEFAULT_REVIEWER_TOKEN, MintToken, Signer};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

const AUDIENCE: &str = "https://example-app.test";

fn claim(claim: &str, pattern: &str) -> WorkloadClaim {
  WorkloadClaim {
    claim: claim.into(),
    pattern: pattern.into(),
  }
}

fn deploy_rule() -> WorkloadRule {
  WorkloadRule {
    id: String::new(),
    name: "Deploy".into(),
    enabled: true,
    claims: vec![
      claim("repository_id", "12345"),
      claim("ref", "refs/heads/release/*"),
    ],
    groups: vec!["deployers".into()],
    admin: false,
    token_ttl_secs: 900,
  }
}

fn issuer(app: &TestApp, rules: Vec<WorkloadRule>) -> TrustedIssuer {
  TrustedIssuer {
    id: String::new(),
    name: "Mock CI".into(),
    enabled: true,
    issuer: app.idp.issuer.clone(),
    keys: TrustedIssuerKeys::Discovery {},
    audiences: vec![AUDIENCE.into()],
    max_token_age_secs: 300,
    rules,
  }
}

fn ci_token(claims: serde_json::Value) -> MintToken {
  MintToken {
    sub: "repo:my-org/my-repo:ref:refs/heads/release/1".into(),
    aud: vec![AUDIENCE.into()],
    claims: claims.as_object().unwrap().clone(),
    ..Default::default()
  }
}

fn release_claims() -> serde_json::Value {
  json!({ "repository_id": "12345", "ref": "refs/heads/release/1" })
}

async fn workload_client(
  app: &TestApp,
  token: MintToken,
) -> ExampleClient {
  let res = app
    .token_exchange(&app.idp.mint(token), TOKEN_TYPE_JWT)
    .await
    .unwrap();
  app.client().with_auth(ClientAuth::Jwt(res.access_token))
}

#[tokio::test]
async fn workload_gets_a_short_lived_token_for_its_rule() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let created = admin
    .manage(CreateTrustedIssuer::from(issuer(
      &app,
      vec![deploy_rule()],
    )))
    .await
    .unwrap();
  assert!(!created.read_only);
  // The server generates the ids, they identify the user of a rule.
  assert!(!created.issuer.id.is_empty());
  assert!(!created.issuer.rules[0].id.is_empty());

  let res = app
    .token_exchange(
      &app.idp.mint(ci_token(release_claims())),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap();
  // The ttl of the rule, not the 24h of user logins.
  assert_eq!(res.expires_in, 900);

  let workload =
    app.client().with_auth(ClientAuth::Jwt(res.access_token));
  let info = workload.read(GetRequestInfo {}).await.unwrap();
  let users = admin.read(ListUsers {}).await.unwrap();
  let user =
    users.iter().find(|user| user.id == info.user_id).unwrap();
  assert_eq!(user.username, "workload-deploy");
  assert_eq!(user.groups, ["deployers"]);
  assert!(!user.admin && user.enabled && !user.has_password);
  let link = user.workload.as_ref().unwrap();
  assert_eq!(link.issuer_id, created.issuer.id);
  assert_eq!(link.rule_id, created.issuer.rules[0].id);
  assert!(link.last_subject.starts_with("repo:my-org/my-repo"));

  // It can use the app ...
  workload
    .write(CreateNote {
      title: "Deployed".into(),
      content: "release/1".into(),
    })
    .await
    .unwrap();

  // ... but can't create credentials which would outlive the rule.
  let res = workload
    .manage(CreateApiKey {
      name: "backdoor".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = workload
    .manage(UpdatePassword {
      password: "a-password-for-later".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  // Asking who it is stays possible.
  let id = workload.manage(GetUserId {}).await.unwrap().id;
  assert_eq!(id, info.user_id);

  // Every job of the rule is the same user.
  let again = workload_client(
    &app,
    ci_token(json!({ "repository_id": "12345", "ref": "refs/heads/release/2" })),
  )
  .await;
  assert_eq!(
    again.read(GetRequestInfo {}).await.unwrap().user_id,
    info.user_id
  );
  assert_eq!(admin.read(ListUsers {}).await.unwrap().len(), 2);
}

#[tokio::test]
async fn tokens_have_to_match_a_rule() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  admin
    .manage(CreateTrustedIssuer::from(issuer(
      &app,
      vec![deploy_rule()],
    )))
    .await
    .unwrap();

  let rejected = [
    (
      "another repository",
      ci_token(
        json!({ "repository_id": "99999", "ref": "refs/heads/release/1" }),
      ),
    ),
    (
      "another branch",
      ci_token(
        json!({ "repository_id": "12345", "ref": "refs/heads/main" }),
      ),
    ),
    (
      "a prefix of the pattern",
      ci_token(
        json!({ "repository_id": "123456", "ref": "refs/heads/release/1" }),
      ),
    ),
    (
      "a claim is missing",
      ci_token(json!({ "repository_id": "12345" })),
    ),
    (
      "the platform default audience",
      MintToken {
        aud: vec!["https://github.com/my-org".into()],
        ..ci_token(release_claims())
      },
    ),
    (
      "signed by somebody else",
      MintToken {
        signer: Signer::Other,
        ..ci_token(release_claims())
      },
    ),
    (
      "too old",
      MintToken {
        issued_ago: 3_000,
        expires_in: 6_000,
        ..ci_token(release_claims())
      },
    ),
    (
      "expired",
      MintToken {
        issued_ago: 100,
        expires_in: -60,
        ..ci_token(release_claims())
      },
    ),
  ];
  for (why, token) in rejected {
    let (status, error) = app
      .token_exchange(&app.idp.mint(token), TOKEN_TYPE_JWT)
      .await
      .expect_err(why);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{why}");
    assert_eq!(error.error, "invalid_grant", "{why}");
  }
  // `alg: none` with the claims of a matching token, and those
  // claims under the signature of another token.
  let valid = app.idp.mint(ci_token(release_claims()));
  let claims = valid.split('.').nth(1).unwrap();
  let other = app.idp.mint(ci_token(json!({ "repository_id": "1" })));
  let (header, _) = other.split_once('.').unwrap();
  let signature = other.rsplit('.').next().unwrap();
  for (why, token) in [
    // {"alg":"none","typ":"JWT"}
    (
      "unsigned",
      format!("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{claims}."),
    ),
    ("tampered", format!("{header}.{claims}.{signature}")),
  ] {
    let (status, error) = app
      .token_exchange(&token, TOKEN_TYPE_JWT)
      .await
      .expect_err(why);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{why}");
    assert_eq!(error.error, "invalid_grant", "{why}");
  }
  // No users were created for refused tokens.
  assert_eq!(admin.read(ListUsers {}).await.unwrap().len(), 1);
}

#[tokio::test]
async fn keys_from_a_url_or_a_fixed_key_set() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  for (name, issuer_url, keys) in [
    (
      "jwks-uri",
      "https://ci-one.example".to_string(),
      TrustedIssuerKeys::JwksUri(format!("{}/jwks", app.idp.issuer)),
    ),
    (
      // Eg. a cluster the server can't reach.
      "static",
      "https://kubernetes.default.svc".to_string(),
      TrustedIssuerKeys::Static(app.idp.jwks_json()),
    ),
  ] {
    admin
      .manage(CreateTrustedIssuer::from(TrustedIssuer {
        name: name.into(),
        issuer: issuer_url.clone(),
        keys,
        rules: vec![WorkloadRule {
          name: name.into(),
          claims: vec![claim("sub", "system:serviceaccount:prod:*")],
          ..deploy_rule()
        }],
        ..issuer(&app, Vec::new())
      }))
      .await
      .unwrap();
    let workload = workload_client(
      &app,
      MintToken {
        iss: Some(issuer_url),
        sub: "system:serviceaccount:prod:deployer".into(),
        ..ci_token(json!({}))
      },
    )
    .await;
    workload.read(GetRequestInfo {}).await.unwrap();
  }

  // Invalid key sets are refused when saving, not at the first exchange.
  let res = admin
    .manage(CreateTrustedIssuer::from(TrustedIssuer {
      keys: TrustedIssuerKeys::Static("not a key set".into()),
      ..issuer(&app, vec![deploy_rule()])
    }))
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unsafe_issuers_and_rules_are_refused() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let invalid = [
    (
      "no audience",
      TrustedIssuer {
        audiences: Vec::new(),
        ..issuer(&app, vec![deploy_rule()])
      },
    ),
    (
      "a rule matching every token",
      issuer(
        &app,
        vec![WorkloadRule {
          claims: Vec::new(),
          ..deploy_rule()
        }],
      ),
    ),
    (
      "a claim matching any value",
      issuer(
        &app,
        vec![WorkloadRule {
          claims: vec![claim("repository_id", "*")],
          ..deploy_rule()
        }],
      ),
    ),
    (
      // Every token of the issuer for the audience has it, and
      // on a public platform anybody can request one.
      "a rule on the audience only",
      issuer(
        &app,
        vec![WorkloadRule {
          claims: vec![
            claim("aud", AUDIENCE),
            claim("iss", "https://*"),
          ],
          ..deploy_rule()
        }],
      ),
    ),
    (
      "issuer is not a url",
      TrustedIssuer {
        issuer: "not a url".into(),
        ..issuer(&app, vec![deploy_rule()])
      },
    ),
    (
      "no name",
      TrustedIssuer {
        name: String::new(),
        ..issuer(&app, vec![deploy_rule()])
      },
    ),
  ];
  for (why, issuer) in invalid {
    let res = admin.manage(CreateTrustedIssuer::from(issuer)).await;
    assert_eq!(status_of(res), StatusCode::BAD_REQUEST, "{why}");
  }
  assert!(
    admin
      .manage(ListTrustedIssuers {})
      .await
      .unwrap()
      .is_empty()
  );

  // Admin only
  let user = app.sign_up("user").await;
  let res = user
    .manage(CreateTrustedIssuer::from(issuer(
      &app,
      vec![deploy_rule()],
    )))
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = user.manage(ListTrustedIssuers {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_rules_and_the_first_matching_rule() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  admin
    .manage(CreateTrustedIssuer::from(issuer(
      &app,
      vec![
        WorkloadRule {
          name: "Disabled".into(),
          enabled: false,
          claims: vec![claim("repository_id", "7*")],
          admin: true,
          ..deploy_rule()
        },
        WorkloadRule {
          name: "Infra".into(),
          claims: vec![claim("repository_id", "777")],
          groups: Vec::new(),
          admin: true,
          ..deploy_rule()
        },
        deploy_rule(),
      ],
    )))
    .await
    .unwrap();

  let infra = workload_client(
    &app,
    ci_token(json!({ "repository_id": "777" })),
  )
  .await;
  // Admin, as its rule says: it can do what app admins can.
  assert_eq!(infra.read(ListUsers {}).await.unwrap().len(), 2);

  let deploy =
    workload_client(&app, ci_token(release_claims())).await;
  let res = deploy.read(ListUsers {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);

  // The access of a workload can't be changed in the app, only by its
  // rule, which sets it again whenever it is saved.
  let deploy_id =
    deploy.read(GetRequestInfo {}).await.unwrap().user_id;
  for (enabled, admin_access) in
    [(None, Some(true)), (Some(false), None)]
  {
    let res =
      admin_client_update(&admin, &deploy_id, enabled, admin_access)
        .await;
    assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
  }
}

async fn admin_client_update(
  admin: &ExampleClient,
  user_id: &str,
  enabled: Option<bool>,
  admin_access: Option<bool>,
) -> anyhow::Result<example_client::entities::User> {
  admin
    .write(UpdateUserAccess {
      user_id: user_id.to_string(),
      enabled,
      admin: admin_access,
      groups: None,
    })
    .await
}

fn find_user(
  users: &[example_client::entities::User],
  id: &str,
) -> example_client::entities::User {
  users.iter().find(|user| user.id == id).unwrap().clone()
}

/// Tokens carry the user id only, and the rule's user keeps its id
/// through changes of the rule: what the rule says now reaches the
/// tokens it issued before, on their next request.
#[tokio::test]
async fn changing_a_rule_reaches_the_tokens_it_issued() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let created = admin
    .manage(CreateTrustedIssuer::from(issuer(
      &app,
      vec![
        WorkloadRule {
          name: "Infra".into(),
          claims: vec![claim("repository_id", "777")],
          groups: Vec::new(),
          admin: true,
          ..deploy_rule()
        },
        deploy_rule(),
      ],
    )))
    .await
    .unwrap()
    .issuer;
  let infra_token = || ci_token(json!({ "repository_id": "777" }));
  let infra = workload_client(&app, infra_token()).await;
  let deploy =
    workload_client(&app, ci_token(release_claims())).await;
  let infra_id = infra.read(GetRequestInfo {}).await.unwrap().user_id;
  let deploy_id =
    deploy.read(GetRequestInfo {}).await.unwrap().user_id;
  infra.read(ListUsers {}).await.unwrap();

  let update = |change: fn(&mut TrustedIssuer)| {
    let mut issuer = created.clone();
    change(&mut issuer);
    admin.manage(UpdateTrustedIssuer::from(issuer))
  };

  // Demoted: the token issued before is no admin anymore.
  update(|issuer| {
    issuer.rules[0].admin = false;
    issuer.rules[0].groups = vec!["readers".into()];
  })
  .await
  .unwrap();
  let res = infra.read(ListUsers {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  infra.read(GetRequestInfo {}).await.unwrap();
  let user =
    find_user(&admin.read(ListUsers {}).await.unwrap(), &infra_id);
  assert!(!user.admin && user.enabled);
  assert_eq!(user.groups, ["readers"]);

  // Disabled: the token issued before is refused, and gets no new one.
  update(|issuer| issuer.rules[1].enabled = false)
    .await
    .unwrap();
  let res = deploy.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let (status, error) = app
    .token_exchange(
      &app.idp.mint(ci_token(release_claims())),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);
  assert_eq!(error.error, "invalid_grant");
  let users = admin.read(ListUsers {}).await.unwrap();
  assert!(!find_user(&users, &deploy_id).enabled);
  // Only the disabled rule's user.
  assert!(find_user(&users, &infra_id).enabled);
  infra.read(GetRequestInfo {}).await.unwrap();

  // Enabled again, the same user works again.
  update(|_| {}).await.unwrap();
  deploy.read(GetRequestInfo {}).await.unwrap();
  let again = workload_client(&app, ci_token(release_claims())).await;
  assert_eq!(
    again.read(GetRequestInfo {}).await.unwrap().user_id,
    deploy_id
  );

  // A disabled issuer disables all of its rules' users.
  update(|issuer| issuer.enabled = false).await.unwrap();
  for workload in [&infra, &deploy, &again] {
    let res = workload.read(GetRequestInfo {}).await;
    assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  }
  let (status, _) = app
    .token_exchange(&app.idp.mint(infra_token()), TOKEN_TYPE_JWT)
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);

  // Enabled again, back to the rules as they are.
  update(|_| {}).await.unwrap();
  let infra_again = workload_client(&app, infra_token()).await;
  assert_eq!(
    infra_again.read(GetRequestInfo {}).await.unwrap().user_id,
    infra_id
  );
  // The rule is admin again (`created`), and so are its tokens.
  infra.read(ListUsers {}).await.unwrap();
  // Nothing was created along the way.
  assert_eq!(admin.read(ListUsers {}).await.unwrap().len(), 3);
}

/// Static issuers change with the config file: the app applies them
/// to the users of their rules when it starts.
#[tokio::test]
async fn static_issuer_changes_apply_on_restart() {
  let idp = example_mock_idp::MockIdp::spawn(0).await.unwrap();
  let idp_issuer = idp.issuer.clone();
  let static_issuer = |deploy_admin: bool, docs_enabled: bool| {
    json!({
      "id": "mock-ci",
      "name": "Mock CI",
      "enabled": true,
      "issuer": idp_issuer,
      "keys": { "source": "Discovery", "params": {} },
      "audiences": [AUDIENCE],
      "rules": [
        {
          "id": "deploy",
          "name": "Deploy",
          "enabled": true,
          "claims": [{ "claim": "repository_id", "pattern": "12345" }],
          "admin": deploy_admin,
        },
        {
          "id": "docs",
          "name": "Docs",
          "enabled": docs_enabled,
          "claims": [{ "claim": "repository_id", "pattern": "555" }],
        },
      ],
    })
  };
  let issuers = static_issuer(true, true);
  let mut app = TestApp::spawn_with_idp(
    TestAppOptions {
      config: json!({ "trusted_issuers": [issuers] }),
      ..Default::default()
    },
    idp,
  )
  .await;
  let admin = app.sign_up("admin").await;
  let deploy =
    workload_client(&app, ci_token(release_claims())).await;
  let docs = workload_client(
    &app,
    ci_token(json!({ "repository_id": "555" })),
  )
  .await;
  deploy.read(ListUsers {}).await.unwrap();
  docs.read(GetRequestInfo {}).await.unwrap();

  let set_issuers = |app: &TestApp, issuers: serde_json::Value| {
    let path = app.dir.path().join("config/core.config.json");
    let mut config: serde_json::Value =
      serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["trusted_issuers"] = issuers;
    std::fs::write(&path, serde_json::to_vec(&config).unwrap())
      .unwrap();
  };

  // Deploy demoted, Docs disabled in the config.
  set_issuers(&app, json!([static_issuer(false, false)]));
  app.restart().await;
  let res = deploy.read(ListUsers {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  deploy.read(GetRequestInfo {}).await.unwrap();
  let res = docs.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);

  // The issuer removed from the config: its users are removed.
  set_issuers(&app, json!([]));
  app.restart().await;
  for workload in [&deploy, &docs] {
    let res = workload.read(GetRequestInfo {}).await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }
  let users = admin.read(ListUsers {}).await.unwrap();
  assert!(users.iter().all(|user| user.workload.is_none()));
}

#[tokio::test]
async fn removing_a_rule_or_issuer_revokes_its_workloads() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let created = admin
    .manage(CreateTrustedIssuer::from(issuer(
      &app,
      vec![
        deploy_rule(),
        WorkloadRule {
          name: "Docs".into(),
          claims: vec![claim("repository_id", "555")],
          ..deploy_rule()
        },
      ],
    )))
    .await
    .unwrap()
    .issuer;
  let deploy =
    workload_client(&app, ci_token(release_claims())).await;
  let docs = workload_client(
    &app,
    ci_token(json!({ "repository_id": "555" })),
  )
  .await;
  assert_eq!(admin.read(ListUsers {}).await.unwrap().len(), 3);

  // Drop the docs rule, keeping the deploy rule (by its id).
  let updated = admin
    .manage(UpdateTrustedIssuer::from(TrustedIssuer {
      rules: vec![created.rules[0].clone()],
      ..created.clone()
    }))
    .await
    .unwrap()
    .issuer;
  assert_eq!(updated.rules[0].id, created.rules[0].id);

  // The token of the removed rule stops working right away,
  // even though it would be valid for minutes.
  let res = docs.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  deploy.read(GetRequestInfo {}).await.unwrap();
  let (status, _) = app
    .token_exchange(
      &app.idp.mint(ci_token(json!({ "repository_id": "555" }))),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);

  // Disabling the issuer stops new tokens.
  admin
    .manage(UpdateTrustedIssuer::from(TrustedIssuer {
      enabled: false,
      ..updated.clone()
    }))
    .await
    .unwrap();
  let (status, _) = app
    .token_exchange(
      &app.idp.mint(ci_token(release_claims())),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);

  admin
    .manage(DeleteTrustedIssuer {
      id: updated.id.clone(),
    })
    .await
    .unwrap();
  let res = deploy.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  assert_eq!(admin.read(ListUsers {}).await.unwrap().len(), 1);
}

#[tokio::test]
async fn static_issuers_from_the_config_file() {
  let idp = example_mock_idp::MockIdp::spawn(0).await.unwrap();
  let app = TestApp::spawn_with_idp(
    TestAppOptions {
      config: json!({
        "trusted_issuers": [{
          "id": "mock-ci",
          "name": "Mock CI",
          "enabled": true,
          "issuer": idp.issuer,
          "keys": { "source": "Discovery", "params": {} },
          "audiences": [AUDIENCE],
          "rules": [
            {
              "id": "deploy",
              "name": "Deploy",
              "enabled": true,
              "claims": [{ "claim": "repository_id", "pattern": "12345" }],
              "groups": ["deployers"],
            },
            {
              // Without an id there is nothing to identify its user by.
              "name": "No id",
              "enabled": true,
              "claims": [{ "claim": "repository_id", "pattern": "222" }],
            },
          ],
        }]
      }),
      ..Default::default()
    },
    idp,
  )
  .await;
  let admin = app.sign_up("admin").await;

  let issuers = admin.manage(ListTrustedIssuers {}).await.unwrap();
  assert_eq!(issuers.len(), 1);
  assert!(issuers[0].read_only);
  let res = admin
    .manage(DeleteTrustedIssuer {
      id: "mock-ci".into(),
    })
    .await;
  assert!(status_of(res).is_client_error());

  let workload =
    workload_client(&app, ci_token(release_claims())).await;
  workload.read(GetRequestInfo {}).await.unwrap();

  // The config is at fault here, not the token: the workload
  // gets no token, and the reason is in the server log.
  let (status, error) = app
    .token_exchange(
      &app.idp.mint(ci_token(json!({ "repository_id": "222" }))),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
  assert_eq!(error.error, "server_error");
  assert!(app.logs().contains("need a unique id"));
}

#[tokio::test]
async fn fetched_keys_are_cached() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  admin
    .manage(CreateTrustedIssuer::from(issuer(
      &app,
      vec![deploy_rule()],
    )))
    .await
    .unwrap();
  // Eg. a CI matrix starting many jobs at once.
  let exchanges = (0..10)
    .map(|_| {
      let token = app.idp.mint(ci_token(release_claims()));
      tokio::spawn(token_exchange(app.address.clone(), token))
    })
    .collect::<Vec<_>>();
  for exchange in exchanges {
    exchange.await.unwrap().unwrap();
  }
  // They shared one load of the key set.
  assert_eq!(app.idp.jwks_requests(), 1);
}

/// A CI matrix starting: many jobs exchange their first token for a
/// rule at once, while its user doesn't exist yet. All of them get
/// a token, and all of them act as the one user of the rule. The
/// app creates it once, even with its first username taken.
#[tokio::test]
async fn concurrent_first_exchanges_share_one_user() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  // Takes the username the workload user would get.
  app.sign_up("workload-deploy").await;
  admin
    .manage(CreateTrustedIssuer::from(issuer(
      &app,
      vec![deploy_rule()],
    )))
    .await
    .unwrap();
  // Load the keys first (a token matching no rule), so the
  // exchanges below meet at the user, not at the key load.
  let (status, _) = app
    .token_exchange(
      &app.idp.mint(ci_token(json!({ "repository_id": "1" }))),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);

  // Every job has its connection open, and they all
  // exchange at the same moment.
  const JOBS: usize = 24;
  let start = std::sync::Arc::new(tokio::sync::Barrier::new(JOBS));
  let mut exchanges = Vec::new();
  for _ in 0..JOBS {
    let reqwest = reqwest::Client::new();
    reqwest
      .get(format!("{}/version", app.address))
      .send()
      .await
      .unwrap();
    let token = app.idp.mint(ci_token(release_claims()));
    let address = app.address.clone();
    let start = start.clone();
    exchanges.push(tokio::spawn(async move {
      start.wait().await;
      example_client::auth::request::token_exchange(
        &reqwest,
        &format!("{address}/auth"),
        &example_client::auth::api::token::TokenExchangeRequest::jwt(
          token,
        ),
      )
      .await
    }));
  }
  let mut user_ids = Vec::new();
  for exchange in exchanges {
    let res = exchange.await.unwrap().unwrap();
    let workload =
      app.client().with_auth(ClientAuth::Jwt(res.access_token));
    user_ids
      .push(workload.read(GetRequestInfo {}).await.unwrap().user_id);
  }
  user_ids.dedup();
  assert_eq!(user_ids.len(), 1, "{user_ids:?}");

  let users = admin.read(ListUsers {}).await.unwrap();
  let workloads = users
    .iter()
    .filter(|user| user.workload.is_some())
    .collect::<Vec<_>>();
  assert_eq!(workloads.len(), 1);
  assert_eq!(workloads[0].id, user_ids[0]);
  assert!(workloads[0].username.starts_with("workload-deploy-"));
  assert!(!app.logs().contains("Token exchange failed"));
}

async fn token_exchange(
  address: String,
  token: String,
) -> anyhow::Result<()> {
  example_client::auth::request::token_exchange(
    &reqwest::Client::new(),
    &format!("{address}/auth"),
    &example_client::auth::api::token::TokenExchangeRequest::jwt(
      token,
    ),
  )
  .await
  .map(|_| ())
}

// =================
// = TOKEN REVIEWS =
// =================

/// The issuer url of the cluster's service account tokens (its
/// `--service-account-issuer`). The mock idp mints them, and plays
/// the cluster's api server which reviews them.
const CLUSTER_ISSUER: &str =
  "https://kubernetes.default.svc.cluster.local";

/// The service account a token is for (`sub`).
const SERVICE_ACCOUNT: &str = "system:serviceaccount:ci:deployer";

/// An issuer whose tokens the cluster's api server at `url` reviews,
/// presenting `credential`.
fn review_issuer(url: &str, credential: &str) -> TrustedIssuer {
  TrustedIssuer {
    id: String::new(),
    name: "Cluster".into(),
    enabled: true,
    issuer: CLUSTER_ISSUER.into(),
    keys: review_keys(url, credential),
    audiences: vec![AUDIENCE.into()],
    max_token_age_secs: 300,
    rules: vec![WorkloadRule {
      id: String::new(),
      name: "Deployer".into(),
      enabled: true,
      claims: vec![claim("sub", SERVICE_ACCOUNT)],
      groups: vec!["deployers".into()],
      admin: false,
      token_ttl_secs: 900,
    }],
  }
}

fn review_keys(url: &str, credential: &str) -> TrustedIssuerKeys {
  TrustedIssuerKeys::TokenReview(TokenReviewConfig {
    url: url.into(),
    token: credential.into(),
    ..Default::default()
  })
}

/// `issuer` (eg. as it was read back) with another review source.
fn reviewed_at(
  issuer: &TrustedIssuer,
  url: &str,
  credential: &str,
) -> TrustedIssuer {
  TrustedIssuer {
    keys: review_keys(url, credential),
    ..issuer.clone()
  }
}

/// A service account token of the cluster, for the app unless
/// `token` names other audiences.
fn service_account_token(app: &TestApp, token: MintToken) -> String {
  let aud = if token.aud.is_empty() {
    vec![AUDIENCE.into()]
  } else {
    token.aud.clone()
  };
  app.idp.mint(MintToken {
    iss: Some(CLUSTER_ISSUER.into()),
    sub: SERVICE_ACCOUNT.into(),
    aud,
    ..token
  })
}

/// The status of exchanging `token`: 200 when it works.
async fn exchange_status(app: &TestApp, token: String) -> StatusCode {
  match app.token_exchange(&token, TOKEN_TYPE_JWT).await {
    Ok(_) => StatusCode::OK,
    Err((status, _)) => status,
  }
}

/// A url-mode TokenReview issuer (`TokenReviewConfig::url`): the
/// cluster's api server reviews each token, presented with the
/// reviewer credential, which is never read back. The token's own
/// claims are checked before (the cluster isn't asked about a token
/// the app refuses anyway), and what the cluster doesn't authenticate
/// is the token's refusal (400), which doesn't hold back the next.
#[tokio::test]
async fn token_review_issuer_reviews_through_the_cluster() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let created = admin
    .manage(CreateTrustedIssuer::from(review_issuer(
      &app.idp.issuer,
      DEFAULT_REVIEWER_TOKEN,
    )))
    .await
    .unwrap();
  assert_eq!(created.issuer.keys.review_token(), Some(REDACTED));
  let listed = admin.manage(ListTrustedIssuers {}).await.unwrap();
  assert_eq!(listed[0].issuer.keys.review_token(), Some(REDACTED));
  assert_eq!(app.idp.token_reviews(), 0);
  // The app keeps the credential encrypted at rest.
  for file in ["data/example.db", "data/example.db-wal"] {
    let contents = std::fs::read(app.path(file)).unwrap_or_default();
    assert!(
      !contents
        .windows(DEFAULT_REVIEWER_TOKEN.len())
        .any(|window| window == DEFAULT_REVIEWER_TOKEN.as_bytes()),
      "The reviewer credential is stored in plain text in {file}"
    );
  }

  // Reviewed, with the credential as the bearer (the mock cluster
  // answers anything else 401).
  let res = app
    .token_exchange(
      &service_account_token(&app, MintToken::default()),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap();
  assert_eq!(res.expires_in, 900);
  assert_eq!(app.idp.token_reviews(), 1);
  let workload =
    app.client().with_auth(ClientAuth::Jwt(res.access_token));
  let info = workload.read(GetRequestInfo {}).await.unwrap();
  let users = admin.read(ListUsers {}).await.unwrap();
  let user =
    users.iter().find(|user| user.id == info.user_id).unwrap();
  assert_eq!(user.username, "workload-deployer");
  assert_eq!(user.groups, ["deployers"]);
  let link = user.workload.as_ref().unwrap();
  assert_eq!(link.issuer_id, created.issuer.id);
  assert_eq!(link.last_subject, SERVICE_ACCOUNT);

  // Expired, for another audience, older than the issuer takes:
  // refused before the review.
  for (case, token) in [
    (
      "expired",
      MintToken {
        expires_in: -600,
        ..Default::default()
      },
    ),
    (
      "another audience",
      MintToken {
        aud: vec!["https://other-app.test".into()],
        ..Default::default()
      },
    ),
    (
      "too old",
      MintToken {
        issued_ago: 600,
        ..Default::default()
      },
    ),
  ] {
    let token = service_account_token(&app, token);
    let (status, error) = app
      .token_exchange(&token, TOKEN_TYPE_JWT)
      .await
      .unwrap_err();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{case}");
    assert_eq!(error.error, "invalid_grant", "{case}");
  }
  assert_eq!(app.idp.token_reviews(), 1);

  // A token the cluster didn't issue (another key): reviewed and
  // refused, and the next one is reviewed right away.
  let forged = service_account_token(
    &app,
    MintToken {
      signer: Signer::Other,
      ..Default::default()
    },
  );
  let (status, error) = app
    .token_exchange(&forged, TOKEN_TYPE_JWT)
    .await
    .unwrap_err();
  assert_eq!(status, StatusCode::BAD_REQUEST);
  assert_eq!(error.error, "invalid_grant");
  assert_eq!(app.idp.token_reviews(), 2);
  app
    .token_exchange(
      &service_account_token(&app, MintToken::default()),
      TOKEN_TYPE_JWT,
    )
    .await
    .unwrap();
  assert_eq!(app.idp.token_reviews(), 3);
}

/// The reviewer credential is a secret the app keeps: saved empty
/// or as read back (redacted) the stored one stays, for the same
/// api server only (another url needs it entered again). It is what
/// the review presents: once the cluster no longer takes it, the
/// issuer is unavailable (503), and the cluster is spared for a while
/// rather than asked on every exchange, until the issuer is saved
/// with the new credential.
#[tokio::test]
async fn token_review_credential_is_kept_until_the_url_changes() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let created = admin
    .manage(CreateTrustedIssuer::from(review_issuer(
      &app.idp.issuer,
      DEFAULT_REVIEWER_TOKEN,
    )))
    .await
    .unwrap()
    .issuer;
  let exchange = || {
    exchange_status(
      &app,
      service_account_token(&app, MintToken::default()),
    )
  };
  assert_eq!(exchange().await, StatusCode::OK);

  for kept in ["", REDACTED] {
    let updated = admin
      .manage(UpdateTrustedIssuer::from(reviewed_at(
        &created,
        &app.idp.issuer,
        kept,
      )))
      .await
      .unwrap();
    assert_eq!(updated.issuer.keys.review_token(), Some(REDACTED));
    assert_eq!(
      exchange().await,
      StatusCode::OK,
      "saved with '{kept}'"
    );
  }

  // The same api server under another url (a trailing slash).
  let moved = format!("{}/", app.idp.issuer);
  let res = admin
    .manage(UpdateTrustedIssuer::from(reviewed_at(
      &created, &moved, "",
    )))
    .await;
  let Err(e) = res else {
    panic!("A new url was saved without the credential");
  };
  assert_eq!(
    example_client::error_status(&e),
    Some(StatusCode::BAD_REQUEST)
  );
  assert!(
    format!("{e:#}").contains("enter the reviewer credential again"),
    "{e:#}"
  );
  let listed = admin.manage(ListTrustedIssuers {}).await.unwrap();
  let TrustedIssuerKeys::TokenReview(stored) = &listed[0].issuer.keys
  else {
    panic!("Not a TokenReview issuer anymore");
  };
  assert_eq!(stored.url, app.idp.issuer);
  admin
    .manage(UpdateTrustedIssuer::from(reviewed_at(
      &created,
      &moved,
      DEFAULT_REVIEWER_TOKEN,
    )))
    .await
    .unwrap();
  assert_eq!(exchange().await, StatusCode::OK);

  // The cluster rotated the reviewer's token: asked once, then spared.
  app.idp.set_reviewer_token("rotated-reviewer-token");
  let reviews = app.idp.token_reviews();
  assert_eq!(exchange().await, StatusCode::SERVICE_UNAVAILABLE);
  assert_eq!(app.idp.token_reviews(), reviews + 1);
  for _ in 0..3 {
    assert_eq!(exchange().await, StatusCode::SERVICE_UNAVAILABLE);
  }
  assert_eq!(app.idp.token_reviews(), reviews + 1);
  // Saved with the new one, it is tried at once.
  admin
    .manage(UpdateTrustedIssuer::from(reviewed_at(
      &created,
      &moved,
      "rotated-reviewer-token",
    )))
    .await
    .unwrap();
  assert_eq!(exchange().await, StatusCode::OK);
  assert_eq!(app.idp.token_reviews(), reviews + 2);
}

/// A TokenReview issuer has its issuer url to itself: the review only
/// says the cluster issued the token, so no other enabled issuer
/// (reviewed or by keys) may take tokens naming the same `iss`,
/// whichever is saved first (409). A disabled one collides with
/// nothing until it is enabled.
#[tokio::test]
async fn token_review_issuer_url_is_its_own() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  admin
    .manage(CreateTrustedIssuer::from(review_issuer(
      &app.idp.issuer,
      DEFAULT_REVIEWER_TOKEN,
    )))
    .await
    .unwrap();
  let keys_issuer = |issuer: &str| TrustedIssuer {
    name: "Keys".into(),
    issuer: issuer.into(),
    keys: TrustedIssuerKeys::Static(app.idp.jwks_json()),
    ..review_issuer(&app.idp.issuer, DEFAULT_REVIEWER_TOKEN)
  };
  for (case, issuer) in [
    (
      "another review issuer",
      TrustedIssuer {
        name: "Other cluster".into(),
        ..review_issuer(&app.idp.issuer, DEFAULT_REVIEWER_TOKEN)
      },
    ),
    ("a keys issuer", keys_issuer(CLUSTER_ISSUER)),
    // The same url with a trailing slash names the same issuer.
    (
      "a keys issuer, slashed",
      keys_issuer(&format!("{CLUSTER_ISSUER}/")),
    ),
  ] {
    let res = admin.manage(CreateTrustedIssuer::from(issuer)).await;
    assert_eq!(status_of(res), StatusCode::CONFLICT, "{case}");
  }

  // The other way around: a keys issuer first.
  let other_cluster = "https://other-cluster.example.test";
  admin
    .manage(CreateTrustedIssuer::from(keys_issuer(other_cluster)))
    .await
    .unwrap();
  let reviewed_other = TrustedIssuer {
    name: "Other cluster".into(),
    issuer: other_cluster.into(),
    ..review_issuer(&app.idp.issuer, DEFAULT_REVIEWER_TOKEN)
  };
  let res = admin
    .manage(CreateTrustedIssuer::from(reviewed_other.clone()))
    .await;
  assert_eq!(status_of(res), StatusCode::CONFLICT);

  // Disabled, it is stored; enabled, refused.
  let disabled = admin
    .manage(CreateTrustedIssuer::from(TrustedIssuer {
      enabled: false,
      ..reviewed_other
    }))
    .await
    .unwrap()
    .issuer;
  let res = admin
    .manage(UpdateTrustedIssuer::from(TrustedIssuer {
      enabled: true,
      ..reviewed_at(&disabled, &app.idp.issuer, "")
    }))
    .await;
  assert_eq!(status_of(res), StatusCode::CONFLICT);
  assert_eq!(
    admin.manage(ListTrustedIssuers {}).await.unwrap().len(),
    3
  );
}
