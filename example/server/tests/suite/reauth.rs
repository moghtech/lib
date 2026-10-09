//! Changes to how a user logs in need a recent login:
//! a token which leaked isn't enough to take over the account.

use std::time::Duration;

use example_client::{
  ClientAuth, ExampleClient,
  api::{
    read::{GetRequestInfo, ListApiKeys},
    write::{CreateNote, UpdateCidrWhitelist, UpdateUserAccess},
  },
  auth::api::manage::{
    BeginExternalLoginLink, BeginPasskeyEnrollment,
    BeginTotpEnrollment, CreateApiKey, CreateExternalLoginProvider,
    CreateSigningKey, DeleteApiKey, GetUserId,
    ListExternalLoginProviders, REAUTHENTICATION_REQUIRED,
    UnlinkLocalLogin, UpdateExternalSkip2fa, UpdatePassword,
    UpdateUsername,
  },
};
use reqwest::StatusCode;

use crate::common::*;

const WINDOW_SECS: u64 = 2;

async fn spawn_with_window(window_secs: u64) -> TestApp {
  TestApp::spawn_with(TestAppOptions {
    env: vec![(
      "EXAMPLE_REAUTHENTICATION_WINDOW_SECONDS".into(),
      window_secs.to_string(),
    )],
    ..Default::default()
  })
  .await
}

fn new_key(name: &str) -> CreateApiKey {
  CreateApiKey {
    name: name.into(),
    expires: 0,
    cidr_whitelist: Vec::new(),
  }
}

/// Admin: whoever controls a login provider controls the app.
fn attacker_sso() -> CreateExternalLoginProvider {
  CreateExternalLoginProvider {
    slug: String::new(),
    name: "Attacker SSO".into(),
    registration_disabled: false,
    token_exchange: Default::default(),
    config:
      example_client::auth::config::ExternalLoginProviderConfig::Oidc(
        Default::default(),
      ),
  }
}

pub(crate) fn assert_reauthentication_required<T>(
  res: anyhow::Result<T>,
  what: &str,
) {
  let Err(e) = res else {
    panic!("{what} was accepted without a recent login");
  };
  assert_eq!(
    example_client::error_status(&e),
    Some(StatusCode::FORBIDDEN),
    "{what}: {e:#}"
  );
  // Clients recognize it by the start of the message.
  assert!(
    e.root_cause()
      .to_string()
      .starts_with(REAUTHENTICATION_REQUIRED),
    "{what}: {e:#}"
  );
}

/// Every request which changes how the caller can log in. The
/// resource requests (a login provider) are asserted by the tests:
/// a stale session is refused them too, an api key is not.
async fn assert_all_sensitive_requests_refused(
  client: &ExampleClient,
) {
  assert_reauthentication_required(
    client
      .manage(UpdatePassword {
        password: "attacker-password".into(),
      })
      .await,
    "UpdatePassword",
  );
  assert_reauthentication_required(
    client
      .manage(UpdateUsername {
        username: "attacker".into(),
      })
      .await,
    "UpdateUsername",
  );
  assert_reauthentication_required(
    client.manage(BeginTotpEnrollment {}).await,
    "BeginTotpEnrollment",
  );
  assert_reauthentication_required(
    client.manage(BeginPasskeyEnrollment {}).await,
    "BeginPasskeyEnrollment",
  );
  assert_reauthentication_required(
    client
      .manage(BeginExternalLoginLink {
        slug: "oidc".into(),
      })
      .await,
    "BeginExternalLoginLink",
  );
  assert_reauthentication_required(
    client.manage(UnlinkLocalLogin {}).await,
    "UnlinkLocalLogin",
  );
  assert_reauthentication_required(
    client
      .manage(UpdateExternalSkip2fa {
        external_skip_2fa: true,
      })
      .await,
    "UpdateExternalSkip2fa",
  );
  assert_reauthentication_required(
    client.manage(new_key("backdoor")).await,
    "CreateApiKey",
  );
  assert_reauthentication_required(
    client
      .manage(CreateSigningKey {
        name: "backdoor".into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
        public_key: String::new(),
      })
      .await,
    "CreateSigningKey",
  );
}

#[tokio::test]
async fn an_old_token_cannot_change_how_the_user_logs_in() {
  let app = spawn_with_window(WINDOW_SECS).await;
  let admin = app.sign_up("admin").await;

  // Right after logging in everything works.
  let key = admin.manage(new_key("mine")).await.unwrap().key;

  tokio::time::sleep(Duration::from_secs(WINDOW_SECS + 2)).await;

  // Eg. a token lifted from a browser hours after the login.
  assert_all_sensitive_requests_refused(&admin).await;
  assert_reauthentication_required(
    admin.manage(attacker_sso()).await,
    "CreateExternalLoginProvider",
  );
  let user = get_user(&admin).await;
  assert_eq!(user.username, "admin");
  assert!(!user.totp_enrolled);
  assert_eq!(admin.read(ListApiKeys {}).await.unwrap().len(), 1);

  // The token itself is still good for everything else.
  admin.read(GetRequestInfo {}).await.unwrap();
  admin
    .write(CreateNote {
      title: "Still works".into(),
      content: String::new(),
    })
    .await
    .unwrap();
  admin.manage(GetUserId {}).await.unwrap();
  admin.manage(ListExternalLoginProviders {}).await.unwrap();
  // Removing a credential is never an escalation.
  admin.manage(DeleteApiKey { key }).await.unwrap();

  // Logging in again (with the password, which the attacker doesn't have).
  let fresh = app.log_in("admin").await;
  fresh
    .manage(UpdatePassword {
      password: "a-whole-new-password".into(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn api_keys_cannot_create_more_credentials() {
  let app = spawn_with_window(15 * 60).await;
  let admin = app.sign_up("admin").await;
  let res = admin.manage(new_key("ci")).await.unwrap();
  let api = admin.with_auth(ClientAuth::ApiKey {
    key: res.key,
    secret: res.secret,
  });

  // An api key is not a login, recent or otherwise: refused every
  // request about the account.
  assert_all_sensitive_requests_refused(&api).await;
  // Managing the login providers is what a key is for.
  api.manage(attacker_sso()).await.unwrap();
  api.manage(GetUserId {}).await.unwrap();
  api.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(admin.read(ListApiKeys {}).await.unwrap().len(), 1);
}

/// `0` disables the check for sessions only: an api key is still not
/// a login, and a leaked one must not be able to set a password,
/// unenroll 2fa or mint a replacement key.
#[tokio::test]
async fn the_check_can_be_disabled_but_not_for_api_keys() {
  let app = spawn_with_window(0).await;
  let admin = app.sign_up("admin").await;
  let res = admin.manage(new_key("automation")).await.unwrap();
  let api = admin.with_auth(ClientAuth::ApiKey {
    key: res.key,
    secret: res.secret,
  });

  assert_all_sensitive_requests_refused(&api).await;
  // The resource requests still take an admin's key.
  api.manage(attacker_sso()).await.unwrap();
  let user = get_user(&admin).await;
  assert_eq!(user.username, "admin");
  assert_eq!(admin.read(ListApiKeys {}).await.unwrap().len(), 1);

  // The session is not held to any window.
  tokio::time::sleep(Duration::from_secs(2)).await;
  admin.manage(new_key("another")).await.unwrap();
  assert_eq!(admin.read(ListApiKeys {}).await.unwrap().len(), 2);
}

/// The app's own writes which grant access (another user's rights,
/// a wider cidr whitelist) need a recent login of a session too
/// (`mogh_auth_server::middleware::require_recent_login`), with the
/// refusal clients recognize. Taking access away doesn't, and api
/// keys, the automation credentials, pass.
#[tokio::test]
async fn app_writes_which_grant_access_need_a_recent_login() {
  let app = spawn_with_window(WINDOW_SECS).await;
  let admin = app.sign_up("admin").await;
  let bob = app.sign_up("bob").await;
  let bob_id = get_user(&bob).await.id;
  let res = admin.manage(new_key("automation")).await.unwrap();
  let api = admin.with_auth(ClientAuth::ApiKey {
    key: res.key,
    secret: res.secret,
  });
  let access =
    |enabled: Option<bool>,
     admin: Option<bool>,
     groups: Option<Vec<String>>| UpdateUserAccess {
      user_id: bob_id.clone(),
      enabled,
      admin,
      groups,
    };
  let whitelist = |cidrs: &[&str]| UpdateCidrWhitelist {
    cidr_whitelist: cidrs
      .iter()
      .map(|cidr| cidr.to_string())
      .collect(),
  };

  // Right after logging in.
  admin.write(access(None, Some(true), None)).await.unwrap();
  admin
    .write(whitelist(&["127.0.0.1", "10.0.0.0/8"]))
    .await
    .unwrap();

  tokio::time::sleep(Duration::from_secs(WINDOW_SECS + 2)).await;

  // Taking access away still works.
  admin.write(access(None, Some(false), None)).await.unwrap();
  admin.write(access(Some(false), None, None)).await.unwrap();
  admin.write(whitelist(&["127.0.0.1"])).await.unwrap();
  // Granting it needs a recent login.
  assert_reauthentication_required(
    admin.write(access(None, Some(true), None)).await,
    "UpdateUserAccess admin",
  );
  assert_reauthentication_required(
    admin.write(access(Some(true), None, None)).await,
    "UpdateUserAccess enabled",
  );
  assert_reauthentication_required(
    admin
      .write(access(None, None, Some(vec!["ops".into()])))
      .await,
    "UpdateUserAccess groups",
  );
  assert_reauthentication_required(
    admin
      .write(whitelist(&["127.0.0.1", "192.168.0.0/16"]))
      .await,
    "UpdateCidrWhitelist with a new entry",
  );
  assert_reauthentication_required(
    admin.write(whitelist(&[])).await,
    "UpdateCidrWhitelist emptied (every ip)",
  );
  let user = get_user(&admin).await;
  assert_eq!(user.cidr_whitelist, vec!["127.0.0.1".to_string()]);

  // An api key has no login to be recent.
  let bob_user = api
    .write(access(Some(true), Some(true), Some(vec!["ops".into()])))
    .await
    .unwrap();
  assert!(bob_user.enabled && bob_user.admin);
  assert_eq!(bob_user.groups, vec!["ops".to_string()]);

  // Logging in again.
  let fresh = app.log_in("admin").await;
  fresh.write(whitelist(&[])).await.unwrap();
  fresh.write(access(None, Some(false), None)).await.unwrap();
  fresh.write(access(None, Some(true), None)).await.unwrap();
}
