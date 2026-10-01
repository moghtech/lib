//! Username / password signup and login, and credential management.

use example_client::{
  ClientAuth,
  api::read::GetUser,
  auth::api::{
    login::{
      GetLoginOptions, JwtOrTwoFactor, LoginLocalUser,
      SignUpLocalUser,
    },
    manage::{GetUserId, UpdatePassword, UpdateUsername},
  },
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

#[tokio::test]
async fn sign_up_and_log_in() {
  let app = TestApp::spawn().await;

  let options = app.client().login(GetLoginOptions {}).await.unwrap();
  assert!(options.local);
  assert!(!options.registration_disabled);
  assert!(options.providers.is_empty());
  assert_eq!(options.auto_redirect, None);

  // The first user is the admin.
  let admin = app.sign_up("admin").await;
  let user = get_user(&admin).await;
  assert_eq!(user.username, "admin");
  assert!(user.admin && user.enabled && user.has_password);

  let other = app.sign_up("other").await;
  let user = get_user(&other).await;
  assert!(!user.admin && user.enabled);

  // The auth api agrees on who the token belongs to.
  let id = other.manage(GetUserId {}).await.unwrap().id;
  assert_eq!(id, user.id);

  let logged_in = app.log_in("other").await;
  assert_eq!(get_user(&logged_in).await.id, user.id);
}

#[tokio::test]
async fn login_failures_are_unauthorized_and_indistinguishable() {
  let app = TestApp::spawn().await;
  app.sign_up("admin").await;

  let wrong_password = app
    .client()
    .login(LoginLocalUser {
      username: "admin".into(),
      password: "not-the-password".into(),
    })
    .await
    .unwrap_err();
  let unknown_user = app
    .client()
    .login(LoginLocalUser {
      username: "nobody".into(),
      password: PASSWORD.into(),
    })
    .await
    .unwrap_err();

  assert_eq!(
    example_client::error_status(&wrong_password),
    Some(StatusCode::UNAUTHORIZED)
  );
  assert_eq!(
    example_client::error_status(&unknown_user),
    Some(StatusCode::UNAUTHORIZED)
  );
  // The message doesn't reveal whether the username exists.
  assert_eq!(
    wrong_password.root_cause().to_string(),
    unknown_user.root_cause().to_string()
  );
}

#[tokio::test]
async fn sign_up_validates_input() {
  let app = TestApp::spawn().await;
  for (username, password) in [
    ("", PASSWORD),
    ("has space", PASSWORD),
    ("semi;colon", PASSWORD),
    ("<script>", PASSWORD),
    ("valid", "short"),
    ("valid", ""),
  ] {
    let status = status_of(
      app
        .client()
        .login(SignUpLocalUser {
          username: username.into(),
          password: password.into(),
        })
        .await,
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{username:?}");
  }
  let too_long = "a".repeat(101);
  let status = status_of(
    app
      .client()
      .login(SignUpLocalUser {
        username: too_long,
        password: PASSWORD.into(),
      })
      .await,
  );
  assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejected_passwords_are_not_echoed() {
  let app = TestApp::spawn().await;
  let e = app
    .client()
    .login(SignUpLocalUser {
      username: "admin".into(),
      password: "hunter2-secret\u{7}-password".into(),
    })
    .await
    .unwrap_err();
  assert_eq!(
    example_client::error_status(&e),
    Some(StatusCode::BAD_REQUEST)
  );
  assert!(!format!("{e:#}").contains("hunter2"), "{e:#}");
  // The server logs at debug level here, including request errors.
  assert!(!app.logs().contains("hunter2"));
}

#[tokio::test]
async fn sign_up_with_taken_username_is_rejected() {
  let app = TestApp::spawn().await;
  app.sign_up("admin").await;
  let e = app
    .client()
    .login(SignUpLocalUser {
      username: "admin".into(),
      password: PASSWORD.into(),
    })
    .await
    .unwrap_err();
  assert_eq!(
    example_client::error_status(&e),
    Some(StatusCode::CONFLICT),
    "{e:#}"
  );
  // Storage details must not reach the client.
  let message = format!("{e:#}").to_lowercase();
  assert!(!message.contains("sqlite"), "{message}");
  assert!(!message.contains("constraint"), "{message}");
}

#[tokio::test]
async fn malformed_requests_are_client_errors() {
  let app = TestApp::spawn().await;
  let reqwest = reqwest::Client::new();
  for (path, body) in [
    // Unknown request type
    ("/auth/login", json!({ "type": "Nope", "params": {} })),
    ("/auth/login/Nope", json!({})),
    // Missing params
    ("/auth/login/LoginLocalUser", json!({})),
    ("/auth/login", json!({ "type": "LoginLocalUser" })),
    // Wrong types
    (
      "/auth/login/LoginLocalUser",
      json!({ "username": 1, "password": [] }),
    ),
  ] {
    let res = reqwest
      .post(format!("{}{path}", app.address))
      .json(&body)
      .send()
      .await
      .unwrap();
    assert!(
      res.status().is_client_error(),
      "{path} {body} -> {}",
      res.status()
    );
  }
  // Not json at all
  let res = reqwest
    .post(format!("{}/auth/login", app.address))
    .header("content-type", "application/json")
    .body("{not json")
    .send()
    .await
    .unwrap();
  assert!(res.status().is_client_error(), "{}", res.status());
  // The error body is still the standard json error.
  let body: serde_json::Value = res.json().await.unwrap();
  assert!(body.get("error").is_some(), "{body}");
}

#[tokio::test]
async fn registration_disabled_still_allows_the_first_user() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "disable_user_registration": true }),
    ..Default::default()
  })
  .await;

  // Reported to the login page
  let options = app.client().login(GetLoginOptions {}).await.unwrap();
  assert!(options.registration_disabled);

  // No users exist yet, so the first one can still sign up.
  let admin = app.sign_up("admin").await;
  assert!(get_user(&admin).await.admin);

  let status = status_of(
    app
      .client()
      .login(SignUpLocalUser {
        username: "second".into(),
        password: PASSWORD.into(),
      })
      .await,
  );
  assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn new_users_can_require_an_admin_to_enable_them() {
  let app = TestApp::spawn_with(TestAppOptions {
    // Also covers env over config file priority.
    config: json!({ "enable_new_users": true }),
    env: vec![("EXAMPLE_ENABLE_NEW_USERS".into(), "false".into())],
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let pending = app.sign_up("pending").await;

  // Disabled users are refused by the app api ...
  assert_eq!(
    status_of(pending.read(GetUser {}).await),
    StatusCode::FORBIDDEN
  );
  // ... but can still see that they are disabled.
  let res = pending
    .authenticate(
      pending.reqwest.get(format!("{}/user", app.address)),
    )
    .unwrap()
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
  let user: example_client::entities::User =
    res.json().await.unwrap();
  assert!(!user.enabled);

  admin
    .write(example_client::api::write::UpdateUserAccess {
      user_id: user.id.clone(),
      enabled: Some(true),
      admin: None,
      groups: None,
    })
    .await
    .unwrap();
  assert!(get_user(&pending).await.enabled);
}

#[tokio::test]
async fn local_auth_can_be_disabled() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "local_auth": false }),
    ..Default::default()
  })
  .await;
  let options = app.client().login(GetLoginOptions {}).await.unwrap();
  assert!(!options.local);
  let status = status_of(
    app
      .client()
      .login(SignUpLocalUser {
        username: "admin".into(),
        password: PASSWORD.into(),
      })
      .await,
  );
  assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn update_username_and_password() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  app.sign_up("taken").await;

  admin
    .manage(UpdateUsername {
      username: "renamed".into(),
    })
    .await
    .unwrap();
  assert_eq!(get_user(&admin).await.username, "renamed");

  // Invalid and taken usernames are refused.
  assert_eq!(
    status_of(
      admin
        .manage(UpdateUsername {
          username: "no spaces".into()
        })
        .await
    ),
    StatusCode::BAD_REQUEST
  );
  assert_eq!(
    status_of(
      admin
        .manage(UpdateUsername {
          username: "taken".into()
        })
        .await
    ),
    StatusCode::CONFLICT
  );
  // Setting the current username again is fine.
  admin
    .manage(UpdateUsername {
      username: "renamed".into(),
    })
    .await
    .unwrap();

  assert_eq!(
    status_of(
      admin
        .manage(UpdatePassword {
          password: "short".into()
        })
        .await
    ),
    StatusCode::BAD_REQUEST
  );
  admin
    .manage(UpdatePassword {
      password: "a-whole-new-password".into(),
    })
    .await
    .unwrap();

  // Only the new credentials work.
  let client = app.client();
  let old = client
    .login(LoginLocalUser {
      username: "renamed".into(),
      password: PASSWORD.into(),
    })
    .await;
  assert_eq!(status_of(old), StatusCode::UNAUTHORIZED);
  let new = client
    .login(LoginLocalUser {
      username: "renamed".into(),
      password: "a-whole-new-password".into(),
    })
    .await
    .unwrap();
  assert!(matches!(new, JwtOrTwoFactor::Jwt(_)));
}

#[tokio::test]
async fn locked_usernames_cannot_change_credentials() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "lock_login_credentials_for": ["demo"] }),
    ..Default::default()
  })
  .await;
  app.sign_up("admin").await;
  let demo = app.sign_up("demo").await;

  for status in [
    status_of(
      demo
        .manage(UpdateUsername {
          username: "demo2".into(),
        })
        .await,
    ),
    status_of(
      demo
        .manage(UpdatePassword {
          password: "another-password".into(),
        })
        .await,
    ),
  ] {
    assert_eq!(status, StatusCode::UNAUTHORIZED);
  }
  // Still the same user.
  assert_eq!(
    get_user(&app.log_in("demo").await).await.username,
    "demo"
  );
}

#[tokio::test]
async fn manage_api_requires_valid_credentials() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  assert_eq!(
    status_of(app.client().manage(GetUserId {}).await),
    StatusCode::UNAUTHORIZED
  );
  for jwt in ["", "garbage", "a.b.c"] {
    let client = admin.with_auth(ClientAuth::Jwt(jwt.to_string()));
    assert_eq!(
      status_of(client.manage(GetUserId {}).await),
      StatusCode::UNAUTHORIZED,
      "{jwt:?}"
    );
    assert_eq!(
      status_of(client.read(GetUser {}).await),
      StatusCode::UNAUTHORIZED,
      "{jwt:?}"
    );
  }
}

/// bcrypt only uses the first 72 bytes of a password: longer ones
/// would log in with anything sharing them, so they are refused.
#[tokio::test]
async fn passwords_longer_than_bcrypt_uses_are_refused() {
  let app = TestApp::spawn().await;
  for password in [
    "a".repeat(73),
    // 25 characters, 75 bytes
    "密".repeat(25),
  ] {
    let res = app
      .client()
      .login(SignUpLocalUser {
        username: "admin".into(),
        password: password.clone(),
      })
      .await;
    assert_eq!(status_of(res), StatusCode::BAD_REQUEST, "{password}");
  }

  // 72 bytes is fine, and all of them count.
  let longest = "密".repeat(24);
  let admin = app
    .client()
    .login(SignUpLocalUser {
      username: "admin".into(),
      password: longest.clone(),
    })
    .await
    .unwrap();
  let admin = app.client().with_auth(ClientAuth::Jwt(admin.jwt));
  let prefix = app
    .client()
    .login(LoginLocalUser {
      username: "admin".into(),
      password: "密".repeat(23),
    })
    .await;
  assert_eq!(status_of(prefix), StatusCode::UNAUTHORIZED);
  app
    .client()
    .login(LoginLocalUser {
      username: "admin".into(),
      password: longest,
    })
    .await
    .unwrap();

  // Updating the password is checked the same way.
  let res = admin
    .manage(UpdatePassword {
      password: "é".repeat(37),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
}

/// Wrong passwords sent at once get no more guesses than the
/// rate limit allows, they don't all run before any is counted.
#[tokio::test]
async fn concurrent_wrong_passwords_are_bounded_by_the_rate_limit() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((5, 60)),
    ..Default::default()
  })
  .await;
  app.sign_up("admin").await;

  let mut requests = tokio::task::JoinSet::new();
  for i in 0..20 {
    let client = app.client();
    requests.spawn(async move {
      status_of(
        client
          .login(LoginLocalUser {
            username: "admin".into(),
            password: format!("wrong-password-{i}"),
          })
          .await,
      )
    });
  }
  let statuses = requests.join_all().await;
  let checked = statuses
    .iter()
    .filter(|status| **status == StatusCode::UNAUTHORIZED)
    .count();
  let refused = statuses
    .iter()
    .filter(|status| **status == StatusCode::TOO_MANY_REQUESTS)
    .count();
  assert_eq!(checked, 5, "{statuses:?}");
  assert_eq!(refused, 15, "{statuses:?}");

  // The right password is refused as well now.
  let res = app
    .client()
    .login(LoginLocalUser {
      username: "admin".into(),
      password: PASSWORD.into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::TOO_MANY_REQUESTS);
}
