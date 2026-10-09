//! TOTP second factor: enrollment, login, replay protection and
//! recovery codes. Passkeys need an authenticator, and are covered by
//! the UI tests using the virtual authenticator of the browser.

use example_client::{
  ClientAuth, ExampleClient,
  auth::api::{
    login::{
      CompleteTotpLogin, CompleteTotpRecoveryLogin, JwtOrTwoFactor,
      LoginLocalUser,
    },
    manage::{
      BeginTotpEnrollment, ConfirmTotpEnrollment, UnenrollTotp,
    },
  },
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

struct Enrolled {
  totp: totp_rs::Totp,
  /// The code the enrollment was confirmed with: used once.
  code: String,
  recovery_codes: Vec<String>,
}

async fn enroll(client: &ExampleClient) -> Enrolled {
  let enrollment =
    client.manage(BeginTotpEnrollment {}).await.unwrap();
  assert!(enrollment.uri.starts_with("otpauth://totp/"));
  assert!(!enrollment.png.is_empty());
  let totp = totp_from_uri(&enrollment.uri);
  let code = totp.generate_current().to_string();
  let recovery_codes = client
    .manage(ConfirmTotpEnrollment { code: code.clone() })
    .await
    .unwrap()
    .recovery_codes;
  Enrolled {
    totp,
    code,
    recovery_codes,
  }
}

/// Logs in with the password, which has to ask for the code.
async fn begin_login(app: &TestApp, username: &str) -> ExampleClient {
  let client = app.client();
  let res = client
    .login(LoginLocalUser {
      username: username.into(),
      password: PASSWORD.into(),
    })
    .await
    .unwrap();
  assert!(matches!(res, JwtOrTwoFactor::Totp {}), "{res:?}");
  client
}

/// A valid code which wasn't used yet: the one of the next step,
/// which the server accepts because of its skew of one step.
fn next_code(totp: &totp_rs::Totp) -> String {
  totp.generate(unix_timestamp_ms() / 1000 + 30).to_string()
}

#[tokio::test]
async fn enroll_and_log_in_with_totp() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  assert!(!get_user(&admin).await.totp_enrolled);

  let enrolled = enroll(&admin).await;
  assert_eq!(enrolled.recovery_codes.len(), 10);
  assert!(get_user(&admin).await.totp_enrolled);

  // The secret is encrypted in the database.
  let db = std::fs::read(app.path("data/example.db")).unwrap();
  let wal = std::fs::read(app.path("data/example.db-wal"))
    .unwrap_or_default();
  let secret = data_encoding_base32(enrolled.totp.secret());
  for file in [&db, &wal] {
    assert!(
      !contains(file, secret.as_bytes()),
      "The TOTP secret is stored in plain text"
    );
  }

  // The password alone doesn't give a token anymore.
  let client = begin_login(&app, "admin").await;
  // The code used for enrollment can't be replayed as a login (the
  // very code: a step may have passed since), the next one works.
  let replayed = client
    .login(CompleteTotpLogin {
      code: enrolled.code.clone(),
    })
    .await;
  assert_eq!(status_of(replayed), StatusCode::UNAUTHORIZED);

  let jwt = client
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await
    .unwrap()
    .jwt;
  let user = get_user(&client.with_auth(ClientAuth::Jwt(jwt))).await;
  assert_eq!(user.username, "admin");
}

#[tokio::test]
async fn mistyped_code_can_be_retried_a_few_times() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;

  let client = begin_login(&app, "admin").await;
  for _ in 0..3 {
    let res = client
      .login(CompleteTotpLogin {
        code: "000000".into(),
      })
      .await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }
  // Still the same login, no need to enter the password again.
  client
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await
    .unwrap();

  // An accepted code ends the login.
  let res = client
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);

  // Too many wrong codes end it as well.
  let client = begin_login(&app, "admin").await;
  for _ in 0..5 {
    let res = client
      .login(CompleteTotpLogin {
        code: "000000".into(),
      })
      .await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }
  let e = client
    .login(CompleteTotpRecoveryLogin {
      code: enrolled.recovery_codes[0].clone(),
    })
    .await
    .unwrap_err();
  assert!(format!("{e:#}").contains("Too many"), "{e:#}");
}

#[tokio::test]
async fn second_factor_needs_the_first_factor_on_the_same_session() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;

  begin_login(&app, "admin").await;
  // Another session (cookie jar) never entered the password.
  let other_session = app.client();
  let res = other_session
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  let res = other_session
    .login(CompleteTotpRecoveryLogin {
      code: enrolled.recovery_codes[0].clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_code_is_only_accepted_once_even_after_a_restart() {
  let mut app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;
  let code = next_code(&enrolled.totp);

  let client = begin_login(&app, "admin").await;
  client
    .login(CompleteTotpLogin { code: code.clone() })
    .await
    .unwrap();

  // Somebody who watched the code being entered can't use it,
  // also not right after a restart (the used steps are stored).
  app.restart().await;
  let client = begin_login(&app, "admin").await;
  let e = client.login(CompleteTotpLogin { code }).await.unwrap_err();
  assert!(format!("{e:#}").contains("already used"), "{e:#}");
}

#[tokio::test]
async fn recovery_codes_work_once() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;
  let code = enrolled.recovery_codes[3].clone();

  let client = begin_login(&app, "admin").await;
  let res = client
    .login(CompleteTotpRecoveryLogin {
      code: "not-a-recovery-code".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  client
    .login(CompleteTotpRecoveryLogin { code: code.clone() })
    .await
    .unwrap();

  let client = begin_login(&app, "admin").await;
  let res = client.login(CompleteTotpRecoveryLogin { code }).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  // The others still work.
  client
    .login(CompleteTotpRecoveryLogin {
      code: enrolled.recovery_codes[4].clone(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn enrollment_needs_a_valid_code_and_unenroll_removes_2fa() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  // Confirm without begin
  let res = admin
    .manage(ConfirmTotpEnrollment {
      code: "123456".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);

  admin.manage(BeginTotpEnrollment {}).await.unwrap();
  let res = admin
    .manage(ConfirmTotpEnrollment {
      code: "000000".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
  assert!(!get_user(&admin).await.totp_enrolled);

  enroll(&admin).await;
  admin.manage(UnenrollTotp {}).await.unwrap();
  assert!(!get_user(&admin).await.totp_enrolled);
  // Back to password only.
  app.log_in("admin").await;
}

#[tokio::test]
async fn locked_usernames_cannot_enroll() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "lock_login_credentials_for": ["__ALL__"] }),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let res = admin.manage(BeginTotpEnrollment {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

/// The failed codes of a user are bounded however many are sent at
/// once, and whatever the session (first factor) or client ip they
/// come with: `mogh_auth_server::api::login::totp::MAX_SECOND_FACTOR_FAILURES`.
#[tokio::test]
async fn concurrent_codes_are_bounded_per_user() {
  const MAX_SECOND_FACTOR_FAILURES: usize = 10;
  // The ip rate limit is disabled, the user's limit applies anyway.
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;
  let valid = [
    enrolled.totp.generate_current().to_string(),
    next_code(&enrolled.totp),
  ];
  let wrong = ["000000", "111111", "222222"]
    .into_iter()
    .find(|code| !valid.iter().any(|valid| valid == code))
    .unwrap();

  // 30 codes at once, 5 on each of 6 logins (below the
  // attempts of one login).
  let mut requests = tokio::task::JoinSet::new();
  for _ in 0..6 {
    let client = begin_login(&app, "admin").await;
    for _ in 0..5 {
      let client = client.clone();
      requests.spawn(async move {
        status_of(
          client
            .login(CompleteTotpLogin { code: wrong.into() })
            .await,
        )
      });
    }
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
  assert_eq!(checked, MAX_SECOND_FACTOR_FAILURES, "{statuses:?}");
  assert_eq!(
    refused,
    30 - MAX_SECOND_FACTOR_FAILURES,
    "{statuses:?}"
  );

  // Used up: the right code is refused too, from another
  // login and client ip, with TOTP and recovery codes alike.
  let client = begin_login(&app, "admin")
    .await
    .with_header("x-forwarded-for", "203.0.113.7")
    .unwrap();
  let e = client
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await
    .unwrap_err();
  assert_eq!(
    example_client::error_status(&e),
    Some(StatusCode::TOO_MANY_REQUESTS)
  );
  assert!(format!("{e:#}").contains("Try again in"), "{e:#}");
  let res = client
    .login(CompleteTotpRecoveryLogin {
      code: enrolled.recovery_codes[0].clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::TOO_MANY_REQUESTS);

  // Other users are not affected.
  let other = app.sign_up("other").await;
  let other_enrolled = enroll(&other).await;
  let client = begin_login(&app, "other").await;
  client
    .login(CompleteTotpLogin {
      code: next_code(&other_enrolled.totp),
    })
    .await
    .unwrap();
}

/// The same recovery code sent twice at once, on two logins,
/// logs in only once.
#[tokio::test]
async fn a_recovery_code_used_twice_at_once_logs_in_once() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;
  let code = enrolled.recovery_codes[0].clone();

  let first = begin_login(&app, "admin").await;
  let second = begin_login(&app, "admin").await;
  let (first, second) = tokio::join!(
    first.login(CompleteTotpRecoveryLogin { code: code.clone() }),
    second.login(CompleteTotpRecoveryLogin { code: code.clone() }),
  );
  assert!(
    first.is_ok() != second.is_ok(),
    "The code logged in {} times",
    first.is_ok() as u8 + second.is_ok() as u8
  );
}

/// An enrollment begun by one user can't be confirmed by another
/// on the same cookie jar (session): the manage api authenticates
/// by the Authorization header, the enrollment rides on the cookie.
/// Neither can a locked user (a shared demo) be enrolled this way.
#[tokio::test]
async fn enrollment_is_confirmed_by_the_user_who_began_it() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "lock_login_credentials_for": ["demo"] }),
    ..Default::default()
  })
  .await;
  let attacker = app.sign_up("attacker").await;
  app.sign_up("demo").await;
  app.sign_up("other").await;

  /// Logs in `username` on the cookie jar of `client`.
  async fn log_in_on(
    client: &ExampleClient,
    username: &str,
  ) -> ExampleClient {
    let res = client
      .login(LoginLocalUser {
        username: username.into(),
        password: PASSWORD.into(),
      })
      .await
      .unwrap();
    let JwtOrTwoFactor::Jwt(jwt) = res else {
      panic!("Expected a jwt, got {res:?}");
    };
    client.with_auth(ClientAuth::Jwt(jwt.jwt))
  }

  for victim in ["demo", "other"] {
    let enrollment =
      attacker.manage(BeginTotpEnrollment {}).await.unwrap();
    let totp = totp_from_uri(&enrollment.uri);
    let as_victim = log_in_on(&attacker, victim).await;
    let res = as_victim
      .manage(ConfirmTotpEnrollment {
        code: totp.generate_current().to_string(),
      })
      .await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED, "{victim}");
    assert!(!get_user(&as_victim).await.totp_enrolled, "{victim}");
    // The victim still logs in with the password alone.
    app.log_in(victim).await;
  }

  // The refused enrollment is gone, the attacker has to begin again.
  let enrollment =
    attacker.manage(BeginTotpEnrollment {}).await.unwrap();
  let totp = totp_from_uri(&enrollment.uri);
  let as_other = log_in_on(&attacker, "other").await;
  as_other
    .manage(ConfirmTotpEnrollment {
      code: totp.generate_current().to_string(),
    })
    .await
    .unwrap_err();
  let res = attacker
    .manage(ConfirmTotpEnrollment {
      code: totp.generate_current().to_string(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  // Begun and confirmed by the same user, it works.
  enroll(&attacker).await;
  assert!(get_user(&attacker).await.totp_enrolled);
}

/// Passing the password gives the login a new session id, so a
/// session planted in the browser beforehand (session fixation)
/// can't send the codes of the user who logs in on it.
#[tokio::test]
async fn first_factor_gets_a_new_session_id() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;
  let attacker = app.sign_up("attacker").await;
  enroll(&attacker).await;

  // Without a cookie store: the cookies are set by hand.
  let reqwest = reqwest::Client::new();
  let login = |variant: &str, cookie: Option<&str>, body| {
    let request = reqwest
      .post(format!("{}/auth/login/{variant}", app.address))
      .json(&body);
    match cookie {
      Some(cookie) => request.header("cookie", cookie),
      None => request,
    }
    .send()
  };
  let credentials = |username: &str| json!({ "username": username, "password": PASSWORD });

  // A live session of the attacker: their own first factor.
  let res = login("LoginLocalUser", None, credentials("attacker"))
    .await
    .unwrap();
  assert!(res.status().is_success());
  let planted = session_cookie(&res);

  // The victim's browser was made to carry it (eg by a sibling
  // subdomain), and they log in with their password.
  let res =
    login("LoginLocalUser", Some(&planted), credentials("admin"))
      .await
      .unwrap();
  assert!(res.status().is_success());
  let cycled = session_cookie(&res);
  assert_ne!(cycled, planted);

  // The planted session holds no login of the victim.
  let code = json!({ "code": next_code(&enrolled.totp) });
  let res = login("CompleteTotpLogin", Some(&planted), code.clone())
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
  let body = res.text().await.unwrap();
  assert!(body.contains("not been initiated"), "{body}");

  // The victim's own cookie completes it.
  let res = login("CompleteTotpLogin", Some(&cycled), code)
    .await
    .unwrap();
  assert!(res.status().is_success(), "{}", res.text().await.unwrap());
}

/// A pending second factor only lives as long as its session, which
/// expires after a while without changes. The steps of the other
/// flows, which anybody holding the cookie can request, don't change
/// a session without that flow in flight: they can't keep a pending
/// login alive (eg. after the password it came from was changed).
/// The pending login itself expires after
/// `Session::MAX_SECOND_FACTOR_LOGIN_AGE` (10 minutes) regardless.
#[tokio::test]
async fn other_flows_do_not_keep_a_pending_login_alive() {
  let app = TestApp::spawn_with(TestAppOptions {
    static_oidc: true,
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;
  let client = begin_login(&app, "admin").await;

  let get =
    |path: &str| client.reqwest.get(format!("{}{path}", app.address));
  for (path, request) in [
    "/auth/oidc/callback?state=x&code=y",
    "/auth/oidc/callback?error=x",
    "/auth/external/unknown/callback",
    "/auth/oidc/link",
    "/auth/external/unknown/link",
  ]
  .map(|path| (path, get(path)))
  .into_iter()
  .chain([(
    "ExchangeForJwt",
    client
      .reqwest
      .post(format!("{}/auth/login/ExchangeForJwt", app.address))
      .json(&json!({})),
  )]) {
    let res = request.send().await.unwrap();
    assert!(
      res.status().is_redirection()
        || res.status() == StatusCode::UNAUTHORIZED,
      "{path}: {}",
      res.status()
    );
    // A saved session gets its cookie again, with a new expiry.
    assert!(
      !sets_session_cookie(&res),
      "{path} saved the session: {:?}",
      res.headers().get_all("set-cookie")
    );
  }

  // The login is still pending.
  client
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await
    .unwrap();
}

/// A pending second factor has its whole
/// `Session::MAX_SECOND_FACTOR_LOGIN_AGE` (10 minutes), whatever the
/// idle expiry of sessions: a code typed after the session would have
/// idled out still completes the login (the auth server keeps the
/// session for the step).
#[tokio::test]
async fn a_pending_login_outlives_the_session_idle_expiry() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "session_expiry_seconds": 1 }),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let enrolled = enroll(&admin).await;
  let client = begin_login(&app, "admin").await;
  // Past the idle expiry of the session.
  tokio::time::sleep(std::time::Duration::from_millis(2_500)).await;
  let jwt = client
    .login(CompleteTotpLogin {
      code: next_code(&enrolled.totp),
    })
    .await
    .unwrap()
    .jwt;
  let user = get_user(&client.with_auth(ClientAuth::Jwt(jwt))).await;
  assert_eq!(user.username, "admin");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
  haystack
    .windows(needle.len())
    .any(|window| window == needle)
}

/// RFC 4648 base32 without padding.
fn data_encoding_base32(bytes: &[u8]) -> String {
  const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let mut out = String::new();
  let mut bits = 0u32;
  let mut bit_count = 0;
  for byte in bytes {
    bits = (bits << 8) | *byte as u32;
    bit_count += 8;
    while bit_count >= 5 {
      bit_count -= 5;
      out.push(ALPHABET[((bits >> bit_count) & 31) as usize] as char);
    }
    bits &= (1 << bit_count) - 1;
  }
  if bit_count > 0 {
    out.push(
      ALPHABET[((bits << (5 - bit_count)) & 31) as usize] as char,
    );
  }
  out
}
