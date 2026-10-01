//! Rate limiting, client ips, cidr whitelists, response headers, CORS and sessions.

use std::time::Duration;

use example_client::{
  ClientAuth,
  api::{
    execute::GenerateKeyPair, read::GetRequestInfo,
    write::UpdateCidrWhitelist,
  },
  auth::api::login::{JwtOrTwoFactor, LoginLocalUser},
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

fn wrong_password(username: &str) -> LoginLocalUser {
  LoginLocalUser {
    username: username.into(),
    password: "not-the-password".into(),
  }
}

#[tokio::test]
async fn failed_logins_are_rate_limited_by_ip() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((3, 2)),
    ..Default::default()
  })
  .await;
  app.sign_up("admin").await;
  let client = app.client();

  for remaining in [2, 1, 0] {
    let e = client.login(wrong_password("admin")).await.unwrap_err();
    assert_eq!(
      example_client::error_status(&e),
      Some(StatusCode::UNAUTHORIZED)
    );
    // The user is told how many attempts are left.
    assert!(
      format!("{e:#}")
        .contains(&format!("{remaining} attempts remaining")),
      "{e:#}"
    );
  }

  // Now even the right password is refused.
  let res = client
    .login(LoginLocalUser {
      username: "admin".into(),
      password: PASSWORD.into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::TOO_MANY_REQUESTS);

  // The proxy (loopback is trusted by default) reports another client, which has its own budget.
  let other_ip = client
    .with_header("x-forwarded-for", "203.0.113.7")
    .unwrap();
  let res = other_ip
    .login(LoginLocalUser {
      username: "admin".into(),
      password: PASSWORD.into(),
    })
    .await
    .unwrap();
  assert!(matches!(res, JwtOrTwoFactor::Jwt(_)));

  // After the window the first client can log in again.
  tokio::time::sleep(Duration::from_millis(2_100)).await;
  app.log_in("admin").await;
}

#[tokio::test]
async fn ipv6_clients_are_rate_limited_per_64() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((2, 60)),
    ..Default::default()
  })
  .await;
  app.sign_up("admin").await;
  let from = |ip: &str| {
    app.client().with_header("x-forwarded-for", ip).unwrap()
  };
  let right_password = || LoginLocalUser {
    username: "admin".into(),
    password: PASSWORD.into(),
  };

  // A client moving to a fresh address in its /64 for every guess
  // keeps using up the same budget.
  for ip in ["2001:db8:1:2::1", "2001:db8:1:2::2"] {
    let res = from(ip).login(wrong_password("admin")).await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }
  let res =
    from("2001:db8:1:2:ffff::3").login(right_password()).await;
  assert_eq!(status_of(res), StatusCode::TOO_MANY_REQUESTS);

  // The next /64 is another client.
  let res = from("2001:db8:1:3::1")
    .login(right_password())
    .await
    .unwrap();
  assert!(matches!(res, JwtOrTwoFactor::Jwt(_)));
}

#[tokio::test]
async fn successful_requests_are_never_rate_limited() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((2, 60)),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  for _ in 0..10 {
    app.log_in("admin").await;
    admin.read(GetRequestInfo {}).await.unwrap();
  }
}

#[tokio::test]
async fn rejected_credentials_are_rate_limited() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((3, 60)),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let forged = admin.with_auth(ClientAuth::Jwt("a.b.c".into()));
  for _ in 0..3 {
    let res = forged.read(GetRequestInfo {}).await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }
  let res = forged.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::TOO_MANY_REQUESTS);
  // Guessing api secrets hits the same limit.
  let guess = admin.with_auth(ClientAuth::ApiKey {
    key: "K_guess_K".into(),
    secret: "S_guess_S".into(),
  });
  let res = guess.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn invalid_request_signatures_are_rate_limited() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((3, 60)),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let public_key =
    admin.execute(GenerateKeyPair {}).await.unwrap().public_key;
  // A signed request whose signature (64 bytes, as one is) is not
  // the signature of the request, with or without the headers it is
  // verified with.
  let host = app.host();
  let send = |complete: bool| {
    let mut request = admin
      .reqwest
      .post(format!("{}/read/GetRequestInfo", app.address))
      .header("x-api-signature", format!("{}==", "A".repeat(86)))
      .header("x-api-timestamp", unix_timestamp_ms().to_string())
      .json(&json!({}));
    if complete {
      request = request
        .header("x-api-public-key", &public_key)
        .header("x-api-host", &host)
        .header("x-api-nonce", "0123456789abcdef0123456789abcdef");
    }
    async move { request.send().await.unwrap().status() }
  };
  // What can't verify whatever the body is (here: a client from
  // before 7.0, which sends no public key or nonce) is refused
  // before the body is read, and costs the server nothing: it isn't
  // counted.
  for _ in 0..10 {
    assert_eq!(send(false).await, StatusCode::UNAUTHORIZED);
  }
  // So is a request signed for another server, whatever its
  // signature: it never gets as far.
  for _ in 0..10 {
    let status = admin
      .reqwest
      .post(format!("{}/read/GetRequestInfo", app.address))
      .header("x-api-signature", format!("{}==", "A".repeat(86)))
      .header("x-api-timestamp", unix_timestamp_ms().to_string())
      .header("x-api-public-key", &public_key)
      .header("x-api-host", "other.example.com")
      .header("x-api-nonce", "0123456789abcdef0123456789abcdef")
      .json(&json!({}))
      .send()
      .await
      .unwrap()
      .status();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
  }
  // Each of these costs the server reading the body and verifying a
  // signature to refuse.
  for _ in 0..3 {
    assert_eq!(send(true).await, StatusCode::UNAUTHORIZED);
  }
  assert_eq!(send(true).await, StatusCode::TOO_MANY_REQUESTS);

  // Requests without any credentials don't count: a UI which isn't
  // logged in yet sends those, and must not lock its own login out.
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((3, 60)),
    ..Default::default()
  })
  .await;
  app.sign_up("admin").await;
  for _ in 0..10 {
    let res = app.client().read(GetRequestInfo {}).await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }
  app.log_in("admin").await;
}

/// The login steps which complete a login pending on the session
/// don't count a session without one: there is nothing to guess, and
/// anyone can get a browser to send `ExchangeForJwt` (eg. with a link
/// to an app which redeems any `?redeem_ready=true` in its url). They
/// must not lock the ip out of the api, nor out of logging in.
#[tokio::test]
async fn login_steps_without_a_pending_login_are_not_counted() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((2, 60)),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  // Well formed, never checked.
  let credential = json!({
    "id": "AQID",
    "rawId": "AQID",
    "response": {
      "authenticatorData": "AQID",
      "clientDataJSON": "AQID",
      "signature": "AQID",
      "userHandle": null,
    },
    "extensions": {},
    "type": "public-key",
  });
  let client = app.client();
  for _ in 0..3 {
    for (method, params) in [
      ("ExchangeForJwt", json!({})),
      ("CompleteTotpLogin", json!({ "code": "123456" })),
      ("CompleteTotpRecoveryLogin", json!({ "code": "recovery" })),
      ("CompletePasskeyLogin", json!({ "credential": credential })),
    ] {
      let res = client
        .reqwest
        .post(format!("{}/auth/login/{method}", app.address))
        .json(&params)
        .send()
        .await
        .unwrap();
      let status = res.status();
      let body = res.text().await.unwrap();
      assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{method}: {body}"
      );
      assert!(
        !body.contains("attempts remaining"),
        "{method}: {body}"
      );
    }
  }
  // Credentials from the same ip are still accepted.
  admin.read(GetRequestInfo {}).await.unwrap();
  app.log_in("admin").await;
}

#[tokio::test]
async fn forwarded_ip_cannot_be_spoofed_without_a_trusted_proxy() {
  let app = TestApp::spawn_with(TestAppOptions {
    rate_limit: Some((2, 60)),
    // Nothing in front of the server, the socket peer is the client.
    config: json!({ "trusted_proxies": ["none"] }),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;

  let spoofed = admin
    .with_header("x-forwarded-for", "203.0.113.7")
    .unwrap()
    .with_header("x-real-ip", "203.0.113.8")
    .unwrap();
  let info = spoofed.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.ip, "127.0.0.1");

  // So rotating the header doesn't get around the rate limit.
  let client = app.client();
  for i in 0..2 {
    let res = client
      .with_header("x-forwarded-for", &format!("203.0.113.{i}"))
      .unwrap()
      .login(wrong_password("admin"))
      .await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }
  let res = client
    .with_header("x-forwarded-for", "203.0.113.99")
    .unwrap()
    .login(wrong_password("admin"))
    .await;
  assert_eq!(status_of(res), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn forwarded_ip_is_taken_from_trusted_proxies_only() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  for (forwarded_for, expected) in [
    ("203.0.113.7", "203.0.113.7"),
    // The rightmost entry which isn't a trusted proxy is the client,
    // whatever the client itself claimed to the left of it.
    ("1.2.3.4, 203.0.113.7", "203.0.113.7"),
    ("1.2.3.4, 203.0.113.7, 10.0.0.5", "203.0.113.7"),
    ("2001:db8::1", "2001:db8::1"),
  ] {
    let info = admin
      .with_header("x-forwarded-for", forwarded_for)
      .unwrap()
      .read(GetRequestInfo {})
      .await
      .unwrap();
    assert_eq!(info.ip, expected, "{forwarded_for}");
  }

  // A malformed header from a trusted proxy is not silently ignored.
  let res = admin
    .with_header("x-forwarded-for", "not-an-ip")
    .unwrap()
    .read(GetRequestInfo {})
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn real_ip_is_taken_from_the_nearest_proxy_line() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  // A proxy (loopback is trusted by default) which sets X-Real-IP.
  let info = admin
    .with_header("x-real-ip", "203.0.113.7")
    .unwrap()
    .read(GetRequestInfo {})
    .await
    .unwrap();
  assert_eq!(info.ip, "203.0.113.7");

  // A proxy which adds its own line after the one the client sent:
  // the nearest (last) line is the client, not the first.
  let mut added = admin.clone();
  for line in ["10.9.9.9", "203.0.113.7"] {
    added.headers.append("x-real-ip", line.parse().unwrap());
  }
  let info = added.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.ip, "203.0.113.7");

  // X-Forwarded-For takes precedence, which is why the proxy must
  // set it too: a client-sent one passed through would win.
  let info = admin
    .with_header("x-forwarded-for", "10.0.0.7")
    .unwrap()
    .with_header("x-real-ip", "203.0.113.7")
    .unwrap()
    .read(GetRequestInfo {})
    .await
    .unwrap();
  assert_eq!(info.ip, "10.0.0.7");
}

#[tokio::test]
async fn user_cidr_whitelist_applies_to_logins_and_requests() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let office = "203.0.113.7";

  let res = admin
    .write(UpdateCidrWhitelist {
      cidr_whitelist: vec!["not-a-range".into()],
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);

  admin
    .write(UpdateCidrWhitelist {
      cidr_whitelist: vec!["203.0.113.0/24".into()],
    })
    .await
    .unwrap();

  // The token is still valid, but not from this ip ...
  let res = admin.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = admin
    .manage(example_client::auth::api::manage::GetUserId {})
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  // ... and neither is the password. The answer is the same as for
  // a wrong one, so from elsewhere it doesn't confirm the password.
  let res = app
    .client()
    .login(LoginLocalUser {
      username: "admin".into(),
      password: PASSWORD.into(),
    })
    .await;
  let Err(right) = res else {
    panic!("Expected the login to fail");
  };
  let wrong = app
    .client()
    .login(wrong_password("admin"))
    .await
    .unwrap_err();
  assert_eq!(
    example_client::error_status(&right),
    Some(StatusCode::UNAUTHORIZED)
  );
  assert_eq!(
    example_client::error_status(&wrong),
    Some(StatusCode::UNAUTHORIZED)
  );
  assert_eq!(
    right.root_cause().to_string(),
    wrong.root_cause().to_string()
  );
  assert!(app.logs().contains("outside the user's cidr whitelist"));

  // From the office everything works.
  let from_office =
    admin.with_header("x-forwarded-for", office).unwrap();
  from_office.read(GetRequestInfo {}).await.unwrap();
  let res = app
    .client()
    .with_header("x-forwarded-for", office)
    .unwrap()
    .login(LoginLocalUser {
      username: "admin".into(),
      password: PASSWORD.into(),
    })
    .await
    .unwrap();
  assert!(matches!(res, JwtOrTwoFactor::Jwt(_)));

  from_office
    .write(UpdateCidrWhitelist {
      cidr_whitelist: Vec::new(),
    })
    .await
    .unwrap();
  admin.read(GetRequestInfo {}).await.unwrap();
}

#[tokio::test]
async fn responses_carry_security_headers() {
  let app = TestApp::spawn().await;
  let reqwest = reqwest::Client::new();
  for path in ["/version", "/read", "/auth/login/GetLoginOptions"] {
    let res = reqwest
      .get(format!("{}{path}", app.address))
      .send()
      .await
      .unwrap();
    let headers = res.headers();
    assert_eq!(
      headers["x-content-type-options"], "nosniff",
      "{path}"
    );
    assert_eq!(headers["x-frame-options"], "DENY", "{path}");
    assert_eq!(
      headers["referrer-policy"], "strict-origin-when-cross-origin",
      "{path}"
    );
  }
}

async fn preflight(
  app: &TestApp,
  origin: &str,
) -> reqwest::header::HeaderMap {
  reqwest::Client::new()
    .request(
      reqwest::Method::OPTIONS,
      format!("{}/read/GetUser", app.address),
    )
    .header("origin", origin)
    .header("access-control-request-method", "POST")
    .header(
      "access-control-request-headers",
      "authorization,content-type",
    )
    .send()
    .await
    .unwrap()
    .headers()
    .clone()
}

#[tokio::test]
async fn cors_only_allows_configured_origins() {
  let app = TestApp::spawn().await;
  let headers = preflight(&app, "https://evil.example").await;
  assert!(!headers.contains_key("access-control-allow-origin"));

  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({
      "cors_allowed_origins": ["https://ui.example.com"],
      "cors_allow_credentials": true,
    }),
    ..Default::default()
  })
  .await;
  let headers = preflight(&app, "https://ui.example.com").await;
  assert_eq!(
    headers["access-control-allow-origin"],
    "https://ui.example.com"
  );
  assert_eq!(headers["access-control-allow-credentials"], "true");
  let headers = preflight(&app, "https://evil.example").await;
  assert!(!headers.contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn cors_wildcard_with_credentials_does_not_panic() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({
      "cors_allowed_origins": ["*"],
      "cors_allow_credentials": true,
    }),
    ..Default::default()
  })
  .await;
  let headers = preflight(&app, "https://anywhere.example").await;
  // `*` isn't valid with credentials, the origin is mirrored instead.
  assert_eq!(
    headers["access-control-allow-origin"],
    "https://anywhere.example"
  );
  // And the server is still up.
  app.sign_up("admin").await;
}

#[tokio::test]
async fn session_cookie_is_http_only_and_same_site() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  // Anything using the session sets the cookie.
  let res = admin
    .authenticate(
      reqwest::Client::new()
        .post(format!(
          "{}/auth/manage/BeginTotpEnrollment",
          app.address
        ))
        .json(&json!({})),
    )
    .unwrap()
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
  let cookie =
    res.headers()["set-cookie"].to_str().unwrap().to_string();
  assert!(cookie.contains("HttpOnly"), "{cookie}");
  assert!(cookie.contains("SameSite=Lax"), "{cookie}");
  // The host is http here, Secure would stop the cookie from being sent.
  assert!(!cookie.contains("Secure"), "{cookie}");
}
