//! Api keys (key + secret) and signing keys (requests signed with a
//! private key).

use example_client::{
  ClientAuth, ExampleClient, SignedRequest,
  api::{
    execute::GenerateKeyPair,
    read::{GetRequestInfo, ListApiKeys},
  },
  auth::{
    api::manage::{
      CreateApiKey, CreateSigningKey, CreateTrustedIssuer,
      DeleteApiKey, DeleteSigningKey, ListTrustedIssuers,
    },
    config::{
      TrustedIssuer, TrustedIssuerKeys, WorkloadClaim, WorkloadRule,
    },
    signature::{
      SIGNED_AT_ANOTHER_TIME, SIGNED_FOR_ANOTHER_HOST, random_nonce,
    },
  },
  entities::{ApiKeyKind, AuthMethod},
  sign_request,
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

async fn create_api_key(
  client: &ExampleClient,
  name: &str,
  expires: u64,
  cidr_whitelist: &[&str],
) -> (String, String) {
  let res = client
    .manage(CreateApiKey {
      name: name.into(),
      expires,
      cidr_whitelist: cidr_whitelist
        .iter()
        .map(|entry| entry.to_string())
        .collect(),
    })
    .await
    .unwrap();
  (res.key, res.secret)
}

fn api_key_client(
  client: &ExampleClient,
  key: &str,
  secret: &str,
) -> ExampleClient {
  client.with_auth(ClientAuth::ApiKey {
    key: key.into(),
    secret: secret.into(),
  })
}

/// Signs its requests with `private_key`, for the host of the
/// address it sends them to.
fn signing_key_client(
  client: &ExampleClient,
  private_key: &str,
) -> ExampleClient {
  client.with_auth(ClientAuth::PrivateKey {
    private_key: private_key.into(),
  })
}

#[tokio::test]
async fn api_key_authenticates_until_deleted() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let (key, secret) = create_api_key(&admin, "ci", 0, &[]).await;
  assert!(key.starts_with("K_") && secret.starts_with("S_"));

  let api = api_key_client(&admin, &key, &secret);
  let info = api.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.auth_method, AuthMethod::ApiKey);
  assert_eq!(info.user_id, get_user(&admin).await.id);

  // The secret is only stored as a hash, and never listed.
  let keys = admin.read(ListApiKeys {}).await.unwrap();
  assert_eq!(keys.len(), 1);
  assert_eq!(keys[0].kind, ApiKeyKind::ApiKey);
  let db = std::fs::read(app.path("data/example.db")).unwrap();
  let wal = std::fs::read(app.path("data/example.db-wal"))
    .unwrap_or_default();
  for file in [&db, &wal] {
    assert!(
      !file
        .windows(secret.len())
        .any(|window| window == secret.as_bytes()),
      "The api secret is stored in plain text"
    );
  }

  // Wrong secret, unknown key, missing secret
  for (key, secret) in [
    (key.as_str(), "S_wrong_S"),
    ("K_unknown_K", secret.as_str()),
    (key.as_str(), ""),
  ] {
    let res = api_key_client(&admin, key, secret)
      .read(GetRequestInfo {})
      .await;
    assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  }

  admin
    .manage(DeleteApiKey { key: key.clone() })
    .await
    .unwrap();
  let res = api.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_key_names_and_whitelists_are_validated() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  for (name, cidr_whitelist) in [
    ("a".repeat(201), vec![]),
    ("has\u{0}control".to_string(), vec![]),
    ("ok".to_string(), vec!["not-an-ip".to_string()]),
    ("ok".to_string(), vec!["10.0.0.0/33".to_string()]),
  ] {
    let res = admin
      .manage(CreateApiKey {
        name: name.clone(),
        expires: 0,
        cidr_whitelist: cidr_whitelist.clone(),
      })
      .await;
    assert_eq!(
      status_of(res),
      StatusCode::BAD_REQUEST,
      "{name:?} {cidr_whitelist:?}"
    );
  }
  assert!(admin.read(ListApiKeys {}).await.unwrap().is_empty());

  // Entries are trimmed, empty ones dropped.
  create_api_key(&admin, "ok", 0, &[" 127.0.0.1 ", "", "10.0.0.0/8"])
    .await;
  let keys = admin.read(ListApiKeys {}).await.unwrap();
  assert_eq!(keys[0].cidr_whitelist, ["127.0.0.1", "10.0.0.0/8"]);
}

#[tokio::test]
async fn api_key_cidr_whitelist_is_enforced() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  let (key, secret) =
    create_api_key(&admin, "local", 0, &["127.0.0.0/8"]).await;
  api_key_client(&admin, &key, &secret)
    .read(GetRequestInfo {})
    .await
    .unwrap();

  let (key, secret) =
    create_api_key(&admin, "elsewhere", 0, &["203.0.113.0/24"]).await;
  let api = api_key_client(&admin, &key, &secret);
  let res = api.read(GetRequestInfo {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  // Also for the auth management api.
  let res = api
    .manage(example_client::auth::api::manage::GetUserId {})
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expired_keys_stop_working_and_can_be_deleted() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  let soon = unix_timestamp_ms() + 1_500;
  let (key, secret) =
    create_api_key(&admin, "short-lived", soon, &[]).await;
  let private_key = admin
    .manage(CreateSigningKey {
      name: "short-lived-signing".into(),
      expires: soon,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap()
    .private_key
    .unwrap();
  let api_key = api_key_client(&admin, &key, &secret);
  let signing_key = signing_key_client(&admin, &private_key);
  api_key.read(GetRequestInfo {}).await.unwrap();
  signing_key.read(GetRequestInfo {}).await.unwrap();

  tokio::time::sleep(std::time::Duration::from_millis(1_600)).await;
  assert_eq!(
    status_of(api_key.read(GetRequestInfo {}).await),
    StatusCode::UNAUTHORIZED
  );
  assert_eq!(
    status_of(signing_key.read(GetRequestInfo {}).await),
    StatusCode::UNAUTHORIZED
  );

  // The owner can still clean them up.
  let keys = admin.read(ListApiKeys {}).await.unwrap();
  assert_eq!(keys.len(), 2);
  admin.manage(DeleteApiKey { key }).await.unwrap();
  let public_key = keys
    .iter()
    .find(|key| key.kind == ApiKeyKind::SigningKey)
    .unwrap()
    .key
    .clone();
  admin.manage(DeleteSigningKey { public_key }).await.unwrap();
  assert!(admin.read(ListApiKeys {}).await.unwrap().is_empty());
}

#[tokio::test]
async fn users_cannot_delete_keys_of_others() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let other = app.sign_up("other").await;

  let (key, _) = create_api_key(&other, "mine", 0, &[]).await;
  other
    .manage(CreateSigningKey {
      name: "mine-signing".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap();
  let public_key = other
    .read(ListApiKeys {})
    .await
    .unwrap()
    .into_iter()
    .find(|key| key.kind == ApiKeyKind::SigningKey)
    .unwrap()
    .key;

  // Not even the admin.
  let res = admin.manage(DeleteApiKey { key }).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = admin.manage(DeleteSigningKey { public_key }).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  assert_eq!(other.read(ListApiKeys {}).await.unwrap().len(), 2);

  // Unknown keys
  let res = admin
    .manage(DeleteApiKey {
      key: "K_unknown_K".into(),
    })
    .await;
  assert!(status_of(res).is_client_error());
}

#[tokio::test]
async fn signing_key_signs_requests() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  // The server generates the key pair, and only keeps the public key.
  let private_key = admin
    .manage(CreateSigningKey {
      name: "generated".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap()
    .private_key
    .expect("No private key for a generated pair");
  let api = signing_key_client(&admin, &private_key);
  let info = api.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.auth_method, AuthMethod::PublicKey);
  // Works for the auth management api too.
  api
    .manage(example_client::auth::api::manage::GetUserId {})
    .await
    .unwrap();

  // A key pair the server doesn't know
  let unknown = admin.execute(GenerateKeyPair {}).await.unwrap();
  let res = signing_key_client(&admin, &unknown.private_key)
    .read(GetRequestInfo {})
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);

  // A request which carries other credentials is not signed: the
  // server would take those over the signature, and count what it
  // makes of them against the client. An address with a
  // `user:password@` is such a request (reqwest sends that as
  // Authorization), and so is one with an api key in its headers.
  let mut with_credentials = signing_key_client(&admin, &private_key);
  with_credentials.address =
    app.address.replacen("://", "://user:hunter2@", 1);
  let mut with_api_key = signing_key_client(&admin, &private_key);
  with_api_key
    .headers
    .insert("x-api-key", "K_some_key_K".parse().unwrap());
  for client in [with_credentials, with_api_key] {
    let err = client.read(GetRequestInfo {}).await.unwrap_err();
    let err = format!("{err:#}");
    assert!(err.contains("carries other credentials"), "{err}");
    assert!(!err.contains("hunter2"), "{err}");
  }
  // The key still works: nothing was sent for the server to count.
  api.read(GetRequestInfo {}).await.unwrap();
}

#[tokio::test]
async fn signing_key_accepts_own_public_key_in_any_encoding() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;

  for (name, pem) in [("base64", false), ("pem", true)] {
    let pair = admin.execute(GenerateKeyPair {}).await.unwrap();
    let public_key = if pem {
      format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        pair.public_key
      )
    } else {
      pair.public_key.clone()
    };
    let res = admin
      .manage(CreateSigningKey {
        name: name.into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
        public_key,
      })
      .await
      .unwrap();
    // The client keeps its own private key.
    assert!(res.private_key.is_none());
    signing_key_client(&admin, &pair.private_key)
      .read(GetRequestInfo {})
      .await
      .unwrap_or_else(|e| panic!("{name} public key: {e:#}"));
  }

  // What isn't an Ed25519 public key is refused rather than stored.
  // So is a low order point (the identity): a request "signed" as
  // it needs no private key at all. And so is an X25519 key, as
  // signing keys were before signatures were Ed25519: nothing
  // verifies with it.
  let x25519 =
    mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::Mutual)
      .unwrap()
      .public
      .into_inner();
  for public_key in [
    "not a key",
    "AAAA",
    "-----BEGIN PUBLIC KEY-----",
    "MCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    x25519.as_str(),
  ] {
    let res = admin
      .manage(CreateSigningKey {
        name: "invalid".into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
        public_key: public_key.into(),
      })
      .await;
    assert_eq!(
      status_of(res),
      StatusCode::BAD_REQUEST,
      "{public_key:?}"
    );
  }
}

#[tokio::test]
async fn signing_keys_cannot_be_registered_twice() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let other = app.sign_up("other").await;

  // Public keys are not secret, eg. published with a deployment.
  let pair = admin.execute(GenerateKeyPair {}).await.unwrap();
  let create = |public_key: &str| CreateSigningKey {
    name: "deploy".into(),
    expires: 0,
    cidr_whitelist: Vec::new(),
    public_key: public_key.into(),
  };
  admin.manage(create(&pair.public_key)).await.unwrap();

  // Nobody can register it again, in any encoding.
  let pem = format!(
    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
    pair.public_key
  );
  for (client, public_key) in [
    (&other, pair.public_key.as_str()),
    (&other, pem.as_str()),
    (&admin, pair.public_key.as_str()),
  ] {
    let res = client.manage(create(public_key)).await;
    assert_eq!(status_of(res), StatusCode::CONFLICT);
  }
  assert!(
    other
      .read(ListApiKeys {})
      .await
      .unwrap()
      .iter()
      .all(|key| key.kind != ApiKeyKind::SigningKey)
  );

  // Requests signed with it are still the owner's, who alone can
  // delete it.
  let info = signing_key_client(&admin, &pair.private_key)
    .read(GetRequestInfo {})
    .await
    .unwrap();
  assert_eq!(info.user_id, get_user(&admin).await.id);
  let res = other
    .manage(DeleteSigningKey {
      public_key: pair.public_key.clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  admin
    .manage(DeleteSigningKey {
      public_key: pair.public_key,
    })
    .await
    .unwrap();
}

/// The headers of a signed request, as sent.
type SignedHeaders = [(&'static str, String); 5];

/// The headers of `method path` with `body`, signed with
/// `private_key` for the server at `host`, at `timestamp`.
fn signed_headers(
  private_key: &str,
  host: &str,
  method: &str,
  path: &str,
  timestamp: i64,
  body: &[u8],
) -> SignedHeaders {
  let nonce = random_nonce().unwrap();
  let signature = sign_request(
    private_key,
    &SignedRequest {
      host,
      method,
      path_and_query: path,
      timestamp,
      nonce: &nonce,
      body,
    },
  )
  .unwrap();
  let public_key = mogh_pki::EncodedKeyPair::from_private_key(
    mogh_pki::PkiKind::Signature,
    private_key,
  )
  .unwrap()
  .public
  .into_inner();
  [
    ("x-api-public-key", public_key),
    ("x-api-host", host.to_string()),
    ("x-api-timestamp", timestamp.to_string()),
    ("x-api-nonce", nonce),
    ("x-api-signature", signature),
  ]
}

/// `headers` with the value of `header` replaced.
fn with_header(
  mut headers: SignedHeaders,
  header: &str,
  value: impl Into<String>,
) -> SignedHeaders {
  let (_, replaced) = headers
    .iter_mut()
    .find(|(name, _)| *name == header)
    .unwrap();
  *replaced = value.into();
  headers
}

/// Sends `POST path` with `body` and `headers` to the app, returning
/// the status.
async fn send_signed(
  app: &TestApp,
  path: &str,
  body: Vec<u8>,
  headers: impl IntoIterator<Item = (&'static str, String)>,
) -> StatusCode {
  send_signed_answer(app, path, body, headers).await.0
}

/// [send_signed], returning the body of the answer as well.
async fn send_signed_answer(
  app: &TestApp,
  path: &str,
  body: Vec<u8>,
  headers: impl IntoIterator<Item = (&'static str, String)>,
) -> (StatusCode, String) {
  let mut request = app
    .client()
    .reqwest
    .post(format!("{}{path}", app.address))
    .header("content-type", "application/json")
    .body(body);
  for (header, value) in headers {
    request = request.header(header, value);
  }
  let res = request.send().await.unwrap();
  (res.status(), res.text().await.unwrap())
}

async fn generated_signing_key(
  client: &ExampleClient,
  name: &str,
) -> String {
  client
    .manage(CreateSigningKey {
      name: name.into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
      public_key: String::new(),
    })
    .await
    .unwrap()
    .private_key
    .unwrap()
}

#[tokio::test]
async fn signature_is_bound_to_the_request_and_time() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let private_key = generated_signing_key(&admin, "generated").await;
  let host = app.host();

  let now = || unix_timestamp_ms() as i64;
  let sign = |method: &str,
              path: &str,
              timestamp: i64,
              body: &[u8]| {
    signed_headers(&private_key, &host, method, path, timestamp, body)
  };

  let path = "/read/GetRequestInfo";
  let body = b"{}".to_vec();
  assert_eq!(
    send_signed(
      &app,
      path,
      body.clone(),
      sign("POST", path, now(), &body)
    )
    .await,
    StatusCode::OK
  );
  // The key of somebody else, who the request then isn't signed by.
  let other = admin.execute(GenerateKeyPair {}).await.unwrap();
  // Signed for another path, method, body, time or nonce, or by
  // another key: the signature is no signature of the request. Each
  // is signed right before it is sent, so none is refused for its
  // age instead.
  type Case<'a> = Box<dyn Fn(i64) -> SignedHeaders + 'a>;
  let cases: Vec<Case> = vec![
    Box::new(|now| sign("POST", "/read/GetUser", now, &body)),
    Box::new(|now| sign("GET", path, now, &body)),
    Box::new(|now| sign("post", path, now, &body)),
    Box::new(|now| sign("POST", path, now, b"")),
    Box::new(|now| sign("POST", path, now, b"{ }")),
    Box::new(|now| {
      with_header(
        sign("POST", path, now, &body),
        "x-api-timestamp",
        (now + 1).to_string(),
      )
    }),
    Box::new(|now| {
      with_header(
        sign("POST", path, now, &body),
        "x-api-nonce",
        "0123456789abcdef0123456789abcdef",
      )
    }),
    Box::new(|now| {
      with_header(
        sign("POST", path, now, &body),
        "x-api-public-key",
        other.public_key.clone(),
      )
    }),
  ];
  for (i, headers) in cases.iter().enumerate() {
    let (status, answer) =
      send_signed_answer(&app, path, body.clone(), headers(now()))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "case {i}");
    assert!(
      answer.contains("Invalid client credentials"),
      "case {i}: {answer}"
    );
  }
  // A captured request can't be replayed later on, and the answer
  // says it is the time (not the key) which is refused.
  for timestamp in [now() - 60_000, now() + 60_000] {
    let (status, answer) = send_signed_answer(
      &app,
      path,
      body.clone(),
      sign("POST", path, timestamp, &body),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(answer.contains(SIGNED_AT_ANOTHER_TIME), "{answer}");
  }
  // Headers which are no signature, nonce, key or timestamp, or not
  // in the one form each has.
  for (header, value, says) in [
    ("x-api-signature", "not-a-signature", "X-API-SIGNATURE"),
    ("x-api-nonce", "short", "X-API-NONCE"),
    ("x-api-public-key", "not-a-key", "X-API-PUBLIC-KEY"),
    ("x-api-timestamp", "soon", "X-API-TIMESTAMP"),
  ] {
    let headers =
      with_header(sign("POST", path, now(), &body), header, value);
    let (status, answer) =
      send_signed_answer(&app, path, body.clone(), headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{header}");
    assert!(answer.contains(says), "{header}: {answer}");
  }
  let timestamp = now();
  let (status, answer) = send_signed_answer(
    &app,
    path,
    body.clone(),
    with_header(
      sign("POST", path, timestamp, &body),
      "x-api-timestamp",
      format!("+{timestamp}"),
    ),
  )
  .await;
  assert_eq!(status, StatusCode::UNAUTHORIZED);
  assert!(answer.contains("X-API-TIMESTAMP"), "{answer}");
  // A client from before signatures were Ed25519 sends the signature
  // and timestamp only: refused, not a server error.
  let old_client = sign("POST", path, now(), &body)
    .into_iter()
    .filter(|(header, _)| {
      ["x-api-signature", "x-api-timestamp"].contains(header)
    });
  assert_eq!(
    send_signed(&app, path, body.clone(), old_client).await,
    StatusCode::UNAUTHORIZED
  );
}

/// A signature is made for one server. The same public key can be
/// registered at another one, where a request captured at the first
/// (eg. by that server itself) must not be accepted.
#[tokio::test]
async fn signature_is_bound_to_the_server() {
  let app = TestApp::spawn().await;
  let other_app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let other_admin = other_app.sign_up("admin").await;

  // One key pair, registered at both.
  let pair = admin.execute(GenerateKeyPair {}).await.unwrap();
  for client in [&admin, &other_admin] {
    client
      .manage(CreateSigningKey {
        name: "shared".into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
        public_key: pair.public_key.clone(),
      })
      .await
      .unwrap();
  }
  // The client signs for the server it sends the request to.
  for client in [&admin, &other_admin] {
    signing_key_client(client, &pair.private_key)
      .read(GetRequestInfo {})
      .await
      .unwrap();
  }

  let path = "/read/GetRequestInfo";
  let body = b"{}".to_vec();
  let sign_for = |app: &TestApp| {
    signed_headers(
      &pair.private_key,
      &app.host(),
      "POST",
      path,
      unix_timestamp_ms() as i64,
      &body,
    )
  };
  // What one server received is passed on to the other within the
  // timestamp tolerance, with everything the request said: also its
  // Host header. The other server says who the request is for.
  for (signed_for, sent_to) in
    [(&app, &other_app), (&other_app, &app)]
  {
    let headers = sign_for(signed_for);
    assert_eq!(
      send_signed(signed_for, path, body.clone(), headers.clone())
        .await,
      StatusCode::OK
    );
    let (status, answer) = send_signed_answer(
      sent_to,
      path,
      body.clone(),
      headers.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
      answer.contains(SIGNED_FOR_ANOTHER_HOST)
        && answer.contains(&signed_for.host()),
      "{answer}"
    );
    let with_host = headers
      .clone()
      .into_iter()
      .chain([("host", signed_for.host())]);
    assert_eq!(
      send_signed(sent_to, path, body.clone(), with_host).await,
      StatusCode::UNAUTHORIZED
    );
    // Saying it is for the other server doesn't make it so: the
    // signature is for the first.
    let relabeled =
      with_header(headers, "x-api-host", sent_to.host());
    let (status, answer) =
      send_signed_answer(sent_to, path, body.clone(), relabeled)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
      answer.contains("Invalid client credentials"),
      "{answer}"
    );
  }
  // A host which is nobody's.
  let headers = signed_headers(
    &pair.private_key,
    "example.com",
    "POST",
    path,
    unix_timestamp_ms() as i64,
    &body,
  );
  assert_eq!(
    send_signed(&app, path, body.clone(), headers).await,
    StatusCode::UNAUTHORIZED
  );
}

/// The app is also reached at other addresses than its `host`, eg.
/// inside the network: requests signed for those are accepted once
/// they are in `extra_hosts`. What the request says its host is (a
/// proxy may rewrite it) doesn't matter.
#[tokio::test]
async fn signature_is_accepted_for_extra_hosts() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({
      "extra_hosts": [
        "https://Example.com",
        "http://example.internal:9220/",
      ],
    }),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let private_key = generated_signing_key(&admin, "generated").await;

  let path = "/read/GetRequestInfo";
  let body = b"{}".to_vec();
  let sign_for = |host: &str| {
    signed_headers(
      &private_key,
      host,
      "POST",
      path,
      unix_timestamp_ms() as i64,
      &body,
    )
  };
  for host in
    [app.host().as_str(), "example.com", "example.internal:9220"]
  {
    assert_eq!(
      send_signed(&app, path, body.clone(), sign_for(host)).await,
      StatusCode::OK,
      "{host}"
    );
    // Whatever the Host header says.
    let with_host = sign_for(host)
      .into_iter()
      .chain([("host", String::from("proxied.internal"))]);
    assert_eq!(
      send_signed(&app, path, body.clone(), with_host).await,
      StatusCode::OK,
      "{host}"
    );
  }
  // The hosts as configured, not anything like them.
  for host in [
    "example.com:8443",
    "example.internal",
    "example.internal:9221",
    "sub.example.com",
    "proxied.internal",
  ] {
    assert_eq!(
      send_signed(&app, path, body.clone(), sign_for(host)).await,
      StatusCode::UNAUTHORIZED,
      "{host}"
    );
  }
}

/// The body of a signed request is read before it is authenticated,
/// up to `AuthImpl::signed_request_body_limit` (2 MB by default): a
/// larger one is refused before its signature is looked at, whether
/// it is valid or not.
#[tokio::test]
async fn signed_request_body_is_limited() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let private_key = generated_signing_key(&admin, "generated").await;
  let host = app.host();

  let path = "/read/GetRequestInfo";
  // Valid JSON of the given length: `{}` and whitespace.
  let body = |len: usize| {
    let mut body = b"{}".to_vec();
    body.resize(len, b' ');
    body
  };
  let send = |body: Vec<u8>, valid: bool| {
    let timestamp = unix_timestamp_ms() as i64;
    let mut headers = signed_headers(
      &private_key,
      &host,
      "POST",
      path,
      timestamp,
      &body,
    );
    if !valid {
      // In form, of no request.
      headers = with_header(
        headers,
        "x-api-signature",
        format!("{}==", "A".repeat(86)),
      );
    }
    send_signed(&app, path, body, headers)
  };

  const MB: usize = 1024 * 1024;
  assert_eq!(send(body(MB), true).await, StatusCode::OK);
  assert_eq!(send(body(2 * MB), true).await, StatusCode::OK);
  for valid in [true, false] {
    assert_eq!(
      send(body(2 * MB + 1), valid).await,
      StatusCode::PAYLOAD_TOO_LARGE,
      "valid signature: {valid}"
    );
  }
}

#[tokio::test]
async fn signature_headers_cannot_carry_another_body() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let private_key = generated_signing_key(&admin, "terraform").await;
  let host = app.host();

  // The admin key runs a harmless request on the route which takes
  // every request type in the body.
  let path = "/auth/manage";
  let listed = serde_json::to_vec(&json!({
    "type": "ListTrustedIssuers",
    "params": {},
  }))
  .unwrap();
  let headers = signed_headers(
    &private_key,
    &host,
    "POST",
    path,
    unix_timestamp_ms() as i64,
    &listed,
  );
  assert_eq!(
    send_signed(&app, path, listed, headers.clone()).await,
    StatusCode::OK
  );

  // Whoever sees its headers can't send another request with them
  // while the timestamp is valid, eg. one creating a trusted issuer
  // whose tokens are exchanged for an admin.
  let created = serde_json::to_vec(&json!({
    "type": "CreateTrustedIssuer",
    "params": CreateTrustedIssuer {
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
    },
  }))
  .unwrap();
  assert_eq!(
    send_signed(&app, path, created.clone(), headers).await,
    StatusCode::UNAUTHORIZED
  );
  assert!(
    admin
      .manage(ListTrustedIssuers {})
      .await
      .unwrap()
      .is_empty()
  );

  // Signed by the key itself it is accepted.
  let headers = signed_headers(
    &private_key,
    &host,
    "POST",
    path,
    unix_timestamp_ms() as i64,
    &created,
  );
  assert_eq!(
    send_signed(&app, path, created, headers).await,
    StatusCode::OK
  );
  assert_eq!(
    admin.manage(ListTrustedIssuers {}).await.unwrap().len(),
    1
  );
}

#[tokio::test]
async fn signature_works_over_http2() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let private_key = generated_signing_key(&admin, "h2").await;
  let api = signing_key_client(&admin, &private_key);

  // The server sees the scheme and authority in the uri of an HTTP/2
  // request, the client signs the path and query, and the host on
  // its own.
  let mut h2 = api.clone();
  h2.reqwest = reqwest::Client::builder()
    .http2_prior_knowledge()
    .build()
    .unwrap();
  let info = h2.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.auth_method, AuthMethod::PublicKey);
  h2.manage(example_client::auth::api::manage::GetUserId {})
    .await
    .unwrap();
}

/// A tcp proxy on `listener` to `to` (`host:port`), whose first
/// connection is slow to get going: what the client sends over it
/// first is passed on `delay` late, as over a link which takes long
/// to set up a connection (DNS, TCP, TLS). Later connections are
/// fast.
fn slow_first_connection_proxy(
  listener: tokio::net::TcpListener,
  to: String,
  delay: std::time::Duration,
) {
  tokio::spawn(async move {
    let mut delay = Some(delay);
    while let Ok((mut inbound, _)) = listener.accept().await {
      let delay = delay.take();
      let to = to.clone();
      tokio::spawn(async move {
        if let Some(delay) = delay {
          tokio::time::sleep(delay).await;
        }
        let Ok(mut outbound) =
          tokio::net::TcpStream::connect(&to).await
        else {
          return;
        };
        let _ =
          tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
            .await;
      });
    }
  });
}

/// A request is signed before it goes out, so the time to set up a
/// connection counts against the timestamp tolerance of the server
/// (1 second). The first request over a slow new connection is
/// refused for its timestamp, and the client sends it once more,
/// signed anew, over a connection it opened before
/// (mogh_auth_client's `signed_post`).
#[tokio::test]
async fn signed_request_is_sent_anew_when_its_timestamp_aged() {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let proxy = format!("http://{}", listener.local_addr().unwrap());
  // The app is reached through the proxy too.
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "extra_hosts": [proxy] }),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let private_key = generated_signing_key(&admin, "slow link").await;
  let delay = std::time::Duration::from_millis(1500);
  slow_first_connection_proxy(
    listener,
    app.address.trim_start_matches("http://").to_string(),
    delay,
  );

  let mut api = signing_key_client(&admin, &private_key);
  api.address = proxy;
  let started = std::time::Instant::now();
  let info = api.read(GetRequestInfo {}).await.unwrap();
  assert_eq!(info.auth_method, AuthMethod::PublicKey);
  // The first attempt was held past the tolerance.
  assert!(started.elapsed() >= delay);
  // Later requests go out over the open connection.
  api
    .manage(example_client::auth::api::manage::GetUserId {})
    .await
    .unwrap();
}
