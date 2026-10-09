//! The resolver based app api (`/read`, `/write`, `/execute`),
//! which also uses the smaller crates: encryption, validations, cache, pki.

use example_client::api::{
  execute::{
    GenerateKeyPair, OpenText, SealText, ValidateString,
    ValidateStringKind,
  },
  read::{
    GetCoreInfo, GetNote, GetStats, GetVersion, ListNotes, ListUsers,
  },
  write::{
    CreateNote, DeleteNote, DeleteUser, UpdateNote, UpdateUserAccess,
  },
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

#[tokio::test]
async fn notes_belong_to_their_owner() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let other = app.sign_up("other").await;

  let note = admin
    .write(CreateNote {
      title: "Shopping".into(),
      content: "SECRET-NOTE-CONTENT\nmultiple lines".into(),
    })
    .await
    .unwrap();
  admin
    .write(CreateNote {
      title: "Work".into(),
      content: String::new(),
    })
    .await
    .unwrap();

  let notes = admin.read(ListNotes::default()).await.unwrap();
  assert_eq!(notes.len(), 2);
  let notes = admin
    .read(ListNotes {
      query: "shop".into(),
    })
    .await
    .unwrap();
  assert_eq!(notes.len(), 1);
  assert_eq!(notes[0].id, note.id);

  let fetched = admin
    .read(GetNote {
      id: note.id.clone(),
    })
    .await
    .unwrap();
  assert_eq!(fetched.content, "SECRET-NOTE-CONTENT\nmultiple lines");

  // The content is encrypted in the database.
  for file in ["data/example.db", "data/example.db-wal"] {
    let contents = std::fs::read(app.path(file)).unwrap_or_default();
    assert!(
      !contents
        .windows(19)
        .any(|window| window == b"SECRET-NOTE-CONTENT"),
      "The note is stored in plain text in {file}"
    );
  }

  // Other users can't see, change or delete it, not even admins of others.
  assert!(other.read(ListNotes::default()).await.unwrap().is_empty());
  let res = other
    .read(GetNote {
      id: note.id.clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::NOT_FOUND);
  let res = other
    .write(UpdateNote {
      id: note.id.clone(),
      title: Some("Hijacked".into()),
      content: None,
    })
    .await;
  assert_eq!(status_of(res), StatusCode::NOT_FOUND);
  let res = other
    .write(DeleteNote {
      id: note.id.clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::NOT_FOUND);

  let updated = admin
    .write(UpdateNote {
      id: note.id.clone(),
      title: None,
      content: Some("new content".into()),
    })
    .await
    .unwrap();
  assert_eq!(updated.title, "Shopping");
  assert_eq!(updated.content, "new content");
  assert!(updated.updated_at >= note.updated_at);

  admin
    .write(DeleteNote {
      id: note.id.clone(),
    })
    .await
    .unwrap();
  let res = admin.read(GetNote { id: note.id }).await;
  assert_eq!(status_of(res), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn note_input_is_validated() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  for (title, content) in [
    (String::new(), String::new()),
    ("a".repeat(101), String::new()),
    ("bad\u{7}title".to_string(), String::new()),
    ("ok".to_string(), "a".repeat(10_001)),
  ] {
    let res = admin
      .write(CreateNote {
        title: title.clone(),
        content,
      })
      .await;
    assert_eq!(status_of(res), StatusCode::BAD_REQUEST, "{title:?}");
  }
  // Counted in characters, not bytes.
  admin
    .write(CreateNote {
      title: "ü".repeat(100),
      content: "日本語".into(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn both_request_forms_are_accepted() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let jwt = match &admin.auth {
    example_client::ClientAuth::Jwt(jwt) => jwt.clone(),
    _ => unreachable!(),
  };
  let reqwest = reqwest::Client::new();

  // `{ type, params }` body, as the rust client sends it ...
  let version = admin.read(GetVersion {}).await.unwrap().version;
  // ... and the type in the path, as the typescript client does.
  // The token is accepted with and without the Bearer prefix.
  for authorization in [jwt.clone(), format!("Bearer {jwt}")] {
    let res = reqwest
      .post(format!("{}/read/GetVersion", app.address))
      .header("authorization", authorization)
      .json(&json!({}))
      .send()
      .await
      .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "application/json");
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["version"], version);
  }

  // An unknown request or params of the wrong shape: 422 on both
  // forms, as axum's Json answers for the tagged body.
  for (path, body) in [
    ("/read/Nope", json!({})),
    ("/read", json!({ "type": "Nope", "params": {} })),
    ("/write/CreateNote", json!({ "title": 5 })),
    (
      "/execute/ValidateString",
      json!({ "kind": "Nope", "input": "" }),
    ),
    // A write request isn't a read request.
    ("/read/CreateNote", json!({ "title": "x" })),
  ] {
    let res = reqwest
      .post(format!("{}{path}", app.address))
      .header("authorization", &jwt)
      .json(&body)
      .send()
      .await
      .unwrap();
    assert_eq!(
      res.status(),
      StatusCode::UNPROCESSABLE_ENTITY,
      "{path}: {}",
      res.status()
    );
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["error"].is_string(), "{path}: {body}");
  }

  // The params' values are never echoed (they can be secrets), the
  // error says where and what was expected.
  for (path, body, secret, expected) in [
    (
      "/execute/ValidateString",
      json!({ "kind": "hunter2-secret", "input": "" }),
      "hunter2",
      "kind: unknown variant, expected one of",
    ),
    (
      "/write/UpdateUserAccess",
      json!({ "user_id": "x", "enabled": "hunter2-secret" }),
      "hunter2",
      "enabled: invalid type, expected a boolean",
    ),
    (
      "/execute/SealText",
      json!({ "text": 20231122 }),
      "20231122",
      "text: invalid type, expected a string",
    ),
  ] {
    let res = reqwest
      .post(format!("{}{path}", app.address))
      .header("authorization", &jwt)
      .json(&body)
      .send()
      .await
      .unwrap();
    assert_eq!(
      res.status(),
      StatusCode::UNPROCESSABLE_ENTITY,
      "{path}"
    );
    let text = res.text().await.unwrap();
    assert!(!text.contains(secret), "{path}: {text}");
    assert!(text.contains(expected), "{path}: {text}");
  }
}

#[tokio::test]
async fn admin_requests_need_an_admin() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let user = app.sign_up("user").await;
  let user_id = get_user(&user).await.id;
  let admin_id = get_user(&admin).await.id;

  let res = user.read(ListUsers {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = user
    .write(UpdateUserAccess {
      user_id: user_id.clone(),
      enabled: None,
      admin: Some(true),
      groups: None,
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = user
    .write(DeleteUser {
      user_id: admin_id.clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);

  let updated = admin
    .write(UpdateUserAccess {
      user_id: user_id.clone(),
      enabled: None,
      admin: None,
      groups: Some(vec!["writers".into(), "readers".into()]),
    })
    .await
    .unwrap();
  assert_eq!(updated.groups, ["readers", "writers"]);

  // Admins can't lock themselves out.
  for (enabled, admin_flag) in
    [(Some(false), None), (None, Some(false))]
  {
    let res = admin
      .write(UpdateUserAccess {
        user_id: admin_id.clone(),
        enabled,
        admin: admin_flag,
        groups: None,
      })
      .await;
    assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
  }
  let res = admin
    .write(DeleteUser {
      user_id: admin_id.clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);

  // A disabled user keeps a valid token, which the app api refuses.
  admin
    .write(UpdateUserAccess {
      user_id: user_id.clone(),
      enabled: Some(false),
      admin: None,
      groups: None,
    })
    .await
    .unwrap();
  let res = user.read(ListNotes::default()).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);

  // A deleted user's token is refused.
  admin.write(DeleteUser { user_id }).await.unwrap();
  let res = user.read(ListNotes::default()).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stats_are_cached_for_a_moment() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let first = admin.read(GetStats {}).await.unwrap();
  assert_eq!((first.users, first.notes), (1, 0));

  admin
    .write(CreateNote {
      title: "One".into(),
      content: String::new(),
    })
    .await
    .unwrap();
  // Rapid requests get the cached result.
  let cached = admin.read(GetStats {}).await.unwrap();
  assert_eq!(cached.notes, 0);
  assert_eq!(cached.computed_at, first.computed_at);

  tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
  let fresh = admin.read(GetStats {}).await.unwrap();
  assert_eq!(fresh.notes, 1);
  assert!(fresh.computed_at > first.computed_at);
}

#[tokio::test]
async fn sealed_text_is_bound_to_the_user() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let other = app.sign_up("other").await;

  let sealed = admin
    .execute(SealText {
      text: "for my eyes only".into(),
    })
    .await
    .unwrap()
    .sealed;
  assert!(!sealed.contains("for my eyes only"));
  // Random nonce and data key: sealing twice gives different results.
  let again = admin
    .execute(SealText {
      text: "for my eyes only".into(),
    })
    .await
    .unwrap()
    .sealed;
  assert_ne!(sealed, again);

  let opened = admin
    .execute(OpenText {
      sealed: sealed.clone(),
    })
    .await
    .unwrap();
  assert_eq!(opened.text, "for my eyes only");

  // The user id is authenticated with the ciphertext.
  let res = other
    .execute(OpenText {
      sealed: sealed.clone(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);

  // Tampered and malformed input errors, it never panics the server.
  let mut tampered = sealed.clone().into_bytes();
  let last = tampered.len() - 2;
  tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
  for sealed in [
    String::from_utf8(tampered).unwrap(),
    String::new(),
    ":::".to_string(),
    "a:b:c:d".to_string(),
    "$unknown$AAAA:AAAA:AAAA:AAAA".to_string(),
    format!("{sealed}:extra"),
    "€".repeat(5_000),
  ] {
    let res = admin.execute(OpenText { sealed }).await;
    assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
  }
  admin.read(GetVersion {}).await.unwrap();
}

#[tokio::test]
async fn string_validation_rules() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  for (kind, input, valid) in [
    (ValidateStringKind::Username, "user.name@example.com", true),
    (ValidateStringKind::Username, "user name", false),
    (ValidateStringKind::Username, "", false),
    (ValidateStringKind::VariableName, "MY_VAR_1", true),
    (ValidateStringKind::VariableName, "my-var", false),
    (
      ValidateStringKind::HttpUrl,
      "https://example.com/path?q=1",
      true,
    ),
    (ValidateStringKind::HttpUrl, "ftp://example.com", false),
    (ValidateStringKind::HttpUrl, "javascript:alert(1)", false),
    (ValidateStringKind::HttpUrl, "https://", false),
    // The auth server's rule: no credentials in a public url.
    (
      ValidateStringKind::HttpUrl,
      "https://user:hunter2@example.com",
      false,
    ),
    (ValidateStringKind::NoteTitle, "A title", true),
    (ValidateStringKind::NoteTitle, "line\nbreak", false),
  ] {
    let res = admin
      .execute(ValidateString {
        kind,
        input: input.into(),
      })
      .await
      .unwrap();
    assert_eq!(
      res.valid, valid,
      "{kind:?} {input:?}: {:?}",
      res.error
    );
    assert_eq!(res.error.is_none(), valid);
    // The input is never echoed.
    if let Some(error) = res.error {
      assert!(!error.contains("hunter2"), "{error}");
    }
  }
}

#[tokio::test]
async fn generated_key_pairs_are_unique_ed25519_keys() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let a = admin.execute(GenerateKeyPair {}).await.unwrap();
  let b = admin.execute(GenerateKeyPair {}).await.unwrap();
  assert_ne!(a.private_key, b.private_key);
  assert_ne!(a.public_key, b.public_key);

  // Base64 pkcs8 / spki der of an Ed25519 key, as signing keys are.
  for pair in [&a, &b] {
    assert_eq!(pair.private_key.len(), 64);
    assert!(pair.private_key.starts_with("MC4CAQAwBQYDK2VwBCIEI"));
    assert_eq!(pair.public_key.len(), 60);
    assert!(pair.public_key.starts_with("MCowBQYDK2VwAyEA"));
    let keys = mogh_pki::EncodedKeyPair::from_private_key(
      mogh_pki::PkiKind::Signature,
      &pair.private_key,
    )
    .unwrap();
    assert_eq!(keys.public(), pair.public_key);
  }

  // The server has no key of its own to serve: signed requests are
  // verified with the public key of the client.
  let info = admin.read(GetCoreInfo {}).await.unwrap();
  assert_eq!(info.app_name, "Example Test");
  let res = reqwest::get(format!("{}/public_key", app.address))
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
