//! Supporter keys (`mogh_supporter`): the embedded api at
//! `/supporter`. The key in use is served signed for the browser's
//! nonce, never itself, and admins set or remove it over the write
//! api, which is used over the key of the config.

use example_client::{
  ExampleClient,
  supporter::{
    MAX_ICON_BYTES, SignedSupporterKey, SupporterBranding, Tier,
    api::{
      DeleteSupporterKey, GetSupporterBranding, GetSupporterKey,
      GetSupporterKeyInfo, SetSupporterBranding, SetSupporterKey,
      SupporterKeyInfo, SupporterKeySource,
    },
    fixture,
  },
};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

/// The fixture key as an operator would paste it: wrapped every 64
/// characters, with a trailing newline.
fn wrapped_key() -> String {
  let mut wrapped = String::new();
  for (i, c) in fixture::KEY.chars().enumerate() {
    if i > 0 && i % 64 == 0 {
      wrapped.push('\n');
    }
    wrapped.push(c);
  }
  wrapped.push('\n');
  wrapped
}

/// The instance private key: the third part of the key, the only
/// secret in it.
fn instance_private_key() -> &'static str {
  fixture::KEY.rsplit('.').next().unwrap()
}

/// The fixture key with another instance key (32 bytes of `0x07`):
/// it parses, but its root signature does not verify.
fn other_instance_key() -> String {
  let (rest, _) = fixture::KEY.rsplit_once('.').unwrap();
  format!("{rest}.BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc")
}

async fn spawn_with_key() -> TestApp {
  TestApp::spawn_with(TestAppOptions {
    config: json!({ "supporter_key": wrapped_key() }),
    ..Default::default()
  })
  .await
}

async fn signed_key(
  client: &ExampleClient,
) -> Option<SignedSupporterKey> {
  client
    .supporter_read(GetSupporterKey {
      nonce: fixture::NONCE.into(),
    })
    .await
    .unwrap()
}

async fn info(client: &ExampleClient) -> SupporterKeyInfo {
  client.supporter_read(GetSupporterKeyInfo {}).await.unwrap()
}

fn assert_acme(info: &SupporterKeyInfo) {
  let supporter = info.supporter.as_ref().expect("no supporter");
  assert_eq!(supporter.name, fixture::NAME);
  assert_eq!(supporter.tier, Tier::Organization);
  assert_eq!(supporter.since, fixture::SINCE);
  assert_eq!(supporter.covers, fixture::COVERS);
  assert_eq!(supporter.id, fixture::ID);
  assert_eq!(supporter.root_key_id, fixture::ROOT_KEY_ID);
  assert_eq!(supporter.app, "komodo");
  assert_eq!(supporter.version, 1);
}

#[tokio::test]
async fn without_a_key_the_response_is_null() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let user = app.sign_up("user").await;
  assert_eq!(signed_key(&admin).await, None);
  assert_eq!(signed_key(&user).await, None);
  // The nonce is checked first: a bad one is a 400 either way.
  let res = admin
    .supporter_read(GetSupporterKey {
      nonce: "not-a-nonce".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
  assert_eq!(
    info(&admin).await,
    SupporterKeyInfo {
      source: SupporterKeySource::None,
      config_key: false,
      supporter: None,
      problem: None,
    }
  );
  // The management requests are for admins.
  let res = user.supporter_read(GetSupporterKeyInfo {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = user
    .supporter_write(SetSupporterKey {
      key: fixture::KEY.into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  let res = user.supporter_write(DeleteSupporterKey {}).await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);
  assert_eq!(signed_key(&user).await, None);
  assert!(
    app.logs().contains("No supporter key configured"),
    "{}",
    app.logs()
  );
}

#[tokio::test]
async fn the_key_is_served_signed_for_the_nonce() {
  let app = spawn_with_key().await;
  let admin = app.sign_up("admin").await;

  // Exactly the answer the fixture pins.
  assert_eq!(signed_key(&admin).await, Some(fixture::response()));

  // Another nonce, another signature over the same key.
  let other = admin
    .supporter_read(GetSupporterKey {
      nonce: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".into(),
    })
    .await
    .unwrap()
    .unwrap();
  assert_eq!(other.payload, fixture::PAYLOAD);
  assert_eq!(other.payload_sig, fixture::PAYLOAD_SIG);
  assert_eq!(other.instance_public_key, fixture::INSTANCE_PUBLIC_KEY);
  assert_ne!(other.nonce_sig, fixture::NONCE_SIG);

  // What the management UI shows: never the key.
  let info = info(&admin).await;
  assert_eq!(info.source, SupporterKeySource::Config);
  assert!(info.config_key);
  assert_eq!(info.problem, None);
  assert_acme(&info);
  let json = serde_json::to_string(&info).unwrap();
  assert!(!json.contains(instance_private_key()), "{json}");

  // Authenticated like every request of the UI: no credentials, and
  // the variant path form.
  let res = app
    .client()
    .supporter_read(GetSupporterKey {
      nonce: fixture::NONCE.into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  let res = admin
    .reqwest
    .post(format!("{}/supporter/read/GetSupporterKey", app.address))
    .header(
      "authorization",
      match &admin.auth {
        example_client::ClientAuth::Jwt(jwt) => jwt.clone(),
        _ => unreachable!(),
      },
    )
    .json(&json!({ "nonce": fixture::NONCE }))
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
  assert_eq!(
    res.json::<SignedSupporterKey>().await.unwrap(),
    fixture::response()
  );

  // Logged at startup with what the badge shows, never the key.
  let logs = app.logs();
  assert!(
    logs.contains(
      "Supporter key configured for Acme Corp (organization), covers releases up to 2027-09-30"
    ),
    "{logs}"
  );
  let secret = instance_private_key();
  // The config wraps the key every 64 characters, which falls inside
  // this part once: its tail is contiguous.
  assert!(!logs.contains(&secret[12..]), "{logs}");
  assert!(!logs.contains(&secret[..12]), "{logs}");
}

#[tokio::test]
async fn the_nonce_must_be_32_bytes() {
  let app = spawn_with_key().await;
  let admin = app.sign_up("admin").await;
  for nonce in [
    // 31 and 33 bytes.
    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
    // Padding, standard base64, whitespace, empty.
    "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
    "+QEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    " AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    "",
  ] {
    let res = admin
      .supporter_read(GetSupporterKey {
        nonce: nonce.into(),
      })
      .await;
    let Err(e) = res else {
      panic!("{nonce:?} was accepted");
    };
    assert_eq!(
      example_client::error_status(&e),
      Some(StatusCode::BAD_REQUEST),
      "{nonce:?}: {e:#}"
    );
    assert!(format!("{e:#}").contains("nonce"), "{nonce:?}: {e:#}");
  }
}

#[tokio::test]
async fn the_key_comes_from_the_environment_or_a_file() {
  // The environment, with spaces in the key.
  let spaced = fixture::KEY.replace('.', " . ");
  let app = TestApp::spawn_with(TestAppOptions {
    env: vec![(
      "EXAMPLE_SUPPORTER_KEY".into(),
      format!(" {spaced} "),
    )],
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  assert_eq!(signed_key(&admin).await, Some(fixture::response()));

  // A file, like a docker secret.
  let dir = tempfile::tempdir().unwrap();
  let path = dir.path().join("supporter_key");
  std::fs::write(&path, wrapped_key()).unwrap();
  let app = TestApp::spawn_with(TestAppOptions {
    env: vec![(
      "EXAMPLE_SUPPORTER_KEY_FILE".into(),
      path.to_string_lossy().into_owned(),
    )],
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  assert_eq!(signed_key(&admin).await, Some(fixture::response()));
}

#[tokio::test]
async fn an_invalid_config_key_is_ignored_and_logged() {
  let (payload, rest) = fixture::KEY.split_once('.').unwrap();
  let (payload_sig, _) = rest.split_once('.').unwrap();
  for (key, reason) in [
    ("not.a.key", "base64url"),
    (fixture::KEY.rsplit_once('.').unwrap().0, "2 parts"),
    // A 31 byte seed.
    (
      &format!(
        "{payload}.{payload_sig}.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"
      ),
      "31 bytes, expected 32",
    ),
    (&format!("{}=.{rest}", payload), "base64url"),
  ] {
    let app = TestApp::spawn_with(TestAppOptions {
      config: json!({ "supporter_key": key }),
      ..Default::default()
    })
    .await;
    let admin = app.sign_up("admin").await;
    // The app runs as if no key were set.
    assert_eq!(signed_key(&admin).await, None, "{key}");
    let info = info(&admin).await;
    assert_eq!(info.source, SupporterKeySource::None, "{key}");
    // The config does set one, which an admin can replace.
    assert!(info.config_key, "{key}");
    let logs = app.logs();
    assert!(
      logs.contains("Ignoring the configured supporter key"),
      "{key}: {logs}"
    );
    assert!(logs.contains(reason), "{key}: {logs}");
    // With the reason, never the key.
    assert!(!logs.contains(key), "{key}: {logs}");
  }
}

#[tokio::test]
async fn admins_set_and_remove_the_key() {
  let mut app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let user = app.sign_up("user").await;

  // A key which does not parse is refused with the reason, and
  // nothing changes.
  let res = admin
    .supporter_write(SetSupporterKey {
      key: "not.a.key".into(),
    })
    .await;
  let Err(e) = res else {
    panic!("The key was accepted");
  };
  assert_eq!(
    example_client::error_status(&e),
    Some(StatusCode::BAD_REQUEST)
  );
  let text = format!("{e:#}");
  assert!(text.contains("Invalid supporter key"), "{text}");
  assert!(text.contains("base64url"), "{text}");
  assert_eq!(info(&admin).await.source, SupporterKeySource::None);

  // The key as pasted, wrapped: used right away, by everyone.
  let info_after = admin
    .supporter_write(SetSupporterKey { key: wrapped_key() })
    .await
    .unwrap();
  assert_eq!(info_after.source, SupporterKeySource::Stored);
  assert!(!info_after.config_key);
  assert_eq!(info_after.problem, None);
  assert_acme(&info_after);
  assert_eq!(info(&admin).await, info_after);
  assert_eq!(signed_key(&admin).await, Some(fixture::response()));
  assert_eq!(signed_key(&user).await, Some(fixture::response()));

  // Kept across restarts, encrypted at rest.
  app.restart().await;
  let admin = app.log_in("admin").await;
  assert_eq!(signed_key(&admin).await, Some(fixture::response()));
  assert_eq!(info(&admin).await.source, SupporterKeySource::Stored);
  let secret = instance_private_key();
  for file in ["data/example.db", "data/example.db-wal"] {
    let contents = std::fs::read(app.path(file)).unwrap_or_default();
    assert!(
      !contents
        .windows(secret.len())
        .any(|window| window == secret.as_bytes()),
      "The supporter key is stored in plain text in {file}"
    );
  }
  let logs = app.logs();
  assert!(logs.contains("Supporter key set by admin"), "{logs}");
  assert!(!logs.contains(secret), "{logs}");

  // Removed: no key again, for everyone, also after a restart.
  let removed =
    admin.supporter_write(DeleteSupporterKey {}).await.unwrap();
  assert_eq!(removed.source, SupporterKeySource::None);
  assert_eq!(removed.supporter, None);
  assert_eq!(signed_key(&admin).await, None);
  assert_eq!(signed_key(&user).await, None);
  // Removing nothing is fine.
  let removed =
    admin.supporter_write(DeleteSupporterKey {}).await.unwrap();
  assert_eq!(removed.source, SupporterKeySource::None);
  app.restart().await;
  let admin = app.log_in("admin").await;
  assert_eq!(signed_key(&admin).await, None);
  assert!(
    app.logs().contains("Supporter key removed by admin"),
    "{}",
    app.logs()
  );
}

#[tokio::test]
async fn a_stored_key_is_used_over_the_config_key() {
  // The config's key parses but does not verify: another instance
  // key than the root signed.
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "supporter_key": other_instance_key() }),
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let before = info(&admin).await;
  assert_eq!(before.source, SupporterKeySource::Config);
  assert!(before.config_key);
  // The payload still decodes, the problem says why there is no
  // badge: the server does not serve a key which does not verify.
  assert_acme(&before);
  let problem = before.problem.as_deref().expect("no problem");
  assert!(problem.contains("root signature"), "{problem}");
  assert_eq!(signed_key(&admin).await, None);
  assert!(
    app
      .logs()
      .contains("it is not served and the badge will not show"),
    "{}",
    app.logs()
  );

  // The stored key wins.
  let stored = admin
    .supporter_write(SetSupporterKey {
      key: fixture::KEY.into(),
    })
    .await
    .unwrap();
  assert_eq!(stored.source, SupporterKeySource::Stored);
  assert!(stored.config_key);
  assert_eq!(stored.problem, None);
  assert_eq!(signed_key(&admin).await, Some(fixture::response()));

  // Removing it falls back to the config's.
  let removed =
    admin.supporter_write(DeleteSupporterKey {}).await.unwrap();
  assert_eq!(removed.source, SupporterKeySource::Config);
  assert!(removed.config_key);
  assert!(removed.problem.is_some());
  assert_eq!(signed_key(&admin).await, None);
}

#[tokio::test]
async fn only_a_key_which_verifies_is_set_served_and_branded() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let user = app.sign_up("user").await;
  let try_set = |key: String| {
    let admin = &admin;
    async move { admin.supporter_write(SetSupporterKey { key }).await }
  };
  let set = |key: String| async move { try_set(key).await.unwrap() };
  let brand = || async {
    admin
      .supporter_write(SetSupporterBranding {
        branding: acme_branding(),
      })
      .await
  };
  // What a refused key leaves behind: the reason, never the key.
  let refused = |key: String, reason: &'static str| async move {
    let secret = key.rsplit('.').next().unwrap().to_string();
    let Err(e) = try_set(key).await else {
      panic!("A key was accepted: {reason}");
    };
    assert_eq!(
      example_client::error_status(&e),
      Some(StatusCode::BAD_REQUEST),
      "{reason}"
    );
    let text = format!("{e:#}");
    assert!(text.contains("Invalid supporter key"), "{text}");
    assert!(text.contains(reason), "{text}");
    assert!(!text.contains(&secret), "{text}");
  };

  // A key which does not verify is refused with the reason, like one
  // which does not parse, whatever its payload says: its root
  // signature, or the app it is for. Nothing is kept, served or
  // branded.
  refused(other_instance_key(), "root signature does not verify")
    .await;
  refused(
    fixture::mint("cicada", "Acme Corp", Tier::Organization),
    "is for `cicada`",
  )
  .await;
  assert_eq!(info(&admin).await.source, SupporterKeySource::None);
  assert_eq!(signed_key(&user).await, None);
  assert_eq!(status_of(brand().await), StatusCode::BAD_REQUEST);

  // An individual's key verifies and is served, without branding.
  let individual =
    set(fixture::mint("komodo", "Ada Lovelace", Tier::Individual))
      .await;
  assert_eq!(individual.problem, None);
  assert_eq!(individual.supporter.unwrap().tier, Tier::Individual);
  assert!(signed_key(&user).await.is_some());
  assert_eq!(status_of(brand().await), StatusCode::BAD_REQUEST);

  // A sponsor's is served and branded.
  let sponsor =
    set(fixture::mint("komodo", "Acme Corp", Tier::Sponsor)).await;
  assert_eq!(sponsor.problem, None);
  assert!(signed_key(&user).await.is_some());
  assert_eq!(brand().await.unwrap(), acme_branding());

  // A refused key changes nothing: the key in use stays in use.
  let served = signed_key(&user).await;
  refused(other_instance_key(), "root signature does not verify")
    .await;
  assert_eq!(
    status_of(try_set("not.a.key".into()).await),
    StatusCode::BAD_REQUEST
  );
  let still = info(&admin).await;
  assert_eq!(still.source, SupporterKeySource::Stored);
  assert_eq!(still.supporter.unwrap().tier, Tier::Sponsor);
  assert_eq!(still.problem, None);
  assert_eq!(signed_key(&user).await, served);
  assert!(!app.logs().contains(instance_private_key()));

  // It is verified again at startup.
  let mut app = app;
  app.restart().await;
  let user = app.log_in("user").await;
  assert!(signed_key(&user).await.is_some());
}

/// The branding of the tests: a path on the app, sized, with the
/// organization's link, as the home button.
fn acme_branding() -> SupporterBranding {
  SupporterBranding {
    icon: Some("/icons/acme.png".into()),
    icon_width: Some(120),
    icon_height: Some(32),
    link: Some("https://acme.example/about".into()),
    replace_home: true,
    hide_name: false,
    uppercase_name: true,
  }
}

async fn branding(client: &ExampleClient) -> SupporterBranding {
  client
    .supporter_read(GetSupporterBranding {})
    .await
    .unwrap()
}

#[tokio::test]
async fn branding_is_for_organization_keys_and_admins() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let user = app.sign_up("user").await;

  // The default, for every user: the topbar reads it.
  assert_eq!(branding(&user).await, SupporterBranding::default());
  let res =
    app.client().supporter_read(GetSupporterBranding {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);

  // Admins alone set it.
  let res = user
    .supporter_write(SetSupporterBranding {
      branding: acme_branding(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::FORBIDDEN);

  // Without the key of an organization there is nothing to brand.
  let res = admin
    .supporter_write(SetSupporterBranding {
      branding: acme_branding(),
    })
    .await;
  let Err(e) = res else {
    panic!("The branding was accepted without a key");
  };
  assert_eq!(
    example_client::error_status(&e),
    Some(StatusCode::BAD_REQUEST)
  );
  assert!(
    format!("{e:#}").contains("organizations and sponsors"),
    "{e:#}"
  );
  assert_eq!(branding(&admin).await, SupporterBranding::default());

  // The default is accepted whatever the key: it clears.
  let cleared = admin
    .supporter_write(SetSupporterBranding {
      branding: SupporterBranding::default(),
    })
    .await
    .unwrap();
  assert_eq!(cleared, SupporterBranding::default());
}

#[tokio::test]
async fn admins_set_the_branding_of_an_organization_key() {
  let mut app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let user = app.sign_up("user").await;
  admin
    .supporter_write(SetSupporterKey {
      key: fixture::KEY.into(),
    })
    .await
    .unwrap();

  // Set whole, the icon and the link trimmed, and read by every
  // user.
  let set = admin
    .supporter_write(SetSupporterBranding {
      branding: SupporterBranding {
        icon: Some("  /icons/acme.png\n".into()),
        link: Some(" https://acme.example/about\n".into()),
        ..acme_branding()
      },
    })
    .await
    .unwrap();
  assert_eq!(set, acme_branding());
  assert_eq!(branding(&user).await, acme_branding());
  assert!(
    app.logs().contains("link https://acme.example/about"),
    "{}",
    app.logs()
  );
  // The name in capitals, as the branding of the tests has it.
  assert!(set.uppercase_name);
  assert!(app.logs().contains("name in capitals: true"));

  // What is not valid is refused with the reason, never the icon,
  // and changes nothing.
  for (bad, reason) in [
    (
      SupporterBranding {
        icon: Some("javascript:alert(1)".into()),
        ..acme_branding()
      },
      "not an image url",
    ),
    (
      SupporterBranding {
        icon: Some("//evil.example/logo.png".into()),
        ..acme_branding()
      },
      "not an image url",
    ),
    (
      SupporterBranding {
        icon: Some("data:text/html;base64,AQID".into()),
        ..acme_branding()
      },
      "not a png",
    ),
    (
      SupporterBranding {
        icon_width: Some(4000),
        ..acme_branding()
      },
      "icon width is 4000 pixels",
    ),
    (
      SupporterBranding {
        icon_height: Some(1),
        ..acme_branding()
      },
      "icon height is 1 pixels",
    ),
    // Nothing but a web address is opened by a click on the badge.
    (
      SupporterBranding {
        link: Some("javascript:alert(1)".into()),
        ..acme_branding()
      },
      "not a web address",
    ),
    (
      SupporterBranding {
        link: Some("/settings".into()),
        ..acme_branding()
      },
      "not a web address",
    ),
  ] {
    let res = admin
      .supporter_write(SetSupporterBranding { branding: bad })
      .await;
    let Err(e) = res else {
      panic!("{reason} was accepted");
    };
    assert_eq!(
      example_client::error_status(&e),
      Some(StatusCode::BAD_REQUEST),
      "{reason}"
    );
    let text = format!("{e:#}");
    assert!(text.contains("Invalid supporter branding"), "{text}");
    assert!(text.contains(reason), "{text}");
    assert!(!text.contains("alert"), "{text}");
  }
  assert_eq!(branding(&admin).await, acme_branding());

  // An uploaded icon is the image as a data url, never logged.
  let image = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
  let uploaded = SupporterBranding {
    icon: Some(image.into()),
    icon_width: None,
    icon_height: Some(40),
    link: None,
    replace_home: false,
    hide_name: false,
    uppercase_name: false,
  };
  let set = admin
    .supporter_write(SetSupporterBranding {
      branding: uploaded.clone(),
    })
    .await
    .unwrap();
  assert_eq!(set, uploaded);
  let logs = app.logs();
  assert!(
    logs.contains("Supporter branding set by admin: icon uploaded"),
    "{logs}"
  );
  assert!(!logs.contains("iVBORw0KGgo"), "{logs}");

  // Kept across restarts.
  app.restart().await;
  let admin = app.log_in("admin").await;
  let user = app.log_in("user").await;
  assert_eq!(branding(&user).await, uploaded);

  // What is unset is left out of the answer.
  let res = admin
    .reqwest
    .post(format!(
      "{}/supporter/read/GetSupporterBranding",
      app.address
    ))
    .header(
      "authorization",
      match &admin.auth {
        example_client::ClientAuth::Jwt(jwt) => jwt.clone(),
        _ => unreachable!(),
      },
    )
    .json(&json!({}))
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), StatusCode::OK);
  assert_eq!(
    res.json::<serde_json::Value>().await.unwrap(),
    json!({
      "icon": image,
      "icon_height": 40,
      "replace_home": false,
      "hide_name": false,
      "uppercase_name": false,
    })
  );

  // The name is hidden behind an icon which includes it, on the
  // badge or as the home button, and never without an icon.
  let alone = SupporterBranding {
    hide_name: true,
    ..uploaded.clone()
  };
  let set = admin
    .supporter_write(SetSupporterBranding {
      branding: alone.clone(),
    })
    .await
    .unwrap();
  assert_eq!(set, alone);
  assert_eq!(branding(&user).await, alone);
  assert!(app.logs().contains("hides the name: true"));
  let set = admin
    .supporter_write(SetSupporterBranding {
      branding: SupporterBranding {
        icon: None,
        ..alone.clone()
      },
    })
    .await
    .unwrap();
  assert!(!set.hide_name, "nothing would name the supporter");
  assert_eq!(branding(&user).await.icon, None);
  // Back to the uploaded icon, with its name.
  admin
    .supporter_write(SetSupporterBranding {
      branding: uploaded.clone(),
    })
    .await
    .unwrap();

  // With the key removed the branding stays kept (the browser shows
  // it only for a key it verified), and only the default is accepted.
  admin.supporter_write(DeleteSupporterKey {}).await.unwrap();
  assert_eq!(branding(&admin).await, uploaded);
  let res = admin
    .supporter_write(SetSupporterBranding {
      branding: acme_branding(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::BAD_REQUEST);
  admin
    .supporter_write(SetSupporterBranding {
      branding: SupporterBranding::default(),
    })
    .await
    .unwrap();
  assert_eq!(branding(&admin).await, SupporterBranding::default());
}

/// An uploaded icon of `bytes` zero bytes, as its `data:` url.
fn icon_of(bytes: usize) -> String {
  // Zero bytes are `A`s in base64, padded to a multiple of four.
  let data = match bytes % 3 {
    0 => "A".repeat(bytes / 3 * 4),
    1 => format!("{}==", "A".repeat(bytes / 3 * 4 + 2)),
    _ => format!("{}=", "A".repeat(bytes / 3 * 4 + 3)),
  };
  format!("data:image/png;base64,{data}")
}

#[tokio::test]
async fn the_largest_uploaded_icon_fits_the_api() {
  let app = TestApp::spawn().await;
  let admin = app.sign_up("admin").await;
  let user = app.sign_up("user").await;
  admin
    .supporter_write(SetSupporterKey {
      key: fixture::KEY.into(),
    })
    .await
    .unwrap();

  // The largest icon goes through the request body limits, both
  // ways, and is kept whole.
  let largest = SupporterBranding {
    icon: Some(icon_of(MAX_ICON_BYTES)),
    ..Default::default()
  };
  let set = admin
    .supporter_write(SetSupporterBranding {
      branding: largest.clone(),
    })
    .await
    .unwrap();
  assert_eq!(set, largest);
  assert_eq!(branding(&user).await, largest);

  // One byte more is refused with the sizes, and changes nothing.
  let res = admin
    .supporter_write(SetSupporterBranding {
      branding: SupporterBranding {
        icon: Some(icon_of(MAX_ICON_BYTES + 1)),
        ..Default::default()
      },
    })
    .await;
  let Err(e) = res else {
    panic!("An icon over the limit was accepted");
  };
  assert_eq!(
    example_client::error_status(&e),
    Some(StatusCode::BAD_REQUEST)
  );
  let text = format!("{e:#}");
  assert!(
    text.contains(&format!(
      "The uploaded icon is {} bytes, the most is {MAX_ICON_BYTES}",
      MAX_ICON_BYTES + 1
    )),
    "{}",
    &text[..text.len().min(400)]
  );
  assert!(!text.contains("AAAAAAAA"));
  assert_eq!(branding(&user).await, largest);
  // Nothing of the image is logged.
  assert!(!app.logs().contains("AAAAAAAA"));
}
