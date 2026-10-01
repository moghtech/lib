//! Startup, configuration loading, static UI hosting and app tokens.

use std::{
  os::unix::fs::PermissionsExt as _,
  process::{Command, Stdio},
  time::Duration,
};

use example_client::{ClientAuth, api::read::GetCoreInfo};
use reqwest::StatusCode;
use serde_json::json;

use crate::common::*;

#[tokio::test]
async fn serves_the_ui_with_client_side_routing() {
  let ui = tempfile::tempdir().unwrap();
  std::fs::write(
    ui.path().join("index.html"),
    "<html><body>example ui</body></html>",
  )
  .unwrap();
  std::fs::create_dir_all(ui.path().join("assets")).unwrap();
  std::fs::write(ui.path().join("assets/app.js"), "console.log(1)")
    .unwrap();
  // Next to the ui directory, must never be served.
  let secret = ui.path().parent().unwrap().join("outside-secret.txt");
  std::fs::write(&secret, "outside").unwrap();

  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "ui_path": ui.path() }),
    ..Default::default()
  })
  .await;
  let reqwest = reqwest::Client::new();
  let get = |path: &'static str| {
    let reqwest = reqwest.clone();
    let url = format!("{}{path}", app.address);
    async move { reqwest.get(url).send().await.unwrap() }
  };

  let index = get("/").await;
  assert_eq!(index.status(), StatusCode::OK);
  let etag = index.headers()["etag"].to_str().unwrap().to_string();
  assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
  assert!(index.text().await.unwrap().contains("example ui"));

  // Paths routed by the ui get the index, with 200 so it is cached.
  let route = get("/notes/123?tab=1").await;
  assert_eq!(route.status(), StatusCode::OK);
  assert_eq!(route.headers()["etag"], etag.as_str());
  // Revalidated on every load, so an upgrade is picked up.
  assert_eq!(route.headers()["cache-control"], "no-cache");
  assert!(route.text().await.unwrap().contains("example ui"));
  // Revalidating gets the full index, never an empty 200.
  for (name, value) in
    [("if-none-match", "*"), ("if-none-match", etag.as_str())]
  {
    let revalidated = reqwest
      .get(format!("{}/notes/123", app.address))
      .header(name, value)
      .send()
      .await
      .unwrap();
    assert_eq!(revalidated.status(), StatusCode::OK, "{value}");
    assert!(
      revalidated.text().await.unwrap().contains("example ui"),
      "{value}"
    );
  }

  let asset = get("/assets/app.js").await;
  assert_eq!(asset.status(), StatusCode::OK);
  assert_eq!(asset.text().await.unwrap(), "console.log(1)");

  // The api still answers on its own paths.
  assert_eq!(get("/version").await.text().await.unwrap(), "0.1.0");
  // (Not the ui: authentication comes first on the api paths.)
  assert_eq!(get("/read").await.status(), StatusCode::UNAUTHORIZED);

  // Nothing outside of the ui directory is served.
  for path in [
    "/../outside-secret.txt",
    "/%2e%2e/outside-secret.txt",
    "/assets/../../outside-secret.txt",
    "/assets/%2e%2e/%2e%2e/outside-secret.txt",
  ] {
    // Raw, as reqwest would normalize the dots away.
    let body = raw_get(&app.address, path).await;
    assert!(!body.contains("outside"), "{path}: {body}");
  }
  std::fs::remove_file(secret).unwrap();
}

/// A GET which sends the path exactly as given.
async fn raw_get(address: &str, path: &str) -> String {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  let host = address.trim_start_matches("http://");
  let mut stream =
    tokio::net::TcpStream::connect(host).await.unwrap();
  stream
    .write_all(
      format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
      )
      .as_bytes(),
    )
    .await
    .unwrap();
  let mut response = String::new();
  let _ = tokio::time::timeout(
    Duration::from_secs(5),
    stream.read_to_string(&mut response),
  )
  .await;
  response
}

#[tokio::test]
async fn secrets_on_disk_are_private_and_config_sources_are_merged() {
  let app = TestApp::spawn().await;
  let file = "data/example.encryption.key";
  let mode = std::fs::metadata(app.path(file))
    .unwrap()
    .permissions()
    .mode();
  assert_eq!(mode & 0o777, 0o600, "{file}");
  // The title comes from the config file, the host from
  // the environment (which wins over the file).
  let admin = app.sign_up("admin").await;
  let info = admin.read(GetCoreInfo {}).await.unwrap();
  assert_eq!(info.app_name, "Example Test");
  assert_eq!(info.host, app.address);
}

#[tokio::test]
async fn config_files_are_layered_and_interpolated() {
  let extra = tempfile::tempdir().unwrap();
  // Later paths override earlier ones, in any supported format.
  std::fs::write(
    extra.path().join("override.config.toml"),
    "title = \"${EXAMPLE_TEST_TITLE} (toml)\"\n",
  )
  .unwrap();
  std::fs::write(
    extra.path().join("ignored.txt"),
    "title = \"not a config file\"\n",
  )
  .unwrap();

  let dir = tempfile::tempdir().unwrap();
  let base = dir.path().join("base.config.yaml");
  std::fs::write(
    &base,
    "title: From yaml\nlock_login_credentials_for: [demo]\nbcrypt_cost: 4\n",
  )
  .unwrap();

  let app = TestApp::spawn_with(TestAppOptions {
    env: vec![
      (
        "EXAMPLE_CONFIG_PATHS".into(),
        format!("{},{}", base.display(), extra.path().display()),
      ),
      ("EXAMPLE_TEST_TITLE".into(), "Interpolated".into()),
      ("EXAMPLE_AUTH_RATE_LIMIT_DISABLED".into(), "true".into()),
    ],
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let info = admin.read(GetCoreInfo {}).await.unwrap();
  assert_eq!(info.app_name, "Interpolated (toml)");
  // The yaml file still applies where the toml one says nothing.
  let demo = app.sign_up("demo").await;
  let res = demo
    .manage(example_client::auth::api::manage::UpdatePassword {
      password: "another-password".into(),
    })
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

/// Runs the server with a config it has to refuse, and returns its output.
fn refused_startup(env: &[(&str, &str)]) -> String {
  let dir = tempfile::tempdir().unwrap();
  let mut child = Command::new(env!("CARGO_BIN_EXE_example_server"))
    .current_dir(dir.path())
    .env_clear()
    .env("EXAMPLE_PORT", "0")
    .env("EXAMPLE_BIND_IP", "127.0.0.1")
    .envs(env.iter().copied())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
  for _ in 0..100 {
    if child.try_wait().unwrap().is_some() {
      let output = child.wait_with_output().unwrap();
      assert!(!output.status.success(), "{env:?} was accepted");
      return format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
      );
    }
    std::thread::sleep(Duration::from_millis(50));
  }
  let _ = child.kill();
  panic!("The server kept running with {env:?}");
}

#[test]
fn invalid_config_fails_the_startup() {
  for (env, expected) in [
    (
      vec![("EXAMPLE_TRUSTED_PROXIES", "10.0.0.0/8,not-a-range")],
      "trusted_proxies",
    ),
    (
      vec![("EXAMPLE_AUTH_RATE_LIMIT_MAX_ATTEMPTS", "0")],
      "auth_rate_limit_max_attempts",
    ),
    (
      vec![("EXAMPLE_ENCRYPTION_KEY", "too-short")],
      "encryption_key",
    ),
    (vec![("EXAMPLE_PORT", "not-a-port")], "environment"),
  ] {
    let output = refused_startup(&env);
    assert!(
      output.to_lowercase().contains(expected),
      "{env:?}: {output}"
    );
    // Secrets from the environment aren't printed back.
    assert!(!output.contains("too-short"), "{output}");
  }
}

#[tokio::test]
async fn app_tokens_are_bound_to_the_secret_and_expire() {
  let app = TestApp::spawn_with(TestAppOptions {
    env: vec![("EXAMPLE_JWT_TTL_SECONDS".into(), "1".into())],
    ..Default::default()
  })
  .await;
  let admin = app.sign_up("admin").await;
  let user_id = get_user(&admin).await.id;
  let ClientAuth::Jwt(jwt) = &admin.auth else {
    unreachable!()
  };

  // Tampering with the claims breaks the signature.
  let mut parts =
    jwt.split('.').map(str::to_string).collect::<Vec<_>>();
  parts[1] = parts[1].replace(
    &parts[1][..4],
    &parts[1][..4].chars().rev().collect::<String>(),
  );
  let tampered = admin.with_auth(ClientAuth::Jwt(parts.join(".")));
  let res = tampered.read(GetCoreInfo {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);

  // A token of another deployment (other secret), for the same user id.
  let other = TestApp::spawn().await;
  let other_admin = other.sign_up("admin").await;
  let res = admin
    .with_auth(other_admin.auth.clone())
    .read(GetCoreInfo {})
    .await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
  assert!(!user_id.is_empty());

  // Expired tokens are accepted for 10 more seconds (clock skew).
  admin.read(GetCoreInfo {}).await.unwrap();
  // (The token carries whole seconds, leave room for rounding.)
  tokio::time::sleep(Duration::from_millis(12_500)).await;
  let res = admin.read(GetCoreInfo {}).await;
  assert_eq!(status_of(res), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logs_as_json_when_configured() {
  let app = TestApp::spawn_with(TestAppOptions {
    config: json!({ "logging": { "stdio": "Json", "level": "info" } }),
    ..Default::default()
  })
  .await;
  app.sign_up("admin").await;
  let logs = app.logs();
  let mut lines = 0;
  for line in logs.lines().filter(|line| !line.trim().is_empty()) {
    let parsed: serde_json::Value = serde_json::from_str(line)
      .unwrap_or_else(|e| panic!("Not json: {line} | {e}"));
    assert!(parsed["level"].is_string(), "{line}");
    lines += 1;
  }
  assert!(lines > 3, "{logs}");
  // Debug logs are filtered at info level.
  assert!(!logs.contains("DEBUG"), "{logs}");
}
