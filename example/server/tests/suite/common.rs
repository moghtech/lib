//! Spawns the example server binary (and a mock identity provider)
//! with its own port, database and config for every test.

use std::{
  net::TcpListener,
  path::PathBuf,
  process::{Child, Command, Stdio},
  time::{Duration, SystemTime, UNIX_EPOCH},
};

use example_client::{
  ClientAuth, ExampleClient,
  auth::api::{
    login::{
      JwtOrTwoFactor, JwtResponse, LoginLocalUser, SignUpLocalUser,
    },
    token::{
      TokenExchangeError, TokenExchangeRequest, TokenExchangeResponse,
    },
  },
  entities::User,
  error_status,
};
use example_mock_idp::{IdpUser, MockIdp};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tempfile::TempDir;

pub const PASSWORD: &str = "correct-horse-battery";

pub struct TestAppOptions {
  /// The config file contents, merged over the defaults of the harness.
  pub config: Value,
  /// Extra environment variables, which override the config file.
  pub env: Vec<(String, String)>,
  /// Configure the mock idp as the static `oidc` provider.
  pub static_oidc: bool,
  /// (max attempts, window seconds). Disabled if `None`.
  pub rate_limit: Option<(usize, u64)>,
}

impl Default for TestAppOptions {
  fn default() -> Self {
    Self {
      config: json!({}),
      env: Vec::new(),
      static_oidc: false,
      rate_limit: None,
    }
  }
}

pub struct TestApp {
  pub address: String,
  pub idp: MockIdp,
  pub dir: TempDir,
  port: u16,
  env: Vec<(String, String)>,
  child: Child,
}

impl Drop for TestApp {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
    if std::thread::panicking() {
      eprintln!("===== SERVER LOG =====\n{}", self.logs());
    }
  }
}

fn free_port() -> u16 {
  TcpListener::bind("127.0.0.1:0")
    .unwrap()
    .local_addr()
    .unwrap()
    .port()
}

fn spawn_server(
  dir: &TempDir,
  port: u16,
  env: &[(String, String)],
) -> Child {
  let log = std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(dir.path().join("server.log"))
    .unwrap();
  Command::new(env!("CARGO_BIN_EXE_example_server"))
    .current_dir(dir.path())
    .env_clear()
    .env("EXAMPLE_CONFIG_PATHS", dir.path().join("config"))
    // The environment overrides the config file.
    .env("EXAMPLE_HOST", format!("http://127.0.0.1:{port}"))
    .env("EXAMPLE_PORT", port.to_string())
    .env("EXAMPLE_BIND_IP", "127.0.0.1")
    // Secrets are passed as files, like docker secrets.
    .env(
      "EXAMPLE_JWT_SECRET_FILE",
      dir.path().join("secrets/jwt_secret"),
    )
    .envs(env.iter().cloned())
    .stdout(Stdio::from(log.try_clone().unwrap()))
    .stderr(Stdio::from(log))
    .spawn()
    .expect("Failed to spawn example server")
}

fn merge(base: &mut Value, overrides: Value) {
  match (base, overrides) {
    (Value::Object(base), Value::Object(overrides)) => {
      for (key, value) in overrides {
        merge(base.entry(key).or_insert(Value::Null), value);
      }
    }
    (base, overrides) => *base = overrides,
  }
}

impl TestApp {
  pub async fn spawn() -> TestApp {
    Self::spawn_with(TestAppOptions::default()).await
  }

  pub async fn spawn_with(options: TestAppOptions) -> TestApp {
    let idp = MockIdp::spawn(0).await.unwrap();
    Self::spawn_with_idp(options, idp).await
  }

  pub async fn spawn_with_idp(
    options: TestAppOptions,
    idp: MockIdp,
  ) -> TestApp {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let address = format!("http://127.0.0.1:{port}");

    let jwt_secret_path = dir.path().join("secrets/jwt_secret");
    std::fs::create_dir_all(jwt_secret_path.parent().unwrap())
      .unwrap();
    // 32 bytes at least, or the server refuses to start.
    std::fs::write(
      &jwt_secret_path,
      "test-jwt-secret-of-the-example-api-suite\n",
    )
    .unwrap();

    let mut config = json!({
      "title": "Example Test",
      "host": "http://wrong-host-overridden-by-env",
      "database_path": dir.path().join("data/example.db"),
      "bcrypt_cost": 4,
      "auth_rate_limit_disabled": options.rate_limit.is_none(),
      // Plain text, the tests read the logs back.
      "logging": { "level": "debug", "ansi": false },
    });
    if let Some((max_attempts, window)) = options.rate_limit {
      merge(
        &mut config,
        json!({
          "auth_rate_limit_max_attempts": max_attempts,
          "auth_rate_limit_window_seconds": window,
        }),
      );
    }
    if options.static_oidc {
      merge(
        &mut config,
        json!({
          "oidc": {
            "enabled": true,
            "provider": idp.issuer,
            "client_id": idp.client_id,
            "client_secret": idp.client_secret,
          }
        }),
      );
    }
    merge(&mut config, options.config);
    let config_dir = dir.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
      config_dir.join("core.config.json"),
      serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();

    let child = spawn_server(&dir, port, &options.env);
    let mut app = TestApp {
      address,
      idp,
      dir,
      port,
      env: options.env,
      child,
    };
    // The port was free when it was picked, but tests running in
    // parallel can pick the same one before the server binds it.
    for _ in 0..5 {
      match app.wait_until_ready().await {
        Ok(()) => return app,
        Err(e) if e.contains("Address already in use") => {
          app.port = free_port();
          app.address = format!("http://127.0.0.1:{}", app.port);
          app.child = spawn_server(&app.dir, app.port, &app.env);
        }
        Err(e) => panic!("{e}"),
      }
    }
    panic!("Failed to find a free port for the example server");
  }

  /// Stops the server and starts it again on the same database and config.
  pub async fn restart(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
    // The same port: tokens are issued for the host, which includes it.
    self.child = spawn_server(&self.dir, self.port, &self.env);
    if let Err(e) = self.wait_until_ready().await {
      panic!("{e}");
    }
  }

  async fn wait_until_ready(&mut self) -> Result<(), String> {
    let reqwest = reqwest::Client::new();
    for _ in 0..200 {
      if let Some(status) = self.child.try_wait().unwrap() {
        return Err(format!(
          "Example server exited with {status}\n{}",
          self.logs()
        ));
      }
      if reqwest
        .get(format!("{}/version", self.address))
        .send()
        .await
        .is_ok_and(|res| res.status().is_success())
      {
        return Ok(());
      }
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!(
      "Example server did not become ready\n{}",
      self.logs()
    ))
  }

  pub fn logs(&self) -> String {
    std::fs::read_to_string(self.dir.path().join("server.log"))
      .unwrap_or_default()
  }

  pub fn path(&self, path: &str) -> PathBuf {
    self.dir.path().join(path)
  }

  /// The host of the app, as requests with a signing key are signed
  /// for it.
  pub fn host(&self) -> String {
    example_client::auth::signature::url_host(&self.address).unwrap()
  }

  /// A client without credentials and its own cookie jar (session).
  pub fn client(&self) -> ExampleClient {
    ExampleClient::new(&self.address, ClientAuth::None).unwrap()
  }

  /// Signs up a user and returns a client authenticated as them.
  /// The first user to sign up is the admin.
  pub async fn sign_up(&self, username: &str) -> ExampleClient {
    let client = self.client();
    let JwtResponse { jwt } = client
      .login(SignUpLocalUser {
        username: username.to_string(),
        password: PASSWORD.to_string(),
      })
      .await
      .unwrap();
    client.with_auth(ClientAuth::Jwt(jwt))
  }

  /// Logs in a user without a second factor.
  pub async fn log_in(&self, username: &str) -> ExampleClient {
    let client = self.client();
    let res = client
      .login(LoginLocalUser {
        username: username.to_string(),
        password: PASSWORD.to_string(),
      })
      .await
      .unwrap();
    let JwtOrTwoFactor::Jwt(JwtResponse { jwt }) = res else {
      panic!("Expected a jwt, got {res:?}");
    };
    client.with_auth(ClientAuth::Jwt(jwt))
  }

  pub fn add_idp_user(&self, username: &str, groups: &[&str]) {
    self.idp.upsert_user(IdpUser {
      sub: format!("{username}-sub"),
      preferred_username: Some(username.to_string()),
      email: Some(format!("{username}@example.com")),
      picture: Some(format!("https://example.com/{username}.png")),
      groups: Some(groups.iter().map(|g| g.to_string()).collect()),
      groups_in_user_info_only: false,
    });
  }

  /// RFC 8693 token exchange at `/auth/token`.
  pub async fn token_exchange(
    &self,
    token: &str,
    token_type: &str,
  ) -> Result<TokenExchangeResponse, (StatusCode, TokenExchangeError)>
  {
    let res = example_client::auth::request::token_exchange(
      &reqwest::Client::new(),
      &format!("{}/auth", self.address),
      &TokenExchangeRequest {
        subject_token_type: token_type.to_string(),
        ..TokenExchangeRequest::id_token(token)
      },
    )
    .await;
    res.map_err(|e| {
      let status = error_status(&e).expect("Error without status");
      let error = e
        .downcast::<TokenExchangeError>()
        .expect("Error is not an oauth error");
      (status, error)
    })
  }
}

/// Follows the redirects of an external login through the mock idp,
/// which logs in its `auto_user`. Returns the final url the browser
/// would land on at the app (eg. `...?redeem_ready=true`).
pub async fn follow_external_flow(
  client: &ExampleClient,
  start_url: &str,
) -> reqwest::Url {
  let mut url = reqwest::Url::parse(start_url).unwrap();
  let app_origin =
    reqwest::Url::parse(&client.address).unwrap().origin();
  for _ in 0..10 {
    let res = client.reqwest.get(url.clone()).send().await.unwrap();
    if !res.status().is_redirection() {
      panic!(
        "Expected a redirect from {url}, got {} | {}",
        res.status(),
        res.text().await.unwrap_or_default()
      );
    }
    let location =
      res.headers().get("location").unwrap().to_str().unwrap();
    let next = url.join(location).unwrap();
    // Back at the app, but not at the auth api: the flow is done.
    if next.origin() == app_origin
      && !next.path().starts_with("/auth")
    {
      return next;
    }
    url = next;
  }
  panic!("Too many redirects");
}

/// The reason a failed external login / link came back to the app with.
pub fn external_error(landed: &reqwest::Url, param: &str) -> String {
  landed
    .query_pairs()
    .find(|(key, _)| key == param)
    .map(|(_, value)| value.to_string())
    .unwrap_or_else(|| panic!("No {param} on {landed}"))
}

pub fn status_of<T>(res: anyhow::Result<T>) -> StatusCode {
  // Responses with secrets have no Debug.
  let Err(e) = res else {
    panic!("Expected the request to fail");
  };
  error_status(&e).unwrap_or_else(|| panic!("No status on {e:#}"))
}

pub async fn get_user(client: &ExampleClient) -> User {
  client
    .read(example_client::api::read::GetUser {})
    .await
    .unwrap()
}

pub fn unix_timestamp_ms() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_millis() as u64
}

/// The TOTP for an `otpauth://` enrollment uri.
pub fn totp_from_uri(uri: &str) -> totp_rs::Totp {
  let url = reqwest::Url::parse(uri).unwrap();
  let secret = url
    .query_pairs()
    .find(|(key, _)| key == "secret")
    .map(|(_, secret)| secret.to_string())
    .expect("No secret in otpauth uri");
  let secret = data_encoding_base32_decode(&secret);
  totp_rs::Builder::new()
    .with_algorithm(totp_rs::Algorithm::SHA1)
    .with_digits(6)
    .with_skew(1)
    .with_step_duration(30)
    .with_secret(secret)
    .build()
    .unwrap()
}

/// RFC 4648 base32 without padding.
fn data_encoding_base32_decode(input: &str) -> Vec<u8> {
  const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let mut bits = 0u32;
  let mut bit_count = 0;
  let mut out = Vec::new();
  for c in input.trim_end_matches('=').bytes() {
    let value = ALPHABET
      .iter()
      .position(|a| *a == c.to_ascii_uppercase())
      .expect("Invalid base32") as u32;
    bits = (bits << 5) | value;
    bit_count += 5;
    if bit_count >= 8 {
      bit_count -= 8;
      out.push((bits >> bit_count) as u8);
      bits &= (1 << bit_count) - 1;
    }
  }
  out
}

/// The `name=value` of the session cookie a response sets, if any.
fn set_session_cookie(res: &reqwest::Response) -> Option<String> {
  res
    .headers()
    .get_all("set-cookie")
    .iter()
    .map(|value| value.to_str().unwrap())
    .find(|cookie| {
      cookie.starts_with("id=") || cookie.starts_with("__Host-id=")
    })
    .map(|cookie| cookie.split(';').next().unwrap().to_string())
}

/// `name=value` of the session cookie a response sets.
pub fn session_cookie(res: &reqwest::Response) -> String {
  set_session_cookie(res).expect("No session cookie set")
}

pub fn sets_session_cookie(res: &reqwest::Response) -> bool {
  set_session_cookie(res).is_some()
}
