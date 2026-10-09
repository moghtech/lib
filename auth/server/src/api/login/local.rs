use std::net::IpAddr;

use anyhow::{Context, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::api::login::{
  JwtOrTwoFactor, JwtResponse, LoginLocalUser, SignUpLocalUser,
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;
use tracing::{info, instrument, warn};

use crate::{
  AuthImpl, LoginKind,
  api::{
    check_new_username,
    login::{
      IssueToken, LoginArgs, SecondFactorChallenge,
      begin_second_factor, issue_login,
    },
  },
  bcrypt_pool::{bcrypt_hash, bcrypt_verify},
  middleware::check_user_cidr_whitelist,
  session::Session,
};

pub async fn sign_up_local_user<I: AuthImpl + ?Sized>(
  auth: &I,
  ip: IpAddr,
  username: String,
  password: &str,
) -> mogh_error::Result<JwtResponse> {
  if !auth.local_auth_enabled() {
    return Err(
      anyhow!("Local auth is not enabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let no_users_exist = auth.no_users_exist().await?;

  if auth.local_registration_disabled() && !no_users_exist {
    return Err(
      anyhow!("User registration is disabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  check_new_username(auth, &username)?;
  auth.validate_password(password)?;
  check_username_available(auth, &username, None).await?;

  let hashed_password =
    bcrypt_hash(password.as_bytes(), auth.local_auth_bcrypt_cost())
      .await?;

  let user_id = auth
    .sign_up_local_user(
      username.clone(),
      hashed_password,
      no_users_exist,
    )
    .await?;

  info!(user_id, username, "New user registration (Local)");

  // Signing up logs the new user in.
  let token = issue_login(
    auth,
    &user_id,
    &username,
    ip,
    LoginKind::Local,
    None,
    IssueToken::Now,
  )
  .await?;
  Ok(token.into())
}

/// Rejects a username another user already has with CONFLICT,
/// rather than leaving it to the app storage to fail with whatever
/// error (and status) a broken unique constraint produces.
///
/// `user_id` is the user taking the username, who may already have it.
///
/// Note. Two requests can still race past this check, so
/// app storage must keep usernames unique as well.
pub async fn check_username_available<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: Option<&str>,
) -> mogh_error::Result<()> {
  match auth.find_user_with_username(username.to_string()).await? {
    Some(existing) if Some(existing.id()) != user_id => Err(
      anyhow!("Username is already taken")
        .status_code(StatusCode::CONFLICT),
    ),
    _ => Ok(()),
  }
}

impl Resolve<LoginArgs> for SignUpLocalUser {
  #[instrument("SignUpLocalUser", skip_all, fields(ip = ip.to_string()))]
  async fn resolve(
    self,
    LoginArgs { auth, ip, .. }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    sign_up_local_user(
      auth.as_ref(),
      *ip,
      self.username,
      &self.password,
    )
    .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), ip)
    .await
  }
}

/// When there is no user or stored password hash to verify against,
/// still run bcrypt before failing so response timing does not
/// reveal whether the username exists.
async fn invalid_credentials_after_dummy_hash<
  I: AuthImpl + ?Sized,
>(
  auth: &I,
  password: &str,
) -> mogh_error::Error {
  let _ =
    bcrypt_hash(password.as_bytes(), auth.local_auth_bcrypt_cost())
      .await;
  anyhow!("Invalid login credentials")
    .status_code(StatusCode::UNAUTHORIZED)
}

pub async fn login_local_user<I: AuthImpl + ?Sized>(
  auth: &I,
  session: &Session,
  ip: IpAddr,
  username: String,
  password: &str,
) -> mogh_error::Result<JwtOrTwoFactor> {
  if !auth.local_auth_enabled() {
    return Err(
      anyhow!("Local auth is not enabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  auth.validate_username(&username)?;

  let Some(user) = auth.find_user_with_username(username).await?
  else {
    return Err(
      invalid_credentials_after_dummy_hash(auth, password).await,
    );
  };

  let Some(hashed_password) = user.hashed_password() else {
    return Err(
      invalid_credentials_after_dummy_hash(auth, password).await,
    );
  };

  // Passwords longer than bcrypt's 72 bytes (which the default
  // validation no longer accepts) still verify on their first 72.
  let verified = bcrypt_verify(password.as_bytes(), hashed_password)
    .await
    .context("Invalid login credentials")
    .status_code(StatusCode::UNAUTHORIZED)?;

  if !verified {
    return Err(
      anyhow!("Invalid login credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  // Checked after credential verification so the whitelist does not
  // reveal whether the username exists, and answered like a wrong
  // password so it does not confirm the password to whoever tries
  // it from elsewhere. The reason is in the log.
  if let Err(e) = check_user_cidr_whitelist(user.as_ref(), ip) {
    warn!(
      user_id = user.id(),
      %ip,
      "Local login refused outside the user's cidr whitelist | {:#}",
      e.error
    );
    return Err(
      anyhow!("Invalid login credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let res = match begin_second_factor(
    auth,
    session,
    user.as_ref(),
    &LoginKind::Local,
  )
  .await?
  {
    Some(SecondFactorChallenge::Passkey(response)) => {
      JwtOrTwoFactor::Passkey(response)
    }
    Some(SecondFactorChallenge::Totp) => JwtOrTwoFactor::Totp {},
    None => {
      let token = issue_login(
        auth,
        user.id(),
        user.username(),
        ip,
        LoginKind::Local,
        None,
        IssueToken::Now,
      )
      .await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "User logged in"
      );

      JwtOrTwoFactor::Jwt(token.into())
    }
  };

  Ok(res)
}

impl Resolve<LoginArgs> for LoginLocalUser {
  #[instrument(
    "LoginLocalUser",
    skip_all,
    fields(
      ip = ip.to_string(),
    )
  )]
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    // Strict: a burst of guesses sent at once is bounded
    // by the budget as well.
    login_local_user(
      auth.as_ref(),
      session,
      *ip,
      self.username,
      &self.password,
    )
    .with_strict_failure_rate_limit_using_ip(
      auth.local_login_rate_limiter(),
      ip,
    )
    .await
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Mutex;

  use crate::{
    DynFuture,
    provider::jwt::JwtProvider,
    test_support::{session, stub_auth_impl, test_jwt_provider},
    user::{AuthUserImpl, BoxAuthUser},
  };

  use super::*;
  use crate::Login;

  struct TestUser {
    id: String,
    username: String,
    hashed_password: Option<String>,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      &self.id
    }
    fn username(&self) -> &str {
      &self.username
    }
    fn hashed_password(&self) -> Option<&str> {
      self.hashed_password.as_deref()
    }
  }

  const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 7));

  #[derive(Default)]
  struct TestAuth {
    /// Its jwt provider has no secret: no token can be encoded.
    jwt_broken: bool,
    /// (id, username)
    users: Mutex<Vec<(String, String)>>,
    /// user id -> hashed password
    hashes: Mutex<std::collections::HashMap<String, String>>,
    logins: Mutex<Vec<Login>>,
    /// Refused by validate_new_username.
    reserved: Vec<&'static str>,
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::default()
    }
    stub_auth_impl!(get_user, handle_request_authentication);
    fn jwt_provider(&self) -> &JwtProvider {
      static BROKEN: std::sync::LazyLock<JwtProvider> =
        std::sync::LazyLock::new(|| JwtProvider::new(b"", 60_000));
      if self.jwt_broken {
        &BROKEN
      } else {
        test_jwt_provider()
      }
    }
    fn local_auth_bcrypt_cost(&self) -> u32 {
      4
    }
    fn validate_new_username(
      &self,
      username: &str,
    ) -> mogh_error::Result<()> {
      if self.reserved.contains(&username) {
        return Err(
          anyhow!("Username is reserved")
            .status_code(StatusCode::BAD_REQUEST),
        );
      }
      Ok(())
    }
    fn update_user_username(
      &self,
      user_id: String,
      username: String,
    ) -> DynFuture<mogh_error::Result<()>> {
      for user in self.users.lock().unwrap().iter_mut() {
        if user.0 == user_id {
          user.1 = username.clone();
        }
      }
      Box::pin(async { Ok(()) })
    }
    fn find_user_with_username(
      &self,
      username: String,
    ) -> DynFuture<mogh_error::Result<Option<BoxAuthUser>>> {
      let user = self
        .users
        .lock()
        .unwrap()
        .iter()
        .find(|(_, name)| name == &username)
        .map(|(id, username)| {
          Box::new(TestUser {
            id: id.clone(),
            username: username.clone(),
            hashed_password: self
              .hashes
              .lock()
              .unwrap()
              .get(id)
              .cloned(),
          }) as BoxAuthUser
        });
      Box::pin(async { Ok(user) })
    }
    fn sign_up_local_user(
      &self,
      username: String,
      hashed_password: String,
      _no_users_exist: bool,
    ) -> DynFuture<mogh_error::Result<String>> {
      let mut users = self.users.lock().unwrap();
      let id = format!("id-{}", users.len());
      users.push((id.clone(), username));
      self
        .hashes
        .lock()
        .unwrap()
        .insert(id.clone(), hashed_password);
      Box::pin(async { Ok(id) })
    }
    fn record_login(
      &self,
      login: Login,
    ) -> DynFuture<mogh_error::Result<()>> {
      self.logins.lock().unwrap().push(login);
      Box::pin(async { Ok(()) })
    }
  }

  /// A sign up and a verified password are logins the app hears
  /// about, a refused password is not.
  #[tokio::test]
  async fn test_login_is_recorded() {
    let auth = TestAuth::default();
    let token =
      sign_up_local_user(&auth, IP, "user".into(), "password-1")
        .await
        .unwrap();
    // Recorded with the expiry of the token it issued.
    let exp =
      auth.jwt_provider().decode_claims(&token.jwt).unwrap().exp;
    assert_eq!(auth.logins.lock().unwrap()[0].token_expires, exp);
    {
      let logins = auth.logins.lock().unwrap();
      assert_eq!(logins.len(), 1, "signing up logs the user in");
      assert_eq!(logins[0].user_id, "id-0");
      assert_eq!(logins[0].username, "user");
      assert_eq!(logins[0].ip, IP);
      assert_eq!(logins[0].kind, LoginKind::Local);
      assert!(logins[0].second_factor.is_none());
      // Stamped with the session token's expiry: the test
      // provider's 60s ttl from about now.
      let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
      let expires = logins[0].token_expires;
      assert!(
        (now + 55..=now + 65).contains(&expires),
        "expires {expires} should be about {now} + 60"
      );
    }
    let ip = IpAddr::from([127, 0, 0, 1]);
    let res = login_local_user(
      &auth,
      &session(),
      ip,
      "user".into(),
      "password-1",
    )
    .await
    .unwrap();
    assert!(matches!(res, JwtOrTwoFactor::Jwt(_)));
    {
      let logins = auth.logins.lock().unwrap();
      assert_eq!(logins.len(), 2);
      assert_eq!(logins[1].user_id, "id-0");
      assert_eq!(logins[1].ip, ip);
      assert_eq!(logins[1].kind, LoginKind::Local);
      assert!(logins[1].second_factor.is_none());
    }
    let err = login_local_user(
      &auth,
      &session(),
      ip,
      "user".into(),
      "wrong-password",
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert_eq!(auth.logins.lock().unwrap().len(), 2);
  }

  /// The token is encoded before the login is recorded: one which
  /// can't be (eg. the jwt secret is missing) fails the login without
  /// recording one the user never got.
  #[tokio::test]
  async fn test_a_token_which_fails_records_no_login() {
    let mut auth = TestAuth::default();
    sign_up_local_user(&auth, IP, "user".into(), "password-1")
      .await
      .unwrap();
    auth.jwt_broken = true;
    let err = login_local_user(
      &auth,
      &session(),
      IP,
      "user".into(),
      "password-1",
    )
    .await
    .unwrap_err();
    assert!(err.status.is_server_error());
    let err =
      sign_up_local_user(&auth, IP, "other".into(), "password-1")
        .await
        .unwrap_err();
    assert!(err.status.is_server_error());
    // Only the first sign up.
    assert_eq!(auth.logins.lock().unwrap().len(), 1);
  }

  #[tokio::test]
  async fn test_sign_up_rejects_taken_username_with_conflict() {
    let auth = TestAuth::default();
    sign_up_local_user(&auth, IP, "user".into(), "password-1")
      .await
      .unwrap();
    let err =
      sign_up_local_user(&auth, IP, "user".into(), "password-2")
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);
    // The app storage was never asked to create the duplicate.
    assert_eq!(auth.users.lock().unwrap().len(), 1);
  }

  /// A name the app keeps for itself can't be taken, by a sign up or
  /// a rename, while the user who had it before keeps logging in.
  #[tokio::test]
  async fn test_new_usernames_pass_validate_new_username() {
    use crate::api::manage::local::update_username;

    let mut auth = TestAuth::default();
    // Taken before the app reserved it.
    sign_up_local_user(&auth, IP, "System".into(), "password-1")
      .await
      .unwrap();
    sign_up_local_user(&auth, IP, "user".into(), "password-1")
      .await
      .unwrap();
    auth.reserved = vec!["System", "Action"];

    let err =
      sign_up_local_user(&auth, IP, "Action".into(), "password-1")
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(
      err.error.to_string().contains("reserved"),
      "{:#}",
      err.error
    );
    assert_eq!(auth.users.lock().unwrap().len(), 2);

    let err =
      update_username(&auth, "user", "id-1".into(), "Action".into())
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    update_username(&auth, "user", "id-1".into(), "user-2".into())
      .await
      .unwrap();
    assert_eq!(auth.users.lock().unwrap()[1].1, "user-2");

    // Its owner logs in with it all the same.
    let res = login_local_user(
      &auth,
      &session(),
      IP,
      "System".into(),
      "password-1",
    )
    .await
    .unwrap();
    assert!(matches!(res, JwtOrTwoFactor::Jwt(_)));
  }

  #[tokio::test]
  async fn test_check_username_available() {
    let auth = TestAuth::default();
    sign_up_local_user(&auth, IP, "user".into(), "password-1")
      .await
      .unwrap();
    // Free
    check_username_available(&auth, "other", None)
      .await
      .unwrap();
    // The user already has it
    check_username_available(&auth, "user", Some("id-0"))
      .await
      .unwrap();
    // Somebody else has it
    let err = check_username_available(&auth, "user", Some("id-1"))
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);
  }
}
