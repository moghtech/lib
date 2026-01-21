use anyhow::{Context, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::api::login::{
  JwtOrTwoFactor, JwtResponse, LoginLocalUser, SignUpLocalUser,
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;

use crate::{AuthImpl, api::login::LoginArgs, session::Session};

pub async fn sign_up_local_user<I: AuthImpl + ?Sized>(
  auth: &I,
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

  if auth.registration_disabled() && !no_users_exist {
    return Err(
      anyhow!("User registration is disabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  auth.validate_username(&username)?;
  auth.validate_password(&password)?;

  let hashed_password =
    bcrypt::hash(password.as_bytes(), auth.local_auth_bcrypt_cost())?;

  let user_id = auth
    .sign_up_local_user(username, hashed_password, no_users_exist)
    .await?;

  auth.jwt_provider().encode_sub(&user_id).map_err(Into::into)
}

impl Resolve<LoginArgs> for SignUpLocalUser {
  async fn resolve(
    self,
    LoginArgs { auth, ip, .. }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    sign_up_local_user(auth.as_ref(), self.username, &self.password)
      .with_failure_rate_limit_using_ip(
        auth.general_rate_limiter(),
        &ip,
      )
      .await
  }
}

pub async fn login_local_user<I: AuthImpl + ?Sized>(
  auth: &I,
  session: &Session,
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

  let user = auth
    .find_user_with_username(username)
    .await?
    .context("Invalid login credentials")
    .status_code(StatusCode::UNAUTHORIZED)?;

  let hashed_password = user
    .hashed_password()
    .context("Invalid login credentials")
    .status_code(StatusCode::UNAUTHORIZED)?;

  let verified = bcrypt::verify(password, hashed_password)
    .context("Invalid login credentials")
    .status_code(StatusCode::UNAUTHORIZED)?;

  if !verified {
    return Err(
      anyhow!("Invalid login credentials")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let res = match (user.passkey(), user.totp_secret()) {
    // Passkey 2FA
    (Some(passkey), _) => {
      let provider = auth.passkey_provider().context(
            "No passkey provider available, possibly invalid 'host' config.",
          )?;
      let (response, state) = provider
        .start_passkey_authentication(passkey)
        .context("Failed to start passkey authentication flow")?;
      session.insert_passkey_login(user.id(), &state).await?;
      JwtOrTwoFactor::Passkey(response)
    }
    // TOTP 2FA
    (None, Some(_)) => {
      session.insert_totp_login_user_id(user.id()).await?;
      JwtOrTwoFactor::Totp {}
    }
    (None, None) => {
      JwtOrTwoFactor::Jwt(auth.jwt_provider().encode_sub(user.id())?)
    }
  };

  Ok(res)
}

impl Resolve<LoginArgs> for LoginLocalUser {
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    login_local_user(
      auth.as_ref(),
      &session,
      self.username,
      &self.password,
    )
    .with_failure_rate_limit_using_ip(
      auth.local_login_rate_limiter(),
      &ip,
    )
    .await
  }
}
