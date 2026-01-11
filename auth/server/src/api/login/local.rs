use anyhow::{Context, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::api::login::{
  JwtOrTwoFactor, JwtResponse, LoginLocalUser, SignUpLocalUser,
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_rate_limit::WithFailureRateLimit;
use resolver_api::Resolve;

use crate::BoxAuthImpl;

#[utoipa::path(
  post,
  path = "/login/SignUpLocalUser",
  description = "Sign up a local user",
  request_body(content = LoginLocalUser),
  responses(
    (status = 200, description = "Authentication JWT", body = JwtResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn sign_up_local_user() {}

impl Resolve<BoxAuthImpl> for SignUpLocalUser {
  async fn resolve(
    self,
    auth: &BoxAuthImpl,
  ) -> Result<Self::Response, Self::Error> {
    async {
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

      auth.validate_username(&self.username)?;
      auth.validate_password(&self.password)?;

      let hashed_password = bcrypt::hash(
        self.password.as_bytes(),
        auth.local_auth_bcrypt_cost(),
      )?;

      let user_id = auth
        .sign_up_local_user(
          self.username,
          hashed_password,
          no_users_exist,
        )
        .await?;

      auth.jwt_provider().encode_sub(&user_id).map_err(Into::into)
    }
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &auth.client().ip,
    )
    .await
  }
}

#[utoipa::path(
  post,
  path = "/login/LoginLocalUser",
  description = "Login as a local user",
  request_body(content = LoginLocalUser),
  responses(
    (status = 200, description = "JWT auth token or 2 factor login continuation", body = JwtOrTwoFactor),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn login_local_user() {}

impl Resolve<BoxAuthImpl> for LoginLocalUser {
  async fn resolve(
    self,
    auth: &BoxAuthImpl,
  ) -> Result<Self::Response, Self::Error> {
    async {
      if !auth.local_auth_enabled() {
        return Err(
          anyhow!("Local auth is not enabled")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      auth.validate_username(&self.username)?;

      let user = auth
        .find_user_with_username(self.username)
        .await?
        .context("Invalid login credentials")
        .status_code(StatusCode::UNAUTHORIZED)?;

      let hashed_password = user
        .hashed_password()
        .context("Invalid login credentials")
        .status_code(StatusCode::UNAUTHORIZED)?;

      let verified = bcrypt::verify(self.password, hashed_password)
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
          auth
            .client()
            .session
            .insert_passkey_login(user.id(), &state)
            .await?;
          JwtOrTwoFactor::Passkey(response)
        }
        // TOTP 2FA
        (None, Some(_)) => {
          auth
            .client()
            .session
            .insert_totp_login_user_id(user.id())
            .await?;
          JwtOrTwoFactor::Totp {}
        }
        (None, None) => {
          JwtOrTwoFactor::Jwt(auth.jwt_provider().encode_sub(user.id())?)
        }
      };

      Ok(res)
    }
      .with_failure_rate_limit_using_ip(
        auth.local_login_rate_limiter(),
        &auth.client().ip,
      )
      .await
  }
}
