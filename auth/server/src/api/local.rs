use anyhow::{Context, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::{
  JwtOrTwoFactor,
  api::{LoginLocalUser, SignUpLocalUser},
  passkey::RequestChallengeResponse,
};
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_rate_limit::WithFailureRateLimit;
use resolver_api::Resolve;

use crate::{
  BoxAuthArgs,
  session::{SessionPasskeyLogin, SessionTotpLogin},
};

impl Resolve<BoxAuthArgs> for SignUpLocalUser {
  async fn resolve(
    self,
    args: &BoxAuthArgs,
  ) -> Result<Self::Response, Self::Error> {
    async {
      if !args.local_auth_enabled() {
        return Err(
          anyhow!("Local auth is not enabled")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      let no_users_exist = args.no_users_exist().await?;

      if args.registration_disabled() && !no_users_exist {
        return Err(
          anyhow!("User registration is disabled")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      args.validate_username(&self.username)?;
      args.validate_password(&self.password)?;

      let hashed_password = bcrypt::hash(
        self.password.as_bytes(),
        args.local_auth_bcrypt_cost(),
      )?;

      let user_id = args
        .sign_up_local_user(
          self.username,
          hashed_password,
          no_users_exist,
        )
        .await?;

      args.jwt_provider().encode(&user_id).map_err(Into::into)
    }
    .with_failure_rate_limit_using_ip(
      args.general_rate_limiter(),
      &args.client().ip,
    )
    .await
  }
}

impl Resolve<BoxAuthArgs> for LoginLocalUser {
  async fn resolve(
    self,
    args: &BoxAuthArgs,
  ) -> Result<Self::Response, Self::Error> {
    async {
      if !args.local_auth_enabled() {
        return Err(
          anyhow!("Local auth is not enabled")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      args.validate_username(&self.username)?;

      let user = args.find_user_with_username(&self.username).await?;
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
          let provider = args.passkey_provider().context(
            "No passkey provider available, possibly invalid 'host' config.",
          )?;
          let (response, state) = provider
            .start_passkey_authentication(&[passkey])
            .context("Failed to start passkey authentication flow")?;
          args
            .client()
            .session
            .clone()
            .context("Method called in context without session")?
            .insert(
              SessionPasskeyLogin::KEY,
              SessionPasskeyLogin {
                user_id: user.id().to_string(),
                state,
              },
            )
            .await?;
          JwtOrTwoFactor::Passkey(RequestChallengeResponse(response))
        }
        // TOTP 2FA
        (None, Some(_)) => {
          args
            .client()
            .session
            .as_ref()
            .context("Method called in context without session")?
            .insert(
              SessionTotpLogin::KEY,
              SessionTotpLogin {
                user_id: user.id().to_string(),
              },
            )
            .await?;
          JwtOrTwoFactor::Totp {}
        }
        (None, None) => {
          JwtOrTwoFactor::Jwt(args.jwt_provider().encode(user.id())?)
        }
      };

      Ok(res)
    }
      .with_failure_rate_limit_using_ip(
        args.local_login_rate_limiter(),
        &args.client().ip,
      )
      .await
  }
}
