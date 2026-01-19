use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use data_encoding::BASE32_NOPAD;
use mogh_auth_client::api::login::CompleteTotpLogin;
use mogh_error::AddStatusCodeError as _;
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;

use crate::BoxAuthImpl;

impl Resolve<BoxAuthImpl> for CompleteTotpLogin {
  async fn resolve(
    self,
    auth: &BoxAuthImpl,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let user_id =
        auth.client().session.retrieve_totp_login_user_id().await?;

      let user = auth.get_user(user_id.clone()).await?;
      let totp_secret = user
        .totp_secret()
        .context("User is not enrolled in TOTP 2FA")?;
      let secret_bytes = BASE32_NOPAD
        .decode(totp_secret.as_bytes())
        .context("Failed to decode TOTP secret to bytes")?;

      let totp = auth.make_totp(secret_bytes, None)?;

      let valid = totp
        .check_current(&self.code)
        .context("Failed to check TOTP code validity")?;

      if !valid {
        return Err(
          anyhow!("Invalid TOTP code")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      auth.jwt_provider().encode_sub(&user_id).map_err(Into::into)
    }
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &auth.client().ip,
    )
    .await
  }
}
