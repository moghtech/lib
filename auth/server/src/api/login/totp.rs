use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use data_encoding::BASE32_NOPAD;
use mogh_auth_client::api::login::{CompleteTotpLogin, JwtResponse};
use mogh_error::AddStatusCodeError as _;
use mogh_rate_limit::WithFailureRateLimit;
use resolver_api::Resolve;

use crate::{BoxAuthImpl, session::SessionTotpLogin};

#[utoipa::path(
  post,
  path = "/login/CompleteTotpLogin",
  description = "Complete login using TOTP code as second factor",
  request_body(content = CompleteTotpLogin),
  responses(
    (status = 200, description = "Authentication JWT", body = JwtResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn complete_totp_login() {}

impl Resolve<BoxAuthImpl> for CompleteTotpLogin {
  async fn resolve(
    self,
    auth: &BoxAuthImpl,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let session = auth.client().session.as_ref().context(
        "Method called in invalid context. This should not happen",
      )?;

      let SessionTotpLogin { user_id } = session
        .get(SessionTotpLogin::KEY)
        .await
        .context("Internal session type error")?
        .context(
          "Totp login has not been initiated for this session",
        )?;

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
