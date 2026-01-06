use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use data_encoding::BASE32_NOPAD;
use mogh_auth_client::{JwtResponse, api::CompleteTotpLogin};
use mogh_error::AddStatusCodeError as _;
use mogh_rate_limit::WithFailureRateLimit;
use resolver_api::Resolve;

use crate::{BoxAuthArgs, session::SessionTotpLogin};

#[utoipa::path(
  post,
  path = "/auth/CompleteTotpLogin",
  description = "Complete login using TOTP code as second factor",
  request_body(content = CompleteTotpLogin),
  responses(
    (status = 200, description = "Authentication JWT", body = JwtResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn complete_totp_login() {}

impl Resolve<BoxAuthArgs> for CompleteTotpLogin {
  async fn resolve(
    self,
    args: &BoxAuthArgs,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let session = args.client().session.as_ref().context(
        "Method called in invalid context. This should not happen",
      )?;

      let SessionTotpLogin { user_id } = session
        .get(SessionTotpLogin::KEY)
        .await
        .context("Internal session type error")?
        .context(
          "Totp login has not been initiated for this session",
        )?;

      let user = args.get_user(&user_id).await?;
      let totp_secret = user
        .totp_secret()
        .context("User is not enrolled in TOTP 2FA")?;
      let secret_bytes = BASE32_NOPAD
        .decode(totp_secret.as_bytes())
        .context("Failed to decode TOTP secret to bytes")?;

      let totp = make_totp(args, secret_bytes, None)?;

      let valid = totp
        .check_current(&self.code)
        .context("Failed to check TOTP code validity")?;

      if !valid {
        return Err(
          anyhow!("Invalid TOTP code")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }

      args.jwt_provider().encode(&user_id).map_err(Into::into)
    }
    .with_failure_rate_limit_using_ip(
      args.general_rate_limiter(),
      &args.client().ip,
    )
    .await
  }
}

pub fn make_totp(
  args: &BoxAuthArgs,
  secret_bytes: Vec<u8>,
  account_name: impl Into<Option<String>>,
) -> anyhow::Result<totp_rs::TOTP> {
  totp_rs::TOTP::new(
    totp_rs::Algorithm::SHA1,
    6,
    1,
    30,
    secret_bytes,
    Some(String::from(args.app_name())),
    account_name.into().unwrap_or_default(),
  )
  .context("Failed to construct TOTP")
}
