use anyhow::Context as _;
use axum::http::StatusCode;
use mogh_auth_client::api::login::{
  CompletePasskeyLogin, JwtResponse,
};
use mogh_error::AddStatusCode;
use mogh_rate_limit::WithFailureRateLimit;
use resolver_api::Resolve;

use crate::{BoxAuthImpl, session::SessionPasskeyLogin};

#[utoipa::path(
  post,
  path = "/login/CompletePasskeyLogin",
  description = "Complete login using passkey as second factor",
  request_body(content = CompletePasskeyLogin),
  responses(
    (status = 200, description = "Authentication JWT", body = JwtResponse),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub fn complete_passkey_login() {}

impl Resolve<BoxAuthImpl> for CompletePasskeyLogin {
  async fn resolve(
    self,
    auth: &BoxAuthImpl,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let provider = auth.passkey_provider().context(
        "No passkey provider available, possibly invalid 'host' config.",
      )?;

      let session = auth.client().session.as_ref().context(
        "Method called in invalid context. This should not happen",
      )?;

      let SessionPasskeyLogin { user_id, state } = session
        .get(SessionPasskeyLogin::KEY)
        .await
        .context("Internal session type error")?
        .context(
          "Passkey login has not been initiated for this session",
        )?;

      // This error if the incoming passkey is invalid
      // The result of this call must be used to
      // update the stored passkey info on database.
      let update = provider
        .finish_passkey_authentication(&self.credential, &state)
        .context("Failed to validate passkey")
        .status_code(StatusCode::UNAUTHORIZED)?;

      let mut passkey = auth
        .get_user(user_id.clone())
        .await?
        .passkey()
        .context("User is not enrolled in Passkey 2FA")?;

      passkey.0.update_credential(&update);

      let response =  auth.jwt_provider().encode_sub(&user_id)?;

      // Update the stored passkey on the database
      auth.update_user_stored_passkey(user_id, Some(passkey)).await?;

      Ok(response)
    }
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &auth.client().ip,
    )
    .await
  }
}
