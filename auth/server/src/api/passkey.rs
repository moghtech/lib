use anyhow::Context as _;
use axum::http::StatusCode;
use mogh_auth_client::api::CompletePasskeyLogin;
use mogh_error::AddStatusCode;
use mogh_rate_limit::WithFailureRateLimit;
use resolver_api::Resolve;

use crate::{BoxAuthArgs, session::SessionPasskeyLogin};

impl Resolve<BoxAuthArgs> for CompletePasskeyLogin {
  async fn resolve(
    self,
    args: &BoxAuthArgs,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let provider = args.passkey_provider().context(
        "No passkey provider available, possibly invalid 'host' config.",
      )?;
      
      let session = args.client().session.as_ref().context(
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
        .finish_passkey_authentication(&self.credential.0, &state)
        .context("Failed to validate passkey")
        .status_code(StatusCode::UNAUTHORIZED)?;

      let mut passkey = args
        .get_user(&user_id)
        .await?
        .passkey()
        .context("User is not enrolled in Passkey 2FA")?;

      passkey.update_credential(&update);

      // Update the stored passkey on the database
      args.update_user_stored_passkey(&user_id, passkey).await?;

      args.jwt_provider().encode(&user_id).map_err(Into::into)
    }
    .with_failure_rate_limit_using_ip(
      args.general_rate_limiter(),
      &args.client().ip,
    )
    .await
  }
}
