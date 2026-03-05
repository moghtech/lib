use anyhow::Context as _;
use axum::http::StatusCode;
use mogh_auth_client::api::login::CompletePasskeyLogin;
use mogh_error::AddStatusCode;
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;
use tracing::{info, instrument};

use crate::api::login::LoginArgs;

impl Resolve<LoginArgs> for CompletePasskeyLogin {
  #[instrument(
    "CompletePasskeyLogin",
    skip_all,
    fields(
      ip = ip.to_string(),
    )
  )]
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    async {
      let provider = auth.passkey_provider().context(
        "No passkey provider available, possibly invalid 'host' config.",
      )?;

      let (user_id, state) = session
        .retrieve_passkey_login()
        .await?;

      // This will error if the incoming passkey is invalid.
      // The result of this call must be used to
      // update the stored passkey info on database.
      let update = provider
        .finish_passkey_authentication(&self.credential, &state)
        .context("Failed to validate passkey")
        .status_code(StatusCode::UNAUTHORIZED)?;

      let user = auth
        .get_user(user_id.clone())
        .await?;

      let mut passkey = user
        .passkey()
        .context("User is not enrolled in Passkey 2FA")?;

      passkey.0.update_credential(&update);

      let response =  auth.jwt_provider().encode_sub(&user_id)?;

      // Update the stored passkey on the database
      auth.update_user_stored_passkey(user_id.clone(), Some(passkey)).await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "Passkey 2FA flow complete, user logged in"
      );

      Ok(response)
    }
    .with_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      &ip,
    )
    .await
  }
}
