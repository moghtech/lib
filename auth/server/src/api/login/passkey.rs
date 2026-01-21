use anyhow::Context as _;
use axum::http::StatusCode;
use mogh_auth_client::api::login::CompletePasskeyLogin;
use mogh_error::AddStatusCode;
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;

use crate::api::login::LoginArgs;

impl Resolve<LoginArgs> for CompletePasskeyLogin {
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
      &ip,
    )
    .await
  }
}
