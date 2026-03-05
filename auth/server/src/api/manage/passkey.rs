use anyhow::Context as _;
use mogh_auth_client::api::manage::{
  BeginPasskeyEnrollment, ConfirmPasskeyEnrollment,
  ConfirmPasskeyEnrollmentResponse, UnenrollPasskey,
  UnenrollPasskeyResponse,
};
use mogh_resolver::Resolve;
use tracing::{info, instrument};

use crate::{AuthImpl, api::manage::ManageArgs};

//

impl Resolve<ManageArgs> for BeginPasskeyEnrollment {
  #[instrument(
    "BeginPasskeyEnrollment",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
    )
  )]
  async fn resolve(
    self,
    ManageArgs {
      auth,
      user,
      session,
    }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let username = user.username();

    auth.check_username_locked(username)?;

    let provider = auth.passkey_provider().context(
      "No passkey provider available, invalid 'host' config",
    )?;

    // Get two parts from this, the first is returned to the client.
    // The second must stay server side and is used in confirmation flow.
    let (challenge, state) =
      provider.start_passkey_registration(username)?;

    session.insert_passkey_enrollment(&state).await?;

    info!("Passkey 2FA enrollment flow initiated");

    Ok(challenge)
  }
}

//

impl Resolve<ManageArgs> for ConfirmPasskeyEnrollment {
  #[instrument(
    "ConfirmPasskeyEnrollment",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
    )
  )]
  async fn resolve(
    self,
    ManageArgs {
      auth,
      user,
      session,
    }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let provider = auth.passkey_provider().context(
      "No passkey provider available, invalid 'host' config",
    )?;

    let state = session.retrieve_passkey_enrollment().await?;

    let passkey = provider
      .finish_passkey_registration(&self.credential, &state)?;

    auth
      .update_user_stored_passkey(
        user.id().to_string(),
        Some(passkey),
      )
      .await?;

    info!("Passkey 2FA enrollment complete");

    Ok(ConfirmPasskeyEnrollmentResponse {})
  }
}

//

pub async fn unenroll_passkey<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: String,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;
  auth.update_user_stored_passkey(user_id, None).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UnenrollPasskey {
  #[instrument(
    "UnenrollPasskey",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    unenroll_passkey(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
    )
    .await?;

    info!("User unenrolled passkey 2FA");

    Ok(UnenrollPasskeyResponse {})
  }
}
