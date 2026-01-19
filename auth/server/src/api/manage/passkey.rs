use anyhow::Context as _;
use mogh_auth_client::api::manage::{
  BeginPasskeyEnrollment, ConfirmPasskeyEnrollment,
  ConfirmPasskeyEnrollmentResponse, UnenrollPasskey,
  UnenrollPasskeyResponse,
};
use mogh_resolver::Resolve;

use crate::api::manage::ManageArgs;

//

impl Resolve<ManageArgs> for BeginPasskeyEnrollment {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
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

    auth
      .client()
      .session
      .insert_passkey_enrollment(&state)
      .await?;

    Ok(challenge)
  }
}

//

impl Resolve<ManageArgs> for ConfirmPasskeyEnrollment {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let provider = auth.passkey_provider().context(
      "No passkey provider available, invalid 'host' config",
    )?;

    let state =
      auth.client().session.retrieve_passkey_enrollment().await?;

    let passkey = provider
      .finish_passkey_registration(&self.credential, &state)?;

    auth
      .update_user_stored_passkey(
        user.id().to_string(),
        Some(passkey),
      )
      .await?;

    Ok(ConfirmPasskeyEnrollmentResponse {})
  }
}

//

impl Resolve<ManageArgs> for UnenrollPasskey {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.check_username_locked(user.username())?;
    auth
      .update_user_stored_passkey(user.id().to_string(), None)
      .await?;
    Ok(UnenrollPasskeyResponse {})
  }
}
