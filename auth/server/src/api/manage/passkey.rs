use anyhow::Context as _;
use axum::http::StatusCode;
use mogh_auth_client::api::manage::{
  BeginPasskeyEnrollment, ConfirmPasskeyEnrollment,
  ConfirmPasskeyEnrollmentResponse, UnenrollPasskey,
  UnenrollPasskeyResponse,
};
use mogh_error::AddStatusCode as _;
use mogh_resolver::Resolve;
use tracing::{info, instrument};

use crate::{AuthImpl, CredentialChange, api::manage::ManageArgs};

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
      ..
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

    session.insert_passkey_enrollment(user.id(), &state).await?;

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
      user_id = args.user.id(),
      username = args.user.username(),
    )
  )]
  async fn resolve(
    self,
    args: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let ManageArgs {
      auth,
      user,
      session,
      ..
    } = args;
    // Checked again, the lock may have been added since the
    // enrollment began.
    auth.check_username_locked(user.username())?;

    let provider = auth.passkey_provider().context(
      "No passkey provider available, invalid 'host' config",
    )?;

    // Only the user who began the enrollment can confirm it.
    let state =
      session.retrieve_passkey_enrollment(user.id()).await?;

    // A credential the authenticator got wrong (another origin, a
    // cancelled or tampered one) or a forged one is the client's
    // failure: refused with the cause, the enrollment taken.
    let passkey = provider
      .finish_passkey_registration(&self.credential, &state)
      .context(
        "The passkey was not accepted. Please try BeginPasskeyEnrollment flow again.",
      )
      .status_code(StatusCode::BAD_REQUEST)?;

    auth
      .update_user_stored_passkey(
        user.id().to_string(),
        Some(passkey),
      )
      .await?;

    info!("Passkey 2FA enrollment complete");

    args
      .credentials_changed(CredentialChange::PasskeyEnrolled)
      .await?;

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
      user_id = args.user.id(),
      username = args.user.username(),
    )
  )]
  async fn resolve(
    self,
    args: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let ManageArgs { auth, user, .. } = args;
    unenroll_passkey(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
    )
    .await?;

    info!("User unenrolled passkey 2FA");

    args
      .credentials_changed(CredentialChange::PasskeyUnenrolled)
      .await?;

    Ok(UnenrollPasskeyResponse {})
  }
}

#[cfg(test)]
mod tests {
  use std::sync::{Arc, LazyLock, Mutex};

  use data_encoding::BASE64URL_NOPAD;
  use mogh_auth_client::passkey::RegisterPublicKeyCredential;

  use super::*;
  use crate::{provider::passkey::PasskeyProvider, session::Session};

  /// Whether a passkey was stored.
  static STORED: Mutex<bool> = Mutex::new(false);

  struct PasskeyAuth;

  impl AuthImpl for PasskeyAuth {
    fn new() -> Self {
      PasskeyAuth
    }
    fn get_user(
      &self,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      unimplemented!()
    }
    fn handle_request_authentication(
      &self,
      _: crate::RequestAuthentication,
      _: std::net::IpAddr,
      _: bool,
      _: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      unimplemented!()
    }
    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      unimplemented!()
    }
    fn passkey_provider(&self) -> Option<&PasskeyProvider> {
      static PROVIDER: LazyLock<PasskeyProvider> =
        LazyLock::new(|| {
          PasskeyProvider::new("https://example.com").unwrap()
        });
      Some(&PROVIDER)
    }
    fn update_user_stored_passkey(
      &self,
      _: String,
      _: Option<crate::Passkey>,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      *STORED.lock().unwrap() = true;
      Box::pin(async { Ok(()) })
    }
  }

  struct User;

  impl crate::user::AuthUserImpl for User {
    fn id(&self) -> &str {
      "user"
    }
    fn username(&self) -> &str {
      "user"
    }
  }

  /// A credential for another challenge (made for another
  /// enrollment, or forged) is the client's failure: 400 with the
  /// cause, nothing stored, and the enrollment begins again.
  #[tokio::test]
  async fn test_a_credential_for_another_challenge_is_refused() {
    let args = ManageArgs {
      auth: Arc::new(PasskeyAuth),
      user: Arc::new(Box::new(User)),
      session: Session(tower_sessions::Session::new(
        None,
        Arc::new(tower_sessions::MemoryStore::default()),
        None,
      )),
      jwt: Some(String::from("session")),
    };
    BeginPasskeyEnrollment {}.resolve(&args).await.unwrap();

    let client_data = serde_json::json!({
      "type": "webauthn.create",
      "challenge": BASE64URL_NOPAD.encode(b"another challenge"),
      "origin": "https://example.com",
    })
    .to_string();
    let credential: RegisterPublicKeyCredential =
      serde_json::from_value(serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "extensions": {},
        "response": {
          "attestationObject": "AAAA",
          "clientDataJSON": BASE64URL_NOPAD.encode(client_data.as_bytes()),
        },
      }))
      .unwrap();

    let err = ConfirmPasskeyEnrollment {
      credential: credential.clone(),
    }
    .resolve(&args)
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    let message = format!("{:#}", err.error);
    assert!(
      message.starts_with("The passkey was not accepted"),
      "{message}"
    );
    // With the cause.
    assert!(
      message.contains("Failed to finish passkey registration"),
      "{message}"
    );
    assert!(!*STORED.lock().unwrap());
    // Taken: the enrollment has to begin again.
    let err = ConfirmPasskeyEnrollment { credential }
      .resolve(&args)
      .await
      .err()
      .unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }
}
