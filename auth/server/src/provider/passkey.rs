use anyhow::Context;
use mogh_auth_client::passkey::{
  CreationChallengeResponse, Passkey, PublicKeyCredential,
  RegisterPublicKeyCredential, RequestChallengeResponse,
};
use tracing::info;
use uuid::Uuid;
use webauthn_rs::{
  Webauthn, WebauthnBuilder,
  prelude::{
    AuthenticationResult, PasskeyAuthentication, PasskeyRegistration,
    Url,
  },
};

pub struct PasskeyProvider(Webauthn);

impl PasskeyProvider {
  /// Pass the app host address, IE 'https://auth.mogh.tech'.
  pub fn new(host: &str) -> anyhow::Result<Self> {
    let rp_origin = Url::parse(host)?;
    let rp_id = rp_origin.domain().context("Host missing domain")?;
    let webauthn =
      WebauthnBuilder::new(rp_id, &rp_origin)?.build()?;
    info!("Using '{rp_id}' as WebAuthn rp_id");
    Ok(Self(webauthn))
  }

  pub fn start_passkey_authentication(
    &self,
    passkey: Passkey,
  ) -> anyhow::Result<(RequestChallengeResponse, PasskeyAuthentication)>
  {
    self
      .0
      .start_passkey_authentication(&[passkey.0])
      .context("Failed to start passkey authentication flow")
      .map(|(response, state)| {
        (RequestChallengeResponse(response), state)
      })
  }

  /// This will error if the incoming passkey is invalid.
  /// The result of this call must be used to
  /// update the stored passkey on database.
  pub fn finish_passkey_authentication(
    &self,
    PublicKeyCredential(credential): &PublicKeyCredential,
    state: &PasskeyAuthentication,
  ) -> anyhow::Result<AuthenticationResult> {
    self
      .0
      .finish_passkey_authentication(credential, state)
      .context("Failed to validate passkey")
  }

  pub fn start_passkey_registration(
    &self,
    username: &str,
  ) -> anyhow::Result<(CreationChallengeResponse, PasskeyRegistration)>
  {
    self
      .0
      .start_passkey_registration(
        Uuid::new_v4(),
        username,
        username,
        None,
      )
      .context("Failed to start passkey registration flow")
      .map(|(response, state)| {
        (CreationChallengeResponse(response), state)
      })
  }

  pub fn finish_passkey_registration(
    &self,
    RegisterPublicKeyCredential(credential): &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
  ) -> anyhow::Result<Passkey> {
    self
      .0
      .finish_passkey_registration(credential, state)
      .context("Failed to finish passkey registration")
      .map(Passkey)
  }
}
