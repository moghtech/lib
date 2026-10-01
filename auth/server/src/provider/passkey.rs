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
  /// Pass the app host address, IE `https://auth.mogh.tech`.
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

/// A passkey with `cred_id` for tests, in the form it is stored.
/// Its key is made up, it never verifies an assertion.
#[cfg(test)]
pub(crate) fn test_passkey(cred_id: &[u8]) -> Passkey {
  use data_encoding::BASE64URL_NOPAD;
  serde_json::from_value(serde_json::json!({
    "cred": {
      "cred_id": BASE64URL_NOPAD.encode(cred_id),
      "cred": {
        "type_": "ES256",
        "key": {
          "EC_EC2": {
            "curve": "SECP256R1",
            "x": BASE64URL_NOPAD.encode(&[2; 32]),
            "y": BASE64URL_NOPAD.encode(&[3; 32]),
          }
        }
      },
      "counter": 1,
      "transports": null,
      "user_verified": true,
      "backup_eligible": false,
      "backup_state": false,
      "registration_policy": "required",
      "extensions": {},
      "attestation": { "data": "None", "metadata": "None" },
      "attestation_format": "none",
    }
  }))
  .expect("Invalid test passkey")
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_start_passkey_authentication() {
    let provider =
      PasskeyProvider::new("https://example.com").unwrap();
    let passkey = test_passkey(&[1; 16]);
    assert_eq!(passkey.0.cred_id().as_slice(), &[1; 16]);
    provider.start_passkey_authentication(passkey).unwrap();
  }
}
