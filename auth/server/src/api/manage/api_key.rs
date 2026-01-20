use anyhow::{Context as _, anyhow};
use mogh_auth_client::api::manage::{
  CreateApiKey, CreateApiKeyResponse, CreateApiKeyV2,
  CreateApiKeyV2Response, DeleteApiKey, DeleteApiKeyResponse,
  DeleteApiKeyV2, DeleteApiKeyV2Response,
};
use mogh_error::AddStatusCodeError as _;
use mogh_resolver::Resolve;
use reqwest::StatusCode;

use crate::{api::manage::ManageArgs, rand::random_string};

//

impl Resolve<ManageArgs> for CreateApiKey {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.validate_api_key_name(&self.name)?;

    let key =
      format!("K_{}_K", random_string(auth.api_key_secret_length()));
    let secret =
      format!("S_{}_S", random_string(auth.api_key_secret_length()));
    let hashed_secret =
      bcrypt::hash(&secret, auth.api_secret_bcrypt_cost())
        .context("Failed at hashing secret string")?;

    auth
      .create_api_key(
        user.id().to_string(),
        self,
        key.clone(),
        hashed_secret,
      )
      .await?;

    Ok(CreateApiKeyResponse { key, secret })
  }
}

//

impl Resolve<ManageArgs> for DeleteApiKey {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let expected_user_id =
      auth.get_api_key_user_id(self.key.clone()).await?;

    if user.id() != expected_user_id {
      return Err(
        anyhow!("Api key does not belong to user")
          .status_code(StatusCode::FORBIDDEN),
      );
    }

    auth.delete_api_key(self.key).await?;

    Ok(DeleteApiKeyResponse {})
  }
}

//

impl Resolve<ManageArgs> for CreateApiKeyV2 {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    auth.validate_api_key_name(&self.name)?;

    let public_key = self.public_key.trim();

    let (private_key, public_key) = if public_key.is_empty() {
      let key_pair = mogh_pki::EncodedKeyPair::generate(
        mogh_pki::PkiKind::OneWay,
      )?;
      (
        Some(key_pair.private.into_inner()),
        key_pair.public.into_inner(),
      )
    } else {
      (None, public_key.to_string())
    };

    auth
      .create_api_key_v2(
        user.id().to_string(),
        CreateApiKey {
          name: self.name,
          expires: self.expires,
        },
        public_key,
      )
      .await?;

    Ok(CreateApiKeyV2Response { private_key })
  }
}

//

impl Resolve<ManageArgs> for DeleteApiKeyV2 {
  async fn resolve(
    self,
    ManageArgs { auth, user }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let expected_user_id =
      auth.get_api_key_v2_user_id(self.public_key.clone()).await?;

    if user.id() != expected_user_id {
      return Err(
        anyhow!("Api key does not belong to user")
          .status_code(StatusCode::FORBIDDEN),
      );
    }

    auth.delete_api_key_v2(self.public_key).await?;

    Ok(DeleteApiKeyV2Response {})
  }
}

//
