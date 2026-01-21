use anyhow::{Context as _, anyhow};
use mogh_auth_client::api::manage::{
  CreateApiKey, CreateApiKeyResponse, CreateApiKeyV2,
  CreateApiKeyV2Response, DeleteApiKey, DeleteApiKeyResponse,
  DeleteApiKeyV2, DeleteApiKeyV2Response,
};
use mogh_error::AddStatusCodeError as _;
use mogh_resolver::Resolve;
use reqwest::StatusCode;

use crate::{AuthImpl, api::manage::ManageArgs, rand::random_string};

//

pub async fn create_api_key<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: String,
  body: CreateApiKey,
) -> mogh_error::Result<CreateApiKeyResponse> {
  auth.validate_api_key_name(&body.name)?;

  let key =
    format!("K_{}_K", random_string(auth.api_key_secret_length()));
  let secret =
    format!("S_{}_S", random_string(auth.api_key_secret_length()));
  let hashed_secret =
    bcrypt::hash(&secret, auth.api_secret_bcrypt_cost())
      .context("Failed at hashing secret string")?;

  auth
    .create_api_key(user_id, body, key.clone(), hashed_secret)
    .await?;

  Ok(CreateApiKeyResponse { key, secret })
}

impl Resolve<ManageArgs> for CreateApiKey {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    create_api_key(auth.as_ref(), user.id().to_string(), self).await
  }
}

//

pub async fn delete_api_key<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: &str,
  key: String,
) -> mogh_error::Result<()> {
  let expected_user_id =
    auth.get_api_key_user_id(key.clone()).await?;

  if user_id != expected_user_id {
    return Err(
      anyhow!("Api key does not belong to user")
        .status_code(StatusCode::FORBIDDEN),
    );
  }

  auth.delete_api_key(key).await?;

  Ok(())
}

impl Resolve<ManageArgs> for DeleteApiKey {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    delete_api_key(auth.as_ref(), user.id(), self.key).await?;
    Ok(DeleteApiKeyResponse {})
  }
}

//

pub async fn create_api_key_v2<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: String,
  body: CreateApiKeyV2,
) -> mogh_error::Result<CreateApiKeyV2Response> {
  auth.validate_api_key_name(&body.name)?;

  let public_key = body.public_key.trim();

  let (private_key, public_key) = if public_key.is_empty() {
    let key_pair =
      mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::OneWay)?;
    (
      Some(key_pair.private.into_inner()),
      key_pair.public.into_inner(),
    )
  } else {
    (None, public_key.to_string())
  };

  auth
    .create_api_key_v2(
      user_id,
      CreateApiKey {
        name: body.name,
        expires: body.expires,
      },
      public_key,
    )
    .await?;

  Ok(CreateApiKeyV2Response { private_key })
}

impl Resolve<ManageArgs> for CreateApiKeyV2 {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    create_api_key_v2(auth.as_ref(), user.id().to_string(), self)
      .await
  }
}

//

pub async fn delete_api_key_v2<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: &str,
  public_key: String,
) -> mogh_error::Result<()> {
  let expected_user_id =
    auth.get_api_key_v2_user_id(public_key.clone()).await?;

  if user_id != expected_user_id {
    return Err(
      anyhow!("Api key does not belong to user")
        .status_code(StatusCode::FORBIDDEN),
    );
  }

  auth.delete_api_key_v2(public_key).await?;

  Ok(())
}

impl Resolve<ManageArgs> for DeleteApiKeyV2 {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    delete_api_key_v2(auth.as_ref(), user.id(), self.public_key)
      .await?;
    Ok(DeleteApiKeyV2Response {})
  }
}

//
