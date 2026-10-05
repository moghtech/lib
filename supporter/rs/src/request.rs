//! Calling the supporter api with [reqwest], like
//! `mogh_auth_client::request`. `address` is where the api is
//! mounted, eg. `https://example.com/supporter`. The requests carry
//! no credentials of their own: add them to the client's default
//! headers (`Authorization: Bearer <jwt>`, or `X-API-KEY` /
//! `X-API-SECRET`).

use anyhow::{Context as _, anyhow};
use mogh_error::deserialize_error;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::api::{
  MoghSupporterReadRequest, MoghSupporterWriteRequest,
};

/// Calls the read api.
pub async fn read<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghSupporterReadRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/read", T::req_type(), &request).await
}

/// Calls the write api.
pub async fn write<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghSupporterWriteRequest,
  T::Response: DeserializeOwned,
{
  post(reqwest, address, "/write", T::req_type(), &request).await
}

async fn post<B: Serialize, R: DeserializeOwned>(
  reqwest: &reqwest::Client,
  address: &str,
  endpoint: &str,
  req_type: &str,
  params: &B,
) -> anyhow::Result<R> {
  let res = reqwest
    .post(format!("{}{endpoint}", address.trim_end_matches('/')))
    .json(&json!({ "type": req_type, "params": params }))
    .send()
    .await
    .context("Failed to reach the supporter api")?;
  let status = res.status();
  let body = res
    .text()
    .await
    .map_err(|e| anyhow!("{e:?}").context(status))?;
  if status.is_success() {
    serde_json::from_str(&body).map_err(|e| {
      anyhow!("{e:#?}")
        .context("Failed to deserialize response body")
        .context(status)
    })
  } else {
    Err(deserialize_error(body).context(status))
  }
}
