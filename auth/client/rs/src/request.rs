use anyhow::{Context, anyhow};
use mogh_error::deserialize_error;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::api::{
  login::MoghAuthLoginRequest, manage::MoghAuthManageRequest,
};

#[cfg(not(feature = "blocking"))]
pub async fn login<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthLoginRequest,
  T::Response: DeserializeOwned,
{
  post(
    reqwest,
    address,
    "/login",
    json!({
      "type": T::req_type(),
      "params": request
    }),
  )
  .await
}

#[cfg(feature = "blocking")]
fn login<T>(
  reqwest: &reqwest::blocking::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthLoginRequest,
  T::Response: DeserializeOwned,
{
  post(
    reqwest,
    address,
    "/login",
    json!({
      "type": T::req_type(),
      "params": request
    }),
  )
}

#[cfg(not(feature = "blocking"))]
pub async fn manage<T>(
  reqwest: &reqwest::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthManageRequest,
  T::Response: DeserializeOwned,
{
  post(
    reqwest,
    address,
    "/manage",
    json!({
      "type": T::req_type(),
      "params": request
    }),
  )
  .await
}

#[cfg(feature = "blocking")]
fn manage<T>(
  reqwest: &reqwest::blocking::Client,
  address: &str,
  request: T,
) -> anyhow::Result<T::Response>
where
  T: Serialize + MoghAuthManageRequest,
  T::Response: DeserializeOwned,
{
  post(
    reqwest,
    address,
    "/manage",
    json!({
      "type": T::req_type(),
      "params": request
    }),
  )
}

#[cfg(not(feature = "blocking"))]
async fn post<B: Serialize + std::fmt::Debug, R: DeserializeOwned>(
  reqwest: &reqwest::Client,
  address: &str,
  endpoint: &str,
  body: B,
) -> anyhow::Result<R> {
  let req = reqwest
    .post(format!("{address}{endpoint}"))
    // .header("x-api-key", &self.key)
    // .header("x-api-secret", &self.secret)
    .header("content-type", "application/json")
    .json(&body);
  let res = req.send().await.context("failed to reach Cicada API")?;
  let status = res.status();
  if status.is_success() {
    match res.json().await {
      Ok(res) => Ok(res),
      Err(e) => Err(anyhow!("{e:#?}").context(status)),
    }
  } else {
    match res.text().await {
      Ok(res) => Err(deserialize_error(res).context(status)),
      Err(e) => Err(anyhow!("{e:?}").context(status)),
    }
  }
}

#[cfg(feature = "blocking")]
fn post<B: Serialize + std::fmt::Debug, R: DeserializeOwned>(
  reqwest: &reqwest::blocking::Client,
  address: &str,
  endpoint: &str,
  body: B,
) -> anyhow::Result<R> {
  let req = reqwest
    .post(format!("{address}{endpoint}"))
    // .header("x-api-key", &self.key)
    // .header("x-api-secret", &self.secret)
    .header("content-type", "application/json")
    .json(&body);
  let res = req.send().context("failed to reach Cicada API")?;
  let status = res.status();
  if status.is_success() {
    match res.json() {
      Ok(res) => Ok(res),
      Err(e) => Err(anyhow!("{e:#?}").context(status)),
    }
  } else {
    match res.text() {
      Ok(res) => Err(deserialize_error(res).context(status)),
      Err(e) => Err(anyhow!("{e:?}").context(status)),
    }
  }
}
