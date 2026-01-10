use anyhow::{Context as _, anyhow};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;

pub mod github;
pub mod google;

/// Length of random token in Oauth 'state'
pub const STATE_PREFIX_LENGTH: usize = 20;

async fn handle_response<T: DeserializeOwned>(
  res: reqwest::Response,
) -> anyhow::Result<T> {
  let status = res.status();
  if status == StatusCode::OK {
    let body = res
      .json()
      .await
      .context("Failed to parse response body into expected type")?;
    Ok(body)
  } else {
    let text = res.text().await.with_context(|| {
      format!("Status: {status} | Failed to get response text")
    })?;
    Err(anyhow!("Status: {status} | Text: {text}"))
  }
}
