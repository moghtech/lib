use anyhow::Context;

mod serror;

pub use serror::Serror;

#[cfg(feature = "axum")]
mod axum;
#[cfg(feature = "axum")]
pub use crate::axum::*;

pub fn serialize_error(e: &anyhow::Error) -> String {
  try_serialize_error(e).unwrap_or_else(|_| format!("{e:#?}"))
}

pub fn try_serialize_error(
  e: &anyhow::Error,
) -> anyhow::Result<String> {
  let serror: Serror = e.into();
  let res = serde_json::to_string(&serror)?;
  Ok(res)
}

pub fn serialize_error_pretty(e: &anyhow::Error) -> String {
  try_serialize_error_pretty(e).unwrap_or_else(|_| format!("{e:#?}"))
}

pub fn try_serialize_error_pretty(
  e: &anyhow::Error,
) -> anyhow::Result<String> {
  let serror: Serror = e.into();
  let res = serde_json::to_string_pretty(&serror)?;
  Ok(res)
}

pub fn serialize_error_bytes(e: &anyhow::Error) -> Vec<u8> {
  try_serialize_error_bytes(e)
    .unwrap_or_else(|_| format!("{e:#?}").into_bytes())
}

pub fn try_serialize_error_bytes(
  e: &anyhow::Error,
) -> anyhow::Result<Vec<u8>> {
  let serror: Serror = e.into();
  let res = serde_json::to_vec(&serror)?;
  Ok(res)
}

pub fn deserialize_error(json: String) -> anyhow::Error {
  serror_into_anyhow_error(deserialize_serror(json))
}

pub fn deserialize_serror(json: String) -> Serror {
  try_deserialize_serror(&json).unwrap_or_else(|_| Serror {
    error: json.clone(),
    trace: Default::default(),
  })
}

pub fn try_deserialize_serror(json: &str) -> anyhow::Result<Serror> {
  serde_json::from_str(json)
    .context("failed to deserialize string into Serror")
}

pub fn deserialize_error_bytes(json: &[u8]) -> anyhow::Error {
  serror_into_anyhow_error(deserialize_serror_bytes(json))
}

pub fn deserialize_serror_bytes(json: &[u8]) -> Serror {
  try_deserialize_serror_bytes(&json).unwrap_or_else(|_| Serror {
    error: match String::from_utf8(json.to_vec()) {
      Ok(res) => res,
      Err(e) => format!("Bytes are not valid utf8 | {e:?}"),
    },
    trace: Default::default(),
  })
}

pub fn try_deserialize_serror_bytes(
  json: &[u8],
) -> anyhow::Result<Serror> {
  serde_json::from_slice(json)
    .context("failed to deserialize string into Serror")
}

pub fn serror_into_anyhow_error(mut serror: Serror) -> anyhow::Error {
  let mut e = match serror.trace.pop() {
    None => return anyhow::Error::msg(serror.error),
    Some(msg) => anyhow::Error::msg(msg),
  };

  while let Some(msg) = serror.trace.pop() {
    e = e.context(msg);
  }

  e = e.context(serror.error);

  e
}
