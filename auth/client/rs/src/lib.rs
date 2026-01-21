use typeshare::typeshare;

pub mod api;
pub mod config;
pub mod event;
pub mod passkey;
pub mod request;

#[allow(unused)]
#[cfg(feature = "utoipa")]
pub mod openapi;

#[typeshare(serialized_as = "any")]
pub type JsonValue = serde_json::Value;
#[typeshare(serialized_as = "number")]
pub type U64 = u64;
