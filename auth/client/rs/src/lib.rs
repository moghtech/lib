#![doc = include_str!("../README.md")]

use typeshare::typeshare;

pub mod api;
pub mod config;
pub mod passkey;
pub mod request;
pub mod signature;

#[allow(unused)]
#[cfg(feature = "utoipa")]
pub mod openapi;

#[cfg(test)]
mod test_server;

#[typeshare(serialized_as = "number")]
pub type U64 = u64;
