#![doc = include_str!("../README.md")]

use typeshare::typeshare;

mod branding;
mod cbor;
mod key;
mod payload;
mod root;

pub mod api;

/// Serving the api, with the `server` feature.
#[cfg(feature = "server")]
pub mod server;

/// Test data: a sample supporter key signed by a test root key, the
/// answer a server gives for it, and that test root. For the tests
/// of this crate and of apps, see the module.
pub mod fixture;

/// The type a supporter key is handed to the app and back in
/// (`server::SupporterImpl`), wiped from memory when dropped: the key
/// holds the instance private key.
pub use zeroize::Zeroizing;

pub use branding::*;
pub use cbor::{
  Error as CborError, MAX_DEPTH as CBOR_MAX_DEPTH,
  Value as CborValue, decode as decode_cbor,
};
pub use key::*;
pub use payload::*;
pub use root::*;

/// `u64` where the typescript types have a `number`.
#[typeshare(serialized_as = "number")]
pub type U64 = u64;

#[cfg(test)]
mod tests;
