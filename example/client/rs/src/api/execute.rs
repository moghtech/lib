//! # Example Execute API
//!
//! Authenticated requests which run an action on the server.

use mogh_resolver::{HasResponse, Resolve};
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

pub trait ExampleExecuteRequest: HasResponse {}

//

/// Generate an Ed25519 key pair, eg. to create a signing key with.
/// Response: [GenerateKeyPairResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleExecuteRequest)]
#[response(GenerateKeyPairResponse)]
#[error(mogh_error::Error)]
pub struct GenerateKeyPair {}

/// Response for [GenerateKeyPair].
#[typeshare]
#[derive(Serialize, Deserialize, Clone)]
pub struct GenerateKeyPairResponse {
  /// The pkcs8 encoded private key. The server doesn't keep it.
  pub private_key: String,
  /// The spki encoded public key.
  pub public_key: String,
}

//

/// Encrypt text with the server key, bound to the calling user.
/// Response: [SealTextResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Clone, Resolve)]
#[empty_traits(ExampleExecuteRequest)]
#[response(SealTextResponse)]
#[error(mogh_error::Error)]
pub struct SealText {
  pub text: String,
}

/// Response for [SealText].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealTextResponse {
  pub sealed: String,
}

//

/// Decrypt text sealed by the calling user with [SealText].
/// Response: [OpenTextResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleExecuteRequest)]
#[response(OpenTextResponse)]
#[error(mogh_error::Error)]
pub struct OpenText {
  pub sealed: String,
}

/// Response for [OpenText].
#[typeshare]
#[derive(Serialize, Deserialize, Clone)]
pub struct OpenTextResponse {
  pub text: String,
}

//

/// What an input is validated as by [ValidateString].
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum ValidateStringKind {
  Username,
  VariableName,
  HttpUrl,
  NoteTitle,
}

/// Check an input against the validation rules of the server.
/// Response: [ValidateStringResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleExecuteRequest)]
#[response(ValidateStringResponse)]
#[error(mogh_error::Error)]
pub struct ValidateString {
  pub kind: ValidateStringKind,
  pub input: String,
}

/// Response for [ValidateString].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidateStringResponse {
  pub valid: bool,
  /// Why the input is not valid.
  pub error: Option<String>,
}
