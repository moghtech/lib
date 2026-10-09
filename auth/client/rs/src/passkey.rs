//! The passkey (WebAuthn) challenges and credentials a client
//! receives and sends during passkey login and enrollment, in the
//! JSON form of `webauthn-rs-proto`.
//!
//! The passkey a server stores for a user is not here: it is
//! `mogh_auth_server::passkey::Passkey`. Reading one takes
//! `webauthn-rs`, and with it OpenSSL, which a client has no use for.

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

/// The challenge a passkey login answers with
/// ([JwtOrTwoFactor::Passkey][crate::api::login::JwtOrTwoFactor::Passkey]),
/// for the browser's `navigator.credentials.get`.
#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestChallengeResponse(
  pub webauthn_rs_proto::RequestChallengeResponse,
);

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for RequestChallengeResponse {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for RequestChallengeResponse {}

/// The browser's answer to a [RequestChallengeResponse], which
/// completes the passkey login
/// ([CompletePasskeyLogin][crate::api::login::CompletePasskeyLogin]).
#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredential(
  pub webauthn_rs_proto::PublicKeyCredential,
);

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for PublicKeyCredential {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for PublicKeyCredential {}

/// The challenge passkey enrollment begins with
/// ([BeginPasskeyEnrollment][crate::api::manage::BeginPasskeyEnrollment]),
/// for the browser's `navigator.credentials.create`.
#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationChallengeResponse(
  pub webauthn_rs_proto::CreationChallengeResponse,
);

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for CreationChallengeResponse {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for CreationChallengeResponse {}

/// The browser's answer to a [CreationChallengeResponse], which
/// completes the enrollment
/// ([ConfirmPasskeyEnrollment][crate::api::manage::ConfirmPasskeyEnrollment]).
#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPublicKeyCredential(
  pub webauthn_rs_proto::RegisterPublicKeyCredential,
);

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for RegisterPublicKeyCredential {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for RegisterPublicKeyCredential {}
