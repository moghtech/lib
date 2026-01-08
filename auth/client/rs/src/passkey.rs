use serde::{Deserialize, Serialize};
use typeshare::typeshare;

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestChallengeResponse(
  pub webauthn_rs::prelude::RequestChallengeResponse,
);

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for RequestChallengeResponse {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for RequestChallengeResponse {}

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredential(
  pub webauthn_rs::prelude::PublicKeyCredential,
);

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for PublicKeyCredential {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for PublicKeyCredential {}

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey(pub webauthn_rs::prelude::Passkey);

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for Passkey {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for Passkey {}

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationChallengeResponse(
  pub webauthn_rs::prelude::CreationChallengeResponse,
);

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for CreationChallengeResponse {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for CreationChallengeResponse {}

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPublicKeyCredential(
  pub webauthn_rs::prelude::RegisterPublicKeyCredential,
);

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for RegisterPublicKeyCredential {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for RegisterPublicKeyCredential {}
