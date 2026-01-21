use serde::{Deserialize, Serialize};
use typeshare::typeshare;

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestChallengeResponse(
  pub webauthn_rs::prelude::RequestChallengeResponse,
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

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredential(
  pub webauthn_rs::prelude::PublicKeyCredential,
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

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey(pub webauthn_rs::prelude::Passkey);

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for Passkey {
  fn schema()
  -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    utoipa::schema!(#[inline] std::collections::HashMap<String, serde_json::Value>).into()
  }
}

#[allow(unused)]
#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for Passkey {}

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreationChallengeResponse(
  pub webauthn_rs::prelude::CreationChallengeResponse,
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

#[typeshare(serialized_as = "any")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPublicKeyCredential(
  pub webauthn_rs::prelude::RegisterPublicKeyCredential,
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
