use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use typeshare::typeshare;

use crate::I64;

/// Represents an empty json object: `{}`
#[typeshare]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoData {}

/// An external login linked to a [User].
#[typeshare]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkedLogin {
  /// The id of the external login provider.
  pub provider_id: String,
  /// The id of the user at the provider.
  pub external_id: String,
  /// The avatar the provider sent, if any.
  pub avatar_url: Option<String>,
}

/// The workload identity rule a workload [User] belongs to.
#[typeshare]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkloadLink {
  /// The id of the trusted issuer.
  pub issuer_id: String,
  /// The id of the rule within the issuer.
  pub rule_id: String,
  /// The subject (`sub`) of the last token exchanged.
  pub last_subject: String,
}

/// An app user. Never includes any credentials.
#[typeshare]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct User {
  pub id: String,
  pub username: String,
  /// Disabled users can log in, but can't use the app api.
  pub enabled: bool,
  pub admin: bool,
  pub groups: Vec<String>,
  /// Whether the user can log in with a password.
  pub has_password: bool,
  pub totp_enrolled: bool,
  pub passkey_enrolled: bool,
  pub external_skip_2fa: bool,
  pub linked_logins: Vec<LinkedLogin>,
  /// Set for users which belong to a workload identity rule.
  pub workload: Option<WorkloadLink>,
  /// The ips the user can log in / call the api from. Empty allows all.
  pub cidr_whitelist: Vec<String>,
  pub created_at: I64,
  pub updated_at: I64,
}

/// The kind of an [ApiKey]: how it authenticates.
#[typeshare]
#[derive(
  Debug,
  Clone,
  Copy,
  PartialEq,
  Eq,
  Serialize,
  Deserialize,
  Display,
  EnumString,
)]
pub enum ApiKeyKind {
  /// An api key: `X-API-KEY` / `X-API-SECRET`.
  ApiKey,
  /// A signing key: the request is signed with its private key
  /// (`X-API-PUBLIC-KEY` / `X-API-HOST` / `X-API-TIMESTAMP` /
  /// `X-API-NONCE` / `X-API-SIGNATURE`).
  SigningKey,
}

/// An api key or signing key of a user. Never includes the secret.
#[typeshare]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiKey {
  /// The key (api key) or public key (signing key).
  pub key: String,
  pub kind: ApiKeyKind,
  pub user_id: String,
  pub name: String,
  /// Unix timestamp in ms the key stops working at. 0 is never.
  pub expires: I64,
  pub cidr_whitelist: Vec<String>,
  pub created_at: I64,
}

/// A note of a user. The content is encrypted at rest.
#[typeshare]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Note {
  pub id: String,
  pub owner_id: String,
  pub title: String,
  pub content: String,
  pub created_at: I64,
  pub updated_at: I64,
}

/// A [Note] without the content.
#[typeshare]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoteListItem {
  pub id: String,
  pub owner_id: String,
  pub title: String,
  pub created_at: I64,
  pub updated_at: I64,
}

/// How the request was authenticated.
#[typeshare]
#[derive(
  Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display,
)]
pub enum AuthMethod {
  Jwt,
  ApiKey,
  PublicKey,
}
