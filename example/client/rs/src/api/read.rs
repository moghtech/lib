//! # Example Read API
//!
//! Authenticated requests which don't change any state.

use mogh_resolver::{HasResponse, Resolve};
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{
  I64,
  entities::{ApiKey, AuthMethod, Note, NoteListItem, User},
};

pub trait ExampleReadRequest: HasResponse {}

//

/// Get the version of the server.
/// Response: [GetVersionResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleReadRequest)]
#[response(GetVersionResponse)]
#[error(mogh_error::Error)]
pub struct GetVersion {}

/// Response for [GetVersion].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetVersionResponse {
  pub version: String,
}

//

/// Get info about the server.
/// Response: [GetCoreInfoResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleReadRequest)]
#[response(GetCoreInfoResponse)]
#[error(mogh_error::Error)]
pub struct GetCoreInfo {}

/// Response for [GetCoreInfo].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetCoreInfoResponse {
  pub app_name: String,
  /// The address the app is reached at. Requests with a signing
  /// key are signed for its host.
  pub host: String,
}

//

/// Get the calling user.
/// Response: [User].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleReadRequest)]
#[response(GetUserResponse)]
#[error(mogh_error::Error)]
pub struct GetUser {}

/// Response for [GetUser].
#[typeshare]
pub type GetUserResponse = User;

//

/// List all users. Admin only.
/// Response: [ListUsersResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleReadRequest)]
#[response(ListUsersResponse)]
#[error(mogh_error::Error)]
pub struct ListUsers {}

/// Response for [ListUsers].
#[typeshare]
pub type ListUsersResponse = Vec<User>;

//

/// List the api keys of the calling user.
/// Response: [ListApiKeysResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleReadRequest)]
#[response(ListApiKeysResponse)]
#[error(mogh_error::Error)]
pub struct ListApiKeys {}

/// Response for [ListApiKeys].
#[typeshare]
pub type ListApiKeysResponse = Vec<ApiKey>;

//

/// List the notes of the calling user.
/// Response: [ListNotesResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Default, Resolve)]
#[empty_traits(ExampleReadRequest)]
#[response(ListNotesResponse)]
#[error(mogh_error::Error)]
pub struct ListNotes {
  /// Only notes with a title containing this.
  #[serde(default)]
  pub query: String,
}

/// Response for [ListNotes].
#[typeshare]
pub type ListNotesResponse = Vec<NoteListItem>;

//

/// Get a note of the calling user, including its content.
/// Response: [Note].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleReadRequest)]
#[response(GetNoteResponse)]
#[error(mogh_error::Error)]
pub struct GetNote {
  pub id: String,
}

/// Response for [GetNote].
#[typeshare]
pub type GetNoteResponse = Note;

//

/// Get what the server knows about the request itself.
/// Response: [GetRequestInfoResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleReadRequest)]
#[response(GetRequestInfoResponse)]
#[error(mogh_error::Error)]
pub struct GetRequestInfo {}

/// Response for [GetRequestInfo].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetRequestInfoResponse {
  /// The client ip, as seen by the server.
  pub ip: String,
  pub auth_method: AuthMethod,
  pub user_id: String,
}

//

/// Get counts of what is stored. Cached for a few seconds.
/// Response: [GetStatsResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(ExampleReadRequest)]
#[response(GetStatsResponse)]
#[error(mogh_error::Error)]
pub struct GetStats {}

/// Response for [GetStats].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GetStatsResponse {
  pub users: I64,
  pub notes: I64,
  pub api_keys: I64,
  /// Unix timestamp in ms the counts were taken at.
  pub computed_at: I64,
}
