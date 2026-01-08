use serde::{Deserialize, Serialize};
use typeshare::typeshare;

pub mod login;
pub mod manage;

/// Represents an empty json object: `{}`
#[typeshare]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct NoData {}
