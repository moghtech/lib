//! The supporter api, which an app serves at `/supporter`
//! ([crate::server], the `server` feature): posted to
//! `/supporter/read` and `/supporter/write` as
//! `{ "type": "<request>", "params": <request> }`, or to
//! `/supporter/read/<request>` with the params alone as the body,
//! like the app's own api. Authenticated like the requests the app's
//! UI makes, with a jwt, api key or signing key of an enabled user;
//! the write api and `GetSupporterKeyInfo` are for admins
//! (`AuthUserImpl::is_admin` of mogh_auth_server).
//!
//! Two things are managed over it: the configured supporter key, and for the
//! key of an organization or sponsor its branding
//! ([SupporterBranding]): the icon the badge shows, its size, and
//! whether it takes the place of the app's home button.
//!
//! The clients: [crate::request] in Rust, `MoghSupporterClient` of
//! the typescript package, and the hooks and components of mogh_ui.

use mogh_resolver::{HasResponse, Resolve};
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::{
  Payload, SignedSupporterKey, SupporterBranding, Tier, U64,
};

/// The requests of `/supporter/read`.
pub trait MoghSupporterReadRequest: HasResponse {}

/// The requests of `/supporter/write`.
pub trait MoghSupporterWriteRequest: HasResponse {}

//

/// Signs the browser's nonce with the supporter key in use, so the
/// browser can verify the key offline. The response holds nothing
/// secret, only what the badge shows. For every user.
/// Response: [GetSupporterKeyResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(MoghSupporterReadRequest)]
#[response(GetSupporterKeyResponse)]
#[error(mogh_error::Error)]
pub struct GetSupporterKey {
  /// 32 bytes the browser drew, base64url without padding. Anything
  /// else is a 400 error.
  pub nonce: String,
}

/// Response for [GetSupporterKey]: `None` without a key, and for a
/// key which does not verify on the server (the root keys the app
/// hardcodes, the format version, the app). In
/// typescript `SignedSupporterKey | null`, see the package's
/// `SupporterReadResponses`.
pub type GetSupporterKeyResponse = Option<SignedSupporterKey>;

//

/// What is configured, for the management UI: the supporter the key
/// in use names, where the key comes from, and whether it would show
/// a badge. Never the key itself. Admin only.
/// Response: [GetSupporterKeyInfoResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(MoghSupporterReadRequest)]
#[response(GetSupporterKeyInfoResponse)]
#[error(mogh_error::Error)]
pub struct GetSupporterKeyInfo {}

/// Response for [GetSupporterKeyInfo].
#[typeshare]
pub type GetSupporterKeyInfoResponse = SupporterKeyInfo;

//

/// Sets the supporter key: kept by the app, and used from now on
/// over the key of the app's config. The key has to parse, and to
/// verify on the server: the root keys the app hardcodes, the format
/// version, the app. A key which does not is refused with a 400 and
/// the reason, and nothing changes. Admin only.
/// Response: [SetSupporterKeyResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(MoghSupporterWriteRequest)]
#[response(SetSupporterKeyResponse)]
#[error(mogh_error::Error)]
pub struct SetSupporterKey {
  /// The key as pasted. Whitespace in it is ignored.
  pub key: String,
}

/// Response for [SetSupporterKey]: what is configured now.
#[typeshare]
pub type SetSupporterKeyResponse = SupporterKeyInfo;

//

/// Removes the key set with [SetSupporterKey]. The key of the app's
/// config, if any, is used again. Admin only.
/// Response: [DeleteSupporterKeyResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(MoghSupporterWriteRequest)]
#[response(DeleteSupporterKeyResponse)]
#[error(mogh_error::Error)]
pub struct DeleteSupporterKey {}

/// Response for [DeleteSupporterKey]: what is configured now.
#[typeshare]
pub type DeleteSupporterKeyResponse = SupporterKeyInfo;

//

/// How the badge of an organization or sponsor is shown: what the
/// topbar reads. Nothing in it is secret. For every user. The
/// browser applies it only for a key it verified as an
/// organization's or sponsor's.
/// Response: [GetSupporterBrandingResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(MoghSupporterReadRequest)]
#[response(GetSupporterBrandingResponse)]
#[error(mogh_error::Error)]
pub struct GetSupporterBranding {}

/// Response for [GetSupporterBranding]. The default while nothing
/// is set.
#[typeshare]
pub type GetSupporterBrandingResponse = SupporterBranding;

//

/// Sets how the badge of an organization or sponsor is shown,
/// replacing what was set: kept by the app, and used from now on.
/// The branding has to be valid ([SupporterBranding::validated], a
/// 400 with the reason otherwise), and the key in use an
/// organization's or sponsor's, unless it is the default, which
/// clears it (a 400 otherwise). Admin only.
/// Response: [SetSupporterBrandingResponse].
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, Resolve)]
#[empty_traits(MoghSupporterWriteRequest)]
#[response(SetSupporterBrandingResponse)]
#[error(mogh_error::Error)]
pub struct SetSupporterBranding {
  pub branding: SupporterBranding,
}

/// Response for [SetSupporterBranding]: the branding as it is kept.
#[typeshare]
pub type SetSupporterBrandingResponse = SupporterBranding;

//

/// Where the key in use comes from.
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum SupporterKeySource {
  /// No key: the topbar shows "Become a supporter".
  None,
  /// The app's config (`supporter_key`), while no key is stored.
  Config,
  /// Set with [SetSupporterKey], used over the config's.
  Stored,
}

/// What is configured, for the management UI. The key itself never
/// leaves the server.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SupporterKeyInfo {
  pub source: SupporterKeySource,
  /// Whether the app's config sets a key: what removing a stored key
  /// falls back to.
  pub config_key: bool,
  /// The supporter the key in use names, decoded from its payload:
  /// what the badge shows. `None` without a key, or for a payload
  /// which does not decode ([Self::problem] says so).
  pub supporter: Option<SupporterKeyPayload>,
  /// Why the key in use does not verify on the server, which then
  /// does not serve it, so it shows no badge: its payload, root
  /// signature, format version or app. `None` when the key
  /// verifies. [SetSupporterKey] refuses such a key, so this is the
  /// key of the app's config, or a stored key which verified under
  /// another release (eg. before a root key was removed). The
  /// browser verifies a served key again, also by its release date
  /// and the revocation list.
  pub problem: Option<String>,
}

/// The payload of a key, as [SupporterKeyInfo] shows it.
#[typeshare]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SupporterKeyPayload {
  /// `v`, the format version.
  pub version: U64,
  /// `k`, the id of the root key which signed the key: lowercase
  /// hex.
  pub root_key_id: String,
  /// `i`, the id of the key: a lowercase hyphenated UUID, the form
  /// the revocation list uses.
  pub id: String,
  /// `a`, the app the key is for.
  pub app: String,
  /// `n`, the name on the badge.
  pub name: String,
  /// `t`.
  pub tier: Tier,
  /// `s`, supporter since, `YYYY-MM-DD`.
  pub since: String,
  /// `c`, the last release date the key covers, `YYYY-MM-DD`.
  pub covers: String,
}

impl From<Payload> for SupporterKeyPayload {
  fn from(payload: Payload) -> Self {
    SupporterKeyPayload {
      version: payload.version,
      root_key_id: payload.root_key_id_hex(),
      id: payload.id_string(),
      app: payload.app,
      name: payload.name,
      tier: payload.tier,
      since: payload.since,
      covers: payload.covers,
    }
  }
}
