//! Serving the supporter api, with the `server` feature: [`router`],
//! which the app mounts at `/supporter`, [`SupporterImpl`], what the
//! app provides for it, and [`init`], called once at startup.
//!
//! Requests are authenticated like the auth management api of
//! mogh_auth_server (a jwt, api key or signing key of an enabled
//! user), and the key is managed by admins (`AuthUserImpl::is_admin`
//! of mogh_auth_server). A key an admin sets is handed to the app to
//! keep ([`SupporterImpl::store_supporter_key`]), and used over the
//! key of the app's config until it is removed. So is the branding
//! of an organization's key (`SetSupporterBranding`), which every
//! user's browser reads.
//!
//! The server verifies the key in use under the root keys the app
//! hardcodes ([`SupporterImpl::supporter_root_keys`]), and serves it
//! (`GetSupporterKey`) only when it verifies. The browser verifies
//! what it is served again, under the same root keys hardcoded in
//! the app's UI.
//!
//! [`router`]: crate::server::router
//! [`SupporterImpl`]: crate::server::SupporterImpl
//! [`init`]: crate::server::init
//! [`SupporterImpl::store_supporter_key`]: crate::server::SupporterImpl::store_supporter_key
//! [`SupporterImpl::supporter_root_keys`]: crate::server::SupporterImpl::supporter_root_keys

use std::sync::Arc;

use anyhow::{Context as _, anyhow};
use arc_swap::ArcSwapOption;
use axum::{
  Router,
  extract::{FromRequestParts, OriginalUri, Path, Request},
  http::{StatusCode, request::Parts},
  middleware::Next,
  response::Response,
  routing::post,
};
use mogh_auth_server::{
  AuthImpl, DynFuture,
  middleware::{
    accept_signed_request, accepted_signature,
    extract_request_authentication_rate_limited,
    get_user_from_request_authentication, read_signed_request_body,
  },
  user::BoxAuthUser,
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _, Json};
use mogh_rate_limit::WithFailureRateLimit as _;
use mogh_request_ip::RequestIp;
use mogh_resolver::Resolve;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumDiscriminants};
use tracing::{debug, info, warn};
use typeshare::typeshare;

use crate::{
  Payload, SupporterBranding, SupporterKey, Tier, VerifyError,
  api::{
    DeleteSupporterKey, GetSupporterBranding, GetSupporterKey,
    GetSupporterKeyInfo, SetSupporterBranding, SetSupporterKey,
    SupporterKeyInfo, SupporterKeySource,
  },
  compact_key, decode_nonce, root_key_id,
};

/// What an app provides to serve supporter keys, implemented on its
/// `AuthImpl`: which app it is, the root keys it trusts, the key its
/// config sets, and where a key set over the api is kept.
pub trait SupporterImpl: AuthImpl {
  /// This app, as the `a` of its keys names it: `komodo`, `cicada`.
  fn supporter_app(&self) -> &'static str;

  /// The key the app's config sets (`supporter_key`: config file,
  /// environment, secret file), empty for none. Used while no key
  /// is stored.
  fn supporter_config_key(&self) -> &str {
    ""
  }

  /// The root public keys which sign this app's supporter keys,
  /// hardcoded in the app: each app has its own. The key in use is
  /// verified under them, and only served (`GetSupporterKey`) when
  /// it verifies ([SupporterKeyInfo::problem] and the startup log
  /// say why it does not). The browser verifies what it is served
  /// again, with the same keys hardcoded in the app's UI: keep the
  /// two in step, and check them in a unit test
  /// ([crate::check_root_keys]). Only a test harness trusts the test
  /// root of [crate::fixture].
  ///
  /// An entry is the Ed25519 public key as base64 SPKI DER. Its id
  /// is derived from it, and logged at startup ([init]).
  fn supporter_root_keys(&self) -> &'static [&'static str];

  /// The key kept by [Self::store_supporter_key], if any. Read once
  /// at startup ([init]).
  fn load_stored_supporter_key(
    &self,
  ) -> DynFuture<mogh_error::Result<Option<String>>>;

  /// Keeps the key an admin set (`SetSupporterKey`), or removes it
  /// (`None`, `DeleteSupporterKey`). The key holds the instance
  /// private key: store it like a secret, encrypted at rest.
  fn store_supporter_key(
    &self,
    key: Option<String>,
  ) -> DynFuture<mogh_error::Result<()>>;

  /// The branding kept by [Self::store_supporter_branding], if any.
  /// Read once at startup ([init]).
  fn load_supporter_branding(
    &self,
  ) -> DynFuture<mogh_error::Result<Option<SupporterBranding>>>;

  /// Keeps the branding an admin set (`SetSupporterBranding`),
  /// replacing what was kept. Nothing in it is secret. An uploaded
  /// icon is in it as a `data:` url, up to about 350 KB of text.
  fn store_supporter_branding(
    &self,
    branding: SupporterBranding,
  ) -> DynFuture<mogh_error::Result<()>>;
}

/// The key in use.
struct Current {
  key: SupporterKey,
  source: SupporterKeySource,
  /// The payload, verified under the app's root keys
  /// ([SupporterKey::verify]), or why the key does not verify. Only
  /// a key which verifies is served and can be branded.
  verified: Result<Payload, VerifyError>,
}

impl Current {
  fn new<I: SupporterImpl + ?Sized>(
    imp: &I,
    key: SupporterKey,
    source: SupporterKeySource,
  ) -> Current {
    let verified = key.verify(imp.supporter_root_keys());
    Current {
      key,
      source,
      verified,
    }
  }
}

static CURRENT: ArcSwapOption<Current> = ArcSwapOption::const_empty();

/// The branding in use. Empty: the default.
static BRANDING: ArcSwapOption<SupporterBranding> =
  ArcSwapOption::const_empty();

/// One change of the key or the branding at a time, so what is
/// stored and what is served stay the same.
static CHANGE: tokio::sync::Mutex<()> =
  tokio::sync::Mutex::const_new(());

/// Loads the key in use, should be called once at startup. Loads the
/// currently stored one ([SupporterImpl::load_stored_supporter_key]),
/// else the key of the app's config. Will log what the badge will / will not show.
/// `GetSupporterKey` answers `None` until this ran. Aftwerwards loads the branding
/// ([SupporterImpl::load_supporter_branding]).
/// Fails when the stored key or branding can't be read.
pub async fn init<I: SupporterImpl>() -> anyhow::Result<()> {
  let imp = I::new();
  // The root keys of this build, by the ids derived from them: to
  // compare with what the platform published. A hardcoded key copied
  // wrong would otherwise silently verify nothing.
  let mut root_key_ids = Vec::new();
  for (i, root) in imp.supporter_root_keys().iter().enumerate() {
    match root_key_id(root) {
      Ok(id) => root_key_ids.push(id),
      Err(e) => warn!(
        "The supporter root key at position {} of this build is not valid | {e}",
        i + 1
      ),
    }
  }
  if root_key_ids.is_empty() {
    debug!("This build trusts no supporter root key");
  } else {
    info!(
      "Supporter keys are verified under the root keys {}",
      root_key_ids.join(", ")
    );
  }
  let stored = imp
    .load_stored_supporter_key()
    .await
    .map_err(|e| e.error)
    .context("Failed to load the stored supporter key")?;
  let current = stored
    .and_then(|key| load(&imp, &key, SupporterKeySource::Stored))
    .or_else(|| {
      load(
        &imp,
        imp.supporter_config_key(),
        SupporterKeySource::Config,
      )
    });
  if current.is_none() {
    info!("No supporter key configured");
  }
  CURRENT.store(current.map(Arc::new));

  // The branding, checked again: what is kept may be older than
  // the rules.
  let branding = imp
    .load_supporter_branding()
    .await
    .map_err(|e| e.error)
    .context("Failed to load the supporter branding")?
    .and_then(|branding| match branding.validated() {
      Ok(branding) => Some(branding),
      Err(e) => {
        warn!("Ignoring the stored supporter branding | {e}");
        None
      }
    });
  BRANDING.store(branding.map(Arc::new));
  Ok(())
}

/// The branding in use.
fn branding() -> SupporterBranding {
  BRANDING.load().as_deref().cloned().unwrap_or_default()
}

/// Whether the key in use verifies and is an organization's or
/// sponsor's. The browser applies the branding only for a key it
/// verified itself.
fn organization_key_in_use() -> bool {
  CURRENT.load().as_ref().is_some_and(|current| {
    current
      .verified
      .as_ref()
      .is_ok_and(|payload| payload.tier != Tier::Individual)
  })
}

fn load<I: SupporterImpl + ?Sized>(
  imp: &I,
  key: &str,
  source: SupporterKeySource,
) -> Option<Current> {
  SupporterKey::load(
    imp.supporter_app(),
    key,
    imp.supporter_root_keys(),
  )
  .map(|key| Current::new(imp, key, source))
}

fn info<I: SupporterImpl + ?Sized>(imp: &I) -> SupporterKeyInfo {
  let config_key = !imp.supporter_config_key().trim().is_empty();
  let Some(current) = CURRENT.load_full() else {
    return SupporterKeyInfo {
      source: SupporterKeySource::None,
      config_key,
      supporter: None,
      problem: None,
    };
  };
  let (supporter, problem) = match &current.verified {
    Ok(payload) => (Some(payload.clone().into()), None),
    Err(e) => (
      current.key.decode_payload().ok().map(Into::into),
      Some(e.to_string()),
    ),
  };
  SupporterKeyInfo {
    source: current.source,
    config_key,
    supporter,
    problem,
  }
}

/// The supporter api, for the app to nest at `/supporter`: the url
/// the typescript client and mogh_ui's `setSupporterUrl` take.
/// Authenticates every request like the auth management api does,
/// and refuses disabled users.
pub fn router<I: SupporterImpl>() -> Router {
  Router::new()
    .nest(
      "/read",
      Router::new()
        .route("/", post(read_handler::<I>))
        .route("/{variant}", post(read_variant_handler::<I>)),
    )
    .nest(
      "/write",
      Router::new()
        .route("/", post(write_handler::<I>))
        .route("/{variant}", post(write_variant_handler::<I>)),
    )
    .layer(axum::middleware::from_fn(attach_user::<I>))
}

/// The user of a request, attached by [attach_user].
#[derive(Clone)]
struct SupporterUser(Arc<BoxAuthUser>);

impl<S: Send + Sync> FromRequestParts<S> for SupporterUser {
  type Rejection = mogh_error::Error;

  async fn from_request_parts(
    parts: &mut Parts,
    _: &S,
  ) -> Result<Self, Self::Rejection> {
    parts
      .extensions
      .get()
      .cloned()
      .context("Missing authorization credentials")
      .status_code(StatusCode::UNAUTHORIZED)
  }
}

/// Authenticates the request with the building blocks of
/// mogh_auth_server, as its management api does, and attaches the
/// user. A disabled user is refused everything.
async fn attach_user<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  OriginalUri(uri): OriginalUri,
  req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  let auth = I::new();
  // The signature of a signed request covers the body.
  let (req, body) = read_signed_request_body(&auth, ip, req).await?;
  let req_auth = extract_request_authentication_rate_limited(
    &auth,
    ip,
    req.method(),
    &uri,
    req.headers(),
    &body,
  )
  .await?;
  let accepted = accepted_signature(&req_auth, req.headers())?;
  // Enforces the api key and user cidr whitelists.
  let user =
    get_user_from_request_authentication(&auth, req_auth, ip)
      .with_failure_rate_limit_using_ip(
        auth.general_rate_limiter(),
        &ip,
      )
      .await?;
  if !user.is_enabled() {
    return Err(
      anyhow!("User is not enabled")
        .status_code(StatusCode::FORBIDDEN),
    );
  }
  let mut req = req;
  accept_signed_request(&auth, ip, accepted, &mut req).await?;
  req.extensions_mut().insert(SupporterUser(Arc::new(user)));
  Ok(next.run(req).await)
}

pub struct SupporterArgs {
  imp: Box<dyn SupporterImpl>,
  user: Arc<BoxAuthUser>,
}

/// The requests of `/supporter/read`.
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[strum_discriminants(name(ReadRequestMethod), derive(Display))]
#[args(SupporterArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names)]
pub enum SupporterReadRequest {
  GetSupporterKey(GetSupporterKey),
  GetSupporterKeyInfo(GetSupporterKeyInfo),
  GetSupporterBranding(GetSupporterBranding),
}

/// The requests of `/supporter/write`.
#[typeshare]
#[derive(
  Debug, Clone, Serialize, Deserialize, Resolve, EnumDiscriminants,
)]
#[strum_discriminants(name(WriteRequestMethod), derive(Display))]
#[args(SupporterArgs)]
#[response(mogh_error::Response)]
#[error(mogh_error::Error)]
#[serde(tag = "type", content = "params")]
#[allow(clippy::enum_variant_names)]
pub enum SupporterWriteRequest {
  SetSupporterKey(SetSupporterKey),
  DeleteSupporterKey(DeleteSupporterKey),
  SetSupporterBranding(SetSupporterBranding),
}

#[derive(Deserialize)]
struct Variant {
  variant: String,
}

/// The tagged request (`{ type, params }`) of a `/{variant}` route.
/// An unknown variant or invalid params is the client's fault.
fn variant_request<R: serde::de::DeserializeOwned>(
  variant: String,
  params: serde_json::Value,
) -> mogh_error::Result<R> {
  serde_json::from_value(serde_json::json!({
    "type": variant,
    "params": params,
  }))
  .context("Invalid request")
  .status_code(StatusCode::BAD_REQUEST)
}

async fn read_variant_handler<I: SupporterImpl>(
  user: SupporterUser,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<Response> {
  read_handler::<I>(user, Json(variant_request(variant, params)?))
    .await
}

async fn read_handler<I: SupporterImpl>(
  SupporterUser(user): SupporterUser,
  Json(request): Json<SupporterReadRequest>,
) -> mogh_error::Result<Response> {
  let method: ReadRequestMethod = (&request).into();
  debug!(
    api = "Supporter",
    method = method.to_string(),
    user_id = user.id(),
    username = user.username(),
  );
  let args = SupporterArgs {
    imp: Box::new(I::new()),
    user,
  };
  let res = request.resolve(&args).await;
  if let Err(e) = &res {
    debug!(
      api = "Supporter",
      method = method.to_string(),
      "ERROR: {:#}",
      e.error
    );
  }
  res.map(|res| res.0)
}

async fn write_variant_handler<I: SupporterImpl>(
  user: SupporterUser,
  Path(Variant { variant }): Path<Variant>,
  Json(params): Json<serde_json::Value>,
) -> mogh_error::Result<Response> {
  write_handler::<I>(user, Json(variant_request(variant, params)?))
    .await
}

async fn write_handler<I: SupporterImpl>(
  SupporterUser(user): SupporterUser,
  Json(request): Json<SupporterWriteRequest>,
) -> mogh_error::Result<Response> {
  let method: WriteRequestMethod = (&request).into();
  debug!(
    api = "Supporter",
    method = method.to_string(),
    user_id = user.id(),
    username = user.username(),
  );
  let args = SupporterArgs {
    imp: Box::new(I::new()),
    user,
  };
  let res = request.resolve(&args).await;
  if let Err(e) = &res {
    debug!(
      api = "Supporter",
      method = method.to_string(),
      "ERROR: {:#}",
      e.error
    );
  }
  res.map(|res| res.0)
}

/// Only non-workload admins manage the key and its branding,.
fn check_admin(user: &BoxAuthUser) -> mogh_error::Result<()> {
  if user.is_admin() && !user.is_workload() {
    Ok(())
  } else {
    Err(
      anyhow!("Only admins can manage the supporter key")
        .status_code(StatusCode::FORBIDDEN),
    )
  }
}

impl Resolve<SupporterArgs> for GetSupporterKey {
  async fn resolve(
    self,
    _: &SupporterArgs,
  ) -> Result<Self::Response, Self::Error> {
    // The nonce first: a bad one is a 400 whether or not a key is
    // configured.
    let nonce = decode_nonce(&self.nonce)
      .context("Invalid nonce")
      .status_code(StatusCode::BAD_REQUEST)?;
    // Only a key which verifies under the app's root keys: nothing
    // is signed with the instance key of another one.
    Ok(
      CURRENT
        .load()
        .as_ref()
        .filter(|current| current.verified.is_ok())
        .map(|current| current.key.respond(&nonce)),
    )
  }
}

impl Resolve<SupporterArgs> for GetSupporterKeyInfo {
  async fn resolve(
    self,
    SupporterArgs { imp, user }: &SupporterArgs,
  ) -> Result<Self::Response, Self::Error> {
    check_admin(user)?;
    Ok(info(imp.as_ref()))
  }
}

impl Resolve<SupporterArgs> for SetSupporterKey {
  async fn resolve(
    self,
    SupporterArgs { imp, user }: &SupporterArgs,
  ) -> Result<Self::Response, Self::Error> {
    check_admin(user)?;
    let key = compact_key(&self.key);
    let parsed = SupporterKey::parse(imp.supporter_app(), &key)
      .context("Invalid supporter key")
      .status_code(StatusCode::BAD_REQUEST)?;
    // Only a key which verifies is kept: one which does not, for
    // whatever reason, is refused like one which does not parse, and
    // changes nothing.
    let payload = parsed
      .verify(imp.supporter_root_keys())
      .context("Invalid supporter key")
      .status_code(StatusCode::BAD_REQUEST)?;
    let _change = CHANGE.lock().await;
    imp.store_supporter_key(Some(key.to_string())).await?;
    info!(
      "Supporter key set by {}: {} ({}), covers releases up to {}",
      user.username(),
      payload.name,
      payload.tier,
      payload.covers
    );
    CURRENT.store(Some(Arc::new(Current {
      key: parsed,
      source: SupporterKeySource::Stored,
      verified: Ok(payload),
    })));
    Ok(info(imp.as_ref()))
  }
}

impl Resolve<SupporterArgs> for DeleteSupporterKey {
  async fn resolve(
    self,
    SupporterArgs { imp, user }: &SupporterArgs,
  ) -> Result<Self::Response, Self::Error> {
    check_admin(user)?;
    let _change = CHANGE.lock().await;
    imp.store_supporter_key(None).await?;
    info!("Supporter key removed by {}", user.username());
    // The config's key, if any, is used again (and logged).
    CURRENT.store(
      load(
        imp.as_ref(),
        imp.supporter_config_key(),
        SupporterKeySource::Config,
      )
      .map(Arc::new),
    );
    Ok(info(imp.as_ref()))
  }
}

impl Resolve<SupporterArgs> for GetSupporterBranding {
  async fn resolve(
    self,
    _: &SupporterArgs,
  ) -> Result<Self::Response, Self::Error> {
    Ok(branding())
  }
}

impl Resolve<SupporterArgs> for SetSupporterBranding {
  async fn resolve(
    self,
    SupporterArgs { imp, user }: &SupporterArgs,
  ) -> Result<Self::Response, Self::Error> {
    check_admin(user)?;
    let branding = self
      .branding
      .validated()
      .context("Invalid supporter branding")
      .status_code(StatusCode::BAD_REQUEST)?;
    let _change = CHANGE.lock().await;
    // For the keys of organizations and sponsors. The default clears
    // it, whatever the key.
    if !branding.is_default() && !organization_key_in_use() {
      return Err(
        anyhow!(
          "Branding is for the supporter keys of organizations and sponsors: no such key is in use and verifies"
        )
        .status_code(StatusCode::BAD_REQUEST),
      );
    }
    imp.store_supporter_branding(branding.clone()).await?;
    BRANDING.store(Some(Arc::new(branding.clone())));
    // Never the icon: an uploaded one is the whole image.
    info!(
      "Supporter branding set by {}: icon {}, width {:?}, height {:?}, link {}, replaces the home button: {}, hides the name: {}, name in capitals: {}",
      user.username(),
      branding.icon_kind(),
      branding.icon_width,
      branding.icon_height,
      branding.link.as_deref().unwrap_or("none"),
      branding.replace_home,
      branding.hide_name,
      branding.uppercase_name
    );
    Ok(branding)
  }
}
