use std::{
  collections::HashMap, future::Future, pin::Pin, sync::OnceLock,
  time::Duration,
};

use anyhow::{Context, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::config::{OidcConfig, TokenExchangeConfig};
use mogh_error::{AddStatusCode as _, AddStatusCodeError};
use openidconnect::{
  AccessTokenHash, AdditionalClaims, AsyncHttpClient,
  AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
  EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet,
  EndpointSet, HttpClientError, HttpRequest, HttpResponse,
  IdTokenFields, IssuerUrl, Nonce, OAuth2TokenResponse,
  PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
  RequestTokenError, Scope, StandardErrorResponse,
  StandardTokenResponse, TokenResponse as _,
  core::*,
  reqwest::{self, Url},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
  provider::{
    CONNECT_TIMEOUT, REQUEST_TIMEOUT, named::sanitize_text,
    token_exchange::TokenVerificationKeys,
  },
  validations::url_has_credentials,
};

pub use openidconnect::SubjectIdentifier;

/// Some OIDC providers use 'username' additional claim
/// rather than the standard 'preferred_username'
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameAdditionalClaims {
  pub username: Option<String>,
  /// All other non standard claims.
  /// The configured 'groups_claim' is extracted from here.
  #[serde(flatten)]
  pub extra: HashMap<String, serde_json::Value>,
}

impl AdditionalClaims for UsernameAdditionalClaims {}

pub type TokenResponse = StandardTokenResponse<
  IdTokenFields<
    UsernameAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
  >,
  CoreTokenType,
>;

/// A client for requests to OIDC providers (and Google), which
/// gives up after `timeout` (see [REQUEST_TIMEOUT]).
///
/// Redirects are not followed: the token request carries the
/// client credentials and the PKCE verifier, which a redirect
/// would send on.
pub(crate) fn http_client(
  app_user_agent: &str,
  timeout: Duration,
) -> reqwest::Result<ProviderHttpClient> {
  reqwest::Client::builder()
    .redirect(reqwest::redirect::Policy::none())
    .timeout(timeout)
    .connect_timeout(CONNECT_TIMEOUT.min(timeout))
    .user_agent(app_user_agent)
    .build()
    .map(ProviderHttpClient)
}

/// The most of a login provider's response which is read: far more
/// than any discovery document, key set, token or user info. Without
/// it, only the request timeout bounded what a provider (or whatever
/// its discovery points the token, user info or key set urls at)
/// could make the server buffer, for every login callback.
pub(crate) const MAX_RESPONSE_LENGTH: usize = 1024 * 1024;

/// The http client of the requests made through openidconnect to OIDC
/// providers and Google (discovery, the key set, the code exchange,
/// user info): reads at most [MAX_RESPONSE_LENGTH] of a response, and
/// refuses the rest unread, also a response declaring more up front.
#[derive(Clone)]
pub(crate) struct ProviderHttpClient(reqwest::Client);

impl<'c> AsyncHttpClient<'c> for ProviderHttpClient {
  type Error = HttpClientError<reqwest::Error>;
  type Future = Pin<
    Box<
      dyn Future<Output = Result<HttpResponse, Self::Error>>
        + Send
        + Sync
        + 'c,
    >,
  >;

  fn call(&'c self, request: HttpRequest) -> Self::Future {
    Box::pin(async move {
      let mut response = self
        .0
        .execute(request.try_into().map_err(Box::new)?)
        .await
        .map_err(Box::new)?;
      let mut builder = openidconnect::http::Response::builder()
        .status(response.status())
        .version(response.version());
      for (name, value) in response.headers() {
        builder = builder.header(name, value);
      }
      let too_large = || {
        HttpClientError::Other(format!(
          "The response is larger than {MAX_RESPONSE_LENGTH} bytes"
        ))
      };
      if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_LENGTH as u64)
      {
        return Err(too_large());
      }
      let mut body = Vec::new();
      while let Some(chunk) =
        response.chunk().await.map_err(Box::new)?
      {
        if body.len() + chunk.len() > MAX_RESPONSE_LENGTH {
          return Err(too_large());
        }
        body.extend_from_slice(&chunk);
      }
      builder.body(body).map_err(HttpClientError::Http)
    })
  }
}

/// The error of the token request redeeming a login's code at an OIDC
/// provider (or Google, `provider` names it).
///
/// The provider's refusal (an OAuth error response, RFC 6749 section
/// 5.2) is the user's failed login (`401`), counted against the
/// client ip like any other: the code expired, was used already (a
/// reloaded callback), was made up, or its PKCE verifier doesn't
/// match. Except the codes saying the app's configuration is wrong
/// (its client credentials, grant type or scopes), which are server
/// errors, as are a provider which can't be reached or answers
/// something else. The error carries what the provider reported
/// (sanitized), never the request.
pub(crate) fn token_request_error<RE>(
  provider: &str,
  e: RequestTokenError<
    RE,
    StandardErrorResponse<CoreErrorResponseType>,
  >,
) -> mogh_error::Error
where
  RE: std::error::Error + Send + Sync + 'static,
{
  let response = match e {
    RequestTokenError::ServerResponse(response) => response,
    e => {
      return anyhow::Error::new(e)
        .context(format!(
          "Failed to get the token of the login from {provider}"
        ))
        .into();
    }
  };
  let status = match response.error() {
    CoreErrorResponseType::InvalidClient
    | CoreErrorResponseType::UnauthorizedClient
    | CoreErrorResponseType::UnsupportedGrantType
    | CoreErrorResponseType::InvalidScope => {
      StatusCode::INTERNAL_SERVER_ERROR
    }
    // Eg. 'invalid_grant': expired, used or made up.
    _ => StatusCode::UNAUTHORIZED,
  };
  let code = sanitize_text(response.error().as_ref());
  let e = match response.error_description().map(|d| sanitize_text(d))
  {
    Some(description) if !description.is_empty() => {
      anyhow!("{description}")
        .context(format!("{provider} refused the login: {code}"))
    }
    _ => anyhow!("{provider} refused the login: {code}"),
  };
  e.status_code(status)
}

/// The client shared by every OIDC provider.
fn shared_http_client(
  app_user_agent: &str,
) -> &'static ProviderHttpClient {
  static REQWEST: OnceLock<ProviderHttpClient> = OnceLock::new();
  REQWEST.get_or_init(|| {
    http_client(app_user_agent, REQUEST_TIMEOUT)
      .expect("Invalid OIDC reqwest client")
  })
}

pub type InnerOidcProvider = Client<
  UsernameAdditionalClaims,
  CoreAuthDisplay,
  CoreGenderClaim,
  CoreJweContentEncryptionAlgorithm,
  CoreJsonWebKey,
  CoreAuthPrompt,
  StandardErrorResponse<CoreErrorResponseType>,
  TokenResponse,
  CoreTokenIntrospectionResponse,
  CoreRevocableToken,
  CoreRevocationErrorResponse,
  EndpointSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointNotSet,
  EndpointMaybeSet,
  EndpointMaybeSet,
>;

pub struct OidcProvider {
  http: ProviderHttpClient,
  client: InnerOidcProvider,
  use_full_email: bool,
  additional_scopes: Vec<String>,
  /// Audiences besides the client id which
  /// the ID tokens of logins may carry.
  additional_audiences: Vec<String>,
  /// To verify tokens presented for token exchange
  verification_keys: TokenVerificationKeys,
}

impl OidcProvider {
  /// Initialize a new OIDC provider using the configured provider's
  /// discovery endpoint.
  pub async fn new(
    app_user_agent: &'static str,
    redirect_uri: String,
    config: &OidcConfig,
  ) -> anyhow::Result<OidcProvider> {
    if !config.enabled() {
      return Err(anyhow!(
        "OIDC provider is disabled or not configured."
      ));
    }

    // Refused by the management api. Configured elsewhere, they
    // would be sent to the discovery endpoint, and end up in the
    // errors of the discovery (eg. the issuer mismatch, as the
    // provider's issuer can't carry them).
    if Url::parse(&config.provider)
      .is_ok_and(|url| url_has_credentials(&url))
    {
      return Err(anyhow!(
        "OIDC 'provider' url must not carry credentials (scheme://user:password@host)"
      ));
    }

    // Use OpenID Connect Discovery to fetch the provider metadata.
    let provider_metadata = CoreProviderMetadata::discover_async(
      IssuerUrl::new(config.provider.clone())?,
      shared_http_client(app_user_agent),
    )
    .await
    .context(
      "Failed to get OIDC /.well-known/openid-configuration",
    )?;

    Self::from_metadata(
      app_user_agent,
      redirect_uri,
      config,
      provider_metadata,
    )
  }

  /// Initialize the provider from already discovered metadata.
  pub fn from_metadata(
    app_user_agent: &'static str,
    redirect_uri: String,
    config: &OidcConfig,
    provider_metadata: CoreProviderMetadata,
  ) -> anyhow::Result<OidcProvider> {
    let verification_keys =
      TokenVerificationKeys::from_metadata(&provider_metadata);

    let additional_scopes = additional_scopes(
      config,
      provider_metadata.scopes_supported().map(Vec::as_slice),
    );

    let client = InnerOidcProvider::from_provider_metadata(
      provider_metadata,
      ClientId::new(config.client_id.to_string()),
      // The secret may be empty / ommitted if auth provider supports PKCE
      if config.client_secret.is_empty() {
        None
      } else {
        Some(ClientSecret::new(config.client_secret.to_string()))
      },
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(
      RedirectUrl::new(redirect_uri)
        .context("Invalid OIDC redirect URI")?,
    );

    Ok(OidcProvider {
      http: shared_http_client(app_user_agent).clone(),
      client,
      use_full_email: config.use_full_email,
      additional_scopes,
      additional_audiences: config.additional_audiences.clone(),
      verification_keys,
    })
  }

  /// Gives up on requests after `timeout`
  /// instead of [REQUEST_TIMEOUT].
  #[cfg(test)]
  fn with_request_timeout(
    mut self,
    timeout: Duration,
  ) -> OidcProvider {
    self.http = http_client("test", timeout).unwrap();
    self
  }

  /// Verifies the ID tokens of logins. Some providers attach
  /// additional audiences, which are trusted when configured
  /// ('additional_audiences'). Every verification of a login's
  /// ID token uses this, otherwise its claims would be verified
  /// by one step and refused by the next.
  fn id_token_verifier(&self) -> CoreIdTokenVerifier<'_> {
    let verifier = self.client.id_token_verifier();
    if self.additional_audiences.is_empty() {
      verifier
    } else {
      verifier.set_other_audience_verifier_fn(|aud| {
        self.additional_audiences.contains(aud)
      })
    }
  }

  /// Verifies a token presented for RFC 8693 token exchange, which
  /// must be signed by the provider and issued to the client id or one
  /// of the exchange audiences. Enforces 'allowed_groups'.
  ///
  /// Groups can only come from the token itself here,
  /// there is no access token to get the networked user info with.
  pub fn verify_exchange_token(
    &self,
    config: &OidcConfig,
    exchange: &TokenExchangeConfig,
    token: &str,
  ) -> mogh_error::Result<OidcLoginInfo> {
    let mut audiences = vec![config.client_id.clone()];
    audiences.extend(exchange.audiences.iter().cloned());

    let claims = self
      .verification_keys
      .verify::<UsernameAdditionalClaims>(
        token,
        &audiences,
        &config.additional_audiences,
        exchange.max_token_age_secs,
      )
      .status_code(StatusCode::BAD_REQUEST)?;

    let groups = config.groups_claim().and_then(|claim| {
      extract_groups(&claims.additional_claims().extra, claim)
    });

    let info =
      OidcLoginInfo::new(config, claims.subject().clone(), groups);
    info.check_allowed_groups(config)?;

    Ok(info)
  }

  pub fn authorize_url(
    &self,
    pkce_challenge: PkceCodeChallenge,
  ) -> (Url, CsrfToken, Nonce) {
    self
      .client
      .authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
      )
      .set_pkce_challenge(pkce_challenge)
      .add_scope(Scope::new("openid".to_string()))
      .add_scope(Scope::new("profile".to_string()))
      .add_scope(Scope::new("email".to_string()))
      .add_scopes(
        self.additional_scopes.iter().cloned().map(Scope::new),
      )
      .url()
  }

  /// Applies security validations and extracts the
  /// oidc user info, including groups if configured.
  ///
  /// Enforces 'allowed_groups', so every flow
  /// using the validated login is gated.
  pub async fn validate_extract_login_info_and_token(
    &self,
    config: &OidcConfig,
    (client, server): (CsrfToken, String),
    code: String,
    pkce_verifier: PkceCodeVerifier,
    nonce: &Nonce,
  ) -> mogh_error::Result<(OidcLoginInfo, TokenResponse)> {
    // Validate CSRF tokens match
    if !crate::validations::constant_time_eq(client.secret(), &server)
    {
      return Err(
        anyhow!("CSRF token invalid")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }

    let token_response = self
      .client
      .exchange_code(AuthorizationCode::new(code))
      .context("Failed to get Oauth token at exchange code")?
      .set_pkce_verifier(pkce_verifier)
      .request_async(&self.http)
      .await
      .map_err(|e| token_request_error("The OIDC provider", e))?;

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response
      .id_token()
      .context("OIDC Server did not return an ID token")?;

    let verifier = self.id_token_verifier();

    // The login can't be trusted, which is not a server error.
    let claims = id_token
      .claims(&verifier, nonce)
      .context("Failed to verify token claims. This issue may be temporary (60 seconds max).")
      .status_code(StatusCode::UNAUTHORIZED)?;

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) =
      claims.access_token_hash()
    {
      let actual_access_token_hash =
        access_token_hash(id_token, &verifier, &token_response)
          .context("Failed to hash the access token")
          .status_code(StatusCode::UNAUTHORIZED)?;
      if actual_access_token_hash != *expected_access_token_hash {
        return Err(
          anyhow!("Invalid access token")
            .status_code(StatusCode::UNAUTHORIZED),
        );
      }
    }

    let subject = claims.subject().clone();

    let groups = match config.groups_claim() {
      Some(claim) => {
        // Priority 1: groups from id_token.
        match extract_groups(&claims.additional_claims().extra, claim)
        {
          Some(groups) => Some(groups),
          // Priority 2: groups from user_info.
          None => {
            self
              .get_user_info_groups(&subject, &token_response, claim)
              .await
          }
        }
      }
      None => None,
    };

    let info = OidcLoginInfo::new(config, subject, groups);
    info.check_allowed_groups(config)?;

    Ok((info, token_response))
  }

  /// Some providers only include the groups claim
  /// in the networked user info.
  async fn get_user_info_groups(
    &self,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
    claim: &str,
  ) -> Option<Vec<String>> {
    let user_info = self
      .user_info(subject, token)
      .await
      .inspect_err(|e| {
        warn!("OIDC groups claim '{claim}' not in id token and failed to get user info | {e:#}")
      })
      .ok()?;
    let groups =
      extract_groups(&user_info.additional_claims().extra, claim);
    if groups.is_none() {
      warn!(
        "OIDC groups claim '{claim}' not found in id token or user info. The scope providing it may need to be added to 'additional_scopes'."
      );
    }
    groups
  }

  /// The networked user info of the login's access token.
  async fn user_info(
    &self,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
  ) -> anyhow::Result<UserInfoClaims> {
    let user_info = self
      .client
      .user_info(token.access_token().clone(), Some(subject.clone()))
      .context("The provider has no user info endpoint")?
      .request_async::<UsernameAdditionalClaims, _, CoreGenderClaim>(
        &self.http,
      )
      .await
      .context("Failed to get the user info")?;
    debug!("OIDC USER INFO: {user_info:?}");
    Ok(user_info)
  }

  /// The name a new user is signed up with: the first of these claims
  /// the provider has for them, each taken from the login's ID token,
  /// else its user info (only requested when the ID token doesn't
  /// have the first): `preferred_username`, `username`, `name`, the
  /// part of `email` before the `@`; with 'use_full_email' the whole
  /// `email` first instead. Else the subject.
  pub async fn get_username(
    &self,
    subject: &SubjectIdentifier,
    token: &TokenResponse,
    nonce: &Nonce,
  ) -> String {
    let id_claims = token.id_token().and_then(|token| {
      token
        .claims(&self.id_token_verifier(), nonce)
        .inspect(|claims| debug!("OIDC ID TOKEN CLAIMS: {claims:?}"))
        .ok()
        .map(NameClaims::of_id_token)
    });
    // Requested once, when the ID token can't answer.
    let mut user_info = None::<Option<NameClaims>>;
    for claim in NameClaim::order(self.use_full_email) {
      if let Some(name) =
        id_claims.as_ref().and_then(|claims| claims.get(*claim))
      {
        return name;
      }
      if user_info.is_none() {
        user_info = Some(
          self
            .user_info(subject, token)
            .await
            .inspect_err(|e| debug!("No OIDC user info | {e:#}"))
            .ok()
            .map(|user_info| NameClaims::of_user_info(&user_info)),
        );
      }
      if let Some(name) = user_info
        .as_ref()
        .and_then(Option::as_ref)
        .and_then(|claims| claims.get(*claim))
      {
        return name;
      }
    }
    subject.to_string()
  }
}

type UserInfoClaims = openidconnect::UserInfoClaims<
  UsernameAdditionalClaims,
  CoreGenderClaim,
>;

/// A claim a new user's name can be taken from, see
/// [OidcProvider::get_username].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameClaim {
  /// The whole email.
  Email,
  PreferredUsername,
  /// The non standard `username` some providers use.
  Username,
  Name,
  /// The part of the email before the `@`.
  EmailLocalPart,
}

impl NameClaim {
  /// The claims tried, in order: the email first with
  /// 'use_full_email', else the usual names, and only then the start
  /// of the email.
  fn order(use_full_email: bool) -> &'static [NameClaim] {
    use NameClaim::*;
    if use_full_email {
      &[Email, PreferredUsername, Username, Name]
    } else {
      &[PreferredUsername, Username, Name, EmailLocalPart]
    }
  }
}

/// The claims of an ID token or user info a name is taken from.
struct NameClaims {
  email: Option<String>,
  preferred_username: Option<String>,
  username: Option<String>,
  name: Option<String>,
}

impl NameClaims {
  fn of_id_token(
    claims: &openidconnect::IdTokenClaims<
      UsernameAdditionalClaims,
      CoreGenderClaim,
    >,
  ) -> NameClaims {
    NameClaims {
      email: claims.email().map(|email| email.to_string()),
      preferred_username: claims
        .preferred_username()
        .map(|username| username.to_string()),
      username: claims.additional_claims().username.clone(),
      name: claims
        .name()
        .and_then(|name| name.get(None))
        .map(|name| name.to_string()),
    }
  }

  fn of_user_info(claims: &UserInfoClaims) -> NameClaims {
    NameClaims {
      email: claims.email().map(|email| email.to_string()),
      preferred_username: claims
        .preferred_username()
        .map(|username| username.to_string()),
      username: claims.additional_claims().username.clone(),
      name: claims
        .name()
        .and_then(|name| name.get(None))
        .map(|name| name.to_string()),
    }
  }

  fn get(&self, claim: NameClaim) -> Option<String> {
    match claim {
      NameClaim::Email => self.email.clone(),
      NameClaim::PreferredUsername => self.preferred_username.clone(),
      NameClaim::Username => self.username.clone(),
      NameClaim::Name => self.name.clone(),
      NameClaim::EmailLocalPart => self.email.as_ref().map(|email| {
        email
          .split_once('@')
          .map(|(local, _)| local)
          .unwrap_or(email)
          .to_string()
      }),
    }
  }
}

/// The `at_hash` of the login's access token, as the ID token which
/// came with it must carry it (OpenID Connect Core 3.1.3.6): the left
/// half of the hash of the token, with the hash function of the ID
/// token's signing algorithm.
///
/// A provider signing ID tokens with the client secret (HS256 / 384 /
/// 512, which the verifier accepts for a confidential client) has no
/// key in its key set. The hash of those depends on the algorithm
/// alone, so a symmetric key stands in, without the secret: only its
/// type is checked against the algorithm.
fn access_token_hash(
  id_token: &openidconnect::IdToken<
    UsernameAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
  >,
  verifier: &CoreIdTokenVerifier<'_>,
  token: &TokenResponse,
) -> anyhow::Result<AccessTokenHash> {
  use openidconnect::{JsonWebKey as _, JwsSigningAlgorithm as _};
  let alg = id_token.signing_alg()?;
  let hash = if alg.uses_shared_secret() {
    AccessTokenHash::from_token(
      token.access_token(),
      alg,
      &CoreJsonWebKey::new_symmetric(Vec::new()),
    )
  } else {
    AccessTokenHash::from_token(
      token.access_token(),
      alg,
      id_token.signing_key(verifier)?,
    )
  }?;
  Ok(hash)
}

/// Information about the user authenticated with the OIDC provider,
/// passed to the app level [AuthImpl][crate::AuthImpl]
/// on signup, login and link.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OidcLoginInfo {
  /// The unique, stable id of the user at the provider.
  pub subject: SubjectIdentifier,
  /// The groups the provider reports for the user.
  ///
  /// - `None`: No group information is available. Either group
  ///   extraction is not configured, or the provider didn't send
  ///   the claim (eg. missing scope, or Azure group overage).
  ///   Apps should leave existing memberships as they are.
  /// - `Some(groups)`: The full list of groups, which may be empty.
  ///
  /// Note. Some providers omit the claim entirely for users
  /// without any groups, which shows up as `None` here.
  pub groups: Option<Vec<String>>,
  /// Whether the user is in one of the configured 'admin_groups'.
  ///
  /// `None` if 'admin_groups' is not configured or no group
  /// information is available, apps should then leave the
  /// users admin status as it is.
  ///
  /// ⚠️ Revoking admin through the provider relies on it sending the
  /// groups claim. A provider which omits the claim for a user left
  /// without any (matching) group reports `None`, and the user keeps
  /// admin. Configure 'allowed_groups' as well: such a user is then
  /// refused the login instead.
  pub admin: Option<bool>,
}

impl OidcLoginInfo {
  pub fn new(
    config: &OidcConfig,
    subject: SubjectIdentifier,
    groups: Option<Vec<String>>,
  ) -> OidcLoginInfo {
    let admin = if config.admin_groups.is_empty() {
      None
    } else {
      groups.as_ref().map(|groups| {
        groups
          .iter()
          .any(|group| config.admin_groups.contains(group))
      })
    };
    OidcLoginInfo {
      subject,
      groups,
      admin,
    }
  }

  /// Enforces 'allowed_groups'. Users in 'admin_groups' are also allowed.
  /// Fails closed if the provider didn't send any group information.
  pub fn check_allowed_groups(
    &self,
    config: &OidcConfig,
  ) -> mogh_error::Result<()> {
    if config.allowed_groups.is_empty() {
      return Ok(());
    }
    let Some(groups) = &self.groups else {
      return Err(
        anyhow!(
          "Provider did not send user groups, which are required for login. The groups scope or claim may be misconfigured."
        )
        .status_code(StatusCode::UNAUTHORIZED),
      );
    };
    let allowed = groups.iter().any(|group| {
      config.allowed_groups.contains(group)
        || config.admin_groups.contains(group)
    });
    if allowed {
      Ok(())
    } else {
      Err(
        anyhow!("User is not a member of any allowed group")
          .status_code(StatusCode::UNAUTHORIZED),
      )
    }
  }
}

/// The scopes to request on top of `openid`, `profile` and `email`.
///
/// The `groups` scope is added automatically if the `groups` claim
/// is used and the provider advertises the scope in its discovery
/// metadata. It is never requested blindly, as some providers
/// reject the whole login on unknown scopes (`invalid_scope`).
fn additional_scopes(
  config: &OidcConfig,
  scopes_supported: Option<&[Scope]>,
) -> Vec<String> {
  let mut scopes = Vec::<String>::new();
  for scope in &config.additional_scopes {
    if !scope.is_empty()
      && !["openid", "profile", "email"].contains(&scope.as_str())
      && !scopes.contains(scope)
    {
      scopes.push(scope.clone());
    }
  }
  let groups_scope_supported =
    scopes_supported.is_some_and(|scopes| {
      scopes.iter().any(|scope| scope.as_str() == "groups")
    });
  if config.groups_claim() == Some("groups")
    && groups_scope_supported
    && !scopes.iter().any(|scope| scope == "groups")
  {
    scopes.push("groups".to_string());
  }
  scopes
}

/// Extracts the groups at the given claim.
/// The exact claim name is tried first (namespaced claims like
/// `https://example.com/groups` include dots), then as a
/// dotted path into nested claims (eg. `realm_access.roles`).
///
/// Accepts a list of strings, or a single string.
/// Returns None if the claim is missing or has another shape.
fn extract_groups(
  claims: &HashMap<String, serde_json::Value>,
  claim: &str,
) -> Option<Vec<String>> {
  let value = claims.get(claim).or_else(|| {
    let mut path = claim.split('.');
    let mut value = claims.get(path.next()?)?;
    for key in path {
      value = value.get(key)?;
    }
    Some(value)
  })?;
  let mut groups = match value {
    serde_json::Value::String(group) => vec![group.clone()],
    serde_json::Value::Array(values) => values
      .iter()
      .map(|value| value.as_str().map(str::to_string))
      .collect::<Option<Vec<_>>>()
      .or_else(|| {
        warn!(
          "OIDC groups claim '{claim}' contains non string values, ignoring"
        );
        None
      })?,
    _ => {
      warn!(
        "OIDC groups claim '{claim}' is not a list of strings, ignoring"
      );
      return None;
    }
  };
  groups.sort();
  groups.dedup();
  Some(groups)
}

#[cfg(test)]
mod tests {
  use openidconnect::IdTokenClaims;
  use serde_json::json;

  use super::*;

  fn claims(
    value: serde_json::Value,
  ) -> HashMap<String, serde_json::Value> {
    serde_json::from_value(value).unwrap()
  }

  fn config(allowed: &[&str], admin: &[&str]) -> OidcConfig {
    OidcConfig {
      allowed_groups: allowed.iter().map(|g| g.to_string()).collect(),
      admin_groups: admin.iter().map(|g| g.to_string()).collect(),
      ..Default::default()
    }
  }

  fn info(
    config: &OidcConfig,
    groups: Option<&[&str]>,
  ) -> OidcLoginInfo {
    OidcLoginInfo::new(
      config,
      SubjectIdentifier::new("subject".to_string()),
      groups
        .map(|groups| groups.iter().map(|g| g.to_string()).collect()),
    )
  }

  fn exchange_provider(config: &OidcConfig) -> OidcProvider {
    use crate::provider::token_exchange::test_tokens::metadata;
    OidcProvider::from_metadata(
      "test",
      "https://app.example.com/auth/oidc/callback".to_string(),
      config,
      metadata(),
    )
    .unwrap()
  }

  fn exchange_token(
    groups: Option<&[&str]>,
  ) -> crate::provider::token_exchange::test_tokens::TestToken<
    UsernameAdditionalClaims,
  > {
    let mut extra = HashMap::new();
    if let Some(groups) = groups {
      extra.insert("groups".to_string(), json!(groups));
    }
    crate::provider::token_exchange::test_tokens::TestToken::new(
      UsernameAdditionalClaims {
        username: None,
        extra,
      },
    )
  }

  fn exchange_config(allowed: &[&str], admin: &[&str]) -> OidcConfig {
    use crate::provider::token_exchange::test_tokens::{
      CLIENT_ID, ISSUER,
    };
    OidcConfig {
      enabled: true,
      provider: ISSUER.to_string(),
      client_id: CLIENT_ID.to_string(),
      // Present, but never used to verify exchanged tokens
      client_secret: "client-secret".to_string(),
      ..config(allowed, admin)
    }
  }

  #[test]
  fn test_exchange_token_subject_groups_and_admin() {
    let config = exchange_config(&[], &["admins"]);
    let provider = exchange_provider(&config);
    let info = provider
      .verify_exchange_token(
        &config,
        &Default::default(),
        &exchange_token(Some(&["users", "admins"])).mint(),
      )
      .unwrap();
    assert_eq!(info.subject.as_str(), "subject-123");
    assert_eq!(
      info.groups,
      Some(vec!["admins".to_string(), "users".to_string()])
    );
    assert_eq!(info.admin, Some(true));
  }

  #[test]
  fn test_exchange_token_enforces_allowed_groups() {
    let config = exchange_config(&["users"], &[]);
    let provider = exchange_provider(&config);
    assert!(
      provider
        .verify_exchange_token(
          &config,
          &Default::default(),
          &exchange_token(Some(&["users"])).mint()
        )
        .is_ok()
    );
    // Not a member, and no group information at all (fails closed)
    for groups in [Some(&["other"][..]), None] {
      let err = provider
        .verify_exchange_token(
          &config,
          &Default::default(),
          &exchange_token(groups).mint(),
        )
        .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }

  #[test]
  fn test_exchange_token_audiences() {
    let config = exchange_config(&[], &[]);
    let provider = exchange_provider(&config);
    let cli_token = || {
      let mut token = exchange_token(None);
      token.audiences = vec!["cli-client".to_string()];
      token.mint()
    };
    // Only the providers own client id by default
    let err = provider
      .verify_exchange_token(
        &config,
        &Default::default(),
        &cli_token(),
      )
      .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(
      provider
        .verify_exchange_token(
          &config,
          &TokenExchangeConfig {
            audiences: vec!["cli-client".to_string()],
            ..Default::default()
          },
          &cli_token()
        )
        .is_ok()
    );
  }

  /// A confidential client would normally accept HS256 tokens signed
  /// with the client secret, exchanged tokens never do.
  #[test]
  fn test_exchange_token_rejects_client_secret_signature() {
    use crate::provider::token_exchange::test_tokens::Signer;
    let config = exchange_config(&[], &[]);
    let provider = exchange_provider(&config);
    let mut token = exchange_token(None);
    token.signer = Signer::Hmac("client-secret");
    assert!(
      provider
        .verify_exchange_token(
          &config,
          &Default::default(),
          &token.mint()
        )
        .is_err()
    );
  }

  /// The ID token of a login, as the provider of the test
  /// metadata signs it, for `audiences`.
  fn login_id_token(audiences: &[&str], nonce: &Nonce) -> String {
    use crate::provider::token_exchange::test_tokens::{
      CLIENT_ID, ISSUER,
    };
    use chrono::{Duration, Utc};
    use openidconnect::{
      Audience, EndUserEmail, EndUserUsername, IdToken, JsonWebKeyId,
      StandardClaims,
    };
    let claims = IdTokenClaims::<
      UsernameAdditionalClaims,
      CoreGenderClaim,
    >::new(
      IssuerUrl::new(ISSUER.to_string()).unwrap(),
      audiences
        .iter()
        .map(|audience| Audience::new(audience.to_string()))
        .collect(),
      Utc::now() + Duration::minutes(5),
      Utc::now(),
      StandardClaims::new(SubjectIdentifier::new(
        "subject-123".to_string(),
      ))
      .set_preferred_username(Some(EndUserUsername::new(
        "alice".to_string(),
      )))
      .set_email(Some(EndUserEmail::new(
        "alice@example.com".to_string(),
      ))),
      UsernameAdditionalClaims {
        username: None,
        extra: HashMap::new(),
      },
    )
    .set_nonce(Some(nonce.clone()))
    .set_authorized_party(Some(ClientId::new(CLIENT_ID.to_string())));
    let key = CoreRsaPrivateSigningKey::from_pem(
      include_str!("../../../test_keys/rsa_a.pem"),
      Some(JsonWebKeyId::new("test-key".to_string())),
    )
    .unwrap();
    IdToken::<
      UsernameAdditionalClaims,
      CoreGenderClaim,
      CoreJweContentEncryptionAlgorithm,
      CoreJwsSigningAlgorithm,
    >::new(
      claims,
      &key,
      CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
      None,
      None,
    )
    .unwrap()
    .to_string()
  }

  /// The username is resolved from the login's ID token, verified
  /// again with the audiences the login was verified with. Without
  /// them its claims were dropped for providers attaching another
  /// audience, and the name fell back to the user info / subject.
  #[tokio::test]
  async fn test_username_from_id_token_with_additional_audiences() {
    use crate::provider::token_exchange::test_tokens::CLIENT_ID;
    let config = OidcConfig {
      additional_audiences: vec!["project-id".to_string()],
      ..exchange_config(&[], &[])
    };
    let nonce = Nonce::new("login-nonce".to_string());
    let token: TokenResponse = serde_json::from_value(json!({
      "access_token": "access-token",
      "token_type": "bearer",
      "id_token": login_id_token(&[CLIENT_ID, "project-id"], &nonce),
    }))
    .unwrap();
    let subject = SubjectIdentifier::new("subject-123".to_string());

    let provider = exchange_provider(&config);
    assert_eq!(
      provider.get_username(&subject, &token, &nonce).await,
      "alice"
    );
    let provider = exchange_provider(&OidcConfig {
      use_full_email: true,
      ..config.clone()
    });
    assert_eq!(
      provider.get_username(&subject, &token, &nonce).await,
      "alice@example.com"
    );
    // An audience which isn't configured is still refused. The
    // test provider has no user info, which leaves the subject.
    let provider = exchange_provider(&exchange_config(&[], &[]));
    assert_eq!(
      provider.get_username(&subject, &token, &nonce).await,
      "subject-123"
    );
  }

  /// The username for a login whose ID token has only an email
  /// (`user@example.com`), and whose user info is `user_info`.
  async fn username_with_user_info(
    use_full_email: bool,
    user_info: serde_json::Value,
  ) -> String {
    use crate::provider::token_exchange::test_tokens::TestToken;
    use openidconnect::UserInfoUrl;
    let id_token = TestToken {
      nonce: Some("login-nonce".to_string()),
      ..TestToken::new(UsernameAdditionalClaims {
        username: None,
        extra: HashMap::new(),
      })
    }
    .mint();
    let token: TokenResponse = serde_json::from_value(json!({
      "access_token": "access-token",
      "token_type": "bearer",
      "id_token": id_token,
    }))
    .unwrap();
    let url = crate::provider::answering_server(
      StatusCode::OK,
      user_info.to_string(),
    )
    .await;
    let config = OidcConfig {
      use_full_email,
      ..exchange_config(&[], &[])
    };
    let provider = impatient_provider(&config, |metadata| {
      metadata.set_userinfo_endpoint(Some(
        UserInfoUrl::new(format!("{url}/userinfo")).unwrap(),
      ))
    });
    provider
      .get_username(
        &SubjectIdentifier::new("subject-123".to_string()),
        &token,
        &Nonce::new("login-nonce".to_string()),
      )
      .await
  }

  /// The name claims are tried in order, each from the ID token and
  /// then the user info: the usual names before the start of the
  /// email, or with 'use_full_email' the email first.
  #[tokio::test]
  async fn test_username_claims_in_order() {
    let user_info = |claims: serde_json::Value| {
      let mut user_info = json!({ "sub": "subject-123" });
      user_info
        .as_object_mut()
        .unwrap()
        .extend(claims.as_object().unwrap().clone());
      user_info
    };
    for (claims, expected) in [
      (
        json!({ "preferred_username": "alice", "name": "Alice Smith" }),
        "alice",
      ),
      (
        json!({ "username": "a.smith", "name": "Alice Smith" }),
        "a.smith",
      ),
      (json!({ "name": "Alice Smith" }), "Alice Smith"),
      (json!({}), "user"),
    ] {
      assert_eq!(
        username_with_user_info(false, user_info(claims.clone()))
          .await,
        expected,
        "{claims}"
      );
    }
    assert_eq!(
      username_with_user_info(
        true,
        user_info(json!({ "preferred_username": "alice" }))
      )
      .await,
      "user@example.com"
    );
  }

  /// The provider of the test metadata, with `endpoints` set on it,
  /// which gives up on requests after a moment.
  fn impatient_provider(
    config: &OidcConfig,
    endpoints: impl FnOnce(CoreProviderMetadata) -> CoreProviderMetadata,
  ) -> OidcProvider {
    use crate::provider::token_exchange::test_tokens::metadata;
    OidcProvider::from_metadata(
      "test",
      "https://app.example.com/auth/oidc/callback".to_string(),
      config,
      endpoints(metadata()),
    )
    .unwrap()
    .with_request_timeout(std::time::Duration::from_millis(200))
  }

  /// A provider which accepts the connection but never answers
  /// fails the login, instead of leaving the callback hanging.
  #[tokio::test]
  async fn test_stalled_token_endpoint_fails_the_login() {
    use openidconnect::TokenUrl;
    let stalled = crate::provider::stalled_server().await;
    let config = exchange_config(&[], &[]);
    let provider = impatient_provider(&config, |metadata| {
      metadata.set_token_endpoint(Some(
        TokenUrl::new(format!("{stalled}/token")).unwrap(),
      ))
    });
    let nonce = Nonce::new("nonce".to_string());
    let login = provider.validate_extract_login_info_and_token(
      &config,
      (CsrfToken::new("state".to_string()), "state".to_string()),
      "code".to_string(),
      PkceCodeVerifier::new("v".repeat(43)),
      &nonce,
    );
    let err =
      tokio::time::timeout(std::time::Duration::from_secs(10), login)
        .await
        .expect("the login must fail, not hang")
        .unwrap_err();
    let message = format!("{:#}", err.error);
    assert!(message.contains("timed out"), "{message}");
  }

  /// The user info a login may ask for (username,
  /// groups) is given up on the same way.
  #[tokio::test]
  async fn test_stalled_user_info_is_given_up_on() {
    use openidconnect::UserInfoUrl;
    let stalled = crate::provider::stalled_server().await;
    let config = exchange_config(&[], &[]);
    let provider = impatient_provider(&config, |metadata| {
      metadata.set_userinfo_endpoint(Some(
        UserInfoUrl::new(format!("{stalled}/userinfo")).unwrap(),
      ))
    });
    // Without an ID token, the name comes from the user info
    let token: TokenResponse = serde_json::from_value(json!({
      "access_token": "access-token",
      "token_type": "bearer",
    }))
    .unwrap();
    let subject = SubjectIdentifier::new("subject-123".to_string());
    let nonce = Nonce::new("nonce".to_string());
    let username = tokio::time::timeout(
      std::time::Duration::from_secs(10),
      provider.get_username(&subject, &token, &nonce),
    )
    .await
    .expect("the user info request must be given up on");
    assert_eq!(username, "subject-123");
    let groups = tokio::time::timeout(
      std::time::Duration::from_secs(10),
      provider.get_user_info_groups(&subject, &token, "groups"),
    )
    .await
    .expect("the user info request must be given up on");
    assert_eq!(groups, None);
  }

  /// Redeems a made up code at the test provider, whose token
  /// endpoint answers `status` with `body`.
  async fn redeem_at(
    status: StatusCode,
    body: serde_json::Value,
  ) -> mogh_error::Error {
    use openidconnect::TokenUrl;
    let url =
      crate::provider::answering_server(status, body.to_string())
        .await;
    let config = exchange_config(&[], &[]);
    let provider = impatient_provider(&config, |metadata| {
      metadata.set_token_endpoint(Some(
        TokenUrl::new(format!("{url}/token")).unwrap(),
      ))
    });
    provider
      .validate_extract_login_info_and_token(
        &config,
        (CsrfToken::new("state".to_string()), "state".to_string()),
        "made-up-code".to_string(),
        PkceCodeVerifier::new("v".repeat(43)),
        &Nonce::new("nonce".to_string()),
      )
      .await
      .err()
      .unwrap()
  }

  /// A code the provider refuses (expired, used, made up) is the
  /// user's failed login, which counts against the ip like any other:
  /// `401` with what the provider reported. The app's misconfiguration,
  /// and a provider answering something else, are server errors.
  #[tokio::test]
  async fn test_refused_code_is_the_users_failed_login() {
    let err = redeem_at(
      StatusCode::BAD_REQUEST,
      json!({
        "error": "invalid_grant",
        "error_description": "Code not valid",
      }),
    )
    .await;
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    let message = format!("{:#}", err.error);
    assert!(message.contains("invalid_grant"), "{message}");
    assert!(message.contains("Code not valid"), "{message}");

    for error in ["invalid_request", "custom_refusal"] {
      let err =
        redeem_at(StatusCode::BAD_REQUEST, json!({ "error": error }))
          .await;
      assert_eq!(err.status, StatusCode::UNAUTHORIZED, "{error}");
    }
    for error in [
      "invalid_client",
      "unauthorized_client",
      "unsupported_grant_type",
      "invalid_scope",
    ] {
      let err =
        redeem_at(StatusCode::BAD_REQUEST, json!({ "error": error }))
          .await;
      assert!(err.status.is_server_error(), "{error}");
      assert!(format!("{:#}", err.error).contains(error));
    }
    let err =
      redeem_at(StatusCode::OK, json!({ "unexpected": true })).await;
    assert!(err.status.is_server_error());
  }

  /// Logs in at the test provider advertising HS256 too, whose token
  /// endpoint answers `response`.
  async fn login_signed_with_the_secret(
    config: &OidcConfig,
    response: serde_json::Value,
  ) -> mogh_error::Result<(OidcLoginInfo, TokenResponse)> {
    use crate::provider::token_exchange::test_tokens::metadata_with_algs;
    use openidconnect::TokenUrl;
    let url = crate::provider::answering_server(
      StatusCode::OK,
      response.to_string(),
    )
    .await;
    let metadata = metadata_with_algs(vec![
      CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
      CoreJwsSigningAlgorithm::HmacSha256,
    ])
    .set_token_endpoint(Some(
      TokenUrl::new(format!("{url}/token")).unwrap(),
    ));
    let provider = OidcProvider::from_metadata(
      "test",
      "https://app.example.com/auth/oidc/callback".to_string(),
      config,
      metadata,
    )
    .unwrap();
    provider
      .validate_extract_login_info_and_token(
        config,
        (CsrfToken::new("state".to_string()), "state".to_string()),
        "code".to_string(),
        PkceCodeVerifier::new("v".repeat(43)),
        &Nonce::new("nonce".to_string()),
      )
      .await
  }

  /// A provider signing ID tokens with the client secret (HS256),
  /// which a confidential client accepts, and their `at_hash`: the
  /// hash is the algorithm's, there is no key of it in the key set.
  /// An access token substituted for another's is refused, `401`.
  #[tokio::test]
  async fn test_at_hash_of_an_id_token_signed_with_the_secret() {
    use crate::provider::token_exchange::test_tokens::{
      Signer, TestToken,
    };
    let config = exchange_config(&[], &[]);
    let id_token = |access_token: &str| {
      TestToken {
        signer: Signer::Hmac("client-secret"),
        nonce: Some("nonce".to_string()),
        access_token: Some(access_token.to_string()),
        ..TestToken::new(UsernameAdditionalClaims {
          username: None,
          extra: HashMap::new(),
        })
      }
      .mint()
    };
    let response = |access_token: &str| {
      json!({
        "access_token": access_token,
        "token_type": "bearer",
        "id_token": id_token("the-access-token"),
      })
    };

    let (info, _) = login_signed_with_the_secret(
      &config,
      response("the-access-token"),
    )
    .await
    .unwrap();
    assert_eq!(info.subject.as_str(), "subject-123");

    let err = login_signed_with_the_secret(
      &config,
      response("another-access-token"),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(
      format!("{:#}", err.error).contains("Invalid access token")
    );
  }

  /// A provider's responses are read up to [MAX_RESPONSE_LENGTH],
  /// whatever it (or whatever its discovery points at) sends: the
  /// discovery, and the token of a login callback.
  #[tokio::test]
  async fn test_oversized_responses_are_not_read() {
    use openidconnect::TokenUrl;
    for url in crate::provider::oversized_servers().await {
      let config = OidcConfig {
        enabled: true,
        provider: url.clone(),
        client_id: "client-id".to_string(),
        ..Default::default()
      };
      let err = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        OidcProvider::new(
          "test",
          "https://app.example.com/auth/oidc/callback".to_string(),
          &config,
        ),
      )
      .await
      .expect("the read must stop at the limit")
      .err()
      .unwrap();
      assert!(format!("{err:#}").contains("larger than"), "{err:#}");

      let config = exchange_config(&[], &[]);
      let provider = impatient_provider(&config, |metadata| {
        metadata.set_token_endpoint(Some(
          TokenUrl::new(format!("{url}/token")).unwrap(),
        ))
      });
      let err = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        provider.validate_extract_login_info_and_token(
          &config,
          (CsrfToken::new("state".to_string()), "state".to_string()),
          "code".to_string(),
          PkceCodeVerifier::new("v".repeat(43)),
          &Nonce::new("nonce".to_string()),
        ),
      )
      .await
      .expect("the read must stop at the limit")
      .unwrap_err();
      assert!(err.status.is_server_error());
      let message = format!("{:#}", err.error);
      assert!(message.contains("larger than"), "{message}");
    }
  }

  #[tokio::test]
  async fn test_provider_url_with_credentials_is_refused() {
    // Refused before any request: nothing listens there
    let listener =
      std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = OidcConfig {
      enabled: true,
      provider: format!("http://user:hunter2@{address}"),
      client_id: "client-id".to_string(),
      ..Default::default()
    };
    let err = OidcProvider::new(
      "test",
      "https://app.example.com/auth/oidc/callback".to_string(),
      &config,
    )
    .await
    .err()
    .unwrap();
    let err = format!("{err:#}");
    assert!(err.contains("must not carry credentials"), "{err}");
    assert!(!err.contains("hunter2"), "{err}");
  }

  #[test]
  fn test_id_token_claims_capture_non_standard_claims() {
    let claims: IdTokenClaims<
      UsernameAdditionalClaims,
      CoreGenderClaim,
    > = serde_json::from_value(json!({
      "iss": "https://idp.example.com",
      "sub": "subject",
      "aud": ["client-id"],
      "exp": 2000000000,
      "iat": 1000000000,
      "email": "user@example.com",
      "username": "user",
      "groups": ["users", "admins"],
      "realm_access": { "roles": ["role"] },
    }))
    .unwrap();
    let additional = claims.additional_claims();
    assert_eq!(additional.username.as_deref(), Some("user"));
    assert_eq!(
      extract_groups(&additional.extra, "groups"),
      Some(vec!["admins".to_string(), "users".to_string()])
    );
    assert_eq!(
      extract_groups(&additional.extra, "realm_access.roles"),
      Some(vec!["role".to_string()])
    );
    // Standard claims are not duplicated into the extra claims
    assert!(!additional.extra.contains_key("email"));
  }

  fn scopes(scopes: &[&str]) -> Vec<Scope> {
    scopes.iter().map(|s| Scope::new(s.to_string())).collect()
  }

  #[test]
  fn test_groups_scope_added_when_advertised() {
    let supported = scopes(&["openid", "profile", "groups"]);
    // Default claim via 'allowed_groups' / 'admin_groups'
    assert_eq!(
      additional_scopes(&config(&["users"], &[]), Some(&supported)),
      vec!["groups".to_string()]
    );
    // Explicit 'groups' claim behaves the same
    let explicit = OidcConfig {
      groups_claim: "groups".into(),
      additional_scopes: vec!["groups".into(), "offline".into()],
      ..Default::default()
    };
    assert_eq!(
      additional_scopes(&explicit, Some(&supported)),
      vec!["groups".to_string(), "offline".to_string()]
    );
  }

  #[test]
  fn test_groups_scope_not_added_blindly() {
    let config = config(&["users"], &[]);
    // Provider doesn't advertise the scope, or any scopes
    assert!(
      additional_scopes(&config, Some(&scopes(&["openid"])))
        .is_empty()
    );
    assert!(additional_scopes(&config, None).is_empty());
  }

  #[test]
  fn test_groups_scope_not_added_when_not_needed() {
    let supported = scopes(&["openid", "groups"]);
    // Group extraction disabled
    assert!(
      additional_scopes(&OidcConfig::default(), Some(&supported))
        .is_empty()
    );
    // Custom claim, scopes are up to the user
    let custom = OidcConfig {
      groups_claim: "realm_access.roles".into(),
      additional_scopes: vec!["roles".into(), "openid".into()],
      ..Default::default()
    };
    assert_eq!(
      additional_scopes(&custom, Some(&supported)),
      vec!["roles".to_string()]
    );
  }

  #[test]
  fn test_extract_groups_list_sorted_and_deduped() {
    let claims = claims(json!({ "groups": ["b", "a", "b"] }));
    assert_eq!(
      extract_groups(&claims, "groups"),
      Some(vec!["a".to_string(), "b".to_string()])
    );
  }

  #[test]
  fn test_extract_groups_empty_list_is_some() {
    let claims = claims(json!({ "groups": [] }));
    assert_eq!(extract_groups(&claims, "groups"), Some(Vec::new()));
  }

  #[test]
  fn test_extract_groups_single_string() {
    let claims = claims(json!({ "groups": "users" }));
    assert_eq!(
      extract_groups(&claims, "groups"),
      Some(vec!["users".to_string()])
    );
  }

  #[test]
  fn test_extract_groups_exact_name_with_dots_before_path() {
    let claims = claims(json!({
      "https://example.com/groups": ["namespaced"],
      "https://example": { "com/groups": ["nested"] },
    }));
    assert_eq!(
      extract_groups(&claims, "https://example.com/groups"),
      Some(vec!["namespaced".to_string()])
    );
  }

  #[test]
  fn test_extract_groups_missing_claim() {
    let claims = claims(json!({ "other": ["users"] }));
    assert_eq!(extract_groups(&claims, "groups"), None);
    assert_eq!(extract_groups(&claims, "other.nested"), None);
    assert_eq!(extract_groups(&claims, ""), None);
  }

  #[test]
  fn test_extract_groups_rejects_other_shapes() {
    let claims = claims(json!({
      "mixed": ["users", 1],
      "objects": [{ "name": "users" }],
      "number": 1,
    }));
    assert_eq!(extract_groups(&claims, "mixed"), None);
    assert_eq!(extract_groups(&claims, "objects"), None);
    assert_eq!(extract_groups(&claims, "number"), None);
  }

  #[test]
  fn test_admin_none_when_not_configured_or_no_groups() {
    assert_eq!(
      info(&config(&[], &[]), Some(&["admins"])).admin,
      None
    );
    assert_eq!(info(&config(&[], &["admins"]), None).admin, None);
  }

  #[test]
  fn test_admin_resolved_from_groups() {
    let config = config(&[], &["admins"]);
    assert_eq!(
      info(&config, Some(&["users", "admins"])).admin,
      Some(true)
    );
    assert_eq!(info(&config, Some(&["users"])).admin, Some(false));
    assert_eq!(info(&config, Some(&[])).admin, Some(false));
  }

  #[test]
  fn test_allowed_groups_not_configured_allows_all() {
    let config = config(&[], &["admins"]);
    assert!(
      info(&config, None).check_allowed_groups(&config).is_ok()
    );
    assert!(
      info(&config, Some(&["other"]))
        .check_allowed_groups(&config)
        .is_ok()
    );
  }

  #[test]
  fn test_allowed_groups_fails_closed_without_group_info() {
    let config = config(&["users"], &[]);
    let err = info(&config, None)
      .check_allowed_groups(&config)
      .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_allowed_groups_membership() {
    let config = config(&["users"], &["admins"]);
    assert!(
      info(&config, Some(&["users"]))
        .check_allowed_groups(&config)
        .is_ok()
    );
    // Admin groups are implicitly allowed
    assert!(
      info(&config, Some(&["admins"]))
        .check_allowed_groups(&config)
        .is_ok()
    );
    for groups in [&["other"][..], &[]] {
      let err = info(&config, Some(groups))
        .check_allowed_groups(&config)
        .unwrap_err();
      assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }
  }
}
