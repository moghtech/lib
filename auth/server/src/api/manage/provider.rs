//! Management of the external login providers stored by the app.
//! Admin only, see [AuthUserImpl::is_admin].

use anyhow::anyhow;
use axum::http::StatusCode;
use mogh_auth_client::{
  api::manage::{
    CreateExternalLoginProvider, DeleteExternalLoginProvider,
    DeleteExternalLoginProviderResponse,
    ExternalLoginProviderListItem, ListExternalLoginProviders,
    UpdateExternalLoginProvider,
  },
  config::{
    ExternalLoginProvider, ExternalLoginProviderConfig, REDACTED,
    TokenExchangeConfig, slugify, validate_slug,
  },
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_logger::redact_url_credentials;
use mogh_resolver::Resolve;
use tracing::{info, instrument, warn};
use zeroize::Zeroize as _;

use crate::{
  AuthImpl,
  api::manage::ManageArgs,
  provider::external::{
    PROVIDER_ID_LENGTH, evict_built_provider,
    list_external_providers, redirect_uri, resolve_external_provider,
  },
  rand::random_string,
  user::AuthUserImpl,
  validations::validate_public_http_url,
};

const MAX_PROVIDER_NAME_LENGTH: usize = 100;
const MAX_TOKEN_EXCHANGE_AUDIENCES: usize = 16;
const MAX_AUDIENCE_LENGTH: usize = 256;

fn check_admin(user: &dyn AuthUserImpl) -> mogh_error::Result<()> {
  if user.is_admin() {
    Ok(())
  } else {
    Err(
      anyhow!("Only admins can manage external login providers")
        .status_code(StatusCode::FORBIDDEN),
    )
  }
}

/// The client secret never leaves the server.
fn list_item<I: AuthImpl + ?Sized>(
  auth: &I,
  mut provider: ExternalLoginProvider,
  read_only: bool,
) -> ExternalLoginProviderListItem {
  provider.config.redact_secret();
  ExternalLoginProviderListItem {
    redirect_uri: redirect_uri(auth.host(), auth.path(), &provider),
    provider,
    read_only,
  }
}

/// A provider's name, trimmed: shown on the login page, listed, and
/// logged, so a control character (Unicode Cc) inside it is refused
/// (the error doesn't repeat the name).
fn validate_name(name: &str) -> mogh_error::Result<String> {
  let name = name.trim();
  if name.is_empty() {
    return Err(
      anyhow!("Provider name cannot be empty")
        .status_code(StatusCode::BAD_REQUEST),
    );
  }
  if name.chars().count() > MAX_PROVIDER_NAME_LENGTH {
    return Err(
      anyhow!(
        "Provider name cannot be longer than {MAX_PROVIDER_NAME_LENGTH} characters"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  if name.chars().any(char::is_control) {
    return Err(
      anyhow!("Provider name cannot contain control characters")
        .status_code(StatusCode::BAD_REQUEST),
    );
  }
  Ok(name.to_string())
}

/// The slug a request gives, or the one made from the name. A slug
/// another provider already uses (a static one counts: its slug is
/// its id) would make the urls ambiguous.
async fn validate_provider_slug<I: AuthImpl + ?Sized>(
  auth: &I,
  slug: &str,
  name: &str,
  except_id: Option<&str>,
) -> mogh_error::Result<String> {
  let from_name = slug.trim().is_empty();
  let slug = if from_name {
    let slug = slugify(name);
    if slug.is_empty() {
      return Err(
        anyhow!(
          "The name '{name}' makes no slug (it needs letters or digits), give the provider one"
        )
        .status_code(StatusCode::BAD_REQUEST),
      );
    }
    slug
  } else {
    let slug = slug.trim().to_string();
    validate_slug(&slug).map_err(|e| {
      anyhow!("{e}").status_code(StatusCode::BAD_REQUEST)
    })?;
    slug
  };
  let taken = list_external_providers(auth).await?.into_iter().any(
    |resolved| {
      except_id != Some(resolved.provider.id.as_str())
        && resolved.provider.slug() == slug
    },
  );
  if taken {
    let hint = if from_name {
      " (made from the name), give the provider a different one"
    } else {
      ""
    };
    return Err(
      anyhow!(
        "Another login provider already uses the slug '{slug}'{hint}"
      )
      .status_code(StatusCode::CONFLICT),
    );
  }
  Ok(slug)
}

fn validate_config(
  config: &ExternalLoginProviderConfig,
) -> mogh_error::Result<()> {
  if config.client_secret() == REDACTED {
    return Err(
      anyhow!(
        "The redacted client secret cannot be used as the secret"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  match config {
    ExternalLoginProviderConfig::Oidc(config) => {
      if !config.provider.is_empty() {
        validate_public_http_url("provider", &config.provider)
          .status_code(StatusCode::BAD_REQUEST)?;
      }
      if !config.redirect_host.is_empty() {
        validate_public_http_url(
          "redirect_host",
          &config.redirect_host,
        )
        .status_code(StatusCode::BAD_REQUEST)?;
      }
    }
    // Unlike OIDC (public clients using PKCE), these can't work
    // without a secret. Enabled, they would show a login
    // button which always fails.
    ExternalLoginProviderConfig::Github(config)
    | ExternalLoginProviderConfig::Google(config) => {
      if config.enabled && config.client_secret.is_empty() {
        return Err(
          anyhow!(
            "A client secret is required to enable this provider"
          )
          .status_code(StatusCode::BAD_REQUEST),
        );
      }
    }
  }
  Ok(())
}

/// Token exchange needs tokens signed by the provider,
/// which Github doesn't issue for user logins.
fn validate_token_exchange(
  mut token_exchange: TokenExchangeConfig,
  config: &ExternalLoginProviderConfig,
) -> mogh_error::Result<TokenExchangeConfig> {
  if token_exchange.enabled
    && matches!(config, ExternalLoginProviderConfig::Github(_))
  {
    return Err(
      anyhow!("Token exchange is not available for Github providers")
        .status_code(StatusCode::BAD_REQUEST),
    );
  }
  let mut audiences = Vec::<String>::new();
  for audience in &token_exchange.audiences {
    let audience = audience.trim();
    if audience.is_empty()
      || audiences.iter().any(|existing| existing == audience)
    {
      continue;
    }
    if audience.len() > MAX_AUDIENCE_LENGTH {
      return Err(
        anyhow!(
          "Token exchange audiences cannot be longer than {MAX_AUDIENCE_LENGTH} characters"
        )
        .status_code(StatusCode::BAD_REQUEST),
      );
    }
    audiences.push(audience.to_string());
  }
  // Every audience is another signature check on each exchange.
  if audiences.len() > MAX_TOKEN_EXCHANGE_AUDIENCES {
    return Err(
      anyhow!(
        "Token exchange accepts at most {MAX_TOKEN_EXCHANGE_AUDIENCES} audiences"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  token_exchange.audiences = audiences;
  Ok(token_exchange)
}

/// An empty or redacted client secret keeps the existing one,
/// unless it is explicitly cleared.
///
/// The secret is sent to the token endpoint the OIDC provider url
/// points to. If the url changes, the secret has to be entered again,
/// otherwise pointing the provider at another server would reveal
/// the stored secret, which can't be read over the API.
fn keep_existing_secret(
  config: &mut ExternalLoginProviderConfig,
  existing: &ExternalLoginProviderConfig,
  clear: bool,
) -> mogh_error::Result<()> {
  let secret = config.client_secret();
  let new_secret = !secret.is_empty() && secret != REDACTED;
  if clear {
    if new_secret {
      return Err(
        anyhow!(
          "Cannot both clear the client secret and set a new one"
        )
        .status_code(StatusCode::BAD_REQUEST),
      );
    }
    // Nothing is kept, so there is nothing to protect
    // if the provider url changes at the same time.
    config.client_secret_mut().clear();
    return Ok(());
  }
  if new_secret {
    return Ok(());
  }
  if let (
    ExternalLoginProviderConfig::Oidc(config),
    ExternalLoginProviderConfig::Oidc(existing),
  ) = (&*config, existing)
    && config.provider != existing.provider
    && !existing.client_secret.is_empty()
  {
    return Err(
      anyhow!(
        "The client secret must be entered again when the provider url changes"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  *config.client_secret_mut() = existing.client_secret().to_string();
  Ok(())
}

//

pub async fn list_providers<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
) -> mogh_error::Result<Vec<ExternalLoginProviderListItem>> {
  check_admin(user)?;
  let providers = list_external_providers(auth)
    .await?
    .into_iter()
    .map(|resolved| {
      list_item(auth, resolved.provider, resolved.is_static)
    })
    .collect();
  Ok(providers)
}

impl Resolve<ManageArgs> for ListExternalLoginProviders {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    list_providers(auth.as_ref(), user.as_ref().as_ref()).await
  }
}

//

pub async fn create_provider<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  request: CreateExternalLoginProvider,
) -> mogh_error::Result<ExternalLoginProviderListItem> {
  check_admin(user)?;
  validate_config(&request.config)?;

  let name = validate_name(&request.name)?;
  let token_exchange =
    validate_token_exchange(request.token_exchange, &request.config)?;
  // Last: the only check which looks at the other providers.
  let slug =
    validate_provider_slug(auth, &request.slug, &name, None).await?;
  let provider = ExternalLoginProvider {
    // Random ids are never reused, so a new provider
    // can't inherit the linked users of a deleted one.
    id: random_string(PROVIDER_ID_LENGTH),
    name,
    slug,
    registration_disabled: request.registration_disabled,
    token_exchange,
    config: request.config,
  };

  let item = list_item(auth, provider.clone(), false);

  auth.create_external_provider(provider).await?;

  info!(
    admin_id = user.id(),
    admin = user.username(),
    provider_id = item.provider.id,
    provider = item.provider.name,
    kind = item.provider.kind().to_string(),
    "External login provider created"
  );

  Ok(item)
}

impl Resolve<ManageArgs> for CreateExternalLoginProvider {
  #[instrument(
    "CreateExternalLoginProvider",
    skip_all,
    fields(user_id = user.id(), username = user.username())
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    create_provider(auth.as_ref(), user.as_ref().as_ref(), self).await
  }
}

//

/// Resolves a provider which can be managed over the API.
async fn resolve_managed_provider<I: AuthImpl + ?Sized>(
  auth: &I,
  provider_id: &str,
) -> mogh_error::Result<ExternalLoginProvider> {
  let resolved = resolve_external_provider(auth, provider_id).await?;
  if resolved.is_static {
    return Err(
      anyhow!(
        "Provider '{}' comes from the app configuration and is read only",
        resolved.provider.name
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  Ok(resolved.provider)
}

/// The (existing, updated) issuer of an OIDC provider
/// whose url the update changes.
///
/// ⚠️ The provider keeps its id, and so the users linked to it: they
/// are found by the subject the new issuer sends. The new issuer can
/// log in as every user linked to the provider, so an update of the
/// url is only for the same identity provider at a new address (a
/// different one is a new provider, whose new id carries no links).
/// Changing it is allowed (with the secret entered again, see
/// [keep_existing_secret]), and logged as a warning.
fn issuer_change<'a>(
  config: &'a ExternalLoginProviderConfig,
  existing: &'a ExternalLoginProviderConfig,
) -> Option<(&'a str, &'a str)> {
  let (
    ExternalLoginProviderConfig::Oidc(config),
    ExternalLoginProviderConfig::Oidc(existing),
  ) = (config, existing)
  else {
    return None;
  };
  let (from, to) = (existing.provider.trim(), config.provider.trim());
  (from.trim_end_matches('/') != to.trim_end_matches('/'))
    .then_some((from, to))
}

/// Validates the updated configuration against the
/// existing one, and carries over the existing secret.
fn merge_update(
  config: &mut ExternalLoginProviderConfig,
  existing: &ExternalLoginProviderConfig,
  clear_client_secret: bool,
) -> mogh_error::Result<()> {
  // The external user ids linked to the provider
  // only have meaning for the same kind.
  if config.kind() != existing.kind() {
    return Err(
      anyhow!(
        "The kind of a provider cannot be changed, create a new provider instead"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  keep_existing_secret(config, existing, clear_client_secret)?;
  validate_config(config)
}

pub async fn update_provider<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  mut request: UpdateExternalLoginProvider,
) -> mogh_error::Result<ExternalLoginProviderListItem> {
  check_admin(user)?;

  let name = validate_name(&request.name)?;
  let token_exchange = validate_token_exchange(
    std::mem::take(&mut request.token_exchange),
    &request.config,
  )?;

  let mut existing =
    resolve_managed_provider(auth, &request.id).await?;

  // For the log. A stored url may predate the refusal of credentials.
  let issuer_change =
    issuer_change(&request.config, &existing.config).map(
      |(from, to)| {
        (redact_url_credentials(from), redact_url_credentials(to))
      },
    );

  // Wipe the secrets held here however the checks turn out.
  let merged = merge_update(
    &mut request.config,
    &existing.config,
    request.clear_client_secret,
  );
  existing.config.zeroize();
  if let Err(e) = merged {
    request.config.zeroize();
    return Err(e);
  }

  // An empty slug keeps the existing one (as it is: a provider from
  // before slugs keeps using its id until it is given one).
  let slug = if request.slug.trim().is_empty() {
    existing.slug.clone()
  } else {
    let slug = validate_provider_slug(
      auth,
      &request.slug,
      &name,
      Some(&existing.id),
    )
    .await;
    match slug {
      Ok(slug) => slug,
      Err(e) => {
        request.config.zeroize();
        return Err(e);
      }
    }
  };

  let provider = ExternalLoginProvider {
    id: existing.id,
    name,
    slug,
    registration_disabled: request.registration_disabled,
    token_exchange,
    config: request.config,
  };

  let item = list_item(auth, provider.clone(), false);

  auth.update_external_provider(provider).await?;

  // Drops the client holding the previous secret.
  evict_built_provider(&item.provider.id);

  if let Some((from, to)) = issuer_change {
    warn!(
      admin_id = user.id(),
      admin = user.username(),
      provider_id = item.provider.id,
      provider = item.provider.name,
      from,
      to,
      "External login provider issuer changed. The users linked to the provider now log in through the new issuer."
    );
  }

  info!(
    admin_id = user.id(),
    admin = user.username(),
    provider_id = item.provider.id,
    provider = item.provider.name,
    "External login provider updated"
  );

  Ok(item)
}

impl Resolve<ManageArgs> for UpdateExternalLoginProvider {
  #[instrument(
    "UpdateExternalLoginProvider",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      provider_id = self.id
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    update_provider(auth.as_ref(), user.as_ref().as_ref(), self).await
  }
}

//

pub async fn delete_provider<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  provider_id: &str,
) -> mogh_error::Result<()> {
  check_admin(user)?;

  let mut provider =
    resolve_managed_provider(auth, provider_id).await?;
  provider.config.zeroize();

  auth.delete_external_provider(provider.id.clone()).await?;

  evict_built_provider(&provider.id);

  info!(
    admin_id = user.id(),
    admin = user.username(),
    provider_id = provider.id,
    provider = provider.name,
    "External login provider deleted"
  );

  Ok(())
}

impl Resolve<ManageArgs> for DeleteExternalLoginProvider {
  #[instrument(
    "DeleteExternalLoginProvider",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      provider_id = self.id
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    delete_provider(auth.as_ref(), user.as_ref().as_ref(), &self.id)
      .await?;
    Ok(DeleteExternalLoginProviderResponse {})
  }
}

#[cfg(test)]
mod tests {
  use std::sync::{Arc, Mutex};

  use mogh_auth_client::config::{
    MAX_SLUG_LENGTH, NamedOauthConfig, OidcConfig,
  };

  use super::*;

  struct TestUser {
    admin: bool,
  }

  impl AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      "user-id"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn is_admin(&self) -> bool {
      self.admin
    }
  }

  const ADMIN: TestUser = TestUser { admin: true };
  const USER: TestUser = TestUser { admin: false };

  #[derive(Default)]
  struct TestAuth {
    static_providers: Vec<ExternalLoginProvider>,
    stored: Arc<Mutex<Vec<ExternalLoginProvider>>>,
  }

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      Self::default()
    }

    fn host(&self) -> &str {
      "https://example.com"
    }

    fn static_external_providers(
      &self,
    ) -> Vec<ExternalLoginProvider> {
      self.static_providers.clone()
    }

    fn list_external_providers(
      &self,
    ) -> crate::DynFuture<
      mogh_error::Result<Vec<ExternalLoginProvider>>,
    > {
      let stored = self.stored.lock().unwrap().clone();
      Box::pin(async move { Ok(stored) })
    }

    fn create_external_provider(
      &self,
      provider: ExternalLoginProvider,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self.stored.lock().unwrap().push(provider);
      Box::pin(async { Ok(()) })
    }

    fn update_external_provider(
      &self,
      provider: ExternalLoginProvider,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      let mut stored = self.stored.lock().unwrap();
      let existing = stored
        .iter_mut()
        .find(|existing| existing.id == provider.id)
        .unwrap();
      *existing = provider;
      Box::pin(async { Ok(()) })
    }

    fn delete_external_provider(
      &self,
      id: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      self
        .stored
        .lock()
        .unwrap()
        .retain(|provider| provider.id != id);
      Box::pin(async { Ok(()) })
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn handle_request_authentication(
      &self,
      _auth: crate::RequestAuthentication,
      _ip: std::net::IpAddr,
      _require_user_enabled: bool,
      _req: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for these tests")
    }
  }

  fn github_config(secret: &str) -> ExternalLoginProviderConfig {
    ExternalLoginProviderConfig::Github(NamedOauthConfig {
      enabled: true,
      client_id: "client-id".into(),
      client_secret: secret.into(),
    })
  }

  fn create_request(secret: &str) -> CreateExternalLoginProvider {
    CreateExternalLoginProvider {
      name: "  Github  ".into(),
      registration_disabled: false,
      slug: String::new(),
      token_exchange: Default::default(),
      config: github_config(secret),
    }
  }

  fn update_request(
    id: &str,
    config: ExternalLoginProviderConfig,
  ) -> UpdateExternalLoginProvider {
    UpdateExternalLoginProvider {
      id: id.into(),
      name: "Renamed".into(),
      registration_disabled: true,
      slug: String::new(),
      token_exchange: Default::default(),
      config,
      clear_client_secret: false,
    }
  }

  fn stored_secret(auth: &TestAuth, id: &str) -> String {
    auth
      .stored
      .lock()
      .unwrap()
      .iter()
      .find(|provider| provider.id == id)
      .unwrap()
      .config
      .client_secret()
      .to_string()
  }

  #[tokio::test]
  async fn test_non_admins_are_forbidden() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;

    let statuses = [
      list_providers(&auth, &USER).await.unwrap_err().status,
      create_provider(&auth, &USER, create_request("secret"))
        .await
        .unwrap_err()
        .status,
      update_provider(
        &auth,
        &USER,
        update_request(&id, github_config("other")),
      )
      .await
      .unwrap_err()
      .status,
      delete_provider(&auth, &USER, &id).await.unwrap_err().status,
    ];
    assert!(
      statuses
        .iter()
        .all(|status| *status == StatusCode::FORBIDDEN)
    );
    // Nothing changed
    assert_eq!(auth.stored.lock().unwrap().len(), 1);
    assert_eq!(stored_secret(&auth, &id), "secret");
  }

  #[tokio::test]
  async fn test_create_generates_id_and_redacts_secret() {
    let auth = TestAuth::default();
    let item =
      create_provider(&auth, &ADMIN, create_request("secret"))
        .await
        .unwrap();
    assert_eq!(item.provider.id.len(), PROVIDER_ID_LENGTH);
    assert_eq!(item.provider.name, "Github");
    assert!(!item.read_only);
    // The urls use the slug, made from the name
    assert_eq!(item.provider.slug, "github");
    assert_eq!(
      item.redirect_uri,
      "https://example.com/auth/external/github/callback"
    );
    // The response is redacted, the stored provider is not
    assert_eq!(item.provider.config.client_secret(), REDACTED);
    assert_eq!(stored_secret(&auth, &item.provider.id), "secret");

    // Ids are unique
    let mut request = create_request("secret");
    request.name = "Other".into();
    let other =
      create_provider(&auth, &ADMIN, request).await.unwrap();
    assert_ne!(item.provider.id, other.provider.id);
  }

  #[tokio::test]
  async fn test_slug_is_made_from_the_name_or_given() {
    let auth = TestAuth::default();
    create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap();
    // The same name makes the same slug, which is taken now
    let err =
      create_provider(&auth, &ADMIN, create_request("secret"))
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);
    assert!(err.error.to_string().contains("made from the name"));

    // Given explicitly, and trimmed
    let mut request = create_request("secret");
    request.slug = " company-github ".into();
    let item = create_provider(&auth, &ADMIN, request).await.unwrap();
    assert_eq!(item.provider.slug, "company-github");
    assert_eq!(
      item.redirect_uri,
      "https://example.com/auth/external/company-github/callback"
    );

    // Given and taken
    let mut request = create_request("secret");
    request.slug = "company-github".into();
    let err =
      create_provider(&auth, &ADMIN, request).await.unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);

    // Malformed slugs, and a name which makes none
    let long = "a".repeat(MAX_SLUG_LENGTH + 1);
    for (name, slug) in [
      ("Github", "Company Github"),
      ("Github", "-github"),
      ("Github", "github--2"),
      ("Github", "UPPER"),
      ("Github", long.as_str()),
      ("!!!", ""),
    ] {
      let mut request = create_request("secret");
      request.name = name.into();
      request.slug = slug.into();
      let err =
        create_provider(&auth, &ADMIN, request).await.unwrap_err();
      assert_eq!(
        err.status,
        StatusCode::BAD_REQUEST,
        "{name} / {slug}"
      );
    }
    assert_eq!(auth.stored.lock().unwrap().len(), 2);
  }

  /// Names are shown on the login page and in every list, and end
  /// up in logs: a control character (Unicode Cc: tab, line breaks,
  /// escape sequences, DEL, NEL) inside one is refused at create and
  /// update, the error not repeating the name. Around it, whitespace
  /// is trimmed as before.
  #[tokio::test]
  async fn test_names_refuse_control_characters() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;
    for name in [
      "Git\thub",
      "Git\nhub",
      "Git\rhub",
      "Git\u{1b}[31mhub",
      "Git\u{7f}hub",
      "Git\u{85}hub",
      "Git\0hub",
    ] {
      let mut create = create_request("secret");
      create.name = name.into();
      let mut update = update_request(&id, github_config("secret"));
      update.name = name.into();
      for err in [
        create_provider(&auth, &ADMIN, create).await.unwrap_err(),
        update_provider(&auth, &ADMIN, update).await.unwrap_err(),
      ] {
        assert_eq!(err.status, StatusCode::BAD_REQUEST, "{name:?}");
        let message = format!("{:#}", err.error);
        assert_eq!(
          message,
          "Provider name cannot contain control characters"
        );
      }
    }
    let stored = auth.stored.lock().unwrap().clone();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].name, "Github");
    drop(stored);
    // Spaces, punctuation and other scripts are names.
    for name in
      ["  My SSO (eu-west)\t", "Connexion d'entreprise", "認証"]
    {
      let mut update = update_request(&id, github_config("secret"));
      update.name = name.into();
      let item =
        update_provider(&auth, &ADMIN, update).await.unwrap();
      assert_eq!(item.provider.name, name.trim());
    }
  }

  #[tokio::test]
  async fn test_update_slug() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;
    let mut request = create_request("secret");
    request.name = "Other".into();
    create_provider(&auth, &ADMIN, request).await.unwrap();

    // Empty keeps the slug, even when the name changes
    let item = update_provider(
      &auth,
      &ADMIN,
      update_request(&id, github_config("secret")),
    )
    .await
    .unwrap();
    assert_eq!(item.provider.name, "Renamed");
    assert_eq!(item.provider.slug, "github");

    // Changing it changes the redirect uri
    let mut request = update_request(&id, github_config("secret"));
    request.slug = "gh".into();
    let item = update_provider(&auth, &ADMIN, request).await.unwrap();
    assert_eq!(item.provider.slug, "gh");
    assert_eq!(
      item.redirect_uri,
      "https://example.com/auth/external/gh/callback"
    );

    // Its own slug is no conflict, another provider's is
    let mut request = update_request(&id, github_config("secret"));
    request.slug = "gh".into();
    update_provider(&auth, &ADMIN, request).await.unwrap();
    let mut request = update_request(&id, github_config("secret"));
    request.slug = "other".into();
    let err =
      update_provider(&auth, &ADMIN, request).await.unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);
    let mut request = update_request(&id, github_config("secret"));
    request.slug = "Not A Slug".into();
    let err =
      update_provider(&auth, &ADMIN, request).await.unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(
      auth.stored.lock().unwrap()[0].slug,
      "gh",
      "refused updates change nothing"
    );
  }

  /// The provider of a kind from the app configuration is addressed
  /// by its reserved id, which is its slug: no stored provider can
  /// take it while it exists. Without it, the slug is free like any
  /// other, and stays under `/external/`.
  #[tokio::test]
  async fn test_static_provider_holds_the_slug_of_its_id() {
    let auth = TestAuth {
      static_providers: vec![ExternalLoginProvider {
        id: "github".into(),
        name: "Github".into(),
        registration_disabled: false,
        slug: String::new(),
        token_exchange: Default::default(),
        config: github_config("static-secret"),
      }],
      ..Default::default()
    };
    let err =
      create_provider(&auth, &ADMIN, create_request("secret"))
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::CONFLICT);
    assert!(auth.stored.lock().unwrap().is_empty());

    let auth = TestAuth::default();
    let item =
      create_provider(&auth, &ADMIN, create_request("secret"))
        .await
        .unwrap();
    assert_eq!(item.provider.slug, "github");
    assert_eq!(
      item.redirect_uri,
      "https://example.com/auth/external/github/callback"
    );
  }

  #[tokio::test]
  async fn test_create_validates_input() {
    let auth = TestAuth::default();
    let mut bad_name = create_request("secret");
    bad_name.name = "   ".into();
    let mut bad_url = create_request("secret");
    bad_url.config = ExternalLoginProviderConfig::Oidc(OidcConfig {
      provider: "javascript:alert(1)".into(),
      ..Default::default()
    });
    // Credentials in the urls would be stored and logged in plain text
    let oidc_request = |provider: &str, redirect_host: &str| {
      let mut request = create_request("secret");
      request.config =
        ExternalLoginProviderConfig::Oidc(OidcConfig {
          enabled: true,
          provider: provider.into(),
          redirect_host: redirect_host.into(),
          client_id: "client-id".into(),
          ..Default::default()
        });
      request
    };
    for request in [
      bad_name,
      bad_url,
      create_request(REDACTED),
      oidc_request("https://user:pass@idp.example.com", ""),
      oidc_request("https://user@idp.example.com", ""),
      oidc_request("https://:pass@idp.example.com", ""),
      oidc_request(
        "https://idp.example.com",
        "https://user:pass@app.example.com",
      ),
      oidc_request(
        "https://idp.example.com",
        "ftp://app.example.com",
      ),
    ] {
      let err =
        create_provider(&auth, &ADMIN, request).await.unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }
    assert!(auth.stored.lock().unwrap().is_empty());

    // The error names the field, not the credentials
    for (request, field) in [
      (
        oidc_request("https://user:hunter2@idp.example.com", ""),
        "provider",
      ),
      (
        oidc_request(
          "https://idp.example.com",
          "https://user:hunter2@app.example.com",
        ),
        "redirect_host",
      ),
    ] {
      let err =
        create_provider(&auth, &ADMIN, request).await.unwrap_err();
      let message = format!("{:#}", err.error);
      assert!(
        message
          .contains(&format!("'{field}' must not carry credentials")),
        "{message}"
      );
      assert!(!message.contains("hunter2"), "{message}");
    }

    // Updates are validated the same way
    let id = create_provider(
      &auth,
      &ADMIN,
      oidc_request(
        "https://idp.example.com",
        "https://app.example.com",
      ),
    )
    .await
    .unwrap()
    .provider
    .id;
    let err = update_provider(
      &auth,
      &ADMIN,
      update_request(
        &id,
        oidc_config("https://user:pass@idp.example.com", "secret"),
      ),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    let stored = auth.stored.lock().unwrap();
    let ExternalLoginProviderConfig::Oidc(config) = &stored[0].config
    else {
      panic!("not an OIDC provider");
    };
    assert_eq!(config.provider, "https://idp.example.com");
  }

  #[tokio::test]
  async fn test_update_keeps_secret_when_empty_or_redacted() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;

    for secret in ["", REDACTED] {
      let item = update_provider(
        &auth,
        &ADMIN,
        update_request(&id, github_config(secret)),
      )
      .await
      .unwrap();
      assert_eq!(item.provider.name, "Renamed");
      assert!(item.provider.registration_disabled);
      assert_eq!(item.provider.config.client_secret(), REDACTED);
      assert_eq!(stored_secret(&auth, &id), "secret");
    }

    update_provider(
      &auth,
      &ADMIN,
      update_request(&id, github_config("rotated")),
    )
    .await
    .unwrap();
    assert_eq!(stored_secret(&auth, &id), "rotated");
  }

  fn oidc_config(
    provider: &str,
    secret: &str,
  ) -> ExternalLoginProviderConfig {
    ExternalLoginProviderConfig::Oidc(OidcConfig {
      enabled: true,
      provider: provider.into(),
      client_id: "client-id".into(),
      client_secret: secret.into(),
      ..Default::default()
    })
  }

  #[test]
  fn test_issuer_change() {
    let oidc = |provider: &str| {
      ExternalLoginProviderConfig::Oidc(OidcConfig {
        provider: provider.to_string(),
        ..Default::default()
      })
    };
    let existing = oidc("https://idp.example.com/realms/a");
    assert_eq!(
      issuer_change(
        &oidc("https://idp.example.com/realms/b"),
        &existing
      ),
      Some((
        "https://idp.example.com/realms/a",
        "https://idp.example.com/realms/b"
      ))
    );
    // Cosmetic edits are not a change of issuer.
    for same in [
      "https://idp.example.com/realms/a",
      "https://idp.example.com/realms/a/",
      " https://idp.example.com/realms/a ",
    ] {
      assert_eq!(
        issuer_change(&oidc(same), &existing),
        None,
        "{same}"
      );
    }
    let github =
      ExternalLoginProviderConfig::Github(Default::default());
    assert_eq!(issuer_change(&github, &github), None);
  }

  #[tokio::test]
  async fn test_update_provider_url_change_requires_secret() {
    let auth = TestAuth::default();
    let id = create_provider(
      &auth,
      &ADMIN,
      CreateExternalLoginProvider {
        name: "OIDC".into(),
        registration_disabled: false,
        slug: String::new(),
        token_exchange: Default::default(),
        config: oidc_config("https://idp.example.com", "secret"),
      },
    )
    .await
    .unwrap()
    .provider
    .id;

    // Pointing the provider elsewhere can't reuse the stored secret
    for secret in ["", REDACTED] {
      let err = update_provider(
        &auth,
        &ADMIN,
        update_request(
          &id,
          oidc_config("https://evil.example.com", secret),
        ),
      )
      .await
      .unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(stored_secret(&auth, &id), "secret");
    assert_eq!(auth.stored.lock().unwrap()[0].name, "OIDC");

    // Same url keeps the secret, a new url works with a new secret
    update_provider(
      &auth,
      &ADMIN,
      update_request(&id, oidc_config("https://idp.example.com", "")),
    )
    .await
    .unwrap();
    assert_eq!(stored_secret(&auth, &id), "secret");
    update_provider(
      &auth,
      &ADMIN,
      update_request(
        &id,
        oidc_config("https://new.example.com", "new"),
      ),
    )
    .await
    .unwrap();
    assert_eq!(stored_secret(&auth, &id), "new");
  }

  #[tokio::test]
  async fn test_token_exchange_settings() {
    let auth = TestAuth::default();
    let exchange = |audiences: &[&str]| TokenExchangeConfig {
      enabled: true,
      audiences: audiences.iter().map(|a| a.to_string()).collect(),
      max_token_age_secs: 300,
    };

    // Github has no signed tokens to exchange
    let err = create_provider(
      &auth,
      &ADMIN,
      CreateExternalLoginProvider {
        slug: String::new(),
        token_exchange: exchange(&[]),
        ..create_request("secret")
      },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);

    let item = create_provider(
      &auth,
      &ADMIN,
      CreateExternalLoginProvider {
        name: "OIDC".into(),
        registration_disabled: false,
        slug: String::new(),
        token_exchange: exchange(&[" cli ", "", "other", "cli"]),
        config: oidc_config("https://idp.example.com", "secret"),
      },
    )
    .await
    .unwrap();
    assert!(item.provider.token_exchange.enabled);
    // Trimmed, without empty entries or duplicates
    assert_eq!(
      item.provider.token_exchange.audiences,
      ["cli", "other"]
    );
    assert_eq!(item.provider.token_exchange.max_token_age_secs, 300);

    let too_many = (0..=MAX_TOKEN_EXCHANGE_AUDIENCES)
      .map(|i| format!("client-{i}"))
      .collect::<Vec<_>>();
    let too_long = "a".repeat(MAX_AUDIENCE_LENGTH + 1);
    for audiences in [
      too_many.iter().map(String::as_str).collect::<Vec<_>>(),
      vec![too_long.as_str()],
    ] {
      let err = create_provider(
        &auth,
        &ADMIN,
        CreateExternalLoginProvider {
          name: "OIDC".into(),
          registration_disabled: false,
          slug: String::new(),
          token_exchange: exchange(&audiences),
          config: oidc_config("https://idp.example.com", "secret"),
        },
      )
      .await
      .unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    // Updates replace the settings, leaving it out disables it
    let item = update_provider(
      &auth,
      &ADMIN,
      update_request(
        &item.provider.id,
        oidc_config("https://idp.example.com", ""),
      ),
    )
    .await
    .unwrap();
    assert!(!item.provider.token_exchange.enabled);
  }

  #[tokio::test]
  async fn test_update_clear_secret() {
    let auth = TestAuth::default();
    let id = create_provider(
      &auth,
      &ADMIN,
      CreateExternalLoginProvider {
        name: "OIDC".into(),
        registration_disabled: false,
        slug: String::new(),
        token_exchange: Default::default(),
        config: oidc_config("https://idp.example.com", "secret"),
      },
    )
    .await
    .unwrap()
    .provider
    .id;

    // Clearing together with a new secret is ambiguous
    let err = update_provider(
      &auth,
      &ADMIN,
      UpdateExternalLoginProvider {
        slug: String::new(),
        clear_client_secret: true,
        ..update_request(
          &id,
          oidc_config("https://idp.example.com", "other"),
        )
      },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(stored_secret(&auth, &id), "secret");

    // The redacted value sent back by the UI counts as no new secret.
    // Nothing is kept, so the url can change in the same update.
    let item = update_provider(
      &auth,
      &ADMIN,
      UpdateExternalLoginProvider {
        slug: String::new(),
        clear_client_secret: true,
        ..update_request(
          &id,
          oidc_config("https://new.example.com", REDACTED),
        )
      },
    )
    .await
    .unwrap();
    assert_eq!(item.provider.config.client_secret(), "");
    assert_eq!(stored_secret(&auth, &id), "");
  }

  #[tokio::test]
  async fn test_named_provider_needs_secret_to_be_enabled() {
    let auth = TestAuth::default();
    let err = create_provider(&auth, &ADMIN, create_request(""))
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);

    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;

    // Can't clear the secret of an enabled provider
    let err = update_provider(
      &auth,
      &ADMIN,
      UpdateExternalLoginProvider {
        slug: String::new(),
        clear_client_secret: true,
        ..update_request(&id, github_config(""))
      },
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(stored_secret(&auth, &id), "secret");

    // Disabled it can, eg. to remove a leaked secret from storage
    let disabled =
      ExternalLoginProviderConfig::Github(NamedOauthConfig {
        enabled: false,
        client_id: "client-id".into(),
        client_secret: String::new(),
      });
    update_provider(
      &auth,
      &ADMIN,
      UpdateExternalLoginProvider {
        slug: String::new(),
        clear_client_secret: true,
        ..update_request(&id, disabled)
      },
    )
    .await
    .unwrap();
    assert_eq!(stored_secret(&auth, &id), "");
  }

  #[tokio::test]
  async fn test_update_rejects_kind_change_and_unknown_provider() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;

    let err = update_provider(
      &auth,
      &ADMIN,
      update_request(
        &id,
        ExternalLoginProviderConfig::Oidc(OidcConfig::default()),
      ),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);

    let err = update_provider(
      &auth,
      &ADMIN,
      update_request("unknown", github_config("secret")),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
  }

  #[tokio::test]
  async fn test_static_providers_are_read_only() {
    let auth = TestAuth {
      static_providers: vec![ExternalLoginProvider {
        id: "github".into(),
        name: "Github".into(),
        registration_disabled: false,
        slug: String::new(),
        token_exchange: Default::default(),
        config: github_config("static-secret"),
      }],
      ..Default::default()
    };

    let providers = list_providers(&auth, &ADMIN).await.unwrap();
    assert_eq!(providers.len(), 1);
    assert!(providers[0].read_only);
    assert_eq!(
      providers[0].provider.config.client_secret(),
      REDACTED
    );
    // Reserved id keeps the original callback path
    assert_eq!(
      providers[0].redirect_uri,
      "https://example.com/auth/github/callback"
    );

    let err = update_provider(
      &auth,
      &ADMIN,
      update_request("github", github_config("other")),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);

    let err =
      delete_provider(&auth, &ADMIN, "github").await.unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
  }

  #[tokio::test]
  async fn test_delete_removes_stored_provider() {
    let auth = TestAuth::default();
    let id = create_provider(&auth, &ADMIN, create_request("secret"))
      .await
      .unwrap()
      .provider
      .id;
    delete_provider(&auth, &ADMIN, &id).await.unwrap();
    assert!(auth.stored.lock().unwrap().is_empty());
    let err = delete_provider(&auth, &ADMIN, &id).await.unwrap_err();
    assert_eq!(err.status, StatusCode::NOT_FOUND);
  }
}
