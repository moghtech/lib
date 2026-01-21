use anyhow::{Context as _, anyhow};
use axum::{
  Router, extract::Query, http::StatusCode, response::Redirect,
  routing::get,
};
use mogh_auth_client::api::login::UserIdOrTwoFactor;
use mogh_error::{AddStatusCode, AddStatusCodeError};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_request_ip::RequestIp;
use openidconnect::{CsrfToken, PkceCodeChallenge};

use crate::{
  AuthImpl,
  api::{
    RedirectQuery, StandardCallbackQuery, get_user_id_or_two_factor,
    user_id_or_two_factor_redirect,
  },
  provider::oidc::{
    OidcProvider, SessionOidcLink, SessionOidcLogin,
    load_oidc_provider,
  },
  rand::random_string,
  session::Session,
};

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/login", get(oidc_login::<I>))
    .route("/link", get(oidc_link::<I>))
    .route("/callback", get(oidc_callback::<I>))
}

pub async fn oidc_login<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  session: Session,
  Query(RedirectQuery { redirect }): Query<RedirectQuery>,
) -> mogh_error::Result<Redirect> {
  let auth = I::new();
  async {
    let config = auth
      .oidc_config()
      .context("OIDC login is not set up")
      .status_code(StatusCode::BAD_REQUEST)?;

    if !config.enabled() {
      return Err(
        anyhow!("OIDC login is not enabled")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }

    let provider =
      load_oidc_provider(auth.app_name(), auth.host(), config)
        .await
        .context("OIDC Provider not available")?;

    let (pkce_challenge, pkce_verifier) =
      PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL.
    let (auth_url, csrf_token, nonce) =
      provider.authorize_url(pkce_challenge);

    // Data inserted here will be matched on callback side for csrf protection.
    session
      .insert_oidc_login(&SessionOidcLogin {
        csrf_token: csrf_token.secret().clone(),
        pkce_verifier,
        nonce,
        redirect,
      })
      .await?;

    auth_redirect(auth_url.as_str(), &config.redirect_host)
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await
}

pub async fn oidc_link<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  session: Session,
) -> mogh_error::Result<Redirect> {
  let auth = I::new();
  async {
    let config = auth
      .oidc_config()
      .context("OIDC login is not set up")
      .status_code(StatusCode::BAD_REQUEST)?;

    if !config.enabled() {
      return Err(
        anyhow!("OIDC login is not enabled")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }

    let user_id = session.retrieve_external_link_user_id().await?;

    let user = auth.get_user(user_id.clone()).await?;
    auth.check_username_locked(user.username())?;

    let provider =
      load_oidc_provider(auth.app_name(), auth.host(), config)
        .await
        .context("OIDC provider not available")
        .status_code(StatusCode::UNAUTHORIZED)?;

    let (pkce_challenge, pkce_verifier) =
      PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL.
    let (auth_url, csrf_token, nonce) =
      provider.authorize_url(pkce_challenge);

    session
      .insert_oidc_link(&SessionOidcLink {
        user_id,
        csrf_token: csrf_token.secret().clone(),
        pkce_verifier,
        nonce,
      })
      .await?;

    auth_redirect(auth_url.as_str(), &config.redirect_host)
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await
}

/// Applies 'oidc_redirect_host'
fn auth_redirect(
  auth_url: &str,
  redirect_host: &str,
) -> mogh_error::Result<Redirect> {
  let redirect = if !redirect_host.is_empty() {
    let (protocol, rest) = auth_url
      .split_once("://")
      .context("Invalid URL: Missing protocol (eg 'https://')")?;
    let host = rest
      .split_once(['/', '?'])
      .map(|(host, _)| host)
      .unwrap_or(rest);
    Redirect::to(
      &auth_url
        .replace(&format!("{protocol}://{host}"), redirect_host),
    )
  } else {
    Redirect::to(auth_url)
  };
  Ok(redirect)
}

pub async fn oidc_callback<I: AuthImpl>(
  RequestIp(ip): RequestIp,
  session: Session,
  Query(query): Query<StandardCallbackQuery>,
) -> mogh_error::Result<Redirect> {
  let auth = I::new();
  async {
    let config = auth
      .oidc_config()
      .context("OIDC login is not set up")
      .status_code(StatusCode::BAD_REQUEST)?;

    if !config.enabled() {
      return Err(
        anyhow!("OIDC login is not enabled")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }

    if let Some(e) = query.error {
      return Err(
        anyhow!("Provider returned error: {e}")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }

    let provider =
      load_oidc_provider(auth.app_name(), auth.host(), config)
        .await
        .context("OIDC Provider not available")?;

    let code = query.code.context("Provider did not return code")?;
    let state = CsrfToken::new(
      query.state.context("Provider did not return state")?,
    );

    // Check first if this is a link callback
    // and use the linking handler if so.
    if let Ok(Some(info)) = session.retrieve_oidc_link().await {
      return link_oidc_callback(&auth, &provider, info, state, code)
        .await;
    }

    let SessionOidcLogin {
      csrf_token,
      pkce_verifier,
      nonce,
      redirect,
    } = session.retrieve_oidc_login().await?;

    let (subject, token) = provider
      .validate_extract_subject_and_token(
        config,
        (state, csrf_token),
        code,
        pkce_verifier,
        nonce,
      )
      .await?;

    let user =
      auth.find_user_with_oidc_subject(subject.clone()).await?;

    let user_id_or_two_factor = match user {
      // Log in existing user
      Some(user) => {
        get_user_id_or_two_factor(&auth, &session, &user).await?
      }
      // Sign up user
      None => {
        let no_users_exist = auth.no_users_exist().await?;

        if auth.registration_disabled() && !no_users_exist {
          return Err(
            anyhow!("User registration is disabled")
              .status_code(StatusCode::UNAUTHORIZED),
          );
        }

        // Fetch user info
        let user_info =
          provider.fetch_user_info(token, subject.clone()).await?;

        // Will use preferred_username, then email, then user_id if it isn't available.
        let mut username = user_info
          .preferred_username()
          .map(|username| username.to_string())
          .unwrap_or_else(|| {
            let email = user_info
              .email()
              .map(|email| email.as_str())
              .unwrap_or(subject.as_str());
            if config.use_full_email {
              email
            } else {
              email
                .split_once('@')
                .map(|(username, _)| username)
                .unwrap_or(email)
            }
            .to_string()
          });

        // Modify username if it already exists
        if auth
          .find_user_with_username(username.clone())
          .await?
          .is_some()
        {
          username += "-";
          username += &random_string(5);
        }

        let user_id = auth
          .sign_up_oidc_user(username, subject, no_users_exist)
          .await?;

        session.insert_authenticated_user_id(&user_id).await?;

        UserIdOrTwoFactor::UserId(user_id)
      }
    };

    user_id_or_two_factor_redirect(
      &auth,
      user_id_or_two_factor,
      redirect.as_deref(),
    )
  }
  .with_failure_rate_limit_using_ip(auth.general_rate_limiter(), &ip)
  .await
}

/// This intercepts during the normal oauth callback if
/// 'oidc-link-info' is found on session.
async fn link_oidc_callback<I: AuthImpl>(
  auth: &I,
  provider: &OidcProvider,
  SessionOidcLink {
    user_id,
    csrf_token,
    pkce_verifier,
    nonce,
  }: SessionOidcLink,
  state: CsrfToken,
  code: String,
) -> mogh_error::Result<Redirect> {
  let config = auth
    .oidc_config()
    .context("OIDC login is not set up")
    .status_code(StatusCode::BAD_REQUEST)?;

  let (subject, _) = provider
    .validate_extract_subject_and_token(
      config,
      (state, csrf_token),
      code,
      pkce_verifier,
      nonce,
    )
    .await?;

  // Ensure there are no other existing users with this login linked.
  if let Some(existing_user) =
    auth.find_user_with_oidc_subject(subject.clone()).await?
  {
    if existing_user.id() == user_id {
      // Link is already complete, this is a no-op
      return Ok(Redirect::to(auth.post_link_redirect()));
    } else {
      return Err(
        anyhow!("Account already linked to another user.").into(),
      );
    }
  }

  auth.link_oidc_login(user_id, subject).await?;

  Ok(Redirect::to(auth.post_link_redirect()))
}
