use anyhow::{Context as _, anyhow};
use axum::{
  Router, extract::Query, http::StatusCode, response::Redirect,
  routing::get,
};
use mogh_auth_client::api::login::UserIdOrTwoFactor;
use mogh_error::AddStatusCodeError;
use mogh_rate_limit::WithFailureRateLimit;
use openidconnect::{CsrfToken, PkceCodeChallenge};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::{
  AuthExtractor, AuthImpl,
  api::{RedirectQuery, format_redirect},
  provider::oidc::{OidcProvider, load_oidc_provider},
  rand::random_string,
  session::{
    SessionOidcLinkInfo, SessionOidcVerificationInfo,
    SessionPasskeyLogin, SessionThirdPartyLinkInfo, SessionTotpLogin,
    SessionUserId,
  },
};

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/login", get(oidc_login::<I>))
    .route("/link", get(oidc_link::<I>))
    .route("/callback", get(oidc_callback::<I>))
}

#[utoipa::path(
  get,
  path = "/oidc/login",
  description = "Login using OIDC",
  params(
    ("redirect", description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to OIDC provider for login"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub async fn oidc_login<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
  Query(RedirectQuery { redirect }): Query<RedirectQuery>,
) -> mogh_error::Result<Redirect> {
  if !auth.oidc_config().enabled() {
    return Err(
      anyhow!("OIDC login is not enabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let session = auth.client().session.as_ref().context(
    "Method called in invalid context. This should not happen",
  )?;

  let provider = load_oidc_provider(
    auth.app_name(),
    auth.host(),
    auth.oidc_config(),
  )
  .await
  .context("OIDC Provider not available")?;

  let (pkce_challenge, pkce_verifier) =
    PkceCodeChallenge::new_random_sha256();

  // Generate the authorization URL.
  let (auth_url, csrf_token, nonce) =
    provider.authorize_url(pkce_challenge);

  // Data inserted here will be matched on callback side for csrf protection.
  session
    .insert(
      SessionOidcVerificationInfo::KEY,
      SessionOidcVerificationInfo {
        csrf_token: csrf_token.secret().clone(),
        pkce_verifier,
        nonce,
        redirect,
      },
    )
    .await
    .context("Failed to insert session verification info")?;

  auth_redirect(auth, auth_url.as_str())
}

#[utoipa::path(
  get,
  path = "/oidc/link",
  description = "Link existing account to OIDC user",
  responses(
    (status = 303, description = "Redirect to OIDC provider for link"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub async fn oidc_link<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
) -> mogh_error::Result<Redirect> {
  if !auth.oidc_config().enabled() {
    return Err(
      anyhow!("OIDC login is not enabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let session = auth.client().session.as_ref().context(
    "Method called in invalid context. This should not happen",
  )?;

  let SessionThirdPartyLinkInfo { user_id } = session
    .remove(SessionThirdPartyLinkInfo::KEY)
    .await
    .context("Invalid session third party link info.")?
    .context("Missing session third party link info")?;

  let provider = load_oidc_provider(
    auth.app_name(),
    auth.host(),
    auth.oidc_config(),
  )
  .await
  .context("OIDC Provider not available")?;

  let (pkce_challenge, pkce_verifier) =
    PkceCodeChallenge::new_random_sha256();

  // Generate the authorization URL.
  let (auth_url, csrf_token, nonce) =
    provider.authorize_url(pkce_challenge);

  session
    .insert(
      SessionOidcLinkInfo::KEY,
      SessionOidcLinkInfo {
        user_id,
        csrf_token: csrf_token.secret().clone(),
        pkce_verifier,
        nonce,
      },
    )
    .await
    .context("Failed to insert session link info")?;

  auth_redirect(auth, auth_url.as_str())
}

/// Applies 'oidc_redirect_host'
fn auth_redirect<I: AuthImpl>(
  auth: I,
  auth_url: &str,
) -> mogh_error::Result<Redirect> {
  let redirect_host = &auth.oidc_config().redirect_host;
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct OidcCallbackQuery {
  state: Option<String>,
  code: Option<String>,
  error: Option<String>,
}

#[utoipa::path(
  get,
  path = "/oidc/callback",
  description = "Callback to finish OIDC login",
  params(
    ("state", description = "OIDC callback state."),
    ("code", description = "OIDC callback code."),
    ("error", description = "OIDC callback error.")
  ),
  responses(
    (status = 303, description = "Redirect to app to continue login steps."),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub async fn oidc_callback<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
  Query(query): Query<OidcCallbackQuery>,
) -> mogh_error::Result<Redirect> {
  async {
    if !auth.oidc_config().enabled() {
      return Err(
        anyhow!("OIDC login is not enabled")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }

    let session = auth.client().session.as_ref().context(
      "Method called in invalid context. This should not happen",
    )?;

    let provider = load_oidc_provider(
      auth.app_name(),
      auth.host(),
      auth.oidc_config(),
    )
    .await
    .context("OIDC Provider not available")?;

    if let Some(e) = query.error {
      return Err(
        anyhow!("Provider returned error: {e}")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }

    let code = query.code.context("Provider did not return code")?;
    let state = CsrfToken::new(
      query.state.context("Provider did not return state")?,
    );

    // Check first if this is a link callback
    // and use the linking handler if so.
    if let Ok(Some(info)) =
      session.remove(SessionOidcLinkInfo::KEY).await
    {
      return link_oidc_callback(&auth, &provider, info, state, code)
        .await;
    }

    let SessionOidcVerificationInfo {
      csrf_token,
      pkce_verifier,
      nonce,
      redirect,
    } = session
      .remove(SessionOidcVerificationInfo::KEY)
      .await
      .context("Invalid session verification info.")?
      .context(
        "Missing session verification info for CSRF protection.",
      )?;

    let (subject, token) = provider
      .validate_extract_subject_and_token(
        auth.oidc_config(),
        (state, csrf_token),
        code,
        pkce_verifier,
        nonce,
      )
      .await?;

    let user = auth.find_user_with_oidc_subject(subject.clone()).await?;

    let user_id_or_two_factor = match user {
      // Log in existing user
      Some(user) => {
        match (
          user.third_party_skip_2fa(),
          user.passkey(),
          user.totp_secret(),
        ) {
          // Skip / No 2FA
          (true, _, _) | (false, None, None) => {
            session
              .insert(
                SessionUserId::KEY,
                SessionUserId(user.id().to_string()),
              )
              .await
              .context(
                "Failed to store user id for client session",
              )?;
            UserIdOrTwoFactor::UserId(user.id().to_string())
          }
          // WebAuthn Passkey 2FA
          (false, Some(passkey), _) => {
            let provider = auth.passkey_provider().context(
              "No passkey provider available, possibly invalid 'host' config.",
            )?;
            let (response, state) = provider
              .start_passkey_authentication(passkey)
              .context("Failed to start passkey authentication flow")?;
            auth
              .client()
              .session
              .clone()
              .context("Method called in context without session")?
              .insert(
                SessionPasskeyLogin::KEY,
                SessionPasskeyLogin {
                  user_id: user.id().to_string(),
                  state,
                },
              )
              .await?;
            UserIdOrTwoFactor::Passkey(response)
          }
          // TOTP 2FA
          (false, None, Some(_)) => {
            auth
              .client()
              .session
              .as_ref()
              .context("Method called in context without session")?
              .insert(
                SessionTotpLogin::KEY,
                SessionTotpLogin {
                  user_id: user.id().to_string(),
                },
              )
              .await?;
            UserIdOrTwoFactor::Totp {}
          }
        }
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
            if auth.oidc_config().use_full_email {
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
        if auth.find_user_with_username(username.clone()).await.is_ok() {
          username += "-";
          username += &random_string(5);
        }

        let user_id = auth
          .sign_up_oidc_user(
            username,
            subject,
            no_users_exist
          )
          .await?;

        UserIdOrTwoFactor::UserId(user_id)
      }
    };

    match user_id_or_two_factor {
      UserIdOrTwoFactor::UserId(_) => Ok(format_redirect(
        auth.host(),
        redirect.as_deref(),
        "redeem_ready=true",
      )),
      UserIdOrTwoFactor::Totp {} => Ok(format_redirect(
        auth.host(),
        redirect.as_deref(),
        "totp=true",
      )),
      UserIdOrTwoFactor::Passkey(passkey) => {
        let passkey = serde_json::to_string(&passkey)
          .context("Failed to serialize passkey response")?;
        let passkey = urlencoding::encode(&passkey);
        Ok(format_redirect(
          auth.host(),
          redirect.as_deref(),
          &format!("passkey={passkey}"),
        ))
      }
    }
  }
  .with_failure_rate_limit_using_ip(
    auth.general_rate_limiter(),
    &auth.client().ip,
  )
  .await
}

/// This intercepts during the normal oauth callback if
/// 'oidc-link-info' is found on session.
async fn link_oidc_callback<I: AuthImpl>(
  auth: &I,
  provider: &OidcProvider,
  SessionOidcLinkInfo {
    user_id,
    csrf_token,
    pkce_verifier,
    nonce,
  }: SessionOidcLinkInfo,
  state: CsrfToken,
  code: String,
) -> mogh_error::Result<Redirect> {
  let (subject, _) = provider
    .validate_extract_subject_and_token(
      auth.oidc_config(),
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
      return Ok(Redirect::to(&format!("{}/settings", auth.host())));
    } else {
      return Err(
        anyhow!("Account already linked to another user.").into(),
      );
    }
  }

  auth.link_oidc_login(user_id, subject).await?;

  Ok(Redirect::to(&format!("{}/settings", auth.host())))
}
