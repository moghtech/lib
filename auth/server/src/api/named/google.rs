use anyhow::{Context as _, anyhow};
use axum::{
  Router, extract::Query, response::Redirect, routing::get,
};
use mogh_auth_client::api::login::UserIdOrTwoFactor;
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_rate_limit::WithFailureRateLimit as _;
use reqwest::StatusCode;

use crate::{
  AuthExtractor, AuthImpl,
  api::{
    RedirectQuery, StandardCallbackQuery, get_user_id_or_two_factor,
    user_id_or_two_factor_redirect,
  },
  provider::named::{
    STATE_PREFIX_LENGTH,
    google::{GoogleProvider, google_provider},
  },
  rand::random_string,
};

pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/login", get(google_login::<I>))
    .route("/link", get(google_link::<I>))
    .route("/callback", get(google_callback::<I>))
}

#[utoipa::path(
  get,
  path = "/google/login",
  description = "Login using Google",
  params(
    ("redirect", description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to Google for login"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub async fn google_login<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
  Query(RedirectQuery { redirect }): Query<RedirectQuery>,
) -> mogh_error::Result<Redirect> {
  if !auth.google_config().enabled() {
    return Err(
      anyhow!("Google login is not enabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let provider = google_provider(auth.host(), auth.google_config())
    .context("Google provider not available")
    .status_code(StatusCode::UNAUTHORIZED)?;

  let (state, uri) =
    provider.get_state_and_login_redirect_url(redirect).await;

  auth.client().session.insert_google_login(&state).await?;

  Ok(Redirect::to(&uri))
}

#[utoipa::path(
  get,
  path = "/google/link",
  description = "Link existing account to Google user",
  responses(
    (status = 303, description = "Redirect to Google for link"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub async fn google_link<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
) -> mogh_error::Result<Redirect> {
  if !auth.google_config().enabled() {
    return Err(
      anyhow!("Google login is not enabled")
        .status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let session = &auth.client().session;

  let user_id = session.retrieve_external_link_user_id().await?;

  let user = auth.get_user(user_id.clone()).await?;
  auth.check_username_locked(user.username())?;

  let provider = google_provider(auth.host(), auth.google_config())
    .context("Google provider not available")
    .status_code(StatusCode::UNAUTHORIZED)?;

  let (state, uri) =
    provider.get_state_and_login_redirect_url(None).await;

  session.insert_google_link(&user_id, &state).await?;

  Ok(Redirect::to(&uri))
}

#[utoipa::path(
  get,
  path = "/google/callback",
  description = "Callback to finish Google login",
  params(
    ("state", description = "Callback state."),
    ("code", description = "Callback code."),
    ("error", description = "Callback error.")
  ),
  responses(
    (status = 303, description = "Redirect back to app to continue login steps."),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
pub async fn google_callback<I: AuthImpl>(
  AuthExtractor(auth): AuthExtractor<I>,
  Query(query): Query<StandardCallbackQuery>,
) -> mogh_error::Result<Redirect> {
  async {
    if !auth.google_config().enabled() {
      return Err(
        anyhow!("Google login is not enabled")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }

    let (client_state, code) = query.open()?;

    let provider = google_provider(auth.host(), auth.google_config())
      .context("Google provider not available")
      .status_code(StatusCode::UNAUTHORIZED)?;

    let session = &auth.client().session;

    // Check first if this is a link callback
    // and use the linking handler if so.
    if let Ok(Some(info)) = session.retrieve_google_link().await {
      return link_google_callback(
        &auth,
        provider,
        info,
        client_state,
        code,
      )
      .await;
    }

    let state = session.retrieve_google_login().await?;

    if client_state != state {
      return Err(
        anyhow!("State mismatch")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }

    let token = provider.get_access_token(&code).await?;
    let google_user = provider.get_google_user(&token.id_token)?;
    let google_id = google_user.id;

    let user =
      auth.find_user_with_google_id(google_id.clone()).await?;

    let user_id_or_two_factor = match user {
      // Log in existing user
      Some(user) => get_user_id_or_two_factor(&auth, &user).await?,
      // Sign up user
      None => {
        let no_users_exist = auth.no_users_exist().await?;

        if auth.registration_disabled() && !no_users_exist {
          return Err(
            anyhow!("User registration is disabled")
              .status_code(StatusCode::UNAUTHORIZED),
          );
        }

        let mut username = google_user
          .email
          .split('@')
          .collect::<Vec<&str>>()
          .first()
          .unwrap()
          .to_string();

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
          .sign_up_google_user(username, google_id, no_users_exist)
          .await?;

        session.insert_authenticated_user_id(&user_id).await?;

        UserIdOrTwoFactor::UserId(user_id)
      }
    };

    user_id_or_two_factor_redirect(
      &auth,
      user_id_or_two_factor,
      Some(&state[STATE_PREFIX_LENGTH..]),
    )
  }
  .with_failure_rate_limit_using_ip(
    auth.general_rate_limiter(),
    &auth.client().ip,
  )
  .await
}

/// This intercepts during the normal oauth callback if
/// 'google-link-info' is found on session.
async fn link_google_callback<I: AuthImpl>(
  auth: &I,
  provider: &GoogleProvider,
  (user_id, state): (String, String),
  client_state: String,
  code: String,
) -> mogh_error::Result<Redirect> {
  if client_state != state {
    return Err(
      anyhow!("State mismatch").status_code(StatusCode::UNAUTHORIZED),
    );
  }

  let token = provider.get_access_token(&code).await?;

  let google_user = provider.get_google_user(&token.id_token)?;
  let google_id = google_user.id.to_string();

  // Ensure there are no other existing users with this login linked.
  if let Some(existing_user) =
    auth.find_user_with_google_id(google_id.clone()).await?
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

  auth.link_google_login(user_id, google_id).await?;

  Ok(Redirect::to(&format!("{}/settings", auth.host())))
}
