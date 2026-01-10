use anyhow::{Context as _, anyhow};
use axum::{Router, response::Redirect, routing::get};
use mogh_auth_client::api::login::UserIdOrTwoFactor;
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use reqwest::StatusCode;
use serde::Deserialize;
use tower_sessions::Session;
use utoipa::ToSchema;

use crate::{
  AuthImpl,
  session::{SessionPasskeyLogin, SessionTotpLogin, SessionUserId},
  user::BoxAuthUser,
};

pub mod login;
pub mod manage;
pub mod named;
pub mod oidc;
pub mod openapi;

/// This router should be nested without any additional middleware
pub fn router<I: AuthImpl>() -> Router {
  Router::new()
    .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
    .nest("/login", login::router::<I>())
    .nest("/manage", manage::router::<I>())
    .nest("/oidc", oidc::router::<I>())
    .merge(named::router::<I>())
}

#[derive(serde::Deserialize)]
struct Variant {
  variant: String,
}

#[derive(serde::Deserialize)]
pub struct RedirectQuery {
  redirect: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct StandardCallbackQuery {
  pub state: Option<String>,
  pub code: Option<String>,
  pub error: Option<String>,
}

impl StandardCallbackQuery {
  /// Returns (state, code)
  pub fn open(self) -> mogh_error::Result<(String, String)> {
    if let Some(e) = self.error {
      return Err(
        anyhow!("Provider returned error: {e}")
          .status_code(StatusCode::UNAUTHORIZED),
      );
    }
    let state = self
      .state
      .context("Callback query does not contain state")
      .status_code(StatusCode::UNAUTHORIZED)?;
    let code = self
      .code
      .context("Callback query does not contain code")
      .status_code(StatusCode::UNAUTHORIZED)?;

    Ok((state, code))
  }
}

fn format_redirect(
  host: &str,
  redirect: Option<&str>,
  extra: &str,
) -> Redirect {
  let redirect_url = if let Some(redirect) = redirect
    && !redirect.is_empty()
  {
    let splitter = if redirect.contains('?') { '&' } else { '?' };
    format!("{redirect}{splitter}{extra}")
  } else {
    format!("{host}?{extra}")
  };
  Redirect::to(&redirect_url)
}

async fn get_user_id_or_two_factor<I: AuthImpl>(
  auth: &I,
  user: &BoxAuthUser,
  session: &Session,
) -> anyhow::Result<UserIdOrTwoFactor> {
  let res = match (
    user.external_skip_2fa(),
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
        .context("Failed to store user id for client session")?;
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
  };
  Ok(res)
}

fn user_id_or_two_factor_redirect<I: AuthImpl>(
  auth: &I,
  user_id_or_two_factor: UserIdOrTwoFactor,
  redirect: Option<&str>,
) -> mogh_error::Result<Redirect> {
  match user_id_or_two_factor {
    UserIdOrTwoFactor::UserId(_) => {
      Ok(format_redirect(auth.host(), redirect, "redeem_ready=true"))
    }
    UserIdOrTwoFactor::Totp {} => {
      Ok(format_redirect(auth.host(), redirect, "totp=true"))
    }
    UserIdOrTwoFactor::Passkey(passkey) => {
      let passkey = serde_json::to_string(&passkey)
        .context("Failed to serialize passkey response")?;
      let passkey = urlencoding::encode(&passkey);
      Ok(format_redirect(
        auth.host(),
        redirect,
        &format!("passkey={passkey}"),
      ))
    }
  }
}
