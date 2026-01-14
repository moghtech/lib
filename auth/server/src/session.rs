use anyhow::Context;
use mogh_error::AddStatusCode;
use reqwest::StatusCode;
use webauthn_rs::prelude::{
  PasskeyAuthentication, PasskeyRegistration,
};

use crate::provider::oidc::{SessionOidcLink, SessionOidcLogin};

#[derive(Clone)]
pub struct Session(pub tower_sessions::Session);

impl Session {
  // =========
  // = LOGIN =
  // =========

  const AUTHENTICATED_USER_ID: &str = "authenticated-user-id";

  pub async fn insert_authenticated_user_id(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::AUTHENTICATED_USER_ID, user_id)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  pub async fn retrieve_authenticated_user_id(
    &self,
  ) -> mogh_error::Result<String> {
    self
      .0
      .remove(Self::AUTHENTICATED_USER_ID)
      .await
      .context("Internal session type error")?
      .context("Authentication steps must be completed before JWT can be retrieved")
      .status_code(StatusCode::UNAUTHORIZED)
  }

  const OIDC_LOGIN: &str = "oidc-login";

  pub async fn insert_oidc_login(
    &self,
    data: &SessionOidcLogin,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::OIDC_LOGIN, data)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  pub async fn retrieve_oidc_login(
    &self,
  ) -> mogh_error::Result<SessionOidcLogin> {
    self
      .0
      .remove(Self::OIDC_LOGIN)
      .await
      .context("Internal session type error")?
      .context("OIDC login has not been initiated for this session")
      .status_code(StatusCode::UNAUTHORIZED)
  }

  const GITHUB_LOGIN: &str = "github-login";

  /// Store the CSRF state for validation
  pub async fn insert_github_login(
    &self,
    state: &str,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::GITHUB_LOGIN, state)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns the CSRF state for validation
  pub async fn retrieve_github_login(
    &self,
  ) -> mogh_error::Result<String> {
    self
      .0
      .remove(Self::GITHUB_LOGIN)
      .await
      .context("Internal session type error")?
      .context("Github login has not been initiated for this session")
      .status_code(StatusCode::UNAUTHORIZED)
  }

  const GOOGLE_LOGIN: &str = "google-login";

  /// Store the CSRF state for validation
  pub async fn insert_google_login(
    &self,
    state: &str,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::GOOGLE_LOGIN, state)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns the CSRF state for validation
  pub async fn retrieve_google_login(
    &self,
  ) -> mogh_error::Result<String> {
    self
      .0
      .remove(Self::GOOGLE_LOGIN)
      .await
      .context("Internal session type error")?
      .context("Google login has not been initiated for this session")
      .status_code(StatusCode::UNAUTHORIZED)
  }

  // =============
  // = 2FA LOGIN =
  // =============

  const PASSKEY_LOGIN: &str = "passkey-login";

  pub async fn insert_passkey_login(
    &self,
    user_id: &str,
    state: &PasskeyAuthentication,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::PASSKEY_LOGIN, (user_id, state))
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  pub async fn retrieve_passkey_login(
    &self,
  ) -> mogh_error::Result<(String, PasskeyAuthentication)> {
    self
      .0
      .remove(Self::PASSKEY_LOGIN)
      .await
      .context("Internal session type error")?
      .context(
        "Passkey login has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)
  }

  const TOTP_LOGIN: &str = "totp-login";

  /// Insert the user id which began totp login
  pub async fn insert_totp_login_user_id(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::TOTP_LOGIN, user_id)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns the user id which began totp login
  pub async fn retrieve_totp_login_user_id(
    &self,
  ) -> mogh_error::Result<String> {
    self
      .0
      .remove(Self::TOTP_LOGIN)
      .await
      .context("Internal session type error")?
      .context("TOTP login has not been initiated for this session")
      .status_code(StatusCode::UNAUTHORIZED)
  }

  // ==================
  // = 2FA ENROLLMENT =
  // ==================

  const PASSKEY_ENROLLMENT: &str = "passkey-enrollment";

  pub async fn insert_passkey_enrollment(
    &self,
    state: &PasskeyRegistration,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::PASSKEY_ENROLLMENT, state)
      .await
      .context("Session: Failed to insert passkey enrollment state")
      .map_err(Into::into)
  }

  pub async fn retrieve_passkey_enrollment(
    &self,
  ) -> mogh_error::Result<PasskeyRegistration> {
    self
      .0
      .remove(Self::PASSKEY_ENROLLMENT)
      .await
      .context("Internal session type error")?
      .context(
        "Passkey enrollment has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)
  }

  const TOTP_ENROLLMENT: &str = "totp-enrollment";

  /// Insert the totp which began totp enrollment
  pub async fn insert_totp_enrollment(
    &self,
    totp: &totp_rs::TOTP,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::TOTP_ENROLLMENT, totp)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns the user id which began totp enrollment
  pub async fn retrieve_totp_enrollment(
    &self,
  ) -> mogh_error::Result<totp_rs::TOTP> {
    self
      .0
      .remove(Self::TOTP_ENROLLMENT)
      .await
      .context("Internal session type error")?
      .context(
        "TOTP enrollment has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)
  }

  // ========
  // = LINK =
  // ========

  const EXTERNAL_LINK: &str = "external-link";

  /// Insert the totp which began totp enrollment
  pub async fn insert_external_link_user_id(
    &self,
    user_id: &str,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::EXTERNAL_LINK, user_id)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns the user id which began totp enrollment
  pub async fn retrieve_external_link_user_id(
    &self,
  ) -> mogh_error::Result<String> {
    self
      .0
      .remove(Self::EXTERNAL_LINK)
      .await
      .context("Internal session type error")?
      .context(
        "External link has not been initiated for this session",
      )
      .status_code(StatusCode::UNAUTHORIZED)
  }

  const OIDC_LINK: &str = "oidc-link";

  pub async fn insert_oidc_link(
    &self,
    link: &SessionOidcLink,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::OIDC_LINK, link)
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  pub async fn retrieve_oidc_link(
    &self,
  ) -> mogh_error::Result<Option<SessionOidcLink>> {
    self
      .0
      .remove(Self::OIDC_LINK)
      .await
      .context("Internal session type error")
      .map_err(Into::into)
  }

  const GITHUB_LINK: &str = "github-link";

  pub async fn insert_github_link(
    &self,
    user_id: &str,
    state: &str,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::GITHUB_LINK, (user_id, state))
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns (user_id, state, redirect)
  pub async fn retrieve_github_link(
    &self,
  ) -> mogh_error::Result<Option<(String, String)>> {
    self
      .0
      .remove(Self::GITHUB_LINK)
      .await
      .context("Internal session type error")
      .map_err(Into::into)
  }

  const GOOGLE_LINK: &str = "google-link";

  pub async fn insert_google_link(
    &self,
    user_id: &str,
    state: &str,
  ) -> mogh_error::Result<()> {
    self
      .0
      .insert(Self::GOOGLE_LINK, (user_id, state))
      .await
      .context("Failed to serialize session data")
      .map_err(Into::into)
  }

  /// Returns (user_id, state)
  pub async fn retrieve_google_link(
    &self,
  ) -> mogh_error::Result<Option<(String, String)>> {
    self
      .0
      .remove(Self::GOOGLE_LINK)
      .await
      .context("Internal session type error")
      .map_err(Into::into)
  }
}
