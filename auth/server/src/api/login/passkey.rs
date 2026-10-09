use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use mogh_auth_client::api::login::CompletePasskeyLogin;
use mogh_error::{AddStatusCode, AddStatusCodeError as _};
use mogh_rate_limit::WithFailureRateLimit;
use mogh_resolver::Resolve;
use tracing::{info, instrument};
use webauthn_rs::prelude::AuthenticationResult;

use crate::{
  SecondFactor,
  api::login::{IssueToken, LoginArgs, issue_login},
  middleware::check_user_cidr_whitelist,
  passkey::Passkey,
};

impl Resolve<LoginArgs> for CompletePasskeyLogin {
  #[instrument(
    "CompletePasskeyLogin",
    skip_all,
    fields(
      ip = ip.to_string(),
    )
  )]
  async fn resolve(
    self,
    LoginArgs { auth, session, ip }: &LoginArgs,
  ) -> Result<Self::Response, Self::Error> {
    // Taken before the rate limit: a session without a passkey login
    // (or with an expired one) holds nothing to guess, and is refused
    // without counting against the ip. Only the assertion (and the
    // user it logs in) counts. A client over the limit loses the
    // login all the same, and logs in again.
    let (user_id, state, kind) =
      session.retrieve_passkey_login().await?;
    async {
      let provider = auth.passkey_provider().context(
        "No passkey provider available, possibly invalid 'host' config.",
      )?;

      // This will error if the incoming passkey is invalid.
      // The result of this call must be used to
      // update the stored passkey info on database.
      let update = provider
        .finish_passkey_authentication(&self.credential, &state)
        .context("Failed to validate passkey")
        .status_code(StatusCode::UNAUTHORIZED)?;

      let user = auth
        .get_user(user_id.clone())
        .await?;

      check_user_cidr_whitelist(user.as_ref(), *ip)?;

      let mut passkey = user
        .passkey()
        .context("User is not enrolled in Passkey 2FA")
        .status_code(StatusCode::UNAUTHORIZED)?;

      if apply_authentication(&mut passkey, &update)? {
        // The same passkey with its new counter: no change of how the
        // user logs in (see AuthImpl::credentials_changed).
        auth
          .update_user_passkey_counter(user_id.clone(), passkey)
          .await?;
      }

      let token = issue_login(
        auth.as_ref(),
        user.id(),
        user.username(),
        *ip,
        kind,
        Some(SecondFactor::Passkey),
        IssueToken::Now,
      )
      .await?;

      info!(
        user_id = user.id(),
        username = user.username(),
        "Passkey 2FA flow complete, user logged in"
      );

      Ok(token.into())
    }
    // Strict, like the other login steps.
    .with_strict_failure_rate_limit_using_ip(
      auth.general_rate_limiter(),
      ip,
    )
    .await
  }
}

/// Checks the passkey which signed the challenge (`update`) is the
/// one the user has enrolled now, and applies the new state it
/// reports (the signature counter, backup state) to it. Returns
/// whether the stored passkey has to be updated.
///
/// The challenge was issued for the passkey the user had at the
/// first factor, and verified against it. The user may have
/// enrolled another one since (to revoke a lost device, say),
/// which the old one must not log in anymore.
fn apply_authentication(
  passkey: &mut Passkey,
  update: &AuthenticationResult,
) -> mogh_error::Result<bool> {
  passkey.0.update_credential(update).ok_or_else(|| {
    anyhow!("Passkey is no longer enrolled for this user")
      .status_code(StatusCode::UNAUTHORIZED)
  })
}

#[cfg(test)]
mod tests {
  use data_encoding::BASE64URL_NOPAD;

  use super::*;
  use crate::provider::passkey::test_passkey;

  /// What a verified assertion of the passkey `cred_id` reports.
  fn authentication(
    cred_id: &[u8],
    counter: u32,
  ) -> AuthenticationResult {
    serde_json::from_value(serde_json::json!({
      "cred_id": BASE64URL_NOPAD.encode(cred_id),
      "needs_update": true,
      "user_verified": true,
      "backup_state": false,
      "backup_eligible": false,
      "counter": counter,
      "extensions": {},
    }))
    .unwrap()
  }

  #[test]
  fn test_enrolled_passkey_is_updated() {
    let mut passkey = test_passkey(&[1; 16]);
    // The counter moved on, which has to be stored.
    assert!(
      apply_authentication(
        &mut passkey,
        &authentication(&[1; 16], 5)
      )
      .unwrap()
    );
    // Nothing changed, nothing to store.
    assert!(
      !apply_authentication(
        &mut passkey,
        &authentication(&[1; 16], 5)
      )
      .unwrap()
    );
  }

  /// The challenge of a login was issued for the passkey the user
  /// had at the first factor. When they enrolled another one before
  /// it completes (to revoke a lost device), the old one is refused.
  #[test]
  fn test_replaced_passkey_is_refused() {
    let mut enrolled_now = test_passkey(&[2; 16]);
    let err = apply_authentication(
      &mut enrolled_now,
      &authentication(&[1; 16], 5),
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    assert!(
      format!("{:#}", err.error).contains("no longer enrolled")
    );
  }
}
