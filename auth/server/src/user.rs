use crate::passkey::Passkey;

/// Implemented for app specific User struct.
pub trait AuthUserImpl: Send + Sync + 'static {
  fn id(&self) -> &str;

  fn username(&self) -> &str;

  fn hashed_password(&self) -> Option<&str> {
    None
  }

  fn passkey(&self) -> Option<Passkey> {
    None
  }

  fn totp_secret(&self) -> Option<&str> {
    None
  }

  /// The bcrypt-hashed TOTP recovery codes which have not been used,
  /// as stored by AuthImpl::update_user_stored_totp at enrollment.
  /// Required for recovery code login to work.
  fn hashed_totp_recovery_codes(&self) -> &[String] {
    &[]
  }

  /// Whether a user enrolled in a second factor ([Self::passkey] /
  /// [Self::totp_secret]) skips it when logging in through an
  /// external login provider: the OIDC / GitHub / Google callbacks,
  /// `ExchangeExternalForJwt`, and the token exchange at `POST /token`.
  ///
  /// - `true` (the default): the provider login alone logs the user
  ///   in, and `POST /token` issues an app token for a token of the
  ///   provider alone.
  /// - `false`: the login continues with the second factor
  ///   (`ExchangeExternalForJwt` answers with it), and `POST /token`
  ///   refuses the user, it has no way to ask for one.
  ///
  /// ⚠️ With the default, the second factor a user enrolled only
  /// protects their local (password) login: whoever can log in as them
  /// at the provider, or holds a token of theirs the provider issued
  /// to an app accepted for token exchange, logs in without it. Apps
  /// offering 2fa should implement this from a per user setting
  /// which defaults to `false`, and implement
  /// [AuthImpl::update_user_external_skip_2fa][crate::AuthImpl::update_user_external_skip_2fa]
  /// so users can change it (`UpdateExternalSkip2fa`).
  fn external_skip_2fa(&self) -> bool {
    true
  }

  /// The ids of the login providers linked to the user
  /// ([AuthImpl::link_external_login][crate::AuthImpl::link_external_login],
  /// or at sign up), or `None` when the app doesn't tell (the
  /// default).
  ///
  /// With them, the auth management api refuses to remove the user's
  /// only way to log in, `400 Cannot remove the only way to log in`:
  /// `UnlinkLocalLogin` without a linked provider, `UnlinkExternalLogin`
  /// of the only one without a password ([Self::hashed_password]). A
  /// user doing it from a stale tab, or a client sending it directly,
  /// would lock themselves out until an admin steps in. With `None`
  /// nothing is checked: the app refuses it in
  /// [AuthImpl::unlink_local_login][crate::AuthImpl::unlink_local_login] /
  /// [unlink_external_login][crate::AuthImpl::unlink_external_login],
  /// or doesn't.
  fn external_login_provider_ids(&self) -> Option<&[String]> {
    None
  }

  /// Whether the user is enabled. Disabled users are refused the whole
  /// auth management API, except `GetUserId`: they can't create api
  /// keys, change how they log in, or (as an admin) manage login
  /// providers and trusted issuers. The default is `true`.
  ///
  /// Logging in is not refused, so a user waiting to be enabled can
  /// still log in and see that. Refusing disabled users the app's own
  /// API is up to [AuthImpl::handle_request_authentication][crate::AuthImpl::handle_request_authentication]
  /// (`require_user_enabled`).
  fn is_enabled(&self) -> bool {
    true
  }

  /// Whether the user can manage app wide auth settings: the login
  /// providers and the trusted issuers (workload identity).
  ///
  /// ⚠️ Managing login providers is equivalent to full control of
  /// the app: a provider under the users control can sign up
  /// new users, and make them admin using 'admin_groups'. So is
  /// managing trusted issuers, whose rules can grant admin. Changing
  /// the issuer of a stored OIDC provider also lets the new identity
  /// provider log in as every user linked to it, other admins
  /// included. Apps which separate admins from super admins should
  /// return `true` only for (enabled) super admins, as Komodo and
  /// Cicada do.
  ///
  /// The auth management API refuses disabled users
  /// ([Self::is_enabled]) whatever this returns. Where else the app
  /// uses it, it should be `false` for a disabled user.
  fn is_admin(&self) -> bool {
    false
  }

  /// Whether this is the user of a workload
  /// ([AuthImpl::get_or_create_workload_user][crate::AuthImpl::get_or_create_workload_user]),
  /// which only ever acts through short lived tokens it gets by
  /// token exchange.
  ///
  /// Workload users are refused by the auth management API
  /// (api keys, passwords, 2fa, linked logins, login providers, ...),
  /// so a workload can't create a credential which outlives its rule.
  ///
  /// ⚠️ Apps with their own ways to create credentials
  /// (eg. api keys) must refuse these users there as well.
  fn is_workload(&self) -> bool {
    false
  }

  /// Whitelist of CIDR ranges (eg `10.0.0.0/8`) or ip addresses
  /// from which user logins / api calls are accepted.
  /// Empty means all ips allowed.
  ///
  /// Enforced by the auth server on all login flows
  /// (local, 2FA completion, OIDC / social callbacks)
  /// and on authenticated auth management API calls. A local
  /// (password) login from outside it gets the same `401 Invalid
  /// login credentials` as a wrong password, and the reason is
  /// logged, so the answer never confirms the password.
  /// Apps must enforce this on their own APIs in
  /// [AuthImpl::handle_request_authentication][crate::AuthImpl::handle_request_authentication],
  /// see [middleware::check_user_cidr_whitelist][crate::middleware::check_user_cidr_whitelist].
  fn cidr_whitelist(&self) -> &[String] {
    &[]
  }
}

pub type BoxAuthUser = Box<dyn AuthUserImpl>;

#[cfg(test)]
mod tests {
  use super::*;

  /// Only what local 2fa needs.
  struct TotpUser;

  impl AuthUserImpl for TotpUser {
    fn id(&self) -> &str {
      "user"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn totp_secret(&self) -> Option<&str> {
      Some("secret")
    }
  }

  #[test]
  fn test_defaults() {
    // Kept for compatibility, see the docs: without an
    // implementation external logins skip the second factor.
    assert!(TotpUser.external_skip_2fa());
    assert!(!crate::api::external_login_requires_two_factor(
      &TotpUser
    ));
    assert!(TotpUser.is_enabled());
    assert!(!TotpUser.is_admin());
    assert!(!TotpUser.is_workload());
  }
}
