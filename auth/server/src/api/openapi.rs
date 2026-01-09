use serde::Serialize;
use utoipa::OpenApi;

mod auth {
  pub use crate::api::{
    login::{local::*, passkey::*, totp::*, *},
    manage::{local::*, passkey::*, totp::*},
    oidc::*,
  };
}

#[derive(OpenApi)]
#[openapi(
  paths(
    // =========
    // = LOGIN =
    // =========
    auth::get_login_options,
    // External
    auth::exchange_for_jwt,
    // Local
    auth::sign_up_local_user,
    auth::login_local_user,
    // Passkey 2FA
    auth::complete_passkey_login,
    // Totp 2FA
    auth::complete_totp_login,
    // ==========
    // = MANAGE =
    // ==========
    // Local
    auth::update_username,
    auth::update_password,
    // Passkey 2FA
    auth::begin_passkey_enrollment,
    auth::confirm_passkey_enrollment,
    auth::unenroll_passkey,
    // Totp 2FA
    auth::begin_totp_enrollment,
    auth::confirm_totp_enrollment,
    auth::unenroll_totp,
    // ========
    // = OIDC =
    // ========
    auth::oidc_login,
    auth::oidc_link,
    auth::oidc_callback,
  ),
  modifiers(&AddSecurityHeaders),
  security(
    ("api-key" = [], "api-secret" = []),
    ("jwt" = [])
  )
)]
pub struct MoghAuthApi;

#[derive(Debug, Serialize)]
pub struct AddSecurityHeaders;

impl utoipa::Modify for AddSecurityHeaders {
  fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
    let schema = openapi.components.get_or_insert_default();

    schema.add_security_schemes_from_iter([
      ("api-key", header_security_scheme("X-Api-Key")),
      ("api-secret", header_security_scheme("X-Api-Secret")),
      ("jwt", header_security_scheme("Authorization")),
    ]);
  }
}

fn header_security_scheme(
  header: &str,
) -> utoipa::openapi::security::SecurityScheme {
  utoipa::openapi::security::SecurityScheme::ApiKey(
    utoipa::openapi::security::ApiKey::Header(
      utoipa::openapi::security::ApiKeyValue::new(header),
    ),
  )
}
