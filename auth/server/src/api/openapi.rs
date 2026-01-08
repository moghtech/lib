use serde::Serialize;
use utoipa::OpenApi;

mod auth {
  pub mod login {
    //! Unauthenticated methods to retrieve temporary access tokens.
    pub use crate::api::login::{local::*, passkey::*, totp::*, *};
  }
  pub mod manage {
    //! Authenticated methods to manage user login options.
    pub use crate::api::manage::{local::*, passkey::*, totp::*};
  }
}

#[derive(OpenApi)]
#[openapi(
  paths(
    // =========
    // = LOGIN =
    // =========
    auth::login::get_login_options,
    // External
    auth::login::exchange_for_jwt,
    // Local
    auth::login::sign_up_local_user,
    auth::login::login_local_user,
    // Passkey 2FA
    auth::login::complete_passkey_login,
    // Totp 2FA
    auth::login::complete_totp_login,
    // =========
    // = LOGIN =
    // =========
    // Local
    auth::manage::update_username,
    auth::manage::update_password,
    // Passkey 2FA
    auth::manage::begin_passkey_enrollment,
    auth::manage::confirm_passkey_enrollment,
    auth::manage::unenroll_passkey,
    // Totp 2FA
    auth::manage::begin_totp_enrollment,
    auth::manage::confirm_totp_enrollment,
    auth::manage::unenroll_totp,
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
