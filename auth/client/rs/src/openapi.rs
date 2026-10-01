use serde::Serialize;
use utoipa::OpenApi;

mod auth {
  pub use crate::api::{external::*, login::*, manage::*, token::*};
}

#[derive(OpenApi)]
#[openapi(
  paths(
    // =========
    // = BASIC =
    // =========
    auth::get_login_options,
    auth::exchange_for_jwt,
    auth::exchange_external_for_jwt,
    auth::token_exchange,
    auth::complete_passkey_login,
    auth::complete_totp_login,
    auth::complete_totp_recovery_login,
    // ==========
    // = MANAGE =
    // ==========
    auth::get_user_id,
    // Local
    auth::update_username,
    auth::update_password,
    // External
    auth::begin_external_login_link,
    auth::unlink_local_login,
    auth::unlink_external_login,
    // External login providers (admin)
    auth::list_external_login_providers,
    auth::create_external_login_provider,
    auth::update_external_login_provider,
    auth::delete_external_login_provider,
    // Trusted issuers for workload identity (admin)
    auth::list_trusted_issuers,
    auth::create_trusted_issuer,
    auth::update_trusted_issuer,
    auth::delete_trusted_issuer,
    // Passkey 2FA
    auth::begin_passkey_enrollment,
    auth::confirm_passkey_enrollment,
    auth::unenroll_passkey,
    // Totp 2FA
    auth::begin_totp_enrollment,
    auth::confirm_totp_enrollment,
    auth::unenroll_totp,
    // Skip 2FA
    auth::update_external_skip_2fa,
    // Api key
    auth::create_api_key,
    auth::delete_api_key,
    // Signing key
    auth::create_signing_key,
    auth::delete_signing_key,
    // =============
    // = PROVIDERS =
    // =============
    // Local
    auth::sign_up_local_user,
    auth::login_local_user,
    // External
    auth::external_login,
    auth::external_link,
    auth::external_callback,
    // Oidc (reserved id 'oidc')
    auth::oidc_login,
    auth::oidc_link,
    auth::oidc_callback,
    // Github (reserved id 'github')
    auth::github_login,
    auth::github_link,
    auth::github_callback,
    // Google (reserved id 'google')
    auth::google_login,
    auth::google_link,
    auth::google_callback,
  ),
  modifiers(&AddSecurityHeaders),
  security(
    ("api-key" = [], "api-secret" = []),
    (
      "api-public-key" = [],
      "api-host" = [],
      "api-timestamp" = [],
      "api-nonce" = [],
      "api-signature" = []
    ),
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
      // Signing key, see [crate::signature].
      ("api-public-key", header_security_scheme("X-Api-Public-Key")),
      ("api-host", header_security_scheme("X-Api-Host")),
      ("api-timestamp", header_security_scheme("X-Api-Timestamp")),
      ("api-nonce", header_security_scheme("X-Api-Nonce")),
      ("api-signature", header_security_scheme("X-Api-Signature")),
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_spec_paths() {
    let spec = serde_json::to_value(MoghAuthApi::openapi()).unwrap();
    let paths = spec["paths"].as_object().unwrap();
    assert!(paths.contains_key("/login/CompleteTotpRecoveryLogin"));
    assert!(paths.contains_key("/external/{slug}/login"));

    for (path, item) in paths {
      for (method, operation) in item.as_object().unwrap() {
        let params = operation["parameters"]
          .as_array()
          .cloned()
          .unwrap_or_default();
        // Exactly the `{segments}` of the path are path parameters.
        let mut declared = params
          .iter()
          .filter(|param| param["in"] == "path")
          .map(|param| param["name"].as_str().unwrap().to_string())
          .collect::<Vec<_>>();
        declared.sort();
        let mut segments = path
          .split('/')
          .filter_map(|segment| {
            segment.strip_prefix('{')?.strip_suffix('}')
          })
          .map(str::to_string)
          .collect::<Vec<_>>();
        segments.sort();
        assert_eq!(declared, segments, "{method} {path}");
        // The query parameters are all optional.
        for param in &params {
          if param["in"] == "query" {
            assert_ne!(param["required"], true, "{method} {path}");
          }
        }

        // Only the manage api needs credentials.
        let security = &operation["security"];
        if path.starts_with("/manage/") {
          assert!(security.is_null(), "{method} {path}: {security}");
        } else {
          assert_eq!(
            security,
            &serde_json::json!([{}]),
            "{method} {path}"
          );
        }
      }
    }

    let schemes =
      spec["components"]["securitySchemes"].as_object().unwrap();
    for scheme in spec["security"].as_array().unwrap() {
      for name in scheme.as_object().unwrap().keys() {
        assert!(schemes.contains_key(name), "{name}");
      }
    }
    for (scheme, header) in [
      ("api-public-key", crate::signature::API_PUBLIC_KEY_HEADER),
      ("api-host", crate::signature::API_HOST_HEADER),
      ("api-timestamp", crate::signature::API_TIMESTAMP_HEADER),
      ("api-nonce", crate::signature::API_NONCE_HEADER),
      ("api-signature", crate::signature::API_SIGNATURE_HEADER),
    ] {
      let name = schemes[scheme]["name"].as_str().unwrap();
      assert!(name.eq_ignore_ascii_case(header), "{name}");
    }
  }

  /// Every status the server's `token_exchange_error` answers with
  /// is declared, with the OAuth error body.
  #[test]
  fn test_token_exchange_responses() {
    let spec = serde_json::to_value(MoghAuthApi::openapi()).unwrap();
    let responses = spec["paths"]["/token"]["post"]["responses"]
      .as_object()
      .unwrap();
    let mut statuses = responses.keys().cloned().collect::<Vec<_>>();
    statuses.sort();
    assert_eq!(statuses, ["200", "400", "429", "500", "503"]);
    for (status, response) in responses {
      let schema = response["content"]["application/json"]["schema"]
        ["$ref"]
        .as_str()
        .unwrap();
      let expected = if status == "200" {
        "#/components/schemas/TokenExchangeResponse"
      } else {
        "#/components/schemas/TokenExchangeError"
      };
      assert_eq!(schema, expected, "{status}");
    }
  }
}
