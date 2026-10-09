//! Default username / password / api key validations.
//! These can be overridden on AuthImpl.

use anyhow::{Context as _, anyhow};
use axum::http::StatusCode;
use mogh_error::AddStatusCodeError as _;
use mogh_validations::{StringValidator, StringValidatorMatches};
use subtle::ConstantTimeEq as _;

use crate::AuthImpl;

pub use mogh_request_ip::cidr::validate_cidr_whitelist;

/// Minimum length for usernames
pub const MIN_USERNAME_LENGTH: usize = 1;
/// Maximum length for usernames
pub const MAX_USERNAME_LENGTH: usize = 100;

/// Validate usernames
///
/// - Between [MIN_USERNAME_LENGTH] and [MAX_USERNAME_LENGTH] characters
/// - Matches `^[a-zA-Z0-9._@-]+$`
/// - Not 24 hex digits, the shape of a Mongo ObjectId (an app finding
///   users by id or name must not take one for the other)
pub fn validate_username(username: &str) -> anyhow::Result<()> {
  StringValidator::default()
    .min_length(MIN_USERNAME_LENGTH)
    .max_length(MAX_USERNAME_LENGTH)
    .matches(StringValidatorMatches::Username)
    .validate(username)
    .context("Failed to validate username")
}

/// Minimum length for passwords
pub const MIN_PASSWORD_LENGTH: usize = 8;
/// Maximum length for passwords, in characters. A password can't be
/// more than [MAX_PASSWORD_BYTES] long either, which is the tighter
/// bound for characters outside of ASCII.
pub const MAX_PASSWORD_LENGTH: usize = MAX_PASSWORD_BYTES;
/// Maximum length for passwords, in bytes of their UTF-8 encoding.
///
/// Passwords are hashed with bcrypt, which only uses the first 72
/// bytes: a longer password would log in with anything sharing its
/// first 72 bytes (24 characters of CJK text, say), so it is refused
/// instead. Passwords stored before this limit still log in.
pub const MAX_PASSWORD_BYTES: usize = 72;

/// Validate passwords
///
/// - Between [MIN_PASSWORD_LENGTH] and [MAX_PASSWORD_LENGTH] characters
/// - At most [MAX_PASSWORD_BYTES] bytes (UTF-8), bcrypt ignores the rest
pub fn validate_password(password: &str) -> anyhow::Result<()> {
  validate_password_with_min_length(password, MIN_PASSWORD_LENGTH)
}

/// [validate_password] with a minimum length of the app's (eg. a
/// configurable one), in characters. Everything else is the same:
/// at most [MAX_PASSWORD_LENGTH] characters and [MAX_PASSWORD_BYTES]
/// bytes, since bcrypt ignores the rest. A minimum above
/// [MAX_PASSWORD_LENGTH] refuses every password.
///
/// For [AuthImpl::validate_password] of an app whose minimum
/// differs, and for its own password writes (eg. an admin setting a
/// user's password), so the rules stay the server's.
pub fn validate_password_with_min_length(
  password: &str,
  min_length: usize,
) -> anyhow::Result<()> {
  StringValidator::default()
    .min_length(min_length)
    .max_length(MAX_PASSWORD_LENGTH)
    .validate(password)
    .context("Failed to validate password")?;
  if password.len() > MAX_PASSWORD_BYTES {
    return Err(
      anyhow!(
        "Input too long. Must be at most {MAX_PASSWORD_BYTES} bytes, \
        characters outside of ASCII take 2 to 4 bytes each."
      )
      .context("Failed to validate password"),
    );
  }
  Ok(())
}

/// Maximum length for API key names
pub const MAX_API_KEY_NAME_LENGTH: usize = 200;

/// Validate api key names
///
/// - Greater than [MAX_API_KEY_NAME_LENGTH] characters
pub fn validate_api_key_name(name: &str) -> anyhow::Result<()> {
  StringValidator::default()
    .max_length(MAX_API_KEY_NAME_LENGTH)
    .validate(name)
    .context("Failed to validate api key name")
}

/// The most entries the cidr whitelist of an api key or signing key
/// takes (`CreateApiKey` / `CreateSigningKey`). The whitelist is
/// stored with the key and parsed again for every request it makes,
/// and any user can create keys: an unbounded one costs storage and
/// time per request for nothing. [normalize_cidr_whitelist] holds a
/// whitelist to it, the whitelists an app sets itself (a user's, a
/// device's) included.
pub const MAX_CIDR_WHITELIST_ENTRIES: usize = 64;

/// Normalizes a cidr whitelist a client sent: trims the entries,
/// drops empty and repeated ones (keeping the order), refuses more
/// than [MAX_CIDR_WHITELIST_ENTRIES] distinct entries with
/// BAD_REQUEST (at the first one over, without reading the rest: the
/// list is as long as the body allows), then validates what is left
/// with [AuthImpl::validate_cidr_whitelist] (an invalid entry is
/// BAD_REQUEST by default), so a whitelist which would fail closed
/// at request time is never stored.
///
/// `CreateApiKey` / `CreateSigningKey` store the whitelist of a key
/// as this returns it. An app setting whitelists itself (a user's,
/// a device's, an onboarding key's) normalizes them with this too,
/// so every whitelist follows the same rules, the entry cap and the
/// app's own validation included.
pub fn normalize_cidr_whitelist<I: AuthImpl + ?Sized>(
  auth: &I,
  cidr_whitelist: Vec<String>,
) -> mogh_error::Result<Vec<String>> {
  let mut seen = std::collections::HashSet::new();
  let mut normalized = Vec::new();
  for entry in cidr_whitelist {
    let entry = entry.trim();
    if entry.is_empty() || !seen.insert(entry.to_string()) {
      continue;
    }
    if normalized.len() == MAX_CIDR_WHITELIST_ENTRIES {
      return Err(
        anyhow!(
          "A cidr whitelist takes at most {MAX_CIDR_WHITELIST_ENTRIES} entries"
        )
        .status_code(StatusCode::BAD_REQUEST),
      );
    }
    normalized.push(entry.to_string());
  }
  auth.validate_cidr_whitelist(&normalized)?;
  Ok(normalized)
}

/// Compare two secrets (eg oauth `state` / csrf tokens)
/// in constant time with respect to their contents.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
  a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Whether the url carries credentials in its authority
/// (`scheme://user:password@host`): a username, or any password.
pub(crate) fn url_has_credentials(url: &reqwest::Url) -> bool {
  !url.username().is_empty() || url.password().is_some()
}

/// Validate a url the app uses without authentication, such as
/// an OIDC issuer / discovery endpoint, a JWKS url or a redirect host.
///
/// - Parses as a url
/// - Has the `http` or `https` scheme
/// - Carries no credentials (`scheme://user:password@host`, a username
///   or any password): these would be
///   stored and shown in plain text with the url, sent along with
///   every request to it, and end up in error messages and logs.
///
/// `field` names the url in the error, and nothing of the url
/// itself is in it.
pub fn validate_public_http_url(
  field: &str,
  url: &str,
) -> anyhow::Result<()> {
  let parsed = reqwest::Url::parse(url)
    .with_context(|| format!("'{field}' is not a valid URL"))?;
  if !matches!(parsed.scheme(), "http" | "https") {
    return Err(anyhow!("'{field}' must be an http(s) URL"));
  }
  if url_has_credentials(&parsed) {
    return Err(anyhow!(
      "'{field}' must not carry credentials (scheme://user:password@host): \
      it is used without authentication, and credentials in a url \
      would be stored and logged in plain text"
    ));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use mogh_error::AddStatusCode as _;

  use super::*;
  use crate::test_support::stub_auth_impl;

  /// The default [AuthImpl::validate_cidr_whitelist].
  struct DefaultAuth;

  impl AuthImpl for DefaultAuth {
    fn new() -> Self {
      DefaultAuth
    }
    stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
  }

  /// Validates whitelists further: no catch all entry.
  struct NoCatchAllAuth;

  impl AuthImpl for NoCatchAllAuth {
    fn new() -> Self {
      NoCatchAllAuth
    }
    stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
    fn validate_cidr_whitelist(
      &self,
      cidr_whitelist: &[String],
    ) -> mogh_error::Result<()> {
      validate_cidr_whitelist(cidr_whitelist)
        .status_code(StatusCode::BAD_REQUEST)?;
      if cidr_whitelist.iter().any(|entry| entry == "0.0.0.0/0") {
        return Err(
          anyhow!("A whitelist must not allow every address")
            .status_code(StatusCode::UNPROCESSABLE_ENTITY),
        );
      }
      Ok(())
    }
  }

  #[test]
  fn test_validate_public_http_url() {
    for url in [
      "https://issuer.example.com",
      "http://localhost:8080/keys?v=2",
      // An '@' outside of the authority is not a credential
      "https://example.com/users/@me",
      "https://example.com/keys?owner=a@b",
    ] {
      assert!(validate_public_http_url("url", url).is_ok(), "{url}");
    }
    for url in [
      "not a url",
      "ftp://issuer.example.com",
      "javascript:alert(1)",
      "https://user:password@issuer.example.com",
      "https://user@issuer.example.com",
      "https://:password@issuer.example.com",
      "https://user:@issuer.example.com/keys",
      "http:user:password@issuer.example.com",
    ] {
      assert!(validate_public_http_url("url", url).is_err(), "{url}");
    }
    let err = validate_public_http_url(
      "keys url",
      "https://user:hunter2@issuer.example.com/keys",
    )
    .unwrap_err();
    let err = format!("{err:#}");
    assert!(err.contains("'keys url' must not carry credentials"));
    assert!(!err.contains("hunter2"), "{err}");
  }

  #[test]
  fn test_constant_time_eq() {
    assert!(constant_time_eq("abc", "abc"));
    assert!(!constant_time_eq("abc", "abd"));
    assert!(!constant_time_eq("abc", "abcd"));
    assert!(constant_time_eq("", ""));
  }

  #[test]
  fn test_validate_username_bounds() {
    assert!(validate_username("").is_err());
    assert!(validate_username("a").is_ok());
    assert!(
      validate_username(&"a".repeat(MAX_USERNAME_LENGTH)).is_ok()
    );
    assert!(
      validate_username(&"a".repeat(MAX_USERNAME_LENGTH + 1))
        .is_err()
    );
  }

  #[test]
  fn test_validate_username_charset() {
    assert!(validate_username("user.name_1@example-com").is_ok());
    assert!(validate_username("user name").is_err());
    assert!(validate_username("user<script>").is_err());
  }

  #[test]
  fn test_validate_password_bounds() {
    assert!(
      validate_password(&"a".repeat(MIN_PASSWORD_LENGTH - 1))
        .is_err()
    );
    assert!(
      validate_password(&"a".repeat(MIN_PASSWORD_LENGTH)).is_ok()
    );
    assert!(
      validate_password(&"a".repeat(MAX_PASSWORD_LENGTH)).is_ok()
    );
    assert!(
      validate_password(&"a".repeat(MAX_PASSWORD_LENGTH + 1))
        .is_err()
    );
  }

  #[test]
  fn test_validate_password_with_min_length() {
    for min_length in [1, 12, MAX_PASSWORD_LENGTH] {
      assert!(
        validate_password_with_min_length(
          &"a".repeat(min_length - 1),
          min_length
        )
        .is_err(),
        "{min_length}"
      );
      validate_password_with_min_length(
        &"a".repeat(min_length),
        min_length,
      )
      .unwrap();
    }
    // Below the default minimum, if the app says so.
    validate_password_with_min_length("short", 4).unwrap();
    assert!(validate_password("short").is_err());
    // The maximum stays, in characters and in bytes.
    for too_long in
      ["a".repeat(MAX_PASSWORD_LENGTH + 1), "密".repeat(25)]
    {
      assert!(
        validate_password_with_min_length(&too_long, 1).is_err()
      );
    }
    let err = validate_password_with_min_length(&"密".repeat(25), 1)
      .unwrap_err();
    assert!(
      format!("{err:#}").contains("at most 72 bytes"),
      "{err:#}"
    );
    // A minimum nothing can reach refuses everything.
    assert!(
      validate_password_with_min_length(
        &"a".repeat(MAX_PASSWORD_LENGTH),
        MAX_PASSWORD_LENGTH + 1
      )
      .is_err()
    );
  }

  #[test]
  fn test_validate_password_bytes() {
    // bcrypt uses all of a 72 byte password...
    let longest = "a".repeat(MAX_PASSWORD_BYTES);
    validate_password(&longest).unwrap();
    let hash = bcrypt::hash(&longest, 4).unwrap();
    assert!(!bcrypt::verify("a".repeat(71), &hash).unwrap());
    // ...but ignores anything after, so longer ones are refused.
    assert!(validate_password(&format!("{longest}b")).is_err());
    assert!(bcrypt::verify(format!("{longest}b"), &hash).unwrap());
    // Counted in bytes: 24 CJK characters are 72 bytes, 25 too many.
    validate_password(&"密".repeat(24)).unwrap();
    let err = validate_password(&"密".repeat(25)).unwrap_err();
    assert!(
      format!("{err:#}").contains("at most 72 bytes"),
      "{err:#}"
    );
    // A multibyte character straddling the limit.
    assert!(
      validate_password(&format!("{}é", "a".repeat(71))).is_err()
    );
  }

  #[test]
  fn test_validate_api_key_name_bounds() {
    assert!(validate_api_key_name("my key").is_ok());
    assert!(
      validate_api_key_name(&"a".repeat(MAX_API_KEY_NAME_LENGTH))
        .is_ok()
    );
    assert!(
      validate_api_key_name(&"a".repeat(MAX_API_KEY_NAME_LENGTH + 1))
        .is_err()
    );
  }

  #[test]
  fn test_normalize_cidr_whitelist() {
    let auth = DefaultAuth;
    let normalized = normalize_cidr_whitelist(
      &auth,
      ["10.0.0.0/8", " 10.0.0.0/8 ", "", "  ", "192.168.1.1"]
        .map(String::from)
        .to_vec(),
    )
    .unwrap();
    assert_eq!(normalized, ["10.0.0.0/8", "192.168.1.1"]);

    let entries = |count: usize| {
      (0..count)
        .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
        .collect::<Vec<_>>()
    };
    let most = normalize_cidr_whitelist(
      &auth,
      entries(MAX_CIDR_WHITELIST_ENTRIES),
    )
    .unwrap();
    assert_eq!(most.len(), MAX_CIDR_WHITELIST_ENTRIES);
    // Repeated ones don't count.
    let repeated = normalize_cidr_whitelist(
      &auth,
      vec![String::from("10.0.0.1"); 100_000],
    )
    .unwrap();
    assert_eq!(repeated, ["10.0.0.1"]);
    for count in [MAX_CIDR_WHITELIST_ENTRIES + 1, 100_000] {
      let err =
        normalize_cidr_whitelist(&auth, entries(count)).unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST, "{count}");
      assert!(format!("{:#}", err.error).contains("at most 64"));
    }
    // An invalid entry is still refused.
    let err = normalize_cidr_whitelist(
      &auth,
      vec![String::from("not an ip")],
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
  }

  /// The app's own validation applies, to what is left after the
  /// trimming and dedupe.
  #[test]
  fn test_normalize_cidr_whitelist_validates_with_the_app() {
    let err = normalize_cidr_whitelist(
      &NoCatchAllAuth,
      [" 10.0.0.0/8", "0.0.0.0/0 ", "10.0.0.0/8"]
        .map(String::from)
        .to_vec(),
    )
    .unwrap_err();
    assert_eq!(err.status, StatusCode::UNPROCESSABLE_ENTITY);
    // Passes the default validation.
    normalize_cidr_whitelist(
      &DefaultAuth,
      vec![String::from("0.0.0.0/0")],
    )
    .unwrap();
    assert_eq!(
      normalize_cidr_whitelist(
        &NoCatchAllAuth,
        vec![String::from(" 10.0.0.0/8 "), String::new()],
      )
      .unwrap(),
      ["10.0.0.0/8"]
    );
  }
}
