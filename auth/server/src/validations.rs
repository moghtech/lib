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

/// Refuses (BAD_REQUEST) an `expires` of a new api key / signing key
/// that an app cannot store: a unix timestamp in milliseconds above
/// `i64::MAX` (apps store it signed: cast, it wraps to a time long
/// past, a key that works for no request). `0` means no expiry.
/// `CreateApiKey` / `CreateSigningKey` run it before the key is made.
pub fn validate_key_expires(expires: u64) -> mogh_error::Result<()> {
  if expires > i64::MAX as u64 {
    return Err(
      anyhow!(
        "'expires' is out of range: a unix timestamp in milliseconds, or 0 for no expiry"
      )
      .status_code(StatusCode::BAD_REQUEST),
    );
  }
  Ok(())
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

/// Validate a url the app sends requests to, such as an OIDC issuer /
/// discovery endpoint, a JWKS url, a redirect host or a TokenReview
/// api server. Whatever authenticates those requests (a reviewer
/// credential, client credentials) is configured apart from the url.
///
/// - Parses as a url
/// - Has the `http` or `https` scheme. Plain `http` is accepted (the
///   server warns about it where it matters, see the README's "Plain
///   http urls").
/// - Carries no credentials in its userinfo
///   (`scheme://user:password@host`, a username or any password):
///   these would be stored and shown in plain text with the url, sent
///   along with every request to it, and end up in error messages and
///   logs.
///
/// `field` names the url in the error, and nothing of the url
/// itself is in it.
pub fn validate_http_url_without_userinfo(
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
      credentials in a url would be stored, shown and logged in plain \
      text with it. Configure them apart from the url"
    ));
  }
  Ok(())
}

// ===================
// = MANAGED CONFIGS =
// ===================
//
// The rules shared by the management api of login providers and of
// trusted issuers (and the trusted issuers of the app
// configuration, held to the same), kept in one place so they stay
// the same for both, and for whatever is managed next.

/// The longest name of a login provider, trusted issuer or rule.
pub(crate) const MAX_NAME_LENGTH: usize = 100;

/// The name of a login provider, trusted issuer or rule (`kind` says
/// which, eg. `Provider`), trimmed. It is listed, shown on the login
/// page, logged, and repeated in errors about it, so a control
/// character (Unicode Cc: a tab, a line break, an escape sequence)
/// inside it is refused. The error doesn't repeat the name.
pub(crate) fn validate_name(
  kind: &str,
  name: &str,
) -> anyhow::Result<String> {
  let name = name.trim();
  if name.is_empty() {
    return Err(anyhow!("{kind} name cannot be empty"));
  }
  if name.chars().count() > MAX_NAME_LENGTH {
    return Err(anyhow!(
      "{kind} name cannot be longer than {MAX_NAME_LENGTH} characters"
    ));
  }
  if name.chars().any(char::is_control) {
    return Err(anyhow!(
      "{kind} name cannot contain control characters"
    ));
  }
  Ok(name.to_string())
}

/// The values of the list `field` (eg. audiences, groups) trimmed,
/// without empty entries or duplicates. Each may be at most
/// `max_length` bytes long, and there may be at most `max_count`
/// (counted once cleaned): every audience is another signature check
/// on each exchange, every value another comparison.
pub(crate) fn clean_list(
  field: &str,
  values: Vec<String>,
  max_length: usize,
  max_count: usize,
) -> anyhow::Result<Vec<String>> {
  let mut cleaned = Vec::<String>::new();
  for value in values {
    let value = value.trim();
    if value.is_empty() || cleaned.iter().any(|v| v == value) {
      continue;
    }
    if value.len() > max_length {
      return Err(anyhow!(
        "'{field}' values cannot be longer than {max_length} characters"
      ));
    }
    cleaned.push(value.to_string());
  }
  if cleaned.len() > max_count {
    return Err(anyhow!(
      "'{field}' accepts at most {max_count} values"
    ));
  }
  Ok(cleaned)
}

/// The credential an update stores, in place of the one it carries
/// (`entered`): a login provider's client secret, a TokenReview
/// source's reviewer credential.
///
/// - A new credential is stored as entered.
/// - An empty or [REDACTED][mogh_auth_client::config::REDACTED] one
///   keeps the `stored` credential: it is never shown, so the edit
///   form of the configuration sends one of those back.
/// - Unless the url the credential is sent to changed (`url_changed`)
///   and there is a stored one: it must be entered again. Otherwise
///   pointing the configuration at another server would send it the
///   stored credential, which can't be read over the api.
///
/// `what` and `url` name the credential and its url in the error.
pub(crate) fn keep_credential(
  entered: &mut String,
  stored: &str,
  url_changed: bool,
  what: &str,
  url: &str,
) -> anyhow::Result<()> {
  let trimmed = entered.trim();
  if !trimmed.is_empty()
    && trimmed != mogh_auth_client::config::REDACTED
  {
    return Ok(());
  }
  if url_changed && !stored.is_empty() {
    return Err(anyhow!("The {url} changed: enter the {what} again"));
  }
  *entered = stored.to_string();
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
  fn test_validate_http_url_without_userinfo() {
    for url in [
      "https://issuer.example.com",
      "http://localhost:8080/keys?v=2",
      // An '@' outside of the authority is not a credential
      "https://example.com/users/@me",
      "https://example.com/keys?owner=a@b",
    ] {
      assert!(
        validate_http_url_without_userinfo("url", url).is_ok(),
        "{url}"
      );
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
      assert!(
        validate_http_url_without_userinfo("url", url).is_err(),
        "{url}"
      );
    }
    let err = validate_http_url_without_userinfo(
      "keys url",
      "https://user:hunter2@issuer.example.com/keys",
    )
    .unwrap_err();
    let err = format!("{err:#}");
    assert!(err.contains("'keys url' must not carry credentials"));
    assert!(!err.contains("hunter2"), "{err}");
    // True for every caller: a TokenReview url is sent a credential.
    assert!(!err.contains("without authentication"), "{err}");
    assert!(
      err.contains("Configure them apart from the url"),
      "{err}"
    );
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

  /// An expiry an app would store wrapped is refused; no expiry and
  /// the largest signed timestamp pass.
  #[test]
  fn key_expiry_fits_a_signed_timestamp() {
    assert!(validate_key_expires(0).is_ok());
    assert!(validate_key_expires(1_794_600_000_000).is_ok());
    assert!(validate_key_expires(i64::MAX as u64).is_ok());
    for expires in [i64::MAX as u64 + 1, u64::MAX] {
      let err = validate_key_expires(expires).unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST, "{expires}");
    }
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

  #[test]
  fn test_validate_name() {
    assert_eq!(
      validate_name("Rule", "  Deploy (prod) ").unwrap(),
      "Deploy (prod)"
    );
    let long = "ü".repeat(MAX_NAME_LENGTH);
    assert_eq!(validate_name("Rule", &long).unwrap(), long);
    for (name, error) in [
      ("  ", "Rule name cannot be empty"),
      (
        &format!("{long}a"),
        "Rule name cannot be longer than 100 characters",
      ),
      ("CI\tjobs", "Rule name cannot contain control characters"),
      (
        "CI\u{85}jobs",
        "Rule name cannot contain control characters",
      ),
    ] {
      let err = validate_name("Rule", name).unwrap_err();
      assert_eq!(format!("{err:#}"), error, "{name:?}");
    }
  }

  #[test]
  fn test_clean_list() {
    let list = |values: &[&str]| {
      values.iter().map(|v| v.to_string()).collect::<Vec<_>>()
    };
    assert_eq!(
      clean_list("groups", list(&[" a ", "", "b", "a", "  "]), 3, 2)
        .unwrap(),
      ["a", "b"]
    );
    let err =
      clean_list("groups", list(&["a", "abcd"]), 3, 2).unwrap_err();
    assert_eq!(
      format!("{err:#}"),
      "'groups' values cannot be longer than 3 characters"
    );
    // Counted once cleaned.
    let err = clean_list("groups", list(&["a", "b", "c", "a"]), 3, 2)
      .unwrap_err();
    assert_eq!(
      format!("{err:#}"),
      "'groups' accepts at most 2 values"
    );
    assert!(
      clean_list("groups", list(&["a", "b", "a"]), 3, 2).is_ok()
    );
  }

  #[test]
  fn test_keep_credential() {
    use mogh_auth_client::config::REDACTED;
    let keep = |entered: &str, stored: &str, url_changed: bool| {
      let mut entered = entered.to_string();
      keep_credential(
        &mut entered,
        stored,
        url_changed,
        "secret",
        "url",
      )
      .map(|()| entered)
    };
    // A new one is stored as entered, also with a new url.
    assert_eq!(keep("new", "stored", false).unwrap(), "new");
    assert_eq!(keep("new", "stored", true).unwrap(), "new");
    // Empty or redacted keeps the stored one.
    for kept in ["", " ", REDACTED, &format!(" {REDACTED} ")] {
      assert_eq!(keep(kept, "stored", false).unwrap(), "stored");
    }
    // Never for another url.
    for kept in ["", REDACTED] {
      let err = keep(kept, "stored", true).unwrap_err();
      assert_eq!(
        format!("{err:#}"),
        "The url changed: enter the secret again"
      );
    }
    // Nothing stored, nothing to protect.
    assert_eq!(keep("", "", true).unwrap(), "");
  }
}
