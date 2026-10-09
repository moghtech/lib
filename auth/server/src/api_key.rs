//! App-level key representation used by the auth server to
//! authenticate the requests of api keys (key + secret) and signing
//! keys (signed with a private key) alike, and the generation of new
//! api keys ([generate_api_key_parts]).

use anyhow::Context as _;

use crate::rand::random_string;

/// Implemented for the app specific api key struct, returned from
/// [AuthImpl::get_api_key][crate::AuthImpl::get_api_key] for an api
/// key and [AuthImpl::get_signing_key][crate::AuthImpl::get_signing_key]
/// for a signing key.
///
/// [AuthApiKey] is a ready made implementation
/// for apps which do not need their own struct.
pub trait AuthApiKeyImpl: Send + Sync + 'static {
  /// The id of the user which owns the key.
  fn user_id(&self) -> &str;

  /// Whitelist of CIDR ranges / ip addresses from which
  /// requests using this key are accepted.
  /// Empty means all ips allowed.
  ///
  /// This is enforced by the auth server in
  /// [AuthImpl::get_user_id_from_request_authentication][crate::AuthImpl::get_user_id_from_request_authentication],
  /// on top of the owning user's
  /// [AuthUserImpl::cidr_whitelist][crate::user::AuthUserImpl::cidr_whitelist].
  fn cidr_whitelist(&self) -> &[String] {
    &[]
  }
}

/// An api key or signing key, see [AuthApiKeyImpl].
pub type BoxAuthApiKey = Box<dyn AuthApiKeyImpl>;

/// Ready made [AuthApiKeyImpl] for apps which do not need their own
/// struct, for api keys and signing keys alike.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthApiKey {
  /// The id of the user which owns the key.
  pub user_id: String,
  /// Whitelist of CIDR ranges / ip addresses from which
  /// requests using this key are accepted.
  /// Empty means all ips allowed.
  pub cidr_whitelist: Vec<String>,
}

impl AuthApiKeyImpl for AuthApiKey {
  fn user_id(&self) -> &str {
    &self.user_id
  }
  fn cidr_whitelist(&self) -> &[String] {
    &self.cidr_whitelist
  }
}

impl From<AuthApiKey> for BoxAuthApiKey {
  fn from(api_key: AuthApiKey) -> Self {
    Box::new(api_key)
  }
}

/// An api key as the app stores it, found by
/// [AuthImpl::find_api_key][crate::AuthImpl::find_api_key]. The
/// server authenticates requests with it
/// ([verify_api_key][crate::middleware::verify_api_key]).
#[derive(Clone, PartialEq, Eq)]
pub struct StoredApiKey {
  /// The id of the user which owns the key.
  pub user_id: String,
  /// The bcrypt hash of the key's secret, as
  /// [AuthImpl::create_api_key][crate::AuthImpl::create_api_key] got
  /// it.
  pub hashed_secret: String,
  /// When the key expires, unix milliseconds, `0` for never: the
  /// [CreateApiKey::expires][mogh_auth_client::api::manage::CreateApiKey::expires]
  /// it was created with.
  pub expires: u64,
  /// See [AuthApiKeyImpl::cidr_whitelist].
  pub cidr_whitelist: Vec<String>,
}

/// The hash of the secret is left out.
impl std::fmt::Debug for StoredApiKey {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("StoredApiKey")
      .field("user_id", &self.user_id)
      .field("expires", &self.expires)
      .field("cidr_whitelist", &self.cidr_whitelist)
      .finish_non_exhaustive()
  }
}

/// A signing key as the app stores it, found by
/// [AuthImpl::find_signing_key][crate::AuthImpl::find_signing_key].
/// The server authenticates requests with it
/// ([verify_signing_key][crate::middleware::verify_signing_key]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSigningKey {
  /// The id of the user which owns the key.
  pub user_id: String,
  /// When the key expires, unix milliseconds, `0` for never: the
  /// [CreateApiKey::expires][mogh_auth_client::api::manage::CreateApiKey::expires]
  /// it was created with.
  pub expires: u64,
  /// See [AuthApiKeyImpl::cidr_whitelist].
  pub cidr_whitelist: Vec<String>,
}

impl From<StoredApiKey> for BoxAuthApiKey {
  fn from(stored: StoredApiKey) -> Self {
    AuthApiKey {
      user_id: stored.user_id,
      cidr_whitelist: stored.cidr_whitelist,
    }
    .into()
  }
}

impl From<StoredSigningKey> for BoxAuthApiKey {
  fn from(stored: StoredSigningKey) -> Self {
    AuthApiKey {
      user_id: stored.user_id,
      cidr_whitelist: stored.cidr_whitelist,
    }
    .into()
  }
}

/// Whether a key which `expires` (unix milliseconds, `0` for never)
/// has expired at `now_ms`.
pub(crate) fn expired(expires: u64, now_ms: u64) -> bool {
  expires != 0 && expires <= now_ms
}

/// A new api key, see [generate_api_key_parts]. Built by the server
/// only: fields may be added.
#[derive(Clone)]
#[non_exhaustive]
pub struct ApiKeyParts {
  /// The key, `K_<random>_K`: stored as it is, and sent as
  /// `X-API-KEY` by the requests made with it.
  pub key: String,
  /// The secret, `S_<random>_S`: shown to the owner of the key once,
  /// and never stored. The requests send it as `X-API-SECRET`.
  pub secret: String,
  /// The bcrypt hash of the secret, stored with the key
  /// ([StoredApiKey::hashed_secret]).
  pub hashed_secret: String,
}

/// The secret and its hash are left out.
impl std::fmt::Debug for ApiKeyParts {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("ApiKeyParts")
      .field("key", &self.key)
      .finish_non_exhaustive()
  }
}

/// Generates a new api key: a key and a secret of `secret_length`
/// random alphanumeric characters each (between `K_` / `_K` and `S_` /
/// `_S`), and the bcrypt hash of the secret at `bcrypt_cost`, as the
/// management api's `CreateApiKey` does.
///
/// It is for an app which mints api keys outside of the management
/// api, eg. a CLI writing one to the app's database directly
/// (Komodo's `km create api-key`), so its keys are made like the
/// others. Pass the app's
/// [AuthImpl::api_key_secret_length][crate::AuthImpl::api_key_secret_length]
/// and [AuthImpl::api_secret_bcrypt_cost][crate::AuthImpl::api_secret_bcrypt_cost]
/// (40 and 10 by default), and store the key and the hash as
/// `create_api_key` stores them: the key then authenticates as one
/// created over the api ([AuthImpl::find_api_key][crate::AuthImpl::find_api_key]
/// returns the stored hash).
///
/// ⚠️ It runs bcrypt on the calling thread, tens to hundreds of
/// milliseconds by the cost: a server calls it off its async runtime
/// (eg. `tokio::task::spawn_blocking`). A CLI can call it as it is.
///
/// ```
/// use mogh_auth_server::api_key::generate_api_key_parts;
///
/// // A low bcrypt cost keeps the example quick, apps pass theirs.
/// let parts = generate_api_key_parts(40, 4)?;
/// assert!(parts.key.starts_with("K_") && parts.key.ends_with("_K"));
/// assert!(parts.secret.starts_with("S_") && parts.secret.ends_with("_S"));
/// assert_eq!(parts.key.len(), 44);
/// // The key and the hash are stored, the secret goes to the owner.
/// assert!(bcrypt::verify(&parts.secret, &parts.hashed_secret)?);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn generate_api_key_parts(
  secret_length: usize,
  bcrypt_cost: u32,
) -> anyhow::Result<ApiKeyParts> {
  let key = format!("K_{}_K", random_string(secret_length));
  let secret = format!("S_{}_S", random_string(secret_length));
  let hashed_secret = bcrypt::hash(&secret, bcrypt_cost)
    .context("Failed at hashing secret string")?;
  Ok(ApiKeyParts {
    key,
    secret,
    hashed_secret,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  // Low cost to keep tests fast.
  const TEST_BCRYPT_COST: u32 = 4;

  #[test]
  fn test_api_key_parts_format() {
    let ApiKeyParts { key, secret, .. } =
      generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    assert_eq!(key.len(), 44);
    assert!(key.starts_with("K_") && key.ends_with("_K"));
    assert_eq!(secret.len(), 44);
    assert!(secret.starts_with("S_") && secret.ends_with("_S"));
    assert!(
      key[2..42].chars().all(|c| c.is_ascii_alphanumeric()),
      "key body must be alphanumeric"
    );
  }

  #[test]
  fn test_api_key_respects_custom_length() {
    let ApiKeyParts { key, secret, .. } =
      generate_api_key_parts(10, TEST_BCRYPT_COST).unwrap();
    assert_eq!(key.len(), 14);
    assert_eq!(secret.len(), 14);
  }

  #[test]
  fn test_api_key_secret_verifies_against_hash() {
    let parts = generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    assert!(
      bcrypt::verify(&parts.secret, &parts.hashed_secret).unwrap()
    );
  }

  #[test]
  fn test_api_key_wrong_secret_fails_verification() {
    let parts = generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    let other = generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    assert!(
      !bcrypt::verify(&other.secret, &parts.hashed_secret).unwrap()
    );
  }

  #[test]
  fn test_api_key_parts_are_unique() {
    let a = generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    let b = generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    assert_ne!(a.key, b.key);
    assert_ne!(a.secret, b.secret);
  }

  /// A key minted outside the management api, stored as it stores
  /// one, authenticates the same: its secret, not another.
  #[tokio::test]
  async fn test_generated_key_authenticates() {
    let parts = generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    let stored = || StoredApiKey {
      user_id: String::from("user"),
      hashed_secret: parts.hashed_secret.clone(),
      expires: 0,
      cidr_whitelist: Vec::new(),
    };
    let verified = crate::middleware::verify_stored_api_key(
      Some(stored()),
      parts.secret.clone(),
    )
    .await
    .unwrap();
    assert_eq!(verified, stored());
    let other = generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    let err = crate::middleware::verify_stored_api_key(
      Some(stored()),
      other.secret,
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, reqwest::StatusCode::UNAUTHORIZED);
  }

  #[test]
  fn test_api_key_parts_debug_leaves_out_the_secret() {
    let parts = generate_api_key_parts(40, TEST_BCRYPT_COST).unwrap();
    let debug = format!("{parts:?}");
    assert!(debug.contains(&parts.key), "{debug}");
    assert!(!debug.contains(&parts.secret), "{debug}");
    assert!(!debug.contains(&parts.hashed_secret), "{debug}");
  }

  #[test]
  fn test_expired() {
    assert!(!expired(0, u64::MAX));
    assert!(!expired(1_001, 1_000));
    assert!(expired(1_000, 1_000));
    assert!(expired(1, 1_000));
  }

  #[test]
  fn test_stored_api_key_debug_leaves_out_the_hash() {
    let stored = StoredApiKey {
      user_id: String::from("user"),
      hashed_secret: String::from("$2b$04$hash"),
      expires: 0,
      cidr_whitelist: Vec::new(),
    };
    let debug = format!("{stored:?}");
    assert!(debug.contains("user"), "{debug}");
    assert!(!debug.contains("hash"), "{debug}");
  }
}
