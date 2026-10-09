use anyhow::{Context as _, anyhow};
use mogh_auth_client::api::manage::{
  CreateApiKey, CreateApiKeyResponse, CreateSigningKey,
  CreateSigningKeyResponse, DeleteApiKey, DeleteApiKeyResponse,
  DeleteSigningKey, DeleteSigningKeyResponse,
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_resolver::Resolve;
use reqwest::StatusCode;
use tracing::{info, instrument};

use crate::{
  AuthImpl,
  api::manage::ManageArgs,
  api_key::{ApiKeyParts, generate_api_key_parts},
  bcrypt_pool::spawn_api_key_bcrypt,
  validations::normalize_cidr_whitelist,
};

//

pub async fn create_api_key<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: String,
  mut body: CreateApiKey,
) -> mogh_error::Result<CreateApiKeyResponse> {
  auth.validate_api_key_name(&body.name)?;
  body.cidr_whitelist =
    normalize_cidr_whitelist(auth, body.cidr_whitelist)?;

  // bcrypt takes a while: off the async runtime, on the bounded
  // budget of api key secrets.
  let secret_length = auth.api_key_secret_length();
  let bcrypt_cost = auth.api_secret_bcrypt_cost();
  let ApiKeyParts {
    key,
    secret,
    hashed_secret,
  } = spawn_api_key_bcrypt(move || {
    generate_api_key_parts(secret_length, bcrypt_cost)
  })
  .await
  .context("Failed to generate api key")??;

  auth
    .create_api_key(user_id.clone(), body, key.clone(), hashed_secret)
    .await?;

  info!(user_id, key, "Api key created");

  Ok(CreateApiKeyResponse { key, secret })
}

impl Resolve<ManageArgs> for CreateApiKey {
  #[instrument(
  "CreateApiKey",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      name = &self.name,
      expires = &self.expires,
      cidr_whitelist = ?self.cidr_whitelist,
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    create_api_key(auth.as_ref(), user.id().to_string(), self).await
  }
}

//

pub async fn delete_api_key<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: &str,
  key: String,
) -> mogh_error::Result<()> {
  let expected_user_id =
    auth.get_api_key_owner_id(key.clone()).await?;

  if user_id != expected_user_id {
    return Err(
      anyhow!("Api key does not belong to user")
        .status_code(StatusCode::FORBIDDEN),
    );
  }

  auth.delete_api_key(key).await?;

  Ok(())
}

impl Resolve<ManageArgs> for DeleteApiKey {
  #[instrument(
    "DeleteApiKey",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      self.key
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    delete_api_key(auth.as_ref(), user.id(), self.key).await?;
    Ok(DeleteApiKeyResponse {})
  }
}

//

/// The public key as signed requests are matched with (base64 spki
/// der), so a key given in another encoding (pem) is stored in the
/// form the middleware returns. BAD_REQUEST if it isn't an Ed25519
/// public key: signatures only verify with one. An X25519 key (as
/// signing keys were before 7.0) is told so.
fn normalize_public_key(
  public_key: &str,
) -> mogh_error::Result<String> {
  mogh_pki::SpkiPublicKey::from_maybe_pem(
    mogh_pki::PkiKind::Signature,
    public_key.trim(),
  )
  .map(mogh_pki::SpkiPublicKey::into_inner)
  .map_err(|e| {
    if e.is::<mogh_pki::WrongKeyAlgorithm>() {
      e.context("Invalid public key: signing keys are Ed25519 keys")
    } else {
      e.context("Invalid public key")
    }
  })
  .status_code(StatusCode::BAD_REQUEST)
}

/// Public keys are not secret, and requests are recognized by the
/// public key alone: one which is stored already (for any user) must
/// not be stored again. Otherwise requests its owner signs could
/// authenticate as whoever stored it second, and whoever did could
/// delete it. CONFLICT, without saying whose it is.
///
/// Best effort, a concurrent create can race it, the storage has to
/// keep public keys unique ([AuthImpl::create_signing_key]).
///
/// Only a key which is not found (`404`) is unused: another failure of
/// the lookup (the storage down, a lookup which refuses some keys) says
/// nothing about whether it is stored, and fails the create.
async fn check_public_key_unused<I: AuthImpl + ?Sized>(
  auth: &I,
  public_key: &str,
) -> mogh_error::Result<()> {
  match auth.get_signing_key_owner_id(public_key.to_string()).await {
    Ok(_) => Err(
      anyhow!("This public key is already in use")
        .status_code(StatusCode::CONFLICT),
    ),
    Err(e) if e.status == StatusCode::NOT_FOUND => Ok(()),
    Err(e) => Err(e),
  }
}

/// Creates a signing key of the user, refused up front (BAD_REQUEST)
/// when the app doesn't take requests signed with one
/// ([AuthImpl::signing_keys_enabled]): the key could never be used,
/// and the storage hook of an app without them isn't implemented.
/// Deleting one ([delete_signing_key]) works either way, so keys
/// stored while they were enabled can be removed.
pub async fn create_signing_key<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: String,
  body: CreateSigningKey,
) -> mogh_error::Result<CreateSigningKeyResponse> {
  if !auth.signing_keys_enabled() {
    return Err(
      anyhow!("Signing keys are not enabled")
        .status_code(StatusCode::BAD_REQUEST),
    );
  }
  auth.validate_api_key_name(&body.name)?;
  let cidr_whitelist =
    normalize_cidr_whitelist(auth, body.cidr_whitelist)?;

  let public_key = body.public_key.trim();

  let (private_key, public_key) = if public_key.is_empty() {
    let key_pair = mogh_pki::EncodedKeyPair::generate(
      mogh_pki::PkiKind::Signature,
    )?;
    (
      Some(key_pair.private.into_inner()),
      key_pair.public.into_inner(),
    )
  } else {
    let public_key = normalize_public_key(public_key)?;
    check_public_key_unused(auth, &public_key).await?;
    (None, public_key)
  };

  auth
    .create_signing_key(
      user_id,
      CreateApiKey {
        name: body.name,
        expires: body.expires,
        cidr_whitelist,
      },
      public_key,
    )
    .await?;

  Ok(CreateSigningKeyResponse { private_key })
}

impl Resolve<ManageArgs> for CreateSigningKey {
  #[instrument(
    "CreateSigningKey",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      name = &self.name,
      expires = &self.expires,
      cidr_whitelist = ?self.cidr_whitelist,
    )
  )]
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    create_signing_key(auth.as_ref(), user.id().to_string(), self)
      .await
  }
}

//

#[instrument(
  "DeleteSigningKey",
  skip_all,
  fields(user_id, public_key)
)]
pub async fn delete_signing_key<I: AuthImpl + ?Sized>(
  auth: &I,
  user_id: &str,
  public_key: String,
) -> mogh_error::Result<()> {
  // Keys stored before public keys were normalized may be in
  // another encoding, and keys stored before 7.0 are X25519 keys
  // (which no request can be signed with anymore): fall back to the
  // key as given, so they can still be deleted.
  let public_key =
    normalize_public_key(&public_key).unwrap_or(public_key);

  let expected_user_id =
    auth.get_signing_key_owner_id(public_key.clone()).await?;

  if user_id != expected_user_id {
    return Err(
      anyhow!("Signing key does not belong to user")
        .status_code(StatusCode::FORBIDDEN),
    );
  }

  auth.delete_signing_key(public_key).await?;

  Ok(())
}

impl Resolve<ManageArgs> for DeleteSigningKey {
  async fn resolve(
    self,
    ManageArgs { auth, user, .. }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    delete_signing_key(auth.as_ref(), user.id(), self.public_key)
      .await?;
    Ok(DeleteSigningKeyResponse {})
  }
}

//

#[cfg(test)]
mod tests {
  use super::*;

  // Low cost to keep tests fast.
  const TEST_BCRYPT_COST: u32 = 4;

  #[test]
  fn test_normalize_public_key_encodings() {
    let keys = mogh_pki::EncodedKeyPair::generate(
      mogh_pki::PkiKind::Signature,
    )
    .unwrap();
    // The form the middleware returns for a signed request.
    let canonical = keys.public().to_string();
    assert_eq!(normalize_public_key(&canonical).unwrap(), canonical);
    assert_eq!(
      normalize_public_key(&format!("  {canonical}\n")).unwrap(),
      canonical
    );
    // Pem (eg. the public key file) matches the same key.
    assert_eq!(
      normalize_public_key(&keys.public.as_pem()).unwrap(),
      canonical
    );
  }

  #[test]
  fn test_normalize_public_key_rejects_invalid() {
    let private = mogh_pki::EncodedKeyPair::generate(
      mogh_pki::PkiKind::Signature,
    )
    .unwrap()
    .private()
    .to_string();
    for invalid in [
      "not a key",
      "AAAA",
      "-----BEGIN PUBLIC KEY-----",
      // A private key is not a public key.
      private.as_str(),
      // The identity: a key of low order, which signatures can be
      // made for without a private key.
      "MCowBQYDK2VwAyEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ] {
      let err = normalize_public_key(invalid).unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST, "{invalid:?}");
      assert_eq!(err.error.to_string(), "Invalid public key");
    }
  }

  /// A signing key from before 7.0 is an X25519 key, which no
  /// signature verifies with: refused, saying which key is needed.
  #[test]
  fn test_normalize_public_key_rejects_x25519() {
    let x25519 =
      mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::Mutual)
        .unwrap();
    for public_key in
      [x25519.public().to_string(), x25519.public.as_pem()]
    {
      let err = normalize_public_key(&public_key).unwrap_err();
      assert_eq!(err.status, StatusCode::BAD_REQUEST);
      assert_eq!(
        err.error.to_string(),
        "Invalid public key: signing keys are Ed25519 keys"
      );
    }
  }

  /// Knows one public key, owned by `owner`.
  struct KnownKeyAuth {
    known: String,
    signing_keys: bool,
    /// The owner lookup fails (the storage is down).
    lookup_fails: bool,
  }

  impl KnownKeyAuth {
    fn knowing(known: String) -> KnownKeyAuth {
      KnownKeyAuth {
        known,
        signing_keys: true,
        lookup_fails: false,
      }
    }
  }

  impl AuthImpl for KnownKeyAuth {
    fn new() -> Self {
      unimplemented!()
    }
    fn get_user(
      &self,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      unimplemented!()
    }
    fn handle_request_authentication(
      &self,
      _: crate::RequestAuthentication,
      _: std::net::IpAddr,
      _: bool,
      _: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      unimplemented!()
    }
    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      unimplemented!()
    }
    fn api_secret_bcrypt_cost(&self) -> u32 {
      TEST_BCRYPT_COST
    }
    fn signing_keys_enabled(&self) -> bool {
      self.signing_keys
    }
    fn create_api_key(
      &self,
      _: String,
      _: CreateApiKey,
      _: String,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
    fn create_signing_key(
      &self,
      _: String,
      _: CreateApiKey,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
    fn get_signing_key_owner_id(
      &self,
      public_key: String,
    ) -> crate::DynFuture<mogh_error::Result<String>> {
      let known = public_key == self.known;
      let fails = self.lookup_fails;
      Box::pin(async move {
        if fails {
          Err(anyhow!("database is down").into())
        } else if known {
          Ok(String::from("owner"))
        } else {
          Err(
            anyhow!("No signing key found")
              .status_code(StatusCode::NOT_FOUND),
          )
        }
      })
    }
    fn delete_signing_key(
      &self,
      public_key: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      let known = public_key == self.known;
      Box::pin(async move {
        if known {
          Ok(())
        } else {
          Err(
            anyhow!("Deleted another key than the known one").into(),
          )
        }
      })
    }
  }

  #[tokio::test]
  async fn test_create_signing_key_refuses_known_public_key() {
    let known = mogh_pki::EncodedKeyPair::generate(
      mogh_pki::PkiKind::Signature,
    )
    .unwrap();
    let auth = KnownKeyAuth::knowing(known.public().to_string());
    let create = |public_key: String| CreateSigningKey {
      name: "key".into(),
      expires: 0,
      cidr_whitelist: Vec::new(),
      public_key,
    };
    // Also in another encoding.
    for public_key in
      [known.public().to_string(), known.public.as_pem()]
    {
      let err = create_signing_key(
        &auth,
        "someone-else".into(),
        create(public_key),
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::CONFLICT);
      // Doesn't say whose it is.
      assert!(!format!("{:#}", err.error).contains("owner"));
    }
    // Other keys are created.
    let other = mogh_pki::EncodedKeyPair::generate(
      mogh_pki::PkiKind::Signature,
    )
    .unwrap();
    create_signing_key(
      &auth,
      "user".into(),
      create(other.public().to_string()),
    )
    .await
    .unwrap();
    // Generated key pairs aren't looked up.
    let res =
      create_signing_key(&auth, "user".into(), create(String::new()))
        .await
        .unwrap();
    // The private key of an Ed25519 pair, which requests are signed
    // with.
    let private_key = res.private_key.unwrap();
    let generated = mogh_pki::EncodedKeyPair::from_private_key(
      mogh_pki::PkiKind::Signature,
      &private_key,
    )
    .unwrap();
    let signature =
      mogh_pki::signature::sign(&generated.private, b"request")
        .unwrap();
    mogh_pki::signature::verify(
      &generated.public,
      b"request",
      &signature,
    )
    .unwrap();

    // An X25519 key (as signing keys were before 7.0) isn't stored.
    let x25519 =
      mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::Mutual)
        .unwrap();
    let err = create_signing_key(
      &auth,
      "user".into(),
      create(x25519.public().to_string()),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
  }

  /// An app built on the defaults: signing keys are off.
  struct DefaultsAuth;

  impl AuthImpl for DefaultsAuth {
    fn new() -> Self {
      DefaultsAuth
    }
    fn get_user(
      &self,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      unimplemented!()
    }
    fn handle_request_authentication(
      &self,
      _: crate::RequestAuthentication,
      _: std::net::IpAddr,
      _: bool,
      _: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      unimplemented!()
    }
    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      unimplemented!()
    }
  }

  /// With signing keys off (the default), creating one is refused as
  /// the client's mistake, up front, and with a key pair to generate
  /// too: no "Must implement" server error, no key stored. Keys stored
  /// while they were on can still be deleted.
  #[tokio::test]
  async fn test_signing_keys_off_refuses_creating_them() {
    let public_key = mogh_pki::EncodedKeyPair::generate(
      mogh_pki::PkiKind::Signature,
    )
    .unwrap()
    .public()
    .to_string();
    for public_key in [public_key.clone(), String::new()] {
      let err = create_signing_key(
        &DefaultsAuth,
        "user".into(),
        CreateSigningKey {
          name: "key".into(),
          expires: 0,
          cidr_whitelist: Vec::new(),
          public_key,
        },
      )
      .await
      .err()
      .unwrap();
      assert_eq!(err.status, StatusCode::BAD_REQUEST);
      assert_eq!(
        format!("{:#}", err.error),
        "Signing keys are not enabled"
      );
    }
    let auth = KnownKeyAuth {
      known: public_key.clone(),
      signing_keys: false,
      lookup_fails: false,
    };
    delete_signing_key(&auth, "owner", public_key)
      .await
      .unwrap();
  }

  /// Only a public key which isn't found (404) is unused: a lookup
  /// which fails says nothing about it, and fails the create rather
  /// than store the key a second time.
  #[tokio::test]
  async fn test_failed_owner_lookup_fails_the_create() {
    let auth = KnownKeyAuth {
      lookup_fails: true,
      ..KnownKeyAuth::knowing(String::new())
    };
    let public_key = mogh_pki::EncodedKeyPair::generate(
      mogh_pki::PkiKind::Signature,
    )
    .unwrap()
    .public()
    .to_string();
    let err = create_signing_key(
      &auth,
      "user".into(),
      CreateSigningKey {
        name: "key".into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
        public_key,
      },
    )
    .await
    .err()
    .unwrap();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
  }

  /// A key stored before 7.0 is an X25519 key: nothing can be signed
  /// with it anymore, but its owner can still delete it.
  #[tokio::test]
  async fn test_delete_signing_key_of_another_algorithm() {
    let x25519 =
      mogh_pki::EncodedKeyPair::generate(mogh_pki::PkiKind::Mutual)
        .unwrap();
    let auth = KnownKeyAuth::knowing(x25519.public().to_string());
    let err = delete_signing_key(
      &auth,
      "someone-else",
      x25519.public().to_string(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
    delete_signing_key(&auth, "owner", x25519.public().to_string())
      .await
      .unwrap();

    // An Ed25519 key is found in any encoding.
    let ed25519 = mogh_pki::EncodedKeyPair::generate(
      mogh_pki::PkiKind::Signature,
    )
    .unwrap();
    let auth = KnownKeyAuth::knowing(ed25519.public().to_string());
    delete_signing_key(&auth, "owner", ed25519.public.as_pem())
      .await
      .unwrap();
  }

  /// The secret of a new api key is hashed on the bounded budget
  /// of api keys: with every permit taken, it waits.
  #[tokio::test]
  async fn test_create_api_key_is_bounded() {
    let held = crate::bcrypt_pool::hold_api_key_permits().await;
    let create = tokio::spawn(async {
      let auth = KnownKeyAuth::knowing(String::new());
      let body = CreateApiKey {
        name: "key".into(),
        expires: 0,
        cidr_whitelist: Vec::new(),
      };
      create_api_key(&auth, "user".into(), body).await
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!create.is_finished(), "hashed without a permit");
    drop(held);
    let res = create.await.unwrap().unwrap();
    assert!(
      res.key.starts_with("K_") && res.secret.starts_with("S_")
    );
  }
}
