//! Verification of tokens presented for RFC 8693 token exchange.
//!
//! Only tokens signed by the provider (ID tokens / JWTs) are accepted.
//! They are verified against the keys the provider publishes,
//! so tokens signed with a shared secret (`HS256`) never verify here.

use std::str::FromStr as _;

use anyhow::{Context as _, anyhow};
use data_encoding::BASE64URL_NOPAD;
use openidconnect::{
  AdditionalClaims, ClientId, IdToken, IdTokenClaims,
  IdTokenVerifier, IssuerUrl, Nonce,
  core::{
    CoreGenderClaim, CoreJsonWebKey, CoreJsonWebKeySet,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata,
  },
};

/// Far larger than any real token, bounds the work done on untrusted input.
pub const MAX_SUBJECT_TOKEN_LENGTH: usize = 16 * 1024;

/// How far the clock of the provider may be ahead when
/// enforcing the maximum token age.
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 60;

/// The only algorithms tokens are verified with: signatures by a
/// key the provider publishes. Shared secrets (`HS256`), no
/// signature (`none`), and anything added in the future never are.
const ASYMMETRIC_ALGS: [CoreJwsSigningAlgorithm; 10] = {
  use CoreJwsSigningAlgorithm::*;
  [
    RsaSsaPkcs1V15Sha256,
    RsaSsaPkcs1V15Sha384,
    RsaSsaPkcs1V15Sha512,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    EcdsaP521Sha512,
    RsaSsaPssSha256,
    RsaSsaPssSha384,
    RsaSsaPssSha512,
    EdDsa,
  ]
};

/// What is needed to verify tokens signed by a provider.
pub struct TokenVerificationKeys {
  issuer: IssuerUrl,
  jwks: CoreJsonWebKeySet,
  signing_algs: Vec<CoreJwsSigningAlgorithm>,
}

impl TokenVerificationKeys {
  /// For issuers without provider metadata (workload identity).
  /// Any asymmetric algorithm the keys support is accepted.
  pub fn new(issuer: IssuerUrl, jwks: CoreJsonWebKeySet) -> Self {
    Self {
      issuer,
      jwks,
      signing_algs: ASYMMETRIC_ALGS.to_vec(),
    }
  }

  /// [Self::verify], returning all the claims of the token.
  pub fn verify_payload(
    &self,
    token: &str,
    audiences: &[String],
    max_age_secs: u64,
  ) -> anyhow::Result<serde_json::Map<String, serde_json::Value>> {
    self.verify::<openidconnect::EmptyAdditionalClaims>(
      token,
      audiences,
      &[],
      max_age_secs,
    )?;
    // Authentic, as the token is verified.
    unverified_payload(token)
      .context("Token payload is not an object")
  }

  pub fn from_metadata(metadata: &CoreProviderMetadata) -> Self {
    Self {
      issuer: metadata.issuer().clone(),
      jwks: metadata.jwks().clone(),
      // Providers may advertise `none` or `HS256`, which must never
      // verify here, whatever the jwt library does with them.
      signing_algs: metadata
        .id_token_signing_alg_values_supported()
        .iter()
        .filter(|alg| is_asymmetric(alg))
        .cloned()
        .collect(),
    }
  }

  /// Verifies the signature, issuer, expiry and audience of the
  /// token, returning its claims.
  ///
  /// The token must be issued to one of `audiences`. This is what
  /// stops a token the same provider issued to another app from
  /// being accepted. Any further audiences on the token must be in
  /// `audiences` or `trusted_other_audiences`.
  ///
  /// There is no nonce to check, as the token wasn't requested by this
  /// app. A captured token can be replayed until it expires, like
  /// any bearer token. `max_age_secs` shortens that to the time
  /// since the token was issued (`0` for no limit).
  pub fn verify<AC: AdditionalClaims + Clone>(
    &self,
    token: &str,
    audiences: &[String],
    trusted_other_audiences: &[String],
    max_age_secs: u64,
  ) -> anyhow::Result<IdTokenClaims<AC, CoreGenderClaim>> {
    if token.len() > MAX_SUBJECT_TOKEN_LENGTH {
      return Err(anyhow!("Token is too large"));
    }

    let raw_token = token;
    let token = IdToken::<
      AC,
      CoreGenderClaim,
      CoreJweContentEncryptionAlgorithm,
      CoreJwsSigningAlgorithm,
    >::from_str(token)
    .context("Token is not a valid JWT")?;

    let mut rejection = None;

    for audience in audiences.iter().filter(|aud| !aud.is_empty()) {
      // Without a client secret, so only asymmetric signatures verify.
      let verifier =
        IdTokenVerifier::<CoreJsonWebKey>::new_public_client(
          ClientId::new(audience.clone()),
          self.issuer.clone(),
          self.jwks.clone(),
        )
        .set_allowed_algs(self.signing_algs.clone())
        .set_other_audience_verifier_fn(|other| {
          audiences.contains(other)
            || trusted_other_audiences.contains(other)
        });

      match token.claims(&verifier, |_: Option<&Nonce>| Ok(())) {
        Ok(claims) => {
          // The payload is authentic at this point.
          if is_security_event_token(raw_token) {
            return Err(anyhow!(
              "Security event tokens (eg. logout tokens) can't be exchanged"
            ));
          }
          check_not_before(raw_token, unix_timestamp_secs())?;
          check_token_age(
            claims.issue_time().timestamp(),
            unix_timestamp_secs(),
            max_age_secs,
          )?;
          return Ok(claims.clone());
        }
        Err(e) => rejection = Some(e),
      }
    }

    match rejection {
      Some(e) => Err(anyhow!("{e}").context("Token was rejected")),
      None => Err(anyhow!("No audience is accepted for tokens")),
    }
  }
}

fn unix_timestamp_secs() -> i64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|duration| duration.as_secs() as i64)
    .unwrap_or_default()
}

/// `nbf` is not part of ID tokens, so the jwt library doesn't
/// check it, but platforms issuing workload tokens set it.
fn check_not_before(token: &str, now: i64) -> anyhow::Result<()> {
  // Some issuers write timestamps as floats
  let not_before = unverified_payload(token).and_then(|payload| {
    let nbf = payload.get("nbf")?;
    nbf.as_i64().or_else(|| nbf.as_f64().map(|nbf| nbf as i64))
  });
  match not_before {
    Some(not_before)
      if not_before
        > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) =>
    {
      Err(anyhow!("Token is not valid yet (nbf)"))
    }
    _ => Ok(()),
  }
}

/// `max_age_secs` of 0 is no limit.
fn check_token_age(
  issued_at: i64,
  now: i64,
  max_age_secs: u64,
) -> anyhow::Result<()> {
  if max_age_secs == 0 {
    return Ok(());
  }
  let age = now.saturating_sub(issued_at);
  // A token from the future would otherwise never get old.
  if age < -CLOCK_SKEW_TOLERANCE_SECS {
    return Err(anyhow!("Token was issued in the future"));
  }
  if age > i64::try_from(max_age_secs).unwrap_or(i64::MAX) {
    return Err(anyhow!(
      "Token was issued {age} seconds ago, only tokens issued in the last {max_age_secs} seconds are accepted. Request a new token and exchange it right away."
    ));
  }
  Ok(())
}

fn is_asymmetric(alg: &CoreJwsSigningAlgorithm) -> bool {
  ASYMMETRIC_ALGS.contains(alg)
}

/// When the provider authenticated the user a token is for: its
/// `auth_time` claim (OIDC), else when it was issued (`iat`). Unix
/// seconds, at most now: a provider clock running ahead doesn't make
/// the login any more recent. `None` without either claim.
///
/// Reads the payload **without verifying anything**, only use it on
/// a token which was verified. Crate private for that reason.
pub(crate) fn authenticated_at(token: &str) -> Option<u64> {
  let now = u64::try_from(unix_timestamp_secs()).unwrap_or_default();
  authenticated_at_from(&unverified_payload(token)?, now)
}

fn authenticated_at_from(
  payload: &serde_json::Map<String, serde_json::Value>,
  now: u64,
) -> Option<u64> {
  // Some issuers write timestamps as floats. One before 1970 is
  // as good as a long time ago.
  let timestamp = |claim: &str| {
    let value = payload.get(claim)?;
    value
      .as_u64()
      .or_else(|| value.as_i64().map(|_| 0))
      .or_else(|| value.as_f64().map(|value| value.max(0.0) as u64))
  };
  timestamp("auth_time")
    .or_else(|| timestamp("iat"))
    .map(|at| at.min(now))
}

/// The payload of a JWT, **without verifying anything**.
fn unverified_payload(
  token: &str,
) -> Option<serde_json::Map<String, serde_json::Value>> {
  if token.len() > MAX_SUBJECT_TOKEN_LENGTH {
    return None;
  }
  let mut parts = token.split('.');
  let (_header, payload, _signature) =
    (parts.next()?, parts.next()?, parts.next()?);
  if parts.next().is_some() {
    return None;
  }
  let payload = BASE64URL_NOPAD
    .decode(payload.trim_end_matches('=').as_bytes())
    .ok()?;
  serde_json::from_slice(&payload).ok()
}

/// The `iss` claim of a JWT, **without verifying anything**.
/// Only used to select the provider which then verifies the token.
pub fn unverified_issuer(token: &str) -> Option<String> {
  unverified_payload(token)?
    .get("iss")?
    .as_str()
    .map(str::to_string)
}

/// Security event tokens (RFC 8417), like OIDC back-channel logout
/// tokens, are signed by the provider for the same audience as ID
/// tokens. They carry an `events` claim, and no nonce precisely so they
/// can't pass as ID tokens, which doesn't help where no nonce is checked.
fn is_security_event_token(token: &str) -> bool {
  unverified_payload(token)
    .is_some_and(|payload| payload.contains_key("events"))
}

/// Issuers match for the purpose of selecting a provider
/// regardless of a trailing slash. The exact issuer is
/// still enforced when the token is verified.
pub fn issuers_match(a: &str, b: &str) -> bool {
  let (a, b) = (a.trim_end_matches('/'), b.trim_end_matches('/'));
  !a.is_empty() && a == b
}

#[cfg(test)]
pub(crate) mod test_tokens {
  //! Mint real signed tokens for tests.

  use chrono::{Duration, Utc};
  use openidconnect::{
    Audience, AuthUrl, EmptyAdditionalProviderMetadata, EndUserEmail,
    JsonWebKeyId, JsonWebKeySetUrl, PrivateSigningKey as _,
    ResponseTypes, StandardClaims, SubjectIdentifier,
    core::{
      CoreHmacKey, CoreResponseType, CoreRsaPrivateSigningKey,
      CoreSubjectIdentifierType,
    },
  };

  use super::*;

  pub const ISSUER: &str = "https://idp.example.com";
  pub const CLIENT_ID: &str = "app-client-id";

  /// Test only keys, generated for this repository. Kept outside the
  /// published crate, see `auth/test_keys/README.md`.
  const KEY_A: &str = include_str!("../../../test_keys/rsa_a.pem");
  const KEY_B: &str = include_str!("../../../test_keys/rsa_b.pem");

  pub enum Signer {
    /// The key the provider publishes
    Provider,
    /// A key the provider doesn't publish
    Other,
    /// HS256 using the given shared secret
    Hmac(&'static str),
  }

  fn rsa_key(pem: &str) -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(
      pem,
      Some(JsonWebKeyId::new("test-key".to_string())),
    )
    .unwrap()
  }

  /// The key set publishing the key of [Signer::Provider], as json.
  pub fn jwks_json() -> String {
    serde_json::to_string(&CoreJsonWebKeySet::new(vec![
      rsa_key(KEY_A).as_verification_key(),
    ]))
    .unwrap()
  }

  /// A key set publishing the key of [Signer::Other] instead.
  pub fn other_jwks_json() -> String {
    serde_json::to_string(&CoreJsonWebKeySet::new(vec![
      rsa_key(KEY_B).as_verification_key(),
    ]))
    .unwrap()
  }

  /// Provider metadata publishing the key of [Signer::Provider].
  pub fn metadata() -> CoreProviderMetadata {
    metadata_with_algs(vec![
      CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
    ])
  }

  pub fn metadata_with_algs(
    algs: Vec<CoreJwsSigningAlgorithm>,
  ) -> CoreProviderMetadata {
    CoreProviderMetadata::new(
      IssuerUrl::new(ISSUER.to_string()).unwrap(),
      AuthUrl::new(format!("{ISSUER}/authorize")).unwrap(),
      JsonWebKeySetUrl::new(format!("{ISSUER}/jwks")).unwrap(),
      vec![ResponseTypes::new(vec![CoreResponseType::Code])],
      vec![CoreSubjectIdentifierType::Public],
      algs,
      EmptyAdditionalProviderMetadata {},
    )
    .set_jwks(CoreJsonWebKeySet::new(vec![
      rsa_key(KEY_A).as_verification_key(),
    ]))
  }

  pub struct TestToken<AC> {
    pub issuer: String,
    pub subject: String,
    pub audiences: Vec<String>,
    pub expires_in: Duration,
    pub issued_ago: Duration,
    /// How long ago the provider authenticated the user
    /// (`auth_time`), not set by default.
    pub auth_time_ago: Option<Duration>,
    /// The `nonce` of a login's ID token, not set by default.
    pub nonce: Option<String>,
    /// The access token issued with a login's ID token, which then
    /// carries its hash (`at_hash`). Not set by default.
    pub access_token: Option<String>,
    pub signer: Signer,
    pub additional_claims: AC,
  }

  impl<AC: AdditionalClaims + Clone> TestToken<AC> {
    pub fn new(additional_claims: AC) -> Self {
      Self {
        issuer: ISSUER.to_string(),
        subject: "subject-123".to_string(),
        audiences: vec![CLIENT_ID.to_string()],
        expires_in: Duration::minutes(5),
        issued_ago: Duration::minutes(1),
        auth_time_ago: None,
        nonce: None,
        access_token: None,
        signer: Signer::Provider,
        additional_claims,
      }
    }

    pub fn mint(self) -> String {
      let claims = IdTokenClaims::<AC, CoreGenderClaim>::new(
        IssuerUrl::new(self.issuer).unwrap(),
        self.audiences.into_iter().map(Audience::new).collect(),
        Utc::now() + self.expires_in,
        Utc::now() - self.issued_ago,
        StandardClaims::new(SubjectIdentifier::new(self.subject))
          .set_email(Some(EndUserEmail::new(
            "user@example.com".to_string(),
          ))),
        self.additional_claims,
      )
      .set_auth_time(self.auth_time_ago.map(|ago| Utc::now() - ago))
      .set_nonce(self.nonce.map(openidconnect::Nonce::new));
      type Token<AC> = IdToken<
        AC,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
      >;
      let access_token =
        self.access_token.map(openidconnect::AccessToken::new);
      let access_token = access_token.as_ref();
      let token = match self.signer {
        Signer::Provider => Token::new(
          claims,
          &rsa_key(KEY_A),
          CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
          access_token,
          None,
        ),
        Signer::Other => Token::new(
          claims,
          &rsa_key(KEY_B),
          CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
          access_token,
          None,
        ),
        Signer::Hmac(secret) => Token::new(
          claims,
          &CoreHmacKey::new(secret.as_bytes()),
          CoreJwsSigningAlgorithm::HmacSha256,
          access_token,
          None,
        ),
      }
      .unwrap();
      token.to_string()
    }
  }
}

#[cfg(test)]
mod tests {
  use chrono::Duration;
  use openidconnect::EmptyAdditionalClaims;

  use super::{test_tokens::*, *};

  fn keys() -> TokenVerificationKeys {
    TokenVerificationKeys::from_metadata(&metadata())
  }

  fn token() -> TestToken<EmptyAdditionalClaims> {
    TestToken::new(EmptyAdditionalClaims {})
  }

  fn verify(
    token: &str,
    audiences: &[&str],
  ) -> anyhow::Result<
    IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>,
  > {
    let audiences =
      audiences.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    keys().verify(token, &audiences, &[], 0)
  }

  #[test]
  fn test_valid_token_is_accepted() {
    let claims = verify(&token().mint(), &[CLIENT_ID]).unwrap();
    assert_eq!(claims.subject().as_str(), "subject-123");
  }

  /// The confused deputy: a token the provider
  /// issued to another app must not be accepted.
  #[test]
  fn test_token_for_another_app_is_rejected() {
    let other_app = TestToken {
      audiences: vec!["another-app".to_string()],
      ..token()
    }
    .mint();
    assert!(verify(&other_app, &[CLIENT_ID]).is_err());
    // Unless that app is explicitly accepted
    assert!(verify(&other_app, &[CLIENT_ID, "another-app"]).is_ok());
  }

  #[test]
  fn test_untrusted_additional_audience_is_rejected() {
    let token = TestToken {
      audiences: vec![
        CLIENT_ID.to_string(),
        "unknown-app".to_string(),
      ],
      ..token()
    }
    .mint();
    assert!(verify(&token, &[CLIENT_ID]).is_err());
    let audiences = [CLIENT_ID.to_string()];
    assert!(
      keys()
        .verify::<EmptyAdditionalClaims>(
          &token,
          &audiences,
          &["unknown-app".to_string()],
          0,
        )
        .is_ok()
    );
  }

  #[test]
  fn test_expired_token_is_rejected() {
    let token = TestToken {
      expires_in: Duration::minutes(-5),
      ..token()
    }
    .mint();
    assert!(verify(&token, &[CLIENT_ID]).is_err());
  }

  #[test]
  fn test_other_issuer_is_rejected() {
    let token = TestToken {
      issuer: "https://evil.example.com".to_string(),
      ..token()
    }
    .mint();
    assert!(verify(&token, &[CLIENT_ID]).is_err());
  }

  #[test]
  fn test_token_signed_by_unknown_key_is_rejected() {
    let token = TestToken {
      signer: Signer::Other,
      ..token()
    }
    .mint();
    assert!(verify(&token, &[CLIENT_ID]).is_err());
  }

  /// Even signed with the client secret or the published
  /// public key as the shared secret, HS256 never verifies.
  #[test]
  fn test_shared_secret_signature_is_rejected() {
    let token = TestToken {
      signer: Signer::Hmac("client-secret"),
      ..token()
    }
    .mint();
    assert!(verify(&token, &[CLIENT_ID]).is_err());
  }

  #[test]
  fn test_tampered_and_unsigned_tokens_are_rejected() {
    let token = token().mint();
    let (header, rest) = token.split_once('.').unwrap();
    let (_, signature) = rest.split_once('.').unwrap();

    // Payload swapped for another subject, original signature
    let forged_payload = BASE64URL_NOPAD.encode(
      format!(
        r#"{{"iss":"{ISSUER}","sub":"admin","aud":["{CLIENT_ID}"],"exp":4102444800,"iat":1}}"#
      )
      .as_bytes(),
    );
    let tampered = format!("{header}.{forged_payload}.{signature}");
    assert!(verify(&tampered, &[CLIENT_ID]).is_err());

    // alg none, no signature
    let none_header =
      BASE64URL_NOPAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let unsigned = format!("{none_header}.{forged_payload}.");
    assert!(verify(&unsigned, &[CLIENT_ID]).is_err());
  }

  /// Providers may advertise `none` and shared secret algorithms.
  #[test]
  fn test_only_asymmetric_algorithms_even_if_advertised() {
    let keys = TokenVerificationKeys::from_metadata(
      &metadata_with_algs(vec![
        CoreJwsSigningAlgorithm::None,
        CoreJwsSigningAlgorithm::HmacSha256,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
      ]),
    );
    assert_eq!(
      keys.signing_algs,
      [CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]
    );
    let audiences = [CLIENT_ID.to_string()];
    let verify = |token: &str| {
      keys.verify::<EmptyAdditionalClaims>(token, &audiences, &[], 0)
    };
    assert!(verify(&token().mint()).is_ok());

    let hmac = TestToken {
      signer: Signer::Hmac("client-secret"),
      ..token()
    }
    .mint();
    assert!(verify(&hmac).is_err());

    let payload = BASE64URL_NOPAD.encode(
      format!(
        r#"{{"iss":"{ISSUER}","sub":"admin","aud":["{CLIENT_ID}"],"exp":4102444800,"iat":1}}"#
      )
      .as_bytes(),
    );
    let header = BASE64URL_NOPAD.encode(br#"{"alg":"none"}"#);
    assert!(verify(&format!("{header}.{payload}.")).is_err());
  }

  /// A logout token is signed by the provider for the same audience.
  #[test]
  fn test_security_event_tokens_are_rejected() {
    use crate::provider::oidc::UsernameAdditionalClaims;
    let logout_token = TestToken::new(UsernameAdditionalClaims {
      username: None,
      extra: [(
        "events".to_string(),
        serde_json::json!({
          "http://schemas.openid.net/event/backchannel-logout": {}
        }),
      )]
      .into(),
    })
    .mint();
    let audiences = [CLIENT_ID.to_string()];
    let err = keys()
      .verify::<EmptyAdditionalClaims>(
        &logout_token,
        &audiences,
        &[],
        0,
      )
      .unwrap_err();
    assert!(format!("{err:#}").contains("Security event"));
  }

  #[test]
  fn test_max_token_age() {
    let audiences = [CLIENT_ID.to_string()];
    let verify = |issued_ago: Duration, max_age_secs: u64| {
      let token = TestToken {
        issued_ago,
        // Still valid for a long time
        expires_in: Duration::hours(10),
        ..token()
      }
      .mint();
      keys().verify::<EmptyAdditionalClaims>(
        &token,
        &audiences,
        &[],
        max_age_secs,
      )
    };
    // No limit by default, the token is good until it expires
    assert!(verify(Duration::hours(5), 0).is_ok());
    assert!(verify(Duration::minutes(2), 300).is_ok());
    let err = verify(Duration::minutes(10), 300).unwrap_err();
    assert!(format!("{err:#}").contains("seconds ago"), "{err:#}");
    // Provider clock slightly ahead is tolerated, far ahead is not
    assert!(verify(Duration::seconds(-30), 300).is_ok());
    assert!(verify(Duration::hours(-1), 300).is_err());
    // Without a limit the issue time is not judged at all
    assert!(verify(Duration::hours(-1), 0).is_ok());
  }

  #[test]
  fn test_not_before() {
    let token = |nbf: i64| {
      let payload = BASE64URL_NOPAD
        .encode(format!(r#"{{"nbf":{nbf}}}"#).as_bytes());
      format!("header.{payload}.signature")
    };
    let now = 1_800_000_000;
    assert!(check_not_before(&token(now - 10), now).is_ok());
    assert!(check_not_before(&token(now + 30), now).is_ok());
    assert!(check_not_before(&token(now + 3600), now).is_err());
    assert!(check_not_before(&token(i64::MAX), now).is_err());
    let float = format!(
      "header.{}.signature",
      BASE64URL_NOPAD.encode(br#"{"nbf":9999999999.5}"#)
    );
    assert!(check_not_before(&float, now).is_err());
    // Tokens without nbf
    assert!(check_not_before("header.e30.signature", now).is_ok());
  }

  #[test]
  fn test_check_token_age_bounds() {
    let now = 1_800_000_000;
    assert!(check_token_age(now - 300, now, 300).is_ok());
    assert!(check_token_age(now - 301, now, 300).is_err());
    assert!(check_token_age(now + 60, now, 300).is_ok());
    assert!(check_token_age(now + 61, now, 300).is_err());
    // Extreme values don't overflow
    assert!(check_token_age(i64::MIN, i64::MAX, u64::MAX).is_ok());
    assert!(check_token_age(i64::MAX, i64::MIN, 1).is_err());
    assert!(check_token_age(i64::MIN, i64::MAX, 0).is_ok());
  }

  /// The keys of trusted issuers (workload identity) are not built
  /// from provider metadata, their algorithms are a list of their own.
  /// This path can issue admin tokens, so the algorithm confusion
  /// tests of [test_tampered_and_unsigned_tokens_are_rejected] and
  /// [test_shared_secret_signature_is_rejected] are repeated for it.
  #[test]
  fn test_workload_keys_only_verify_asymmetric_signatures() {
    let keys = TokenVerificationKeys::new(
      IssuerUrl::new(ISSUER.to_string()).unwrap(),
      serde_json::from_str(&jwks_json()).unwrap(),
    );
    assert!(keys.signing_algs.iter().all(is_asymmetric));
    assert!(
      !keys.signing_algs.contains(&CoreJwsSigningAlgorithm::None)
    );
    assert!(
      !keys
        .signing_algs
        .contains(&CoreJwsSigningAlgorithm::HmacSha256)
    );
    let audiences = [CLIENT_ID.to_string()];
    let verify =
      |token: &str| keys.verify_payload(token, &audiences, 0);

    let valid = token().mint();
    assert_eq!(verify(&valid).unwrap()["sub"], "subject-123");

    // HS256, keyed with a secret or with the published public key
    let jwks = jwks_json();
    let public_key: &'static str = Box::leak(jwks.into_boxed_str());
    for secret in ["client-secret", public_key] {
      let hmac = TestToken {
        signer: Signer::Hmac(secret),
        ..token()
      }
      .mint();
      assert!(verify(&hmac).is_err());
    }

    let (header, rest) = valid.split_once('.').unwrap();
    let (_, signature) = rest.split_once('.').unwrap();
    let forged_payload = BASE64URL_NOPAD.encode(
      format!(
        r#"{{"iss":"{ISSUER}","sub":"admin-workload","aud":["{CLIENT_ID}"],"exp":4102444800,"iat":1}}"#
      )
      .as_bytes(),
    );
    // Another payload under the original signature
    let tampered = format!("{header}.{forged_payload}.{signature}");
    assert!(verify(&tampered).is_err());
    // alg none, no signature
    for none_header in [
      r#"{"alg":"none","typ":"JWT"}"#,
      r#"{"alg":"none"}"#,
      r#"{"alg":"None"}"#,
    ] {
      let none_header =
        BASE64URL_NOPAD.encode(none_header.as_bytes());
      let unsigned = format!("{none_header}.{forged_payload}.");
      assert!(verify(&unsigned).is_err(), "{unsigned}");
      let unsigned =
        format!("{none_header}.{forged_payload}.{signature}");
      assert!(verify(&unsigned).is_err(), "{unsigned}");
    }
  }

  /// Even with a shared secret algorithm allowed, the verifier has no
  /// client secret to check it with: a second guard, independent of
  /// the list of algorithms.
  #[test]
  fn test_no_client_secret_to_verify_shared_secret_signatures() {
    let mut keys = keys();
    keys.signing_algs.push(CoreJwsSigningAlgorithm::HmacSha256);
    let hmac = TestToken {
      signer: Signer::Hmac("client-secret"),
      ..token()
    }
    .mint();
    let audiences = [CLIENT_ID.to_string()];
    assert!(keys.verify_payload(&hmac, &audiences, 0).is_err());
  }

  #[test]
  fn test_authenticated_at() {
    let now = 1_800_000_000;
    let at = |payload: serde_json::Value| {
      authenticated_at_from(payload.as_object().unwrap(), now)
    };
    // When the provider authenticated the user, not when it
    // issued this token (eg. refreshed without a login).
    assert_eq!(
      at(
        serde_json::json!({ "auth_time": now - 3600, "iat": now - 60 })
      ),
      Some(now - 3600)
    );
    assert_eq!(
      at(serde_json::json!({ "iat": now - 60 })),
      Some(now - 60)
    );
    assert_eq!(
      at(serde_json::json!({ "auth_time": 1.5e9, "iat": now })),
      Some(1_500_000_000)
    );
    // Not in the future, and nothing before 1970
    assert_eq!(
      at(serde_json::json!({ "auth_time": now + 600 })),
      Some(now)
    );
    assert_eq!(at(serde_json::json!({ "auth_time": -5 })), Some(0));
    assert_eq!(at(serde_json::json!({ "auth_time": -5.5 })), Some(0));
    // Not a timestamp
    assert_eq!(
      at(serde_json::json!({ "auth_time": "yesterday", "iat": now })),
      Some(now)
    );
    assert_eq!(at(serde_json::json!({})), None);

    // Of a minted token
    let issued = TestToken {
      issued_ago: Duration::minutes(30),
      ..token()
    }
    .mint();
    let at = authenticated_at(&issued).unwrap();
    let expected =
      (chrono::Utc::now() - Duration::minutes(30)).timestamp() as u64;
    assert!(at.abs_diff(expected) <= 5, "{at} / {expected}");
    let refreshed = TestToken {
      auth_time_ago: Some(Duration::hours(3)),
      ..token()
    }
    .mint();
    let at = authenticated_at(&refreshed).unwrap();
    let expected =
      (chrono::Utc::now() - Duration::hours(3)).timestamp() as u64;
    assert!(at.abs_diff(expected) <= 5, "{at} / {expected}");
    assert_eq!(authenticated_at("not-a-jwt"), None);
  }

  #[test]
  fn test_garbage_and_oversized_tokens_are_rejected() {
    for garbage in ["", "not-a-jwt", "a.b", "a.b.c", "....."] {
      assert!(verify(garbage, &[CLIENT_ID]).is_err(), "{garbage}");
    }
    let oversized = "a".repeat(MAX_SUBJECT_TOKEN_LENGTH + 1);
    assert!(verify(&oversized, &[CLIENT_ID]).is_err());
    assert_eq!(unverified_issuer(&oversized), None);
  }

  #[test]
  fn test_no_accepted_audience_rejects_everything() {
    assert!(verify(&token().mint(), &[]).is_err());
    assert!(verify(&token().mint(), &[""]).is_err());
  }

  #[test]
  fn test_unverified_issuer() {
    assert_eq!(
      unverified_issuer(&token().mint()).as_deref(),
      Some(ISSUER)
    );
    for garbage in ["", "a.b.c", "a.b", "a.b.c.d"] {
      assert_eq!(unverified_issuer(garbage), None, "{garbage}");
    }
  }

  #[test]
  fn test_issuers_match() {
    assert!(issuers_match(
      "https://idp.example.com/",
      "https://idp.example.com"
    ));
    assert!(!issuers_match(
      "https://idp.example.com",
      "https://idp.example.com.evil.com"
    ));
    assert!(!issuers_match("", ""));
  }
}
