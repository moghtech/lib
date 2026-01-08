use std::{
  sync::LazyLock,
  time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, anyhow};
use jsonwebtoken::{
  DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use mogh_auth_client::api::login::JwtResponse;
use serde::{Deserialize, Serialize};

static DEFAULT_HEADER: LazyLock<Header> =
  LazyLock::new(Default::default);
static DEFAULT_VALIDATION: LazyLock<Validation> =
  LazyLock::new(Default::default);

/// JWT Clock skew tolerance in milliseconds (10 seconds for JWTs)
const JWT_CLOCK_SKEW_TOLERANCE_MS: u128 = 10 * 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct JwtClaims {
  /// Client identifier, eg user id
  pub sub: String,
  /// Issued at time
  pub iat: u128,
  /// Expiry time
  pub exp: u128,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BorrowedJwtClaims<'a> {
  /// Client identifier, eg user id
  pub sub: &'a str,
  /// Issued at time
  pub iat: u128,
  /// Expiry time
  pub exp: u128,
}

pub struct JwtProvider {
  header: Option<Header>,
  validation: Option<Validation>,
  encoding_key: EncodingKey,
  decoding_key: DecodingKey,
  ttl_ms: u128,
}

impl JwtProvider {
  pub fn new(secret: &[u8], ttl_ms: u128) -> Self {
    Self {
      header: None,
      validation: None,
      encoding_key: EncodingKey::from_secret(secret),
      decoding_key: DecodingKey::from_secret(secret),
      ttl_ms,
    }
  }

  pub fn with_header(mut self, header: Header) -> Self {
    self.header = Some(header);
    self
  }

  pub fn with_validation(mut self, validation: Validation) -> Self {
    self.validation = Some(validation);
    self
  }

  pub fn header(&self) -> &Header {
    self.header.as_ref().unwrap_or(&DEFAULT_HEADER)
  }

  pub fn validation(&self) -> &Validation {
    self.validation.as_ref().unwrap_or(&DEFAULT_VALIDATION)
  }

  pub fn encode_sub(&self, sub: &str) -> anyhow::Result<JwtResponse> {
    let iat =
      SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let exp = iat + self.ttl_ms;
    let claims = BorrowedJwtClaims { sub, iat, exp };
    let jwt = encode(self.header(), &claims, &self.encoding_key)
      .context("Failed at signing claim")?;
    Ok(JwtResponse { jwt })
  }

  /// Decodes JWT, checks not expired, returns the claims 'sub', ie the User ID
  pub fn decode_sub(&self, jwt: &str) -> anyhow::Result<String> {
    let claims =
      decode::<JwtClaims>(jwt, &self.decoding_key, self.validation())
        .map(|res| res.claims)
        .map_err(|_| anyhow!("Invalid user credentials"))?;

    let now =
      SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

    if claims.exp > now.saturating_sub(JWT_CLOCK_SKEW_TOLERANCE_MS) {
      Ok(claims.sub)
    } else {
      Err(anyhow!("Invalid user credentials"))
    }
  }
}
