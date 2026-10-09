//! # Example Client
//!
//! API types and a client for the Mogh example app.

use anyhow::Context as _;
use mogh_auth_client::{
  api::{login::MoghAuthLoginRequest, manage::MoghAuthManageRequest},
  request::{SignedPost, json_response, signed_post},
  signature::{signed_request_headers_for_url, signing_keys},
};

pub use mogh_auth_client::signature::{SignedRequest, sign_request};
use mogh_supporter::api::{
  MoghSupporterReadRequest, MoghSupporterWriteRequest,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use typeshare::typeshare;

pub mod api;
pub mod entities;

pub use mogh_auth_client as auth;
pub use mogh_supporter as supporter;

use crate::api::{
  execute::ExampleExecuteRequest, read::ExampleReadRequest,
  write::ExampleWriteRequest,
};

#[typeshare(serialized_as = "number")]
pub type I64 = i64;

/// The most a successful response of the example api may have, which
/// the client reads it up to (mogh_auth_client's `json_response`).
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// How the client authenticates its requests.
#[derive(Clone)]
pub enum ClientAuth {
  /// No credentials, only the login api can be used.
  None,
  /// `Authorization: Bearer <jwt>`
  Jwt(String),
  /// `X-API-KEY` / `X-API-SECRET`
  ApiKey { key: String, secret: String },
  /// A signing key: the request is signed with its private key for
  /// the host of the server (`X-API-PUBLIC-KEY` / `X-API-HOST` /
  /// `X-API-TIMESTAMP` / `X-API-NONCE` / `X-API-SIGNATURE`).
  PrivateKey { private_key: String },
}

#[derive(Clone)]
pub struct ExampleClient {
  /// Keeps cookies, login flows using
  /// multiple requests depend on the session.
  pub reqwest: reqwest::Client,
  pub address: String,
  pub auth: ClientAuth,
  /// Added to every request.
  pub headers: reqwest::header::HeaderMap,
}

impl ExampleClient {
  pub fn new(
    address: impl Into<String>,
    auth: ClientAuth,
  ) -> anyhow::Result<ExampleClient> {
    let reqwest = reqwest::Client::builder()
      .cookie_store(true)
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .context("Failed to build reqwest client")?;
    Ok(ExampleClient {
      reqwest,
      address: address.into().trim_end_matches('/').to_string(),
      auth,
      headers: Default::default(),
    })
  }

  /// The same client (and session) sending an additional header.
  pub fn with_header(
    &self,
    name: &'static str,
    value: &str,
  ) -> anyhow::Result<ExampleClient> {
    let mut client = self.clone();
    client
      .headers
      .insert(name, value.parse().context("Invalid header value")?);
    Ok(client)
  }

  /// The same client (and session) with other credentials.
  pub fn with_auth(&self, auth: ClientAuth) -> ExampleClient {
    ExampleClient {
      reqwest: self.reqwest.clone(),
      address: self.address.clone(),
      auth,
      headers: self.headers.clone(),
    }
  }

  pub fn auth_address(&self) -> String {
    format!("{}/auth", self.address)
  }

  pub async fn read<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + ExampleReadRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/read", T::req_type(), &request).await
  }

  pub async fn write<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + ExampleWriteRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/write", T::req_type(), &request).await
  }

  pub async fn execute<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + ExampleExecuteRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/execute", T::req_type(), &request).await
  }

  /// The unauthenticated auth login api.
  pub async fn login<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghAuthLoginRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/auth/login", T::req_type(), &request).await
  }

  /// The authenticated auth management api.
  pub async fn manage<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghAuthManageRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/auth/manage", T::req_type(), &request).await
  }

  /// The supporter api's read requests (`mogh_supporter`).
  pub async fn supporter_read<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghSupporterReadRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/supporter/read", T::req_type(), &request).await
  }

  /// The supporter api's write requests, for admins.
  pub async fn supporter_write<T>(
    &self,
    request: T,
  ) -> anyhow::Result<T::Response>
  where
    T: Serialize + MoghSupporterWriteRequest,
    T::Response: DeserializeOwned,
  {
    self.post("/supporter/write", T::req_type(), &request).await
  }

  /// Adds the credential headers to `request`. A signature (signing
  /// key) covers its method, url and body, so set them on `request`
  /// before. It signs a request built by hand, once: the requests of
  /// the client itself go out with mogh_auth_client's `signed_post`,
  /// which also sends one again when the server refused its
  /// timestamp.
  pub fn authenticate(
    &self,
    request: reqwest::RequestBuilder,
  ) -> anyhow::Result<reqwest::RequestBuilder> {
    let request = request.headers(self.headers.clone());
    let request = match &self.auth {
      ClientAuth::None => request,
      ClientAuth::Jwt(jwt) => {
        request.header("authorization", format!("Bearer {jwt}"))
      }
      ClientAuth::ApiKey { key, secret } => request
        .header("x-api-key", key)
        .header("x-api-secret", secret),
      ClientAuth::PrivateKey { private_key } => {
        let (client, request) = request.build_split();
        let mut request = request.context("Invalid request")?;
        // The server takes these over a signature. reqwest makes an
        // Authorization header of credentials in the url
        // (`user:password@`), which the url doesn't show anymore.
        if request.headers().contains_key("authorization")
          || request.headers().contains_key("x-api-key")
        {
          anyhow::bail!(
            "The request carries other credentials (an Authorization header, also of a `user:password@` in the address, or an api key), which the server takes over the signature"
          );
        }
        // Signed for where it goes: the host the request is sent to
        // (which the server must know itself by), its path and query.
        let headers = signed_request_headers_for_url(
          private_key,
          request.method().as_str(),
          request.url(),
          request
            .body()
            .and_then(|body| body.as_bytes())
            .unwrap_or_default(),
        )?;
        for (header, value) in headers {
          request.headers_mut().insert(
            header,
            value.parse().context("Invalid signature header")?,
          );
        }
        reqwest::RequestBuilder::from_parts(client, request)
      }
    };
    Ok(request)
  }

  async fn post<B: Serialize, R: DeserializeOwned>(
    &self,
    path: &str,
    req_type: &str,
    params: &B,
  ) -> anyhow::Result<R> {
    let url = format!("{}{path}", self.address);
    let body = json!({ "type": req_type, "params": params });
    if let ClientAuth::PrivateKey { private_key } = &self.auth {
      // Signed for its host, path and body right before it goes out,
      // and sent once more, signed anew, when the server refused its
      // timestamp (the connection took too long to set up).
      let keys = signing_keys(private_key)?;
      let mut post = SignedPost::new(&url, &keys, &body)?;
      post.headers = self.headers.clone();
      return signed_post(&self.reqwest, &post, MAX_RESPONSE_BYTES)
        .await;
    }
    let request = self.reqwest.post(url).json(&body);
    let res = self
      .authenticate(request)?
      .send()
      .await
      .context("Failed to reach Example API")?;
    // A successful body which fails to parse holds credentials (a jwt,
    // an api key secret): the error leaves its values out.
    json_response(res, MAX_RESPONSE_BYTES).await
  }
}

/// The http status an error returned by [ExampleClient] carries.
pub fn error_status(
  e: &anyhow::Error,
) -> Option<reqwest::StatusCode> {
  e.downcast_ref::<reqwest::StatusCode>().copied()
}
