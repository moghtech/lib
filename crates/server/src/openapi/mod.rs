//! The Scalar API reference, and the OpenAPI spec it renders. See
//! the `README.md` next to this file to bump Scalar.

use std::io::Write as _;

use axum::{
  Router,
  body::Bytes,
  http::{HeaderMap, HeaderValue, StatusCode, header},
  response::{Html, IntoResponse, Response},
  routing::get,
};
use serde::Serialize;

use crate::ui::content_hash;

/// Serves the [Scalar](https://github.com/scalar/scalar) API
/// reference at `/docs`, and the OpenAPI spec it renders at
/// `/docs/openapi.json`.
///
/// A spec can run to hundreds of KB of JSON (most of it the
/// component schemas), so rather than inlining it into the page it
/// is served from its own route, serialized / gzipped / hashed once
/// here. Browsers cache it and revalidate with the ETag (an empty
/// 304) instead of downloading the whole thing on every load of the
/// docs. The page hides Scalar's models section for the same
/// reason, the schemas still render inline on each operation.
///
/// `spec` is anything serializing to an OpenAPI document, eg the
/// `utoipa::openapi::OpenApi` of a `#[derive(utoipa::OpenApi)]`
/// type. `title` is the page title.
///
/// Under an app's `Content-Security-Policy`
/// ([crate::ServerConfig::content_security_policy]) the page is
/// answered with the policy plus the sources it loads, see
/// [crate::docs_content_security_policy].
///
/// ```
/// use axum::Router;
///
/// let spec = serde_json::json!({ "openapi": "3.1.0", "paths": {} });
/// let app = Router::new()
///   .merge(mogh_server::openapi::serve_docs("Example API Docs", &spec));
/// ```
///
/// # Panics
///
/// If `spec` fails to serialize.
pub fn serve_docs(title: &str, spec: &impl Serialize) -> Router {
  let spec = Spec::new(spec);
  let page = Bytes::from(
    include_str!("docs.html").replace("$title", &escape_text(title)),
  );
  Router::new()
    .route(
      "/docs",
      get(move || {
        let page = page.clone();
        async move {
          // Marked, so `configure_app` allows the sources the page
          // loads in the app's Content-Security-Policy.
          let mut response = Html(page).into_response();
          response.extensions_mut().insert(crate::DocsPage);
          response
        }
      }),
    )
    .route(
      "/docs/openapi.json",
      get(move |headers: HeaderMap| {
        let spec = spec.clone();
        async move { spec.respond(&headers) }
      }),
    )
}

/// Escapes `text` for the `<title>` of the page.
fn escape_text(text: &str) -> String {
  text
    .replace('&', "&amp;")
    .replace('<', "&lt;")
    .replace('>', "&gt;")
}

/// The spec, ready to serve in either encoding.
#[derive(Clone)]
struct Spec {
  json: Bytes,
  gzip: Bytes,
  /// Content hash of the JSON, the same scheme as the static UI
  /// index (see [content_hash]). Weak, as it validates both
  /// encodings.
  etag: HeaderValue,
}

impl Spec {
  fn new(spec: &impl Serialize) -> Spec {
    let json = serde_json::to_vec(spec)
      .expect("Failed to serialize the OpenAPI spec");
    let mut encoder = flate2::write::GzEncoder::new(
      Vec::with_capacity(json.len() / 4),
      flate2::Compression::best(),
    );
    let gzip = encoder
      .write_all(&json)
      .and_then(|_| encoder.finish())
      .expect("Failed to gzip the OpenAPI spec");
    let etag = HeaderValue::from_str(&format!(
      "W/\"{}\"",
      content_hash(&json)
    ))
    .expect("BASE64URL is a valid header value");
    Spec {
      json: json.into(),
      gzip: gzip.into(),
      etag,
    }
  }

  fn respond(&self, request: &HeaderMap) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::ETAG, self.etag.clone());
    headers.insert(
      header::CACHE_CONTROL,
      HeaderValue::from_static("no-cache"),
    );
    headers.insert(
      header::VARY,
      HeaderValue::from_static("accept-encoding"),
    );
    if if_none_match(request, &self.etag) {
      return (StatusCode::NOT_MODIFIED, headers).into_response();
    }
    headers.insert(
      header::CONTENT_TYPE,
      HeaderValue::from_static("application/json"),
    );
    let body = if accepts_gzip(request) {
      headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static("gzip"),
      );
      self.gzip.clone()
    } else {
      self.json.clone()
    };
    (headers, body).into_response()
  }
}

/// Whether the request's `If-None-Match` matches `etag`, using the
/// weak comparison (RFC 9110 §8.8.3.2) conditional requests use.
fn if_none_match(request: &HeaderMap, etag: &HeaderValue) -> bool {
  let Ok(etag) = etag.to_str() else {
    return false;
  };
  let etag = opaque_tag(etag);
  request
    .get_all(header::IF_NONE_MATCH)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .map(opaque_tag)
    .any(|tag| tag == "*" || tag == etag)
}

fn opaque_tag(tag: &str) -> &str {
  tag.trim().trim_start_matches("W/")
}

/// Whether the request accepts a gzip encoded response, ie its
/// `Accept-Encoding` lists `gzip` without refusing it (`gzip;q=0`).
fn accepts_gzip(request: &HeaderMap) -> bool {
  request
    .get_all(header::ACCEPT_ENCODING)
    .iter()
    .filter_map(|value| value.to_str().ok())
    .flat_map(|value| value.split(','))
    .filter_map(|coding| {
      let (name, params) =
        coding.split_once(';').unwrap_or((coding, ""));
      name.trim().eq_ignore_ascii_case("gzip").then_some(params)
    })
    .any(|params| {
      params
        .split(';')
        .find_map(|param| param.trim().strip_prefix("q="))
        .and_then(|q| q.trim().parse::<f32>().ok())
        .is_none_or(|q| q > 0.0)
    })
}

#[cfg(test)]
mod tests {
  use std::io::Read as _;

  use axum::{body::Body, http::Request};
  use tower::ServiceExt as _;

  use super::*;

  /// Repetitive enough to compress well, like a real spec.
  fn spec() -> serde_json::Value {
    let paths = (0..200)
      .map(|i| {
        let operation = serde_json::json!({
          "get": {
            "summary": "Get a thing",
            "responses": { "200": { "description": "The thing" } }
          }
        });
        (format!("/things/{i}"), operation)
      })
      .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
      "openapi": "3.1.0",
      "info": { "title": "Test", "version": "1" },
      "paths": paths,
    })
  }

  async fn get(
    path: &str,
    headers: &[(header::HeaderName, &str)],
  ) -> Response {
    let mut request = Request::get(path);
    for (name, value) in headers {
      request = request.header(name.clone(), *value);
    }
    serve_docs("Test & Docs", &spec())
      .oneshot(request.body(Body::empty()).unwrap())
      .await
      .unwrap()
  }

  async fn body(res: Response) -> Vec<u8> {
    axum::body::to_bytes(res.into_body(), usize::MAX)
      .await
      .unwrap()
      .to_vec()
  }

  /// Under an app's Content-Security-Policy the page is answered
  /// with the sources it loads; the spec route with the app's policy.
  #[tokio::test]
  async fn the_page_gets_its_sources_under_the_apps_policy() {
    struct Policy;
    impl crate::ServerConfig for Policy {
      fn port(&self) -> u16 {
        0
      }
      fn content_security_policy(&self) -> &str {
        "default-src 'self'"
      }
    }
    let policy_of = async |path: &str| {
      let app =
        crate::configure_app(serve_docs("Test", &spec()), &Policy)
          .unwrap();
      app
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_string()
    };
    let page = policy_of("/docs").await;
    assert_eq!(
      page,
      crate::docs_content_security_policy("default-src 'self'")
    );
    // The bundle of docs.html comes from the script source, and its
    // fonts from the font source.
    assert!(
      include_str!("docs.html")
        .contains("src=\"https://cdn.jsdelivr.net/npm/@scalar/")
    );
    assert!(page.contains(
      "script-src 'self' https://cdn.jsdelivr.net/npm/@scalar/"
    ));
    assert!(
      page.contains("font-src 'self' https://fonts.scalar.com")
    );
    assert_eq!(
      policy_of("/docs/openapi.json").await,
      "default-src 'self'"
    );
  }

  #[tokio::test]
  async fn page_has_the_title_and_loads_the_spec_route() {
    let res = get("/docs", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
      res.headers()[header::CONTENT_TYPE]
        .to_str()
        .unwrap()
        .starts_with("text/html")
    );
    let page = String::from_utf8(body(res).await).unwrap();
    assert!(
      page.contains("<title>Test &amp; Docs</title>"),
      "{page}"
    );
    assert!(
      page.contains("data-url=\"/docs/openapi.json\""),
      "{page}"
    );
  }

  #[tokio::test]
  async fn spec_is_compressed_and_revalidated() {
    // Identity encoding when none is accepted (eg plain curl).
    let res = get("/docs/openapi.json", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
      res.headers()[header::CONTENT_TYPE],
      "application/json"
    );
    assert_eq!(res.headers()[header::CACHE_CONTROL], "no-cache");
    assert_eq!(res.headers()[header::VARY], "accept-encoding");
    assert!(res.headers().get(header::CONTENT_ENCODING).is_none());
    let etag =
      res.headers()[header::ETAG].to_str().unwrap().to_string();
    assert!(etag.starts_with("W/\""), "{etag}");
    let json = body(res).await;
    assert_eq!(json, serde_json::to_vec(&spec()).unwrap());

    // Gzip when the browser accepts it, decoding to the same bytes.
    let res = get(
      "/docs/openapi.json",
      &[(header::ACCEPT_ENCODING, "gzip, deflate, br, zstd")],
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_ENCODING], "gzip");
    assert_eq!(res.headers()[header::ETAG], etag.as_str());
    let gzip = body(res).await;
    assert!(
      gzip.len() < json.len() / 4,
      "{} vs {}",
      gzip.len(),
      json.len()
    );
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(gzip.as_slice())
      .read_to_end(&mut decoded)
      .unwrap();
    assert_eq!(decoded, json);

    // Refused gzip is honored.
    let res = get(
      "/docs/openapi.json",
      &[(header::ACCEPT_ENCODING, "gzip;q=0, br")],
    )
    .await;
    assert!(res.headers().get(header::CONTENT_ENCODING).is_none());

    // Revalidating with the ETag gets an empty 304, whatever encoding.
    for tag in [etag.as_str(), etag.trim_start_matches("W/")] {
      let res = get(
        "/docs/openapi.json",
        &[
          (header::IF_NONE_MATCH, tag),
          (header::ACCEPT_ENCODING, "gzip"),
        ],
      )
      .await;
      assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
      assert_eq!(res.headers()[header::ETAG], etag.as_str());
      assert!(body(res).await.is_empty());
    }

    // A stale ETag gets the body again.
    let res = get(
      "/docs/openapi.json",
      &[(header::IF_NONE_MATCH, "\"stale\", W/\"older\"")],
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body(res).await, json);
  }
}
