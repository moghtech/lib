use std::time::Duration;

pub mod external;
pub mod jwt;
pub mod load_cache;
pub mod named;
pub mod oidc;
pub mod passkey;
pub mod token_exchange;
pub mod workload;

/// How long a request of a login to its provider (the code exchange,
/// user info) may take. A provider which accepts the connection but
/// never answers fails the login after this, instead of leaving it
/// (and the browser) hanging. Loading the provider's discovery
/// document and key set is bounded by `load_cache::LOAD_TIMEOUT`
/// instead: 15 seconds for both requests together, as the logins
/// waiting on the load wait with it.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long connecting to a login provider may take.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The url of a server which accepts connections and
/// reads the requests, but never answers them.
#[cfg(test)]
pub(crate) async fn stalled_server() -> String {
  use tokio::io::AsyncReadExt as _;
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  tokio::spawn(async move {
    while let Ok((mut connection, _)) = listener.accept().await {
      // Open until the client gives up
      tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while connection.read(&mut buf).await.is_ok_and(|n| n > 0) {}
      });
    }
  });
  format!("http://{address}")
}

/// The url of a server answering every request with `status` and the
/// json `body`, eg. a provider's token endpoint refusing a code.
#[cfg(test)]
pub(crate) async fn answering_server(
  status: axum::http::StatusCode,
  body: String,
) -> String {
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let address = listener.local_addr().unwrap();
  let app = axum::Router::new().fallback(move || {
    let body = body.clone();
    async move {
      (status, [("content-type", "application/json")], body)
    }
  });
  tokio::spawn(async move { axum::serve(listener, app).await });
  format!("http://{address}")
}

/// The urls of two servers answering every request with a body
/// larger than any provider response is read: one declaring its
/// length up front, one which doesn't and keeps sending until the
/// client hangs up.
#[cfg(test)]
pub(crate) async fn oversized_servers() -> [String; 2] {
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
  let declared = answering_server(
    axum::http::StatusCode::OK,
    " ".repeat(oidc::MAX_RESPONSE_LENGTH + 1),
  )
  .await;
  let listener =
    tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let endless = format!("http://{}", listener.local_addr().unwrap());
  tokio::spawn(async move {
    while let Ok((mut socket, _)) = listener.accept().await {
      tokio::spawn(async move {
        let mut request = [0u8; 4096];
        let _ = socket.read(&mut request).await;
        let _ = socket
          .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
          .await;
        let chunk = vec![b' '; 64 * 1024];
        while socket.write_all(&chunk).await.is_ok() {}
      });
    }
  });
  [declared, endless]
}
