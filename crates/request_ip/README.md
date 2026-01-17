# Mogh Request IP

Axum extractor for client request IP.

```rust
// Use as axum extractor
async fn auth_request(
  RequestIp(ip): RequestIp,
  req: Request
) -> mogh_error::Result<String> {
  println!("Client IP: {ip:?}");
  Ok(ip.to_string())
}
```