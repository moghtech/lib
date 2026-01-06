use axum::{extract::Request, middleware::Next, response::Response};

use crate::AuthImpl;

pub fn auth_request<I: AuthImpl>(
  mut req: Request,
  next: Next,
) -> mogh_error::Result<Response> {
  todo!()
}
