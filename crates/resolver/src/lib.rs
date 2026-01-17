use std::future::Future;

extern crate mogh_resolver_derive;
pub use mogh_resolver_derive::Resolve;

pub trait HasResponse {
  type Response;
  type Error;

  fn req_type() -> &'static str;
  fn res_type() -> &'static str;
}

pub trait Resolve<Args = ()>: HasResponse {
  fn resolve(self, args: &Args) -> impl Future<Output = Result<Self::Response, Self::Error>>;
}
