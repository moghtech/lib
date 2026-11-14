// The README's examples are compiled as this crate's doctests, so
// they keep compiling. Their dependencies are dev-dependencies only
// the doctests use.
#![doc = include_str!("../README.md")]
#![cfg_attr(test, allow(unused_crate_dependencies))]

use std::future::Future;

extern crate mogh_resolver_derive;
pub use mogh_resolver_derive::Resolve;

pub trait HasResponse {
  type Response;
  type Error;

  /// The request's type name, the `"type"` of a tagged request
  /// (`{ "type": ..., "params": ... }`).
  fn req_type() -> &'static str;
}

pub trait Resolve<Args = ()>: HasResponse {
  fn resolve(
    self,
    args: &Args,
  ) -> impl Future<Output = Result<Self::Response, Self::Error>>;
}
