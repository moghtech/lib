#![allow(unused_crate_dependencies)]

use mogh_resolver::{HasResponse, Resolve};

/// The resolve futures here never await anything,
/// so they resolve without a runtime.
fn block_on<F: Future>(fut: F) -> F::Output {
  let mut fut = std::pin::pin!(fut);
  let waker = std::task::Waker::noop();
  let mut cx = std::task::Context::from_waker(waker);
  loop {
    match fut.as_mut().poll(&mut cx) {
      std::task::Poll::Ready(value) => return value,
      std::task::Poll::Pending => std::thread::yield_now(),
    }
  }
}

trait MarkerA {}
trait MarkerB {}

struct Args {
  base: i64,
}

#[derive(Resolve)]
#[response(i64)]
#[error(String)]
#[empty_traits(MarkerA)]
#[empty_traits(MarkerB)]
struct GetNumber {
  value: i64,
}

impl Resolve<Args> for GetNumber {
  async fn resolve(self, args: &Args) -> Result<i64, String> {
    if self.value < 0 {
      Err(String::from("negative value"))
    } else {
      Ok(self.value + args.base)
    }
  }
}

#[derive(Resolve)]
#[response(String)]
#[error(String)]
struct GetGreeting {
  name: String,
}

impl Resolve<Args> for GetGreeting {
  async fn resolve(self, _: &Args) -> Result<String, String> {
    Ok(format!("Hello, {}!", self.name))
  }
}

/// Without `#[error]`, Error defaults to Infallible.
#[derive(Resolve)]
#[response(Vec<String>)]
struct DefaultError {}

#[derive(Debug, PartialEq)]
enum Response {
  Number(i64),
  Greeting(String),
}

impl From<i64> for Response {
  fn from(value: i64) -> Response {
    Response::Number(value)
  }
}

impl From<String> for Response {
  fn from(value: String) -> Response {
    Response::Greeting(value)
  }
}

#[derive(Resolve)]
#[response(Response)]
#[error(String)]
#[args(Args)]
enum Request {
  GetNumber(GetNumber),
  GetGreeting(GetGreeting),
}

#[derive(Resolve)]
#[response(i64)]
#[error(String)]
struct GetNumberNoArgs {
  value: i64,
}

impl Resolve for GetNumberNoArgs {
  async fn resolve(self, _: &()) -> Result<i64, String> {
    Ok(self.value)
  }
}

/// Enum without `#[args]` dispatches over `Resolve<()>`.
#[derive(Resolve)]
#[response(Response)]
#[error(String)]
enum RequestNoArgs {
  GetNumber(GetNumberNoArgs),
}

#[test]
fn derive_implements_has_response() {
  assert_eq!(GetNumber::req_type(), "GetNumber");
  assert_eq!(Request::req_type(), "Request");
  assert_eq!(DefaultError::req_type(), "DefaultError");
  fn assert_response<T: HasResponse<Response = Vec<String>>>() {}
  assert_response::<DefaultError>();
}

#[test]
fn derive_error_defaults_to_infallible() {
  fn assert_infallible<
    T: HasResponse<Error = std::convert::Infallible>,
  >() {
  }
  assert_infallible::<DefaultError>();
}

#[test]
fn derive_generates_empty_trait_impls() {
  fn assert_markers<T: MarkerA + MarkerB>() {}
  assert_markers::<GetNumber>();
}

#[test]
fn enum_dispatches_to_variant_resolvers() {
  let args = Args { base: 10 };
  let response = block_on(
    Request::GetNumber(GetNumber { value: 32 }).resolve(&args),
  )
  .unwrap();
  assert_eq!(response, Response::Number(42));
  let response = block_on(
    Request::GetGreeting(GetGreeting {
      name: String::from("World"),
    })
    .resolve(&args),
  )
  .unwrap();
  assert_eq!(
    response,
    Response::Greeting(String::from("Hello, World!"))
  );
}

#[test]
fn enum_propagates_variant_errors() {
  let args = Args { base: 10 };
  let error = block_on(
    Request::GetNumber(GetNumber { value: -1 }).resolve(&args),
  )
  .unwrap_err();
  assert_eq!(error, "negative value");
}

#[test]
fn enum_without_args_uses_unit_args() {
  let response = block_on(
    RequestNoArgs::GetNumber(GetNumberNoArgs { value: 7 })
      .resolve(&()),
  )
  .unwrap();
  assert_eq!(response, Response::Number(7));
}
