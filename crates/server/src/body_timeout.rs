//! A total deadline for each request body, see
//! [crate::ServerConfig::request_body_timeout].

use std::{
  io,
  pin::Pin,
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  task::{Context, Poll},
  time::Duration,
};

use axum::{
  body::{Body, Bytes, HttpBody},
  extract::Request,
  http::{HeaderValue, StatusCode, Version, header},
  middleware::Next,
  response::{IntoResponse as _, Response},
};
use http_body::{Frame, SizeHint};
use tokio::time::{Instant, Sleep};

/// Gives the request body `timeout` from now (the headers just
/// arrived) to arrive whole, see [DeadlineBody]. When the handler
/// read a body which missed it, the request is answered 408,
/// whatever the handler made of the failed read (eg. a 400 from the
/// `Json` extractor): the deadline is the reason.
pub(crate) async fn request_body_deadline(
  timeout: Duration,
  req: Request,
  next: Next,
) -> Response {
  // Nothing to wait for: no body, or an upgrade (a websocket, a
  // CONNECT tunnel), whose upgraded connection is no request body.
  if req.body().is_end_stream() {
    return next.run(req).await;
  }
  let version = req.version();
  let expired = Arc::new(AtomicBool::new(false));
  let deadline = Instant::now() + timeout;
  let req = req.map(|body| {
    Body::new(DeadlineBody {
      inner: body,
      deadline: Box::pin(tokio::time::sleep_until(deadline)),
      expired: expired.clone(),
    })
  });
  let response = next.run(req).await;
  if !expired.load(Ordering::Acquire) {
    return response;
  }
  let mut response =
    (StatusCode::REQUEST_TIMEOUT, "Request body timed out")
      .into_response();
  // RFC 9110: 408 means the server closes the connection rather
  // than wait on it. http/2 has no such header, its stream ends.
  if version < Version::HTTP_2 {
    response
      .headers_mut()
      .insert(header::CONNECTION, HeaderValue::from_static("close"));
  }
  response
}

/// The `inner` body, failing once `deadline` passes before it
/// ended, and flagging `expired`. Frames which already arrived are
/// read first, so a handler which only reads the body after working
/// a while (on a body which came in time) does not fail: only a
/// body still owed fails. Every read after the deadline fails again,
/// so a handler ignoring the error can't take the cut body as whole.
struct DeadlineBody {
  inner: Body,
  deadline: Pin<Box<Sleep>>,
  expired: Arc<AtomicBool>,
}

impl HttpBody for DeadlineBody {
  type Data = Bytes;
  type Error = axum::Error;

  fn poll_frame(
    mut self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
    let this = &mut *self;
    if !this.expired.load(Ordering::Acquire)
      && let Poll::Ready(frame) =
        Pin::new(&mut this.inner).poll_frame(cx)
    {
      return Poll::Ready(frame);
    }
    if this.deadline.as_mut().poll(cx).is_pending() {
      return Poll::Pending;
    }
    this.expired.store(true, Ordering::Release);
    Poll::Ready(Some(Err(axum::Error::new(io::Error::new(
      io::ErrorKind::TimedOut,
      "request body deadline passed",
    )))))
  }

  fn is_end_stream(&self) -> bool {
    !self.expired.load(Ordering::Acquire)
      && self.inner.is_end_stream()
  }

  fn size_hint(&self) -> SizeHint {
    self.inner.size_hint()
  }
}

#[cfg(test)]
mod tests {
  use axum::body::to_bytes;

  use super::*;

  /// A body which sends `sent`, then never the rest.
  struct Stalled(Option<Bytes>);

  impl HttpBody for Stalled {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
      mut self: Pin<&mut Self>,
      _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
      match self.0.take() {
        Some(sent) => Poll::Ready(Some(Ok(Frame::data(sent)))),
        // The deadline's timer wakes the reader.
        None => Poll::Pending,
      }
    }
  }

  fn stalled(sent: &'static [u8]) -> Body {
    Body::new(Stalled(Some(Bytes::from_static(sent))))
  }

  fn deadline_body(
    inner: Body,
    timeout: Duration,
  ) -> (DeadlineBody, Arc<AtomicBool>) {
    let expired = Arc::new(AtomicBool::new(false));
    let body = DeadlineBody {
      inner,
      deadline: Box::pin(tokio::time::sleep(timeout)),
      expired: expired.clone(),
    };
    (body, expired)
  }

  #[tokio::test]
  async fn a_body_still_owed_fails_at_the_deadline() {
    let (body, expired) =
      deadline_body(stalled(b"start"), Duration::from_millis(50));
    let started = std::time::Instant::now();
    let error =
      to_bytes(Body::new(body), usize::MAX).await.unwrap_err();
    assert!(started.elapsed() >= Duration::from_millis(50));
    assert!(expired.load(Ordering::Acquire));
    assert!(format!("{error:?}").contains("deadline"), "{error:?}");
  }

  #[tokio::test]
  async fn a_body_which_arrived_passes_after_the_deadline() {
    let (body, expired) = deadline_body(
      Body::from("arrived in time"),
      Duration::from_millis(10),
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    let bytes = to_bytes(Body::new(body), usize::MAX).await.unwrap();
    assert_eq!(bytes, "arrived in time");
    assert!(!expired.load(Ordering::Acquire));
  }

  #[tokio::test]
  async fn reads_after_the_deadline_keep_failing() {
    let (mut body, _) =
      deadline_body(stalled(b"start"), Duration::from_millis(10));
    let mut body = Pin::new(&mut body);
    let first =
      std::future::poll_fn(|cx| body.as_mut().poll_frame(cx))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap(), "start");
    for _ in 0..2 {
      let next =
        std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await;
      assert!(matches!(next, Some(Err(_))));
      assert!(!body.is_end_stream());
    }
  }
}
