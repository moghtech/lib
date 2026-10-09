use std::fmt;

/// Marks an error as a refusal which is not a guess, so that
/// `mogh_rate_limit` does not count it as a failed attempt: an
/// authentication refusal of an authentic but expired token, of an
/// ended session, or a server error. Counting these would lock out
/// clients (eg. every tab still holding a token after a log out
/// everywhere, behind one NAT) for no guessing at all.
///
/// Mark a [crate::Error] with `.uncounted()` and check it with
/// `.is_uncounted()` (feature `axum`), which also finds the marker
/// below context added after marking.
///
/// The marker is transparent: it displays as the wrapped error's
/// top-level message and its `source` is the wrapped error's
/// source, so the chain (`{:#}`, a serialized error's `trace`)
/// renders unchanged. The wrapped error's own top-level type sits
/// behind the marker though: downcast to [NotAnAttempt] and use
/// `.0` to reach it (its causes stay in the chain).
#[derive(Debug)]
pub struct NotAnAttempt(pub anyhow::Error);

impl fmt::Display for NotAnAttempt {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt::Display::fmt(&self.0, f)
  }
}

impl std::error::Error for NotAnAttempt {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    self.0.source()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn chain(e: &anyhow::Error) -> Vec<String> {
    e.chain().map(|e| e.to_string()).collect()
  }

  #[derive(Debug)]
  struct SessionEnded;

  impl fmt::Display for SessionEnded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      f.write_str("Session ended")
    }
  }

  impl std::error::Error for SessionEnded {}

  #[test]
  fn not_an_attempt_renders_like_the_wrapped_error() {
    let wrapped = || {
      anyhow::anyhow!("root cause")
        .context("middle")
        .context("top")
    };
    let error = anyhow::Error::new(NotAnAttempt(wrapped()));
    assert_eq!(chain(&error), chain(&wrapped()));
    assert_eq!(chain(&error), ["top", "middle", "root cause"]);
    assert_eq!(format!("{error:#}"), format!("{:#}", wrapped()));
    assert_eq!(error.to_string(), "top");
    let marker = error.downcast_ref::<NotAnAttempt>().unwrap();
    assert_eq!(marker.to_string(), "top");
    // Like the wrapped anyhow error, the alternate form has it all.
    assert_eq!(format!("{marker:#}"), "top: middle: root cause");
    let source = std::error::Error::source(marker).unwrap();
    assert_eq!(source.to_string(), "middle");
  }

  #[test]
  fn the_wrapped_error_is_reached_through_the_marker() {
    let error = anyhow::Error::new(NotAnAttempt(SessionEnded.into()));
    assert_eq!(chain(&error), ["Session ended"]);
    assert!(error.downcast_ref::<SessionEnded>().is_none());
    let NotAnAttempt(wrapped) =
      error.downcast_ref::<NotAnAttempt>().unwrap();
    assert!(wrapped.downcast_ref::<SessionEnded>().is_some());
  }
}
