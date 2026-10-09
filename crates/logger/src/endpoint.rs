//! Url helpers: [redact_url_credentials] for anything shown, and the
//! string splits of the OTLP endpoint url, which may carry
//! credentials (`https://user:password@collector:4318`).

/// Shown in place of the credentials of a url, the same marker as
/// the apps' sanitized configs (`mogh_auth_client::config::REDACTED`).
pub(crate) const REDACTED: &str = "##############";

/// The url as it can be shown in a log line or an error message,
/// without the credentials it may carry: its userinfo
/// (`user:password@`) and its query (tokens and api keys tend to
/// live there) are each replaced whole by the marker of the apps'
/// sanitized configs, `##############`. The scheme, host, port, path
/// and fragment stay, for debugging. A url with neither is returned
/// as it is.
///
/// ```rust
/// use mogh_logger::redact_url_credentials;
///
/// assert_eq!(
///   redact_url_credentials("https://otel:hunter2@collector:4318/v1/traces?key=x"),
///   "https://##############@collector:4318/v1/traces?##############"
/// );
/// assert_eq!(
///   redact_url_credentials("http://localhost:4318/v1/traces"),
///   "http://localhost:4318/v1/traces"
/// );
/// ```
///
/// A url is read the way http clients read it (the WHATWG url
/// parser), so what they would send as credentials is redacted:
/// `http:user:password@host` (no `//`) and backslashes included. It
/// is then shown as the parser writes it (eg. with a `/` added after
/// the host). A string the parser can't read, or one with
/// an `@` past its authority, is redacted from the string instead: an
/// unencoded `/`, `?` or `#` in a password ends the authority early,
/// so what parsed as the host and port was the credentials.
/// Everything up to its last `@` is replaced by the marker, which
/// stays visible because that `@` may sit in the path (what follows
/// it is not always the host), and when a `?` or `#` comes before
/// that `@` the whole rest goes, as it may be the query. Both redact
/// more than the credentials rather than guess where they end
/// (`https://example.com/users/@me` is shown `https://##############@me`).
/// A string without a scheme (`/var/run/docker.sock`,
/// `user:password@host`) is treated the same way.
///
/// ⚠️ The path is shown: a url whose path is the secret (eg. most
/// webhook urls) must not be logged at all.
pub fn redact_url_credentials(url: &str) -> String {
  match url::Url::parse(url) {
    Ok(parsed) if parsed_exactly(&parsed) => {
      redact_parsed_url(url, &parsed)
    }
    _ => redact_unparsed_url(url),
  }
}

/// Whether the parser's reading of a url can be trusted with its
/// credentials: it has an authority (or at least a path starting
/// with `/`), and no `@` past it. An `@` in the path, query or
/// fragment may end credentials which held a `/`, `?` or `#`.
pub(crate) fn parsed_exactly(url: &url::Url) -> bool {
  !url.cannot_be_a_base()
    && !url.path().contains('@')
    && !url.query().is_some_and(|query| query.contains('@'))
    && !url
      .fragment()
      .is_some_and(|fragment| fragment.contains('@'))
}

/// [redact_url_credentials] of a url whose credentials, if any, the
/// parser found.
fn redact_parsed_url(original: &str, url: &url::Url) -> String {
  let credentials =
    !url.username().is_empty() || url.password().is_some();
  if !credentials && url.query().is_none() {
    // Nothing to hide: as it was written, not as the parser
    // normalizes it.
    return original.to_string();
  }
  // Built from the parser's pieces rather than with its setters,
  // which would percent-encode the marker.
  let mut out = String::from(&url[..url::Position::BeforeUsername]);
  if credentials {
    out.push_str(REDACTED);
    out.push('@');
  }
  out.push_str(
    &url[url::Position::BeforeHost..url::Position::AfterPath],
  );
  if url.query().is_some() {
    out.push('?');
    out.push_str(REDACTED);
  }
  if let Some(fragment) = url.fragment() {
    out.push('#');
    out.push_str(fragment);
  }
  out
}

/// [redact_url_credentials] of a url the parser can't be trusted
/// with: everything up to the last `@` is redacted.
fn redact_unparsed_url(url: &str) -> String {
  // A scheme only when it looks like one: `://` may also sit in
  // the query of a string without one.
  let (prefix, rest) = match url.split_once("://") {
    Some((scheme, _)) if is_scheme(scheme) => {
      url.split_at(scheme.len() + 3)
    }
    _ => ("", url),
  };
  let (rest, marked) = match rest.rsplit_once('@') {
    // The `@` may end credentials holding a `?` or `#`, or sit in
    // the query itself: what follows it can't be told apart from
    // the query.
    Some((dropped, _)) if dropped.contains(['?', '#']) => {
      return format!("{prefix}{REDACTED}");
    }
    Some((_, rest)) => (rest, true),
    None => (rest, false),
  };
  let (rest, fragment) = match rest.split_once('#') {
    Some((rest, fragment)) => (rest, Some(fragment)),
    None => (rest, None),
  };
  let mut out = String::from(prefix);
  if marked {
    out.push_str(REDACTED);
    out.push('@');
  }
  match rest.split_once('?') {
    Some((rest, _)) => {
      out.push_str(rest);
      out.push('?');
      out.push_str(REDACTED);
    }
    None => out.push_str(rest),
  }
  if let Some(fragment) = fragment {
    out.push('#');
    out.push_str(fragment);
  }
  out
}

/// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, RFC 3986 section 3.1.
fn is_scheme(scheme: &str) -> bool {
  scheme.starts_with(|c: char| c.is_ascii_alphabetic())
    && scheme.chars().all(|c| {
      c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
    })
}

/// Splits a url into `scheme://authority`, the path, and the query
/// / fragment. `None` without a scheme.
#[cfg(feature = "init")]
pub(crate) fn split_url(url: &str) -> Option<(&str, &str, &str)> {
  let authority_start = url.find("://")? + 3;
  let path_start = url[authority_start..]
    .find(['/', '?', '#'])
    .map_or(url.len(), |index| authority_start + index);
  let (base, rest) = url.split_at(path_start);
  let suffix_start = rest.find(['?', '#']).unwrap_or(rest.len());
  let (path, suffix) = rest.split_at(suffix_start);
  Some((base, path, suffix))
}

/// Splits the userinfo (`user:password`) out of a url's authority:
/// what comes before it (`https://`), the userinfo, and what comes
/// after its `@` (the host and the rest). `None` without a scheme
/// or without userinfo. The last `@` of the authority ends the
/// userinfo, as in browsers, so an `@` left unencoded in the
/// password still splits there.
#[cfg(feature = "init")]
pub(crate) fn split_userinfo(
  url: &str,
) -> Option<(&str, &str, &str)> {
  let (base, _, _) = split_url(url)?;
  let authority_start = base.find("://")? + 3;
  let at = base[authority_start..].rfind('@')? + authority_start;
  Some((
    &url[..authority_start],
    &url[authority_start..at],
    &url[at + 1..],
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(feature = "init")]
  #[test]
  fn split_userinfo_finds_the_credentials() {
    for (url, expected) in [
      (
        "https://user:pass@otel:4318/v1/traces?key=value",
        Some((
          "https://",
          "user:pass",
          "otel:4318/v1/traces?key=value",
        )),
      ),
      ("http://token@otel", Some(("http://", "token", "otel"))),
      // The last `@` of the authority ends the userinfo.
      (
        "https://user@corp:p@ss@[::1]:4318",
        Some(("https://", "user@corp:p@ss", "[::1]:4318")),
      ),
      ("https://@otel", Some(("https://", "", "otel"))),
      // An `@` after the authority is not userinfo.
      ("https://otel/v1/traces@x", None),
      ("https://otel?key=a@b", None),
      ("https://otel#a@b", None),
      ("https://otel:4318", None),
      // No scheme, nothing to split.
      ("user:pass@otel:4318", None),
    ] {
      assert_eq!(split_userinfo(url), expected, "{url}");
    }
  }

  /// The userinfo and the query go whole, the rest stays. Urls the
  /// parser reads as written are redacted exactly, the others up to
  /// their last `@`.
  #[test]
  fn redact_url_credentials_hides_the_userinfo_and_query() {
    let r = REDACTED;
    for (url, expected) in [
      // Nothing to hide: as written, not normalized.
      (
        "https://issuer.example.com",
        String::from("https://issuer.example.com"),
      ),
      (
        "http://localhost:4318/v1/traces",
        String::from("http://localhost:4318/v1/traces"),
      ),
      ("https://h/p#f", String::from("https://h/p#f")),
      ("https://@host", String::from("https://@host")),
      (
        "https://example.com/users/%40me",
        String::from("https://example.com/users/%40me"),
      ),
      (
        "unix:///var/run/docker.sock",
        String::from("unix:///var/run/docker.sock"),
      ),
      ("/var/run/docker.sock", String::from("/var/run/docker.sock")),
      ("tcp://h:2375", String::from("tcp://h:2375")),
      ("plain", String::from("plain")),
      ("not a url", String::from("not a url")),
      ("", String::new()),
      // The userinfo, user and password alike.
      (
        "https://user:hunter2@issuer.example.com/keys",
        format!("https://{r}@issuer.example.com/keys"),
      ),
      (
        "http://user@localhost:8080/.well-known/openid-configuration",
        format!(
          "http://{r}@localhost:8080/.well-known/openid-configuration"
        ),
      ),
      (
        "https://:hunter2@issuer.example.com",
        format!("https://{r}@issuer.example.com/"),
      ),
      (
        "https://u:p@[::1]:4318/v1/traces",
        format!("https://{r}@[::1]:4318/v1/traces"),
      ),
      ("tcp://u:p@proxy:2375", format!("tcp://{r}@proxy:2375")),
      (
        "redis://:p@cache:6379/0",
        format!("redis://{r}@cache:6379/0"),
      ),
      (
        "postgres://app:hunter2@db:5432/app?sslmode=require",
        format!("postgres://{r}@db:5432/app?{r}"),
      ),
      // An `@` in the password, raw or encoded, and encoded
      // delimiters.
      ("https://admin:p@ss@host/p", format!("https://{r}@host/p")),
      (
        "https://admin:a%2Fb%3Fc%40d@host/p",
        format!("https://{r}@host/p"),
      ),
      // The query, whole. The fragment stays.
      ("https://u:p@h/p?q=1#f", format!("https://{r}@h/p?{r}#f")),
      ("https://a:b@h?x=1", format!("https://{r}@h/?{r}")),
      (
        "http://localhost:8080/keys?v=2",
        format!("http://localhost:8080/keys?{r}"),
      ),
      // Credentials as http clients read them: without the `//`,
      // with backslashes, around tabs, inside spaces.
      ("http:user:hunter2@host", format!("http://{r}@host/")),
      (
        "https:\\\\user:hunter2@host\\p",
        format!("https://{r}@host/p"),
      ),
      ("https://user:hun\tter2@host", format!("https://{r}@host/")),
      (" https://user:hunter2@host ", format!("https://{r}@host/")),
      // An unencoded `/`, `?` or `#` in a password ends the
      // authority early: the url doesn't parse (the password is
      // read as a port), or parses with the credentials as the host.
      (
        "https://admin:abc/def==@grafana:3000/api/reload",
        format!("https://{r}@grafana:3000/api/reload"),
      ),
      (
        "https://admin:abc/def==@grafana/hook?token=1#f",
        format!("https://{r}@grafana/hook?{r}#f"),
      ),
      ("https://tok/en@host/p", format!("https://{r}@host/p")),
      // An `@` in the path takes the same road, the marker shows
      // that what follows it is not passed off as the host.
      ("https://example.com/users/@me", format!("https://{r}@me")),
      (
        "https://hooks.example.com/notify/@channel?token=x",
        format!("https://{r}@channel?{r}"),
      ),
      // An `@` in the query or the fragment: all of the rest may
      // follow it.
      (
        "https://host/hook?mail=a@b.c&token=12",
        format!("https://{r}"),
      ),
      ("https://host/p#a@b", format!("https://{r}")),
      // Strings the parser can't read.
      (
        "https://user:hunter2@bad host/keys",
        format!("https://{r}@bad host/keys"),
      ),
      (
        "https://a@b:hunter2@bad host",
        format!("https://{r}@bad host"),
      ),
      (
        "mongodb://u:p@h1:27017,h2:27017/db?replicaSet=rs",
        format!("mongodb://{r}@h1:27017,h2:27017/db?{r}"),
      ),
      // No scheme.
      ("user:pw@host/p", format!("{r}@host/p")),
      ("host/hook?next=https://a@b&token=12", String::from(r)),
    ] {
      assert_eq!(redact_url_credentials(url), expected, "{url:?}");
    }
  }

  /// However the credentials end up placed, none of them shows.
  #[test]
  fn redact_url_credentials_never_shows_credentials() {
    for (url, secrets) in [
      ("https://admin:ab?cd@host/p", &["admin", "ab", "cd"][..]),
      ("https://admin:ab#cd@host/p", &["admin", "ab", "cd"]),
      ("https://admin:12/34@host/p", &["admin", "12", "34"]),
      ("https://admin:12?34@host/p", &["admin", "12", "34"]),
      ("https://admin:12#34@host/p", &["admin", "12", "34"]),
      ("https://admin:12\\34@host/p", &["admin", "12", "34"]),
      ("https://tok/en@host/p", &["tok", "en"]),
      ("https://to\\ken@host/p", &["to", "ken"]),
      ("https://admin:12:34@host/p", &["admin", "12", "34"]),
      ("https://admin:pa[s]s@host/p", &["admin", "pa"]),
      ("http:admin:hunter2@host", &["admin", "hunter2"]),
      ("http:/admin:hunter2@host", &["admin", "hunter2"]),
      ("http:\\admin:hunter2@host", &["admin", "hunter2"]),
      ("ftp://admin:hunter2@host/file", &["admin", "hunter2"]),
      ("ws://admin:hunter2@host/socket", &["admin", "hunter2"]),
      ("file://admin:hunter2@host/file", &["admin", "hunter2"]),
      ("custom://admin:hun\\ter2@host", &["admin", "hun", "ter2"]),
      ("https://h/hook?token=hunter2", &["hunter2"]),
      ("https://h/hook?token=hunter2#f", &["hunter2"]),
      ("https://h/hook?mail=a@b.c&token=12", &["token", "12"]),
      ("h/hook?next=https://a@b&token=12", &["token", "12"]),
      ("https://admin:hunter2@", &["admin", "hunter2"]),
      ("admin:hunter2@", &["admin", "hunter2"]),
    ] {
      let shown = redact_url_credentials(url);
      for secret in secrets {
        assert!(
          !shown.contains(secret),
          "{url:?} -> {shown:?} shows {secret:?}"
        );
      }
    }
  }
}
