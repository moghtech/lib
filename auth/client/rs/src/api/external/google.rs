#[allow(unused)]
#[utoipa::path(
  get,
  path = "/google/login",
  description = "Login using Google",
  params(
    ("redirect", description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to Google for login"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn google_login() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/google/link",
  description = "Link existing account to Google user",
  responses(
    (status = 303, description = "Redirect to Google for link"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn google_link() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/google/callback",
  description = "Callback to finish Google login",
  params(
    ("state", description = "Callback state."),
    ("code", description = "Callback code."),
    ("error", description = "Callback error.")
  ),
  responses(
    (status = 303, description = "Redirect back to app to continue login steps."),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn google_callback() {}
