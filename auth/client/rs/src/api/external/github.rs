#[allow(unused)]
#[utoipa::path(
  get,
  path = "/github/login",
  description = "Login using Github",
  params(
    ("redirect", description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to Github for login"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn github_login() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/github/link",
  description = "Link existing account to Github user",
  responses(
    (status = 303, description = "Redirect to Github for link"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn github_link() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/github/callback",
  description = "Callback to finish Github login",
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
fn github_callback() {}
