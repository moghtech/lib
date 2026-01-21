#[allow(unused)]
#[utoipa::path(
  get,
  path = "/oidc/login",
  description = "Login using OIDC",
  params(
    ("redirect", description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to OIDC provider for login"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn oidc_login() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/oidc/link",
  description = "Link existing account to OIDC user",
  params(
    ("redirect", description = "Optional path to redirect back to after login.")
  ),
  responses(
    (status = 303, description = "Redirect to OIDC provider for link"),
    (status = 401, description = "Unauthorized", body = mogh_error::Serror),
    (status = 500, description = "Request failed", body = mogh_error::Serror)
  ),
)]
fn oidc_link() {}

#[allow(unused)]
#[utoipa::path(
  get,
  path = "/oidc/callback",
  description = "Callback to finish OIDC login",
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
fn oidc_callback() {}
