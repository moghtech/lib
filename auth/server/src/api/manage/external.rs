use anyhow::anyhow;
use axum::http::StatusCode;
use mogh_auth_client::api::manage::{
  BeginExternalLoginLink, BeginExternalLoginLinkResponse,
  UnlinkExternalLogin, UnlinkExternalLoginResponse, UnlinkLocalLogin,
  UnlinkLocalLoginResponse,
};
use mogh_error::{AddStatusCode as _, AddStatusCodeError as _};
use mogh_resolver::Resolve;
use tracing::instrument;

use crate::{
  AuthImpl, CredentialChange,
  api::manage::ManageArgs,
  provider::external::{
    resolve_external_provider_by_slug, validate_provider_id,
  },
  session::Session,
  user::AuthUserImpl,
};

//

/// Begins a link of `user_id` to the provider of `slug` on the
/// session. The provider must exist (NOT_FOUND) and be enabled
/// (BAD_REQUEST): the client hears about it here rather than as a
/// redirect back from `/link`. The link is begun for it alone
/// ([ExternalLink::check_slug][crate::session::ExternalLink::check_slug]).
pub(crate) async fn begin_external_login_link<
  I: AuthImpl + ?Sized,
>(
  auth: &I,
  session: &Session,
  username: &str,
  user_id: &str,
  slug: &str,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;

  let provider = resolve_external_provider_by_slug(auth, slug)
    .await?
    .provider;
  if !provider.enabled() {
    return Err(
      anyhow!("Login with '{}' is not enabled", provider.name)
        .status_code(StatusCode::BAD_REQUEST),
    );
  }

  // Cycles the session id: the response carries the cookie
  // the client has to start the link (`/link`) with.
  session
    .insert_external_link_user_id(user_id, provider.slug())
    .await
}

impl Resolve<ManageArgs> for BeginExternalLoginLink {
  #[instrument(
    "BeginExternalLoginLink",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
      slug = self.slug,
    )
  )]
  async fn resolve(
    self,
    ManageArgs {
      auth,
      user,
      session,
      ..
    }: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    begin_external_login_link(
      auth.as_ref(),
      session,
      user.username(),
      user.id(),
      &self.slug,
    )
    .await?;
    Ok(BeginExternalLoginLinkResponse {})
  }
}

//

/// Removes the password of `user`, unless it is their only way to
/// log in ([AuthUserImpl::external_login_provider_ids]).
pub async fn unlink_local_login<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
) -> mogh_error::Result<()> {
  auth.check_username_locked(user.username())?;
  if let Some(provider_ids) = user.external_login_provider_ids()
    && provider_ids.is_empty()
  {
    return Err(only_way_to_log_in());
  }
  auth.unlink_local_login(user.id().to_string()).await?;
  Ok(())
}

/// The refusal of a change which would leave the user without a way
/// to log in.
fn only_way_to_log_in() -> mogh_error::Error {
  anyhow!("Cannot remove the only way to log in")
    .status_code(StatusCode::BAD_REQUEST)
}

impl Resolve<ManageArgs> for UnlinkLocalLogin {
  #[instrument(
    "UnlinkLocalLogin",
    skip_all,
    fields(
      user_id = args.user.id(),
      username = args.user.username(),
    )
  )]
  async fn resolve(
    self,
    args: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let ManageArgs { auth, user, .. } = args;
    unlink_local_login(auth.as_ref(), user.as_ref().as_ref()).await?;
    args
      .credentials_changed(CredentialChange::LocalLoginUnlinked)
      .await?;
    Ok(UnlinkLocalLoginResponse {})
  }
}

//

/// Removes the link of `user` to the provider, unless it is their only
/// way to log in ([AuthUserImpl::external_login_provider_ids]).
pub async fn unlink_external_login<I: AuthImpl + ?Sized>(
  auth: &I,
  user: &dyn AuthUserImpl,
  provider_id: String,
) -> mogh_error::Result<()> {
  auth.check_username_locked(user.username())?;
  // The provider may already be deleted, only validate the id shape.
  validate_provider_id(&provider_id)
    .status_code(StatusCode::BAD_REQUEST)?;
  if let Some(provider_ids) = user.external_login_provider_ids() {
    let others = provider_ids.iter().filter(|id| **id != provider_id);
    if user.hashed_password().is_none() && others.count() == 0 {
      return Err(only_way_to_log_in());
    }
  }
  auth
    .unlink_external_login(user.id().to_string(), provider_id)
    .await?;
  Ok(())
}

impl Resolve<ManageArgs> for UnlinkExternalLogin {
  #[instrument(
    "UnlinkExternalLogin",
    skip_all,
    fields(
      user_id = args.user.id(),
      username = args.user.username(),
      provider_id = self.provider_id
    )
  )]
  async fn resolve(
    self,
    args: &ManageArgs,
  ) -> Result<Self::Response, Self::Error> {
    let ManageArgs { auth, user, .. } = args;
    unlink_external_login(
      auth.as_ref(),
      user.as_ref().as_ref(),
      self.provider_id.clone(),
    )
    .await?;
    args
      .credentials_changed(CredentialChange::ExternalLoginUnlinked {
        provider_id: self.provider_id,
      })
      .await?;
    Ok(UnlinkExternalLoginResponse {})
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Removes whatever it is asked to.
  struct UnlinkAuth;

  impl AuthImpl for UnlinkAuth {
    fn new() -> Self {
      UnlinkAuth
    }
    fn get_user(
      &self,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<crate::user::BoxAuthUser>>
    {
      unimplemented!()
    }
    fn handle_request_authentication(
      &self,
      _: crate::RequestAuthentication,
      _: std::net::IpAddr,
      _: bool,
      _: axum::extract::Request,
    ) -> crate::DynFuture<mogh_error::Result<axum::extract::Request>>
    {
      unimplemented!()
    }
    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      unimplemented!()
    }
    fn unlink_local_login(
      &self,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
    fn unlink_external_login(
      &self,
      _: String,
      _: String,
    ) -> crate::DynFuture<mogh_error::Result<()>> {
      Box::pin(async { Ok(()) })
    }
  }

  struct LoginsUser {
    password: bool,
    /// `None`: the app doesn't tell.
    providers: Option<Vec<String>>,
  }

  impl AuthUserImpl for LoginsUser {
    fn id(&self) -> &str {
      "user"
    }
    fn username(&self) -> &str {
      "user"
    }
    fn hashed_password(&self) -> Option<&str> {
      self.password.then_some("$2b$04$hash")
    }
    fn external_login_provider_ids(&self) -> Option<&[String]> {
      self.providers.as_deref()
    }
  }

  fn user(password: bool, providers: Option<&[&str]>) -> LoginsUser {
    LoginsUser {
      password,
      providers: providers.map(|providers| {
        providers.iter().map(|id| id.to_string()).collect()
      }),
    }
  }

  fn assert_only_way(res: mogh_error::Result<()>, what: &str) {
    let err = res.expect_err(what);
    assert_eq!(err.status, StatusCode::BAD_REQUEST, "{what}");
    assert_eq!(
      format!("{:#}", err.error),
      "Cannot remove the only way to log in",
      "{what}"
    );
  }

  /// The password goes only when a linked provider remains.
  #[tokio::test]
  async fn test_unlink_local_login_keeps_a_way_to_log_in() {
    assert_only_way(
      unlink_local_login(&UnlinkAuth, &user(true, Some(&[]))).await,
      "password only",
    );
    unlink_local_login(&UnlinkAuth, &user(true, Some(&["oidc"])))
      .await
      .unwrap();
    // Unknown to the server: up to the app.
    unlink_local_login(&UnlinkAuth, &user(true, None))
      .await
      .unwrap();
  }

  /// A linked provider goes only when the password, or another one,
  /// remains.
  #[tokio::test]
  async fn test_unlink_external_login_keeps_a_way_to_log_in() {
    let unlink = |user: LoginsUser, provider_id: &str| {
      let provider_id = provider_id.to_string();
      async move {
        unlink_external_login(&UnlinkAuth, &user, provider_id).await
      }
    };
    assert_only_way(
      unlink(user(false, Some(&["oidc"])), "oidc").await,
      "only link",
    );
    // Nothing would be left either way.
    assert_only_way(
      unlink(user(false, Some(&[])), "oidc").await,
      "not linked",
    );
    for (password, providers) in [
      (true, &["oidc"][..]),
      (false, &["oidc", "github"][..]),
      (true, &["oidc", "github"][..]),
    ] {
      unlink(user(password, Some(providers)), "oidc")
        .await
        .unwrap();
    }
    unlink(user(false, None), "oidc").await.unwrap();
    // The provider id is checked first.
    let err = unlink(user(false, Some(&["oidc"])), "../etc")
      .await
      .unwrap_err();
    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert!(
      !format!("{:#}", err.error).contains("only way"),
      "{:#}",
      err.error
    );
  }
}
