use anyhow::Context as _;
use axum::http::StatusCode;
use data_encoding::BASE32_NOPAD;
use mogh_auth_client::api::manage::{
  BeginTotpEnrollment, BeginTotpEnrollmentResponse,
  ConfirmTotpEnrollment, ConfirmTotpEnrollmentResponse, UnenrollTotp,
  UnenrollTotpResponse,
};
use mogh_error::AddStatusCode as _;
use mogh_resolver::Resolve;
use tracing::{error, info, instrument};
use zeroize::Zeroizing;

use crate::{
  AuthImpl, CredentialChange,
  api::manage::ManageArgs,
  bcrypt_pool::spawn_bcrypt,
  rand::{random_bytes, random_string},
};

/// In bytes: 320 bits (RFC 4226 asks for at least 128, and
/// recommends 160).
const TOTP_ENROLLMENT_SECRET_LENGTH: usize = 40;

/// How many recovery codes an enrollment gives.
const RECOVERY_CODE_COUNT: usize = 10;

/// Random alphanumeric characters, about 119 bits.
const RECOVERY_CODE_LENGTH: usize = 20;

/// The bcrypt cost recovery codes are hashed with: the minimum (4).
///
/// The cost slows down guessing a secret from its hash, which only
/// matters for secrets a person picks (passwords). Random recovery
/// codes can't be guessed at any speed, while the cost is paid for
/// each code at enrollment, and for each unused code on every
/// recovery login (a wrong code is checked against all of them).
/// Codes hashed with a higher cost before still verify, bcrypt reads
/// the cost from the hash.
const RECOVERY_CODE_BCRYPT_COST: u32 = 4;

/// Hashes the recovery codes for storage, in one task off the
/// async runtime.
async fn hash_recovery_codes(
  codes: Vec<String>,
) -> anyhow::Result<Vec<String>> {
  let codes = Zeroizing::new(codes);
  spawn_bcrypt(move || {
    codes
      .iter()
      .map(|code| {
        bcrypt::hash(code, RECOVERY_CODE_BCRYPT_COST)
          .context("Failed to hash a recovery code.")
      })
      .collect()
  })
  .await?
}

//

impl Resolve<ManageArgs> for BeginTotpEnrollment {
  #[instrument(
    "BeginTotpEnrollment",
    skip_all,
    fields(
      user_id = user.id(),
      username = user.username(),
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
    auth.check_username_locked(user.username())?;

    let totp = auth.make_totp(
      random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH),
      Some(user.id().to_string()),
    )?;

    let png = totp
      .to_qr_base64()
      .map_err(anyhow::Error::msg)
      .context("Failed to generate QR code png")?;
    let uri =
      totp.to_url().context("Failed to generate QR code uri")?;

    session.insert_totp_enrollment(user.id(), &totp).await?;

    info!("Totp 2FA enrollment flow initiated");

    Ok(BeginTotpEnrollmentResponse { uri, png })
  }
}

//

impl Resolve<ManageArgs> for ConfirmTotpEnrollment {
  #[instrument(
    "ConfirmTotpEnrollment",
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
    let ManageArgs {
      auth,
      user,
      session,
      ..
    } = args;
    // Checked again, the lock may have been added since the
    // enrollment began.
    auth.check_username_locked(user.username())?;

    // Only the user who began the enrollment can confirm it.
    let totp = session.retrieve_totp_enrollment(user.id()).await?;

    // The step is the 30s window since epoch
    // which the TOTP is valid for.
    let step = totp
      .check_current(&self.code)
      .context("The provided code was not valid. Please try BeginTotpEnrollment flow again.")
      .status_code(StatusCode::BAD_REQUEST)?;

    let recovery_codes = (0..RECOVERY_CODE_COUNT)
      .map(|_| random_string(RECOVERY_CODE_LENGTH))
      .collect::<Vec<_>>();
    let hashed_recovery_codes =
      hash_recovery_codes(recovery_codes.clone())
        .await
        .context("Failed to generate valid recovery codes")?;

    auth
      .update_user_stored_totp(
        user.id().to_string(),
        BASE32_NOPAD.encode(totp.secret()),
        hashed_recovery_codes,
      )
      .await?;

    // Consume the step so the enrollment code cannot be replayed
    // as a login code in the same window. Done after persisting
    // so a storage failure leaves the code usable for a retry,
    // and an already consumed step (re-enrollment within the
    // window) does not fail the enrollment.
    let _ = auth.consume_totp_step(user.id().to_string(), step).await;

    info!("TOTP 2FA enrollment complete");

    // The recovery codes are shown once, in this response, and the
    // enrollment is in effect already: an error of the app's hook
    // must not keep them from the user, who could only enroll again
    // to get new ones. It is logged instead.
    if let Err(e) = args
      .credentials_changed(CredentialChange::TotpEnrolled)
      .await
    {
      error!(
        "TOTP was enrolled, but the app failed to handle the credential change. \
         The user's other sessions may not have ended | {:#}",
        e.error
      );
    }

    Ok(ConfirmTotpEnrollmentResponse { recovery_codes })
  }
}

//

pub async fn unenroll_totp<I: AuthImpl + ?Sized>(
  auth: &I,
  username: &str,
  user_id: String,
) -> mogh_error::Result<()> {
  auth.check_username_locked(username)?;
  auth.remove_user_stored_totp(user_id).await?;
  Ok(())
}

impl Resolve<ManageArgs> for UnenrollTotp {
  #[instrument(
    "UnenrollTotp",
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
    unenroll_totp(
      auth.as_ref(),
      user.username(),
      user.id().to_string(),
    )
    .await?;

    info!("User unenrolled TOTP 2FA");

    args
      .credentials_changed(CredentialChange::TotpUnenrolled)
      .await?;

    Ok(UnenrollTotpResponse {})
  }
}

#[cfg(test)]
mod tests {
  use axum::extract::Request;
  use data_encoding::BASE32_NOPAD;

  use super::*;
  use crate::{
    DynFuture, RequestAuthentication, rand::random_bytes,
    user::BoxAuthUser,
  };

  struct TestAuth;

  impl AuthImpl for TestAuth {
    fn new() -> Self {
      TestAuth
    }

    fn app_name(&self) -> &'static str {
      "TestApp"
    }

    fn get_user(
      &self,
      _user_id: String,
    ) -> DynFuture<mogh_error::Result<BoxAuthUser>> {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn handle_request_authentication(
      &self,
      _auth: RequestAuthentication,
      _ip: std::net::IpAddr,
      _require_user_enabled: bool,
      _req: Request,
    ) -> DynFuture<mogh_error::Result<Request>> {
      Box::pin(async {
        Err(anyhow::anyhow!("not implemented").into())
      })
    }

    fn jwt_provider(&self) -> &crate::provider::jwt::JwtProvider {
      panic!("not needed for these tests")
    }
  }

  #[test]
  fn test_totp_current_code_round_trip() {
    let auth = TestAuth;
    let totp = auth
      .make_totp(random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH), None)
      .unwrap();
    let code = totp.generate_current().to_string();
    assert_eq!(code.len(), 6);
    assert!(totp.check_current(&code).is_some());
  }

  #[test]
  fn test_totp_rejects_wrong_code() {
    let auth = TestAuth;
    let totp = auth
      .make_totp(random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH), None)
      .unwrap();
    let code = totp.generate_current().to_string();
    // Flip the first digit
    let first = code.chars().next().unwrap();
    let flipped = if first == '9' { '0' } else { '9' };
    let wrong = format!("{flipped}{}", &code[1..]);
    assert!(totp.check_current(&wrong).is_none());
  }

  #[test]
  fn test_totp_rejects_malformed_code() {
    let auth = TestAuth;
    let totp = auth
      .make_totp(random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH), None)
      .unwrap();
    assert!(totp.check_current("").is_none());
    assert!(totp.check_current("not-a-code").is_none());
    assert!(totp.check_current("12345").is_none());
  }

  #[tokio::test]
  async fn test_recovery_codes_hash_cheaply() {
    let codes = (0..RECOVERY_CODE_COUNT)
      .map(|_| random_string(RECOVERY_CODE_LENGTH))
      .collect::<Vec<_>>();
    let hashed = hash_recovery_codes(codes.clone()).await.unwrap();
    assert_eq!(hashed.len(), RECOVERY_CODE_COUNT);
    for (code, hash) in codes.iter().zip(&hashed) {
      assert!(hash.starts_with("$2b$04$"), "{hash}");
      assert!(bcrypt::verify(code, hash).unwrap());
    }
    assert!(!bcrypt::verify(&codes[1], &hashed[0]).unwrap());
  }

  /// The TOTP secrets [FailingHookAuth] stored, by user.
  static STORED: std::sync::Mutex<Vec<(String, String)>> =
    std::sync::Mutex::new(Vec::new());

  /// Stores TOTP enrollments, and fails to handle every credential
  /// change.
  struct FailingHookAuth;

  impl AuthImpl for FailingHookAuth {
    fn new() -> Self {
      FailingHookAuth
    }
    fn app_name(&self) -> &'static str {
      "TestApp"
    }
    crate::test_support::stub_auth_impl!(
      get_user,
      handle_request_authentication,
      jwt_provider
    );
    fn update_user_stored_totp(
      &self,
      user_id: String,
      encoded_secret: String,
      _hashed_recovery_codes: Vec<String>,
    ) -> DynFuture<mogh_error::Result<()>> {
      STORED.lock().unwrap().push((user_id, encoded_secret));
      Box::pin(async { Ok(()) })
    }
    fn remove_user_stored_totp(
      &self,
      user_id: String,
    ) -> DynFuture<mogh_error::Result<()>> {
      STORED.lock().unwrap().retain(|(id, _)| *id != user_id);
      Box::pin(async { Ok(()) })
    }
    fn credentials_changed(
      &self,
      _user_id: String,
      _change: CredentialChange,
      _kept_jwt: Option<String>,
    ) -> DynFuture<mogh_error::Result<()>> {
      Box::pin(async {
        Err(anyhow::anyhow!("the session store is down").into())
      })
    }
  }

  /// A user of its own: the default
  /// [AuthImpl::consume_totp_step] keeps the steps of every user in
  /// the process, which the tests share.
  struct TestUser;

  impl crate::user::AuthUserImpl for TestUser {
    fn id(&self) -> &str {
      "enrollment-hook-user"
    }
    fn username(&self) -> &str {
      "user"
    }
  }

  /// The recovery codes are shown once, in the response of the
  /// enrollment, which is stored by then: an app failing to handle
  /// the change doesn't keep them from the user. Other changes fail
  /// the request, see [AuthImpl::credentials_changed].
  #[tokio::test]
  async fn test_a_failed_change_hook_still_returns_the_recovery_codes()
   {
    let args = ManageArgs {
      auth: std::sync::Arc::new(FailingHookAuth),
      user: std::sync::Arc::new(Box::new(TestUser)),
      session: crate::test_support::session(),
      jwt: Some(String::from("the-session")),
    };
    let totp = FailingHookAuth
      .make_totp(random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH), None)
      .unwrap();
    args
      .session
      .insert_totp_enrollment("enrollment-hook-user", &totp)
      .await
      .unwrap();
    let response = ConfirmTotpEnrollment {
      code: totp.generate_current().to_string(),
    }
    .resolve(&args)
    .await
    .unwrap();
    assert_eq!(response.recovery_codes.len(), RECOVERY_CODE_COUNT);
    assert_eq!(
      *STORED.lock().unwrap(),
      [(
        String::from("enrollment-hook-user"),
        BASE32_NOPAD.encode(totp.secret())
      )]
    );

    let err = UnenrollTotp {}.resolve(&args).await.unwrap_err();
    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(STORED.lock().unwrap().is_empty());
  }

  #[test]
  fn test_totp_secret_base32_storage_round_trip() {
    // Enrollment stores BASE32_NOPAD(secret) (ConfirmTotpEnrollment),
    // login decodes it back (CompleteTotpLogin). A code generated by
    // the enrollment Totp must validate on the login Totp.
    let auth = TestAuth;
    let enrollment_totp = auth
      .make_totp(
        random_bytes(TOTP_ENROLLMENT_SECRET_LENGTH),
        Some("user-id".to_string()),
      )
      .unwrap();

    let stored = BASE32_NOPAD.encode(enrollment_totp.secret());
    let secret_bytes =
      BASE32_NOPAD.decode(stored.as_bytes()).unwrap();
    let login_totp = auth.make_totp(secret_bytes, None).unwrap();

    let code = enrollment_totp.generate_current().to_string();
    assert!(login_totp.check_current(&code).is_some());
  }
}
