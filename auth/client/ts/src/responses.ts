import * as Types from "./types.js";

export type LoginResponses = {
  GetLoginOptions: Types.GetLoginOptionsResponse;
  SignUpLocalUser: Types.SignUpLocalUserResponse;
  LoginLocalUser: Types.LoginLocalUserResponse;
  ExchangeForJwt: Types.ExchangeForJwtResponse;
  CompleteTotpLogin: Types.CompleteTotpLoginResponse;
  CompletePasskeyLogin: Types.CompletePasskeyLoginResponse;
};

export type ManageResponses = {
  // Local
  UpdateUsername: Types.UpdateUsernameResponse;
  UpdatePassword: Types.UpdatePasswordResponse;
  // External
  BeginExternalLoginLink: Types.BeginExternalLoginLinkResponse;
  UnlinkLogin: Types.UnlinkLoginResponse;
  // Passkey
  BeginPasskeyEnrollment: Types.BeginPasskeyEnrollmentResponse;
  ConfirmPasskeyEnrollment: Types.ConfirmPasskeyEnrollmentResponse;
  UnenrollPasskey: Types.UnenrollPasskeyResponse;
  // Totp
  BeginTotpEnrollment: Types.BeginTotpEnrollmentResponse;
  ConfirmTotpEnrollment: Types.ConfirmTotpEnrollmentResponse;
  UnenrollTotp: Types.UnenrollTotpResponse;
  // Skip
  UpdateExternalSkip2fa: Types.UpdateExternalSkip2faResponse;
  // API KEY
  CreateApiKey: Types.CreateApiKeyResponse;
  DeleteApiKey: Types.DeleteApiKeyResponse;
  CreateApiKeyV2: Types.CreateApiKeyV2Response;
  DeleteApiKeyV2: Types.DeleteApiKeyV2Response;
};
