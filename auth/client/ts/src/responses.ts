import * as Types from "./types.js";

export type AuthResponses = {
  GetLoginOptions: Types.GetLoginOptionsResponse;
  SignUpLocalUser: Types.SignUpLocalUserResponse;
  LoginLocalUser: Types.LoginLocalUserResponse;
  ExchangeForJwt: Types.ExchangeForJwtResponse;
  CompleteTotpLogin: Types.CompleteTotpLoginResponse;
  CompletePasskeyLogin: Types.CompletePasskeyLoginResponse;
};
