import * as MoghAuth from "mogh_auth_client";

// The passkey of a login's second factor. Not exported from the
// package.

/** A passkey request, for `navigator.credentials.get`. */
export type PasskeyRequest = ReturnType<
  typeof MoghAuth.Passkey.prepareRequestChallengeResponse
>;

/**
 * The passkey request an external login returns with for its second
 * factor (the `passkey` param of the url). Throws for one which can't
 * be read: a link can carry anything.
 */
export function passkeyRequestFromParam(encoded: string): PasskeyRequest {
  return MoghAuth.Passkey.prepareRequestChallengeResponse(
    JSON.parse(MoghAuth.Passkey.base64UrlDecode(encoded)),
  );
}
