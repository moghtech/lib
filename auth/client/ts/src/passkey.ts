import { Types } from "./lib";

/**
 ## USAGE:
 ```
 navigator.credentials
  .get(prepareRequestChallengeResponse(requestChallengeResponse))
  .then((credential) => completePasskeyLogin({ credential }))
 ```
 */
export const prepareRequestChallengeResponse = (
  challenge: Types.RequestChallengeResponse
) => {
  return {
    ...challenge,
    publicKey: {
      ...challenge.publicKey,
      challenge: base64urlToArrayBuffer(challenge.publicKey.challenge),
      allowCredentials: challenge.publicKey.allowCredentials?.map(
        (cred: any) => ({
          ...cred,
          id: base64urlToArrayBuffer(cred.id),
        })
      ),
    },
  };
};

/**
 ## USAGE:
 ```
 navigator.credentials
  .create(prepareCreationChallengeResponse(creationChallengeResponse))
  .then((credential) => confirmPasskeyEnrollment({ credential }))
 ```
 */
export const prepareCreationChallengeResponse = (
  challenge: Types.CreationChallengeResponse
) => {
  return {
    ...challenge,
    publicKey: {
      ...challenge.publicKey,
      challenge: base64urlToArrayBuffer(challenge.publicKey.challenge),
      user: {
        ...challenge.publicKey.user,
        id: base64urlToArrayBuffer(challenge.publicKey.user.id),
      },
      excludeCredentials: challenge.publicKey.excludeCredentials?.map(
        (cred: any) => ({ ...cred, id: base64urlToArrayBuffer(cred.id) })
      ),
    },
  };
};

export const base64urlToArrayBuffer = (base64url: any) => {
  // Convert from URL-safe base64 to normal base64
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad =
    base64.length % 4 === 0 ? "" : "=".repeat(4 - (base64.length % 4));
  const bstr = atob(base64 + pad);
  const bytes = new Uint8Array(bstr.length);
  for (let i = 0; i < bstr.length; i++) {
    bytes[i] = bstr.charCodeAt(i);
  }
  return bytes.buffer;
};

export const arrayBufferToBase64url = (buffer: any) => {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
