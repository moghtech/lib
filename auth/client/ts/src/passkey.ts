export const preparePasskeyCredential = (data: any) => {
  return {
    ...data,
    publicKey: {
      ...data.publicKey,
      challenge: base64urlToArrayBuffer(data.publicKey.challenge),
      allowCredentials: data.publicKey.allowCredentials?.map((cred: any) => ({
        ...cred,
        id: base64urlToArrayBuffer(cred.id),
      })),
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
