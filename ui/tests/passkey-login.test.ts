import { test } from "node:test";
import assert from "node:assert/strict";
import { passkeyRequestFromParam } from "../src/auth/passkey-login.ts";

// The `passkey` param an external login returns with: the server's
// request challenge, as base64url json. The login page keeps the
// request it reads from it, for "Try Again".
const encode = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

test("the passkey param of the url is the request for the browser", () => {
  const challenge = Buffer.from("the challenge").toString("base64url");
  const request = passkeyRequestFromParam(
    encode({
      publicKey: {
        challenge,
        rpId: "app.example",
        allowCredentials: [{ type: "public-key", id: challenge }],
      },
    }),
  );
  assert.equal(request.publicKey.rpId, "app.example");
  assert.equal(
    Buffer.from(request.publicKey.challenge as ArrayBuffer).toString(),
    "the challenge",
  );
  assert.equal(request.publicKey.allowCredentials?.length, 1);
});

test("a passkey param which can't be read throws", () => {
  // A link can carry anything here.
  for (const garbage of ["garbage", encode("not an object"), encode({})]) {
    assert.throws(() => passkeyRequestFromParam(garbage), garbage);
  }
});
