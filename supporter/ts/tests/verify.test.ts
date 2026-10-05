import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  SupporterKeyError,
  base64urlDecode,
  base64urlEncode,
  checkSupporterKey,
  newNonce,
  rootKeyId,
  verifySupporterKey,
  type SignedSupporterKey,
} from "../src/index.ts";
import * as fixture from "./fixture.ts";

const OPTIONS = {
  app: fixture.APP,
  releaseDate: "2026-11-01",
  nonce: fixture.NONCE_BYTES,
  response: fixture.RESPONSE,
  rootKeys: fixture.ROOT_KEYS,
  revoked: [] as string[],
};

/** Runs `checkSupporterKey` and returns the reason it refused with. */
async function reason(options: Partial<typeof OPTIONS> & { response?: unknown }) {
  try {
    await checkSupporterKey({ ...OPTIONS, ...options } as never);
  } catch (e) {
    assert.ok(e instanceof Error, String(e));
    return `${e.name}: ${e.message}`;
  }
  assert.fail("The key verified");
}

/** The fixture response with one field replaced. */
function withField(name: keyof SignedSupporterKey, value: string) {
  return { ...fixture.RESPONSE, [name]: value };
}

/** The fixture response with one byte of `payload` changed. */
function withPayloadByte(at: number, change: (byte: number) => number) {
  const payload = base64urlDecode(fixture.RESPONSE.payload);
  payload[at] = change(payload[at]) & 0xff;
  return withField("payload", base64urlEncode(payload));
}

describe("the fixture response", () => {
  test("shows the badge for komodo on a covered release", async () => {
    const supporter = await checkSupporterKey(OPTIONS);
    assert.deepEqual(supporter, fixture.SUPPORTER);
    assert.deepEqual(await verifySupporterKey(OPTIONS), fixture.SUPPORTER);
    // A `Nonce` works like its bytes.
    const nonce = { bytes: fixture.NONCE_BYTES, encoded: fixture.NONCE };
    assert.deepEqual(await checkSupporterKey({ ...OPTIONS, nonce }), fixture.SUPPORTER);
  });

  test("covers releases up to its date, inclusive", async () => {
    assert.ok(await verifySupporterKey({ ...OPTIONS, releaseDate: "2027-09-30" }));
    assert.ok(await verifySupporterKey({ ...OPTIONS, releaseDate: "2025-01-01" }));
    assert.match(await reason({ releaseDate: "2027-10-01" }), /covers releases up to 2027-09-30, this release is 2027-10-01/);
    assert.match(await reason({ releaseDate: "2028-01-01" }), /covers releases up to/);
    // A release date which is no date is no badge either.
    assert.match(await reason({ releaseDate: "2027-9-30" }), /release date is not/);
    assert.match(await reason({ releaseDate: "" }), /release date is not/);
    assert.match(await reason({ releaseDate: undefined as never }), /release date is not/);
  });

  test("is no badge once revoked", async () => {
    assert.match(await reason({ revoked: [fixture.ID] }), /is revoked/);
    assert.match(await reason({ revoked: ["other", fixture.ID] }), /is revoked/);
    assert.ok(await verifySupporterKey({ ...OPTIONS, revoked: ["0190a3c2-7b6a-7cc2-b1f0-4a5d9e3c8f22"] }));
    // Only the exact lowercase hyphenated form is the id.
    assert.ok(await verifySupporterKey({ ...OPTIONS, revoked: [fixture.ID.toUpperCase()] }));
  });

  test("is for komodo only", async () => {
    assert.match(await reason({ app: "cicada" }), /is for `komodo`, this app is `cicada`/);
    assert.match(await reason({ app: "" }), /is for `komodo`/);
    assert.match(await reason({ app: "Komodo" }), /is for `komodo`/);
  });

  test("verifies for its nonce only", async () => {
    const other = new Uint8Array(32).fill(2);
    assert.match(await reason({ nonce: other }), /nonce signature does not verify/);
    const almost = new Uint8Array(32).fill(1);
    almost[31] = 0;
    assert.match(await reason({ nonce: almost }), /nonce signature does not verify/);
    assert.match(await reason({ nonce: new Uint8Array(31).fill(1) }), /nonce is 31 bytes/);
    assert.match(await reason({ nonce: new Uint8Array(33).fill(1) }), /nonce is 33 bytes/);
    assert.match(await reason({ nonce: new Uint8Array(0) }), /nonce is 0 bytes/);
  });

  test("needs its root key", async () => {
    // The root is found by the id derived from its key.
    assert.equal(await rootKeyId(fixture.ROOT_SPKI), fixture.ROOT_KID);
    assert.match(await reason({ rootKeys: [] }), /No root key with the id fe812c12f3ab4ce6/);
    // Another key (the example key of RFC 8410) does not stand in.
    const other = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
    assert.match(await reason({ rootKeys: [other] }), /No root key with the id fe812c12f3ab4ce6/);
    // Among several, and entries which are no key: passed over.
    const several = [other, "not a key", 5 as never, fixture.ROOT_SPKI];
    assert.ok(await verifySupporterKey({ ...OPTIONS, rootKeys: several }));
    assert.match(await reason({ rootKeys: ["not a key", 5 as never] }), /No root key/);
    // An X25519 key is no root key.
    const x25519 = ["MCowBQYDK2VuAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="];
    assert.match(await reason({ rootKeys: x25519 }), /No root key/);
    // The old form, ids to keys, is refused whole.
    assert.match(
      await reason({ rootKeys: { [fixture.ROOT_KID]: fixture.ROOT_SPKI } as never }),
      /No root keys are given/,
    );
  });

  test("fails for another instance key", async () => {
    // Who has the payload and root signature, but not the instance
    // private key, can sign the nonce with a key of their own.
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const payload = base64urlDecode(fixture.RESPONSE.payload);
    const message = new Uint8Array([
      ...new TextEncoder().encode("komodo-supporter-v1"),
      ...fixture.NONCE_BYTES,
      ...new Uint8Array(await crypto.subtle.digest("SHA-256", payload)),
    ]);
    const nonceSig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, message));
    const forged = {
      ...fixture.RESPONSE,
      instance_public_key: base64urlEncode(publicKey),
      nonce_sig: base64urlEncode(nonceSig),
    };
    assert.match(await reason({ response: forged }), /root signature does not verify/);
    // The real instance public key with the forged signature.
    assert.match(
      await reason({ response: { ...fixture.RESPONSE, nonce_sig: base64urlEncode(nonceSig) } }),
      /nonce signature does not verify/,
    );
  });

  test("fails when any byte of the payload changes", async () => {
    const payload = base64urlDecode(fixture.RESPONSE.payload);
    assert.equal(payload.length, 96);
    for (let at = 0; at < payload.length; at++) {
      const response = withPayloadByte(at, (byte) => byte ^ 0x01);
      assert.equal(await verifySupporterKey({ ...OPTIONS, response }), null, `byte ${at}`);
    }
    // One which still decodes: the `A` of `Acme Corp` to `B`.
    const at = fixture.PAYLOAD_HEX.indexOf("41636d65") / 2;
    assert.match(await reason({ response: withPayloadByte(at, () => 0x42) }), /root signature does not verify/);
  });

  test("fails for a changed signature, key or nonce signature", async () => {
    for (const name of ["payload_sig", "instance_public_key", "nonce_sig"] as const) {
      const bytes = base64urlDecode(fixture.RESPONSE[name]);
      bytes[0] ^= 0x80;
      assert.equal(await verifySupporterKey({ ...OPTIONS, response: withField(name, base64urlEncode(bytes)) }), null, name);
    }
  });
});

describe("the response", () => {
  test("null or undefined is no badge", async () => {
    assert.match(await reason({ response: null }), /No supporter key is configured/);
    assert.match(await reason({ response: undefined }), /No supporter key is configured/);
    assert.equal(await verifySupporterKey({ ...OPTIONS, response: null }), null);
  });

  test("is checked field by field", async () => {
    assert.match(await reason({ response: "text" }), /not an object/);
    assert.match(await reason({ response: {} }), /`payload` of the response is not text/);
    assert.match(await reason({ response: { ...fixture.RESPONSE, nonce_sig: 5 } }), /`nonce_sig` of the response is not text/);
    assert.match(await reason({ response: withField("payload", fixture.RESPONSE.payload + "=") }), /`payload` of the response is not base64url/);
    assert.match(await reason({ response: withField("payload", "") }), /payload is 0 bytes/);
    assert.match(await reason({ response: withField("payload", base64urlEncode(new Uint8Array(4097))) }), /payload is 4097 bytes/);
    assert.match(await reason({ response: withField("payload_sig", fixture.RESPONSE.payload_sig.slice(0, -6)) }), /`payload_sig` of the response is 60 bytes, expected 64/);
    assert.match(await reason({ response: withField("instance_public_key", fixture.RESPONSE.instance_public_key + "A") }), /`instance_public_key` of the response is 33 bytes, expected 32/);
    assert.match(await reason({ response: withField("nonce_sig", fixture.RESPONSE.nonce_sig.replace("_", "/")) }), /`nonce_sig` of the response is not base64url/);
    assert.match(await reason({ response: withField("nonce_sig", " " + fixture.RESPONSE.nonce_sig) }), /`nonce_sig` of the response is not base64url/);
    // A payload which is no CBOR map.
    assert.match(await reason({ response: withField("payload", base64urlEncode(new Uint8Array([0x80]))) }), /payload is not a map/);
    assert.match(await reason({ response: withField("payload", base64urlEncode(new Uint8Array([0xa0]))) }), /payload has no `k`/);
    assert.match(await reason({ response: withField("payload", base64urlEncode(new Uint8Array([0xff]))) }), /CborError/);
  });

  test("never throws out of verifySupporterKey", async () => {
    const debug = console.debug;
    const logged: unknown[][] = [];
    console.debug = (...args: unknown[]) => void logged.push(args);
    try {
      const throwing = {
        get payload(): string {
          throw new Error("getter");
        },
      };
      for (const response of [null, undefined, 5, "x", [], {}, throwing, { payload: {} }]) {
        assert.equal(await verifySupporterKey({ ...OPTIONS, response: response as never }), null);
      }
      assert.equal(await verifySupporterKey({ ...OPTIONS, nonce: null as never }), null);
      assert.equal(await verifySupporterKey({ ...OPTIONS, rootKeys: null as never }), null);
      // An app which forgot its root keys: no badge, with the reason.
      assert.equal(await verifySupporterKey({ ...OPTIONS, rootKeys: undefined as never }), null);
      assert.match(String(logged.at(-1)?.[1]), /No root keys are given/);
      assert.equal(await verifySupporterKey({ ...OPTIONS, revoked: null as never }), null);
      assert.equal(await verifySupporterKey({ ...OPTIONS, subtle: {} as never }), null);
      assert.equal(logged.length, 13);
      assert.ok(logged.every(([first]) => first === "No supporter badge:"));
      assert.match(String(logged[0][1]), /SupporterKeyError: No supporter key is configured/);
    } finally {
      console.debug = debug;
    }
  });
});

test("nonces are 32 random bytes", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 100; i++) {
    const nonce = newNonce();
    assert.equal(nonce.bytes.length, 32);
    assert.equal(nonce.encoded.length, 43);
    assert.deepEqual(base64urlDecode(nonce.encoded), nonce.bytes);
    seen.add(nonce.encoded);
  }
  assert.equal(seen.size, 100);
});

test("root key ids are the hash of the raw key", async () => {
  assert.equal(await rootKeyId(fixture.ROOT_SPKI), fixture.ROOT_KID);
  assert.equal(await rootKeyId(` ${fixture.ROOT_SPKI}\n`), fixture.ROOT_KID);
  await assert.rejects(rootKeyId("not a key"), /base64/);
  await assert.rejects(rootKeyId("MCowBQYDK2VuAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="), /not the SPKI DER/);
  // Valid base64 of another length than an Ed25519 SPKI.
  await assert.rejects(rootKeyId(fixture.ROOT_SPKI.slice(0, 56)), /not the SPKI DER/);
});

test("errors are SupporterKeyErrors with the reason", async () => {
  await assert.rejects(
    checkSupporterKey({ ...OPTIONS, releaseDate: "2027-10-01" }),
    (e: unknown) => e instanceof SupporterKeyError && /covers/.test(e.message),
  );
});
