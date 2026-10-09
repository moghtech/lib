import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  SupporterKeyError,
  base64urlDecode,
  base64urlEncode,
  checkRootKeys,
  checkSupporterKey,
  findRootKey,
  newNonce,
  rootKeyId,
  verifySupporterKey,
  type SignedSupporterKey,
} from "../src/index.ts";
import * as fixture from "./fixture.ts";

/** Node's WebCrypto, which does Ed25519: the tests' secure page. */
const SUBTLE = crypto.subtle;

const OPTIONS = {
  app: fixture.APP,
  releaseDate: "2026-11-01",
  nonce: fixture.NONCE_BYTES,
  response: fixture.RESPONSE,
  rootKeys: fixture.ROOT_KEYS,
  revoked: [] as string[],
};

type Options = Partial<typeof OPTIONS> & {
  response?: unknown;
  subtle?: SubtleCrypto | null;
};

/** Runs `checkSupporterKey` and returns the reason it refused with. */
async function reason(options: Options) {
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

/**
 * Every verdict, with each of the two implementations: the page's
 * WebCrypto (the default where it does Ed25519), and the JavaScript one
 * of `@noble/ed25519` and `@noble/hashes` (`subtle: null`, what a page
 * without WebCrypto gets). Same responses, same verdicts, same reasons.
 */
for (const [implementation, subtle] of [
  ["WebCrypto", undefined],
  ["JavaScript", null],
] as const) {
  /** `reason`, with this implementation. */
  const refused = (options: Options) => reason({ subtle, ...options });
  /** `verifySupporterKey`, with this implementation. */
  const verify = (options: Options) =>
    verifySupporterKey({ ...OPTIONS, subtle, ...options } as never);

  describe(`the fixture response (${implementation})`, () => {
    test("shows the badge for komodo on a covered release", async () => {
      const supporter = await checkSupporterKey({ ...OPTIONS, subtle });
      assert.deepEqual(supporter, fixture.SUPPORTER);
      assert.deepEqual(await verify({}), fixture.SUPPORTER);
      // A `Nonce` works like its bytes.
      const nonce = { bytes: fixture.NONCE_BYTES, encoded: fixture.NONCE };
      assert.deepEqual(await checkSupporterKey({ ...OPTIONS, subtle, nonce }), fixture.SUPPORTER);
    });

    test("covers releases up to its date, inclusive", async () => {
      assert.ok(await verify({ releaseDate: "2027-09-30" }));
      assert.ok(await verify({ releaseDate: "2025-01-01" }));
      assert.match(await refused({ releaseDate: "2027-10-01" }), /covers releases up to 2027-09-30, this release is 2027-10-01/);
      assert.match(await refused({ releaseDate: "2028-01-01" }), /covers releases up to/);
      // A release date which is no date is no badge either.
      assert.match(await refused({ releaseDate: "2027-9-30" }), /release date is not/);
      assert.match(await refused({ releaseDate: "" }), /release date is not/);
      assert.match(await refused({ releaseDate: undefined as never }), /release date is not/);
    });

    test("is no badge once revoked", async () => {
      assert.match(await refused({ revoked: [fixture.ID] }), /is revoked/);
      assert.match(await refused({ revoked: ["other", fixture.ID] }), /is revoked/);
      assert.ok(await verify({ revoked: ["0190a3c2-7b6a-7cc2-b1f0-4a5d9e3c8f22"] }));
      // Only the exact lowercase hyphenated form is the id.
      assert.ok(await verify({ revoked: [fixture.ID.toUpperCase()] }));
    });

    test("is for komodo only", async () => {
      assert.match(await refused({ app: "cicada" }), /is for `komodo`, this app is `cicada`/);
      assert.match(await refused({ app: "" }), /is for `komodo`/);
      assert.match(await refused({ app: "Komodo" }), /is for `komodo`/);
    });

    test("verifies for its nonce only", async () => {
      const other = new Uint8Array(32).fill(2);
      assert.match(await refused({ nonce: other }), /nonce signature does not verify/);
      const almost = new Uint8Array(32).fill(1);
      almost[31] = 0;
      assert.match(await refused({ nonce: almost }), /nonce signature does not verify/);
      assert.match(await refused({ nonce: new Uint8Array(31).fill(1) }), /nonce is 31 bytes/);
      assert.match(await refused({ nonce: new Uint8Array(33).fill(1) }), /nonce is 33 bytes/);
      assert.match(await refused({ nonce: new Uint8Array(0) }), /nonce is 0 bytes/);
    });

    test("needs its root key", async () => {
      // The root is found by the id derived from its key.
      assert.equal(await rootKeyId(fixture.ROOT_SPKI, subtle), fixture.ROOT_KID);
      assert.match(await refused({ rootKeys: [] }), /No root key with the id fe812c12f3ab4ce6/);
      // Another key (the example key of RFC 8410) does not stand in.
      const other = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
      assert.match(await refused({ rootKeys: [other] }), /No root key with the id fe812c12f3ab4ce6/);
      // Among several, and entries which are no key: passed over.
      const several = [other, "not a key", 5 as never, fixture.ROOT_SPKI];
      assert.ok(await verify({ rootKeys: several }));
      assert.match(await refused({ rootKeys: ["not a key", 5 as never] }), /No root key/);
      // An X25519 key is no root key.
      const x25519 = ["MCowBQYDK2VuAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="];
      assert.match(await refused({ rootKeys: x25519 }), /No root key/);
      // The old form, ids to keys, is refused whole.
      assert.match(
        await refused({ rootKeys: { [fixture.ROOT_KID]: fixture.ROOT_SPKI } as never }),
        /No root keys are given/,
      );
    });

    test("fails for another instance key", async () => {
      // Who has the payload and root signature, but not the instance
      // private key, can sign the nonce with a key of their own.
      const pair = await SUBTLE.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as CryptoKeyPair;
      const publicKey = new Uint8Array(await SUBTLE.exportKey("raw", pair.publicKey));
      const payload = base64urlDecode(fixture.RESPONSE.payload);
      const message = new Uint8Array([
        ...new TextEncoder().encode("komodo-supporter-v1"),
        ...fixture.NONCE_BYTES,
        ...new Uint8Array(await SUBTLE.digest("SHA-256", payload)),
      ]);
      const nonceSig = new Uint8Array(await SUBTLE.sign({ name: "Ed25519" }, pair.privateKey, message));
      const forged = {
        ...fixture.RESPONSE,
        instance_public_key: base64urlEncode(publicKey),
        nonce_sig: base64urlEncode(nonceSig),
      };
      assert.match(await refused({ response: forged }), /root signature does not verify/);
      // The real instance public key with the forged signature.
      assert.match(
        await refused({ response: { ...fixture.RESPONSE, nonce_sig: base64urlEncode(nonceSig) } }),
        /nonce signature does not verify/,
      );
    });

    test("fails when any byte of the payload changes", async () => {
      const payload = base64urlDecode(fixture.RESPONSE.payload);
      assert.equal(payload.length, 96);
      for (let at = 0; at < payload.length; at++) {
        const response = withPayloadByte(at, (byte) => byte ^ 0x01);
        assert.equal(await verify({ response }), null, `byte ${at}`);
      }
      // One which still decodes: the `A` of `Acme Corp` to `B`.
      const at = fixture.PAYLOAD_HEX.indexOf("41636d65") / 2;
      assert.match(await refused({ response: withPayloadByte(at, () => 0x42) }), /root signature does not verify/);
    });

    test("fails for a changed signature, key or nonce signature", async () => {
      for (const name of ["payload_sig", "instance_public_key", "nonce_sig"] as const) {
        const bytes = base64urlDecode(fixture.RESPONSE[name]);
        bytes[0] ^= 0x80;
        assert.equal(await verify({ response: withField(name, base64urlEncode(bytes)) }), null, name);
      }
      // A signature's S of the group order or more: no other encoding
      // of a valid signature verifies (RFC 8032 §5.1.7).
      const sig = base64urlDecode(fixture.RESPONSE.nonce_sig);
      const order = fixture.hexToBytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
      let carry = 0;
      for (let i = 0; i < 32; i++) {
        const sum = sig[32 + i] + order[i] + carry;
        sig[32 + i] = sum & 0xff;
        carry = sum >> 8;
      }
      assert.equal(carry, 0);
      assert.match(await refused({ response: withField("nonce_sig", base64urlEncode(sig)) }), /nonce signature does not verify/);
    });
  });

  describe(`the response (${implementation})`, () => {
    test("null or undefined is no badge", async () => {
      assert.match(await refused({ response: null }), /No supporter key is configured/);
      assert.match(await refused({ response: undefined }), /No supporter key is configured/);
      assert.equal(await verify({ response: null }), null);
    });

    test("is checked field by field", async () => {
      assert.match(await refused({ response: "text" }), /not an object/);
      assert.match(await refused({ response: {} }), /`payload` of the response is not text/);
      assert.match(await refused({ response: { ...fixture.RESPONSE, nonce_sig: 5 } }), /`nonce_sig` of the response is not text/);
      assert.match(await refused({ response: withField("payload", fixture.RESPONSE.payload + "=") }), /`payload` of the response is not base64url/);
      assert.match(await refused({ response: withField("payload", "") }), /payload is 0 bytes/);
      assert.match(await refused({ response: withField("payload", base64urlEncode(new Uint8Array(4097))) }), /payload is 4097 bytes/);
      assert.match(await refused({ response: withField("payload_sig", fixture.RESPONSE.payload_sig.slice(0, -6)) }), /`payload_sig` of the response is 60 bytes, expected 64/);
      assert.match(await refused({ response: withField("instance_public_key", fixture.RESPONSE.instance_public_key + "A") }), /`instance_public_key` of the response is 33 bytes, expected 32/);
      assert.match(await refused({ response: withField("nonce_sig", fixture.RESPONSE.nonce_sig.replace("_", "/")) }), /`nonce_sig` of the response is not base64url/);
      assert.match(await refused({ response: withField("nonce_sig", " " + fixture.RESPONSE.nonce_sig) }), /`nonce_sig` of the response is not base64url/);
      // A payload which is no CBOR map.
      assert.match(await refused({ response: withField("payload", base64urlEncode(new Uint8Array([0x80]))) }), /payload is not a map/);
      assert.match(await refused({ response: withField("payload", base64urlEncode(new Uint8Array([0xa0]))) }), /payload has no `k`/);
      assert.match(await refused({ response: withField("payload", base64urlEncode(new Uint8Array([0xff]))) }), /CborError/);
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
          assert.equal(await verify({ response: response as never }), null);
        }
        assert.equal(await verify({ nonce: null as never }), null);
        assert.equal(await verify({ rootKeys: null as never }), null);
        // An app which forgot its root keys: no badge, with the reason.
        assert.equal(await verify({ rootKeys: undefined as never }), null);
        assert.match(String(logged.at(-1)?.[1]), /No root keys are given/);
        assert.equal(await verify({ revoked: null as never }), null);
        // A WebCrypto given is used as given, however broken.
        assert.equal(await verify({ subtle: {} as never }), null);
        assert.equal(logged.length, 13);
        assert.ok(logged.every(([first]) => first === "No supporter badge:"));
        assert.match(String(logged[0][1]), /SupporterKeyError: No supporter key is configured/);
      } finally {
        console.debug = debug;
      }
    });
  });
}

/**
 * The page's `crypto` replaced by `page` while `run` runs: what a
 * browser gives a page.
 */
async function onPage(
  page: { crypto: unknown; isSecureContext?: boolean },
  run: () => Promise<void>,
) {
  const descriptors = {
    crypto: Object.getOwnPropertyDescriptor(globalThis, "crypto"),
    isSecureContext: Object.getOwnPropertyDescriptor(globalThis, "isSecureContext"),
  };
  for (const [name, value] of Object.entries(page)) {
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  }
  try {
    await run();
  } finally {
    for (const [name, descriptor] of Object.entries(descriptors)) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete (globalThis as Record<string, unknown>)[name];
    }
  }
}

/** The calls made to the methods of a WebCrypto, by method. */
type Calls = Record<string, number>;

/**
 * Node's WebCrypto behind a proxy which counts the calls, and refuses
 * Ed25519 keys with `NotSupportedError` when `ed25519` is false, as
 * browsers before Chrome 137, Safari 17 and Firefox 130 do.
 */
function countingWebCrypto(ed25519: boolean): { subtle: SubtleCrypto; calls: Calls } {
  const calls: Calls = {};
  const subtle = new Proxy(SUBTLE, {
    get(target, name) {
      const method = Reflect.get(target, name);
      if (typeof method !== "function") return method;
      return (...args: unknown[]) => {
        calls[String(name)] = (calls[String(name)] ?? 0) + 1;
        const algorithm = name === "importKey" ? args[2] : undefined;
        if (!ed25519 && (algorithm as { name?: string })?.name === "Ed25519") {
          return Promise.reject(new DOMException("Algorithm: Unrecognized name", "NotSupportedError"));
        }
        return method.apply(target, args);
      };
    },
  });
  return { subtle, calls };
}

describe("WebCrypto or JavaScript", () => {
  test("a page without WebCrypto verifies in JavaScript", async () => {
    // A page served over plain http from another host than localhost
    // (eg. a LAN install without TLS): `crypto.getRandomValues` works,
    // `crypto.subtle` is undefined.
    const page = {
      crypto: { getRandomValues: crypto.getRandomValues.bind(crypto), subtle: undefined },
      isSecureContext: false,
    };
    await onPage(page, async () => {
      assert.equal(globalThis.crypto.subtle, undefined);
      assert.deepEqual(await checkSupporterKey(OPTIONS), fixture.SUPPORTER);
      assert.deepEqual(await verifySupporterKey(OPTIONS), fixture.SUPPORTER);
      // The same reasons as with WebCrypto.
      assert.match(await reason({ releaseDate: "2027-10-01" }), /covers releases up to 2027-09-30/);
      assert.match(await reason({ nonce: new Uint8Array(32).fill(2) }), /nonce signature does not verify/);
      const acme = fixture.PAYLOAD_HEX.indexOf("41636d65") / 2;
      assert.match(await reason({ response: withPayloadByte(acme, () => 0x42) }), /root signature does not verify/);
      assert.match(await reason({ rootKeys: [] }), /No root key with the id fe812c12f3ab4ce6/);
      // The nonce is drawn all the same.
      assert.equal(newNonce().bytes.length, 32);
      // And root keys have their ids.
      assert.equal(await rootKeyId(fixture.ROOT_SPKI), fixture.ROOT_KID);
      assert.deepEqual(await checkRootKeys(["MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE="]), ["e744c0791320c328"]);
      assert.deepEqual(await findRootKey(fixture.ROOT_KEYS, fixture.ROOT_KID), new Uint8Array(Buffer.from(fixture.ROOT_SPKI, "base64")));
    });
  });

  test("a WebCrypto without Ed25519 leaves it to JavaScript", async () => {
    const old = countingWebCrypto(false);
    await onPage({ crypto: { getRandomValues: crypto.getRandomValues.bind(crypto), subtle: old.subtle } }, async () => {
      assert.deepEqual(await checkSupporterKey(OPTIONS), fixture.SUPPORTER);
      assert.match(await reason({ nonce: new Uint8Array(32).fill(2) }), /nonce signature does not verify/);
      assert.equal(await rootKeyId(fixture.ROOT_SPKI), fixture.ROOT_KID);
    });
    // Asked once whether it does Ed25519, then left alone.
    assert.deepEqual(old.calls, { importKey: 1 });
  });

  test("the page's WebCrypto verifies where it does Ed25519", async () => {
    const current = countingWebCrypto(true);
    await onPage({ crypto: { getRandomValues: crypto.getRandomValues.bind(crypto), subtle: current.subtle } }, async () => {
      assert.deepEqual(await checkSupporterKey(OPTIONS), fixture.SUPPORTER);
      // `null` takes JavaScript all the same.
      const before = { ...current.calls };
      assert.deepEqual(await checkSupporterKey({ ...OPTIONS, subtle: null }), fixture.SUPPORTER);
      assert.equal(await rootKeyId(fixture.ROOT_SPKI, null), fixture.ROOT_KID);
      assert.deepEqual(current.calls, before);
    });
    // Once the probe (an import and a verify of RFC 8032's first test
    // vector), then the root id, the two signatures and the hash of the
    // payload.
    assert.deepEqual(current.calls, { importKey: 3, verify: 3, digest: 2 });
  });

  test("a WebCrypto given is used as given: failing is no untrusted root", async () => {
    const failing = {
      digest: async () => {
        throw new Error("digest failed");
      },
    } as unknown as SubtleCrypto;
    assert.equal(await reason({ subtle: failing }), "Error: digest failed");
    await assert.rejects(findRootKey(fixture.ROOT_KEYS, fixture.ROOT_KID, failing), /digest failed/);
    // An entry which is no key is passed over before WebCrypto.
    assert.equal(await findRootKey(["not a key", 5 as never], fixture.ROOT_KID, failing), undefined);
    assert.deepEqual(await findRootKey(fixture.ROOT_KEYS, fixture.ROOT_KID), new Uint8Array(Buffer.from(fixture.ROOT_SPKI, "base64")));
    // One without Ed25519 too: no badge, rather than another one.
    const old = countingWebCrypto(false);
    assert.match(await reason({ subtle: old.subtle }), /NotSupportedError/);
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
  for (const subtle of [undefined, null]) {
    assert.equal(await rootKeyId(fixture.ROOT_SPKI, subtle), fixture.ROOT_KID);
    assert.equal(await rootKeyId(` ${fixture.ROOT_SPKI}\n`, subtle), fixture.ROOT_KID);
    await assert.rejects(rootKeyId("not a key", subtle), /base64/);
    await assert.rejects(rootKeyId("MCowBQYDK2VuAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=", subtle), /not the SPKI DER/);
    // Valid base64 of another length than an Ed25519 SPKI.
    await assert.rejects(rootKeyId(fixture.ROOT_SPKI.slice(0, 56), subtle), /not the SPKI DER/);
  }
});

test("errors are SupporterKeyErrors with the reason", async () => {
  await assert.rejects(
    checkSupporterKey({ ...OPTIONS, releaseDate: "2027-10-01" }),
    (e: unknown) => e instanceof SupporterKeyError && /covers/.test(e.message),
  );
});
