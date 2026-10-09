import * as ed from "@noble/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2.js";

/**
 * The cryptography a supporter key is verified with: SHA-256 and
 * Ed25519 signatures. Either the page's WebCrypto, or the JavaScript
 * implementation of `@noble/ed25519` and `@noble/hashes` this package
 * ships for a page which has none, with the same verdicts:
 * `chooseWebCrypto` makes the choice, `supporterCrypto` gives the one
 * chosen.
 */
export interface SupporterCrypto {
  /** `WebCrypto` or `JavaScript`. */
  readonly name: string;
  sha256(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>>;
  /**
   * Whether `signature` (64 bytes) is the Ed25519 signature of
   * `publicKey` (its 32 raw bytes) over `message`.
   */
  verifyEd25519(
    publicKey: Uint8Array<ArrayBuffer>,
    signature: Uint8Array<ArrayBuffer>,
    message: Uint8Array<ArrayBuffer>,
  ): Promise<boolean>;
}

const ED25519 = { name: "Ed25519" };

function webCrypto(subtle: SubtleCrypto): SupporterCrypto {
  return {
    name: "WebCrypto",
    sha256: async (data) =>
      new Uint8Array(await subtle.digest("SHA-256", data)),
    verifyEd25519: async (publicKey, signature, message) =>
      await subtle.verify(
        ED25519,
        await subtle.importKey("raw", publicKey, ED25519, false, ["verify"]),
        signature,
        message,
      ),
  };
}

const JAVASCRIPT: SupporterCrypto = {
  name: "JavaScript",
  sha256: async (data) => new Uint8Array(sha256(data)),
  verifyEd25519: async (publicKey, signature, message) => {
    // The synchronous api of `@noble/ed25519` hashes with
    // `hashes.sha512`, which it leaves unset so that it needs no
    // dependency. Its asynchronous api would hash with WebCrypto, the
    // very thing this page lacks. A SHA-512 set by the app stays: it is
    // SHA-512 all the same.
    ed.hashes.sha512 ??= sha512;
    // The RFC 8032 / FIPS 186-5 rules rather than noble's default
    // ZIP-215 ones, under which a signature of a small order public key
    // verifies for any message: non canonical encodings and small order
    // keys are refused, as the WebCrypto specification and the Rust
    // crate's `verify_strict` refuse a small order key, and an S of the
    // group order or more is refused under either.
    return ed.verify(signature, message, publicKey, { zip215: false });
  },
};

/**
 * RFC 8032 §7.1 TEST 1: a public key, and its signature of the empty
 * message. A WebCrypto which verifies it does Ed25519.
 */
const PROBE_PUBLIC_KEY = hexBytes(
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
);
const PROBE_SIGNATURE = hexBytes(
  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
);

function hexBytes(hex: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(
    hex.match(/../g)!.map((byte) => Number.parseInt(byte, 16)),
  );
}

/** Whether each WebCrypto a page had does Ed25519, asked once. */
const DOES_ED25519 = new WeakMap<SubtleCrypto, Promise<boolean>>();

/**
 * Whether `subtle` verifies Ed25519 signatures. Browsers before Chrome
 * 137, Safari 17 and Firefox 130 have WebCrypto without it (the import
 * of a key throws `NotSupportedError`). Anything but the right answer
 * for the test vector counts as no.
 */
function doesEd25519(subtle: SubtleCrypto): Promise<boolean> {
  let does = DOES_ED25519.get(subtle);
  if (does === undefined) {
    does = (async () => {
      try {
        const key = await subtle.importKey(
          "raw",
          PROBE_PUBLIC_KEY,
          ED25519,
          false,
          ["verify"],
        );
        return (
          (await subtle.verify(
            ED25519,
            key,
            PROBE_SIGNATURE,
            new Uint8Array(0),
          )) === true
        );
      } catch {
        return false;
      }
    })();
    DOES_ED25519.set(subtle, does);
  }
  return does;
}

/**
 * The WebCrypto to verify with, or `null` for the JavaScript
 * implementation: the one place the choice is made.
 *
 * - A `subtle` given is used as given (eg. a test's).
 * - `null` is the JavaScript implementation, whatever the page has.
 * - Otherwise the page's `crypto.subtle` where it does Ed25519, else
 *   JavaScript. WebCrypto exists in a secure context only (https, or
 *   localhost): a page served over plain http from another host, such
 *   as a LAN install reached at `http://192.168.1.10:9120`, has none,
 *   while `crypto.getRandomValues` (the nonce) works anywhere.
 *
 * The answer for a page is the same each time (the probe of its
 * WebCrypto is kept), and passing it on chooses nothing again.
 */
export async function chooseWebCrypto(
  subtle?: SubtleCrypto | null,
): Promise<SubtleCrypto | null> {
  if (subtle !== undefined) return subtle;
  const page = globalThis.crypto?.subtle;
  return page && (await doesEd25519(page)) ? page : null;
}

/**
 * The cryptography of a choice of `chooseWebCrypto`: WebCrypto, or
 * JavaScript for `null`.
 */
export function supporterCrypto(subtle: SubtleCrypto | null): SupporterCrypto {
  return subtle === null ? JAVASCRIPT : webCrypto(subtle);
}
