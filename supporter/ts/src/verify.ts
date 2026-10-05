import { base64urlDecode, base64urlEncode, concatBytes, utf8 } from "./encoding.ts";
import {
  FORMAT_VERSION,
  MAX_PAYLOAD_BYTES,
  decodePayloadMap,
  isDate,
  payloadRootKeyId,
  readPayload,
  type SupporterPayload,
} from "./payload.ts";
import { REVOKED, type RootKeys, findRootKey } from "./roots.ts";
import type { SignedSupporterKey } from "./types.ts";

/** Where "Become a supporter" leads. */
export const SUPPORTER_URL = "https://mogh.tech/supporter";

/** The length of the nonce the browser draws, in bytes. */
export const NONCE_BYTES = 32;

/** A nonce for one `GetSupporterKey`, see `newNonce`. */
export interface Nonce {
  bytes: Uint8Array<ArrayBuffer>;
  /** base64url without padding: the `nonce` of the request. */
  encoded: string;
}

/**
 * Draws the nonce of a `GetSupporterKey`: 32 random bytes. Draw a new
 * one for every request, never reuse one from an earlier response or
 * from storage: the server's signature over it is what tells a live
 * answer from a captured one.
 */
export function newNonce(): Nonce {
  const bytes = crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  return { bytes, encoded: base64urlEncode(bytes) };
}

/** A verified supporter key: what the badge shows. */
export type Supporter = SupporterPayload;

export interface VerifySupporterKeyOptions {
  /** This app: `komodo` or `cicada`. The key has to be for it. */
  app: string;
  /**
   * The `YYYY-MM-DD` this build was released, set at build time. Never
   * the current date: a key keeps working on every release it covered,
   * forever, so the comparison is against the build, not the clock.
   */
  releaseDate: string;
  /** The nonce the request was made with. */
  nonce: Nonce | Uint8Array;
  /** What the server answered. */
  response: SignedSupporterKey | null | undefined;
  /**
   * The root public keys this app trusts, hardcoded in the app: each
   * app has its own. The root of a key is found among them by the id
   * derived from each. Without one nothing verifies.
   */
  rootKeys: RootKeys;
  /** The revoked key ids. Default: `REVOKED`. */
  revoked?: readonly string[];
  /** Default: `crypto.subtle`. */
  subtle?: SubtleCrypto;
}

/** Why a response shows no badge. */
export class SupporterKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SupporterKeyError";
  }
}

const ED25519 = { name: "Ed25519" };

function decodeField(
  response: SignedSupporterKey,
  name: keyof SignedSupporterKey,
  length?: number,
): Uint8Array<ArrayBuffer> {
  const text = response[name];
  if (typeof text !== "string") {
    throw new SupporterKeyError(`The \`${name}\` of the response is not text`);
  }
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = base64urlDecode(text);
  } catch (e) {
    throw new SupporterKeyError(
      `The \`${name}\` of the response is not base64url without padding (${
        e instanceof Error ? e.message : e
      })`,
    );
  }
  if (length !== undefined && bytes.length !== length) {
    throw new SupporterKeyError(
      `The \`${name}\` of the response is ${bytes.length} bytes, expected ${length}`,
    );
  }
  return bytes;
}

/**
 * Verifies a `GetSupporterKey` response offline, and throws with the
 * reason when it shows no badge (a `SupporterKeyError`, or whatever
 * decoding or WebCrypto threw). `verifySupporterKey` is this with the
 * reason logged instead. In order:
 *
 * 1. The response is decoded: `payload_sig` 64 bytes,
 *    `instance_public_key` 32, `nonce_sig` 64, `payload` at most 4 KiB.
 * 2. The payload's `k` picks the root key in `rootKeys`, nothing else
 *    of it is trusted yet.
 * 3. The root verifies `payload_sig` over `payload || instance_public_key`.
 * 4. Now trusted, the payload has `v` 1 and `a` this app.
 * 5. The instance key verifies `nonce_sig` over
 *    `UTF-8("{app}-supporter-v1") || nonce || SHA-256(payload)` for the
 *    nonce this page drew: a captured response, or a proxy without the
 *    instance private key, verifies for no other nonce.
 * 6. `releaseDate` is at most `c`.
 * 7. `i` is not in `revoked`.
 *
 * Ed25519 in WebCrypto needs Chrome 137, Safari 17 or Firefox 130; on
 * an older browser the import throws, which is no badge.
 */
export async function checkSupporterKey(
  options: VerifySupporterKeyOptions,
): Promise<Supporter> {
  const {
    app,
    releaseDate,
    response,
    rootKeys,
    revoked = REVOKED,
    subtle = crypto.subtle,
  } = options;
  const nonce =
    options.nonce instanceof Uint8Array ? options.nonce : options.nonce.bytes;
  if (nonce.length !== NONCE_BYTES) {
    throw new SupporterKeyError(
      `The nonce is ${nonce.length} bytes, expected ${NONCE_BYTES}`,
    );
  }
  if (typeof releaseDate !== "string" || !isDate(releaseDate)) {
    throw new SupporterKeyError("The release date is not a `YYYY-MM-DD` date");
  }
  if (response === null || response === undefined) {
    throw new SupporterKeyError("No supporter key is configured");
  }
  if (typeof response !== "object") {
    throw new SupporterKeyError("The response is not an object");
  }

  // 1
  const payload = decodeField(response, "payload");
  if (payload.length === 0 || payload.length > MAX_PAYLOAD_BYTES) {
    throw new SupporterKeyError(
      `The payload is ${payload.length} bytes, expected 1 to ${MAX_PAYLOAD_BYTES}`,
    );
  }
  const payloadSig = decodeField(response, "payload_sig", 64);
  const instancePublicKey = decodeField(response, "instance_public_key", 32);
  const nonceSig = decodeField(response, "nonce_sig", 64);

  // 2
  if (!Array.isArray(rootKeys)) {
    throw new SupporterKeyError(
      "No root keys are given: the app passes the ones it trusts",
    );
  }
  const map = decodePayloadMap(payload);
  // The root whose id, derived from its key, the payload names.
  const kid = payloadRootKeyId(map);
  const rootDer = await findRootKey(rootKeys, kid, subtle);
  if (rootDer === undefined) {
    throw new SupporterKeyError(`No root key with the id ${kid} is trusted`);
  }

  // 3
  const root = await subtle.importKey("spki", rootDer, ED25519, false, [
    "verify",
  ]);
  const signed = concatBytes(payload, instancePublicKey);
  if (!(await subtle.verify(ED25519, root, payloadSig, signed))) {
    throw new SupporterKeyError("The root signature does not verify");
  }

  // 4
  const supporter = readPayload(map);
  if (supporter.version !== FORMAT_VERSION) {
    throw new SupporterKeyError(
      `The key has the format version ${supporter.version}, this package reads ${FORMAT_VERSION}`,
    );
  }
  if (supporter.app !== app) {
    throw new SupporterKeyError(
      `The key is for \`${supporter.app}\`, this app is \`${app}\``,
    );
  }

  // 5
  const instance = await subtle.importKey("raw", instancePublicKey, ED25519, false, [
    "verify",
  ]);
  const message = concatBytes(
    utf8(`${app}-supporter-v1`),
    nonce,
    new Uint8Array(await subtle.digest("SHA-256", payload)),
  );
  if (!(await subtle.verify(ED25519, instance, nonceSig, message))) {
    throw new SupporterKeyError("The nonce signature does not verify");
  }

  // 6
  if (!(releaseDate <= supporter.covers)) {
    throw new SupporterKeyError(
      `The key covers releases up to ${supporter.covers}, this release is ${releaseDate}`,
    );
  }

  // 7
  if (revoked.includes(supporter.id)) {
    throw new SupporterKeyError(`The key ${supporter.id} is revoked`);
  }

  return supporter;
}

/**
 * Verifies a `GetSupporterKey` response offline (`checkSupporterKey`):
 * the supporter to show a badge for, or `null` for no badge, whatever
 * the reason, which is logged with `console.debug`. Never throws. Call
 * it once per page load and keep the result in memory, not in storage.
 */
export async function verifySupporterKey(
  options: VerifySupporterKeyOptions,
): Promise<Supporter | null> {
  try {
    return await checkSupporterKey(options);
  } catch (e) {
    console.debug(
      "No supporter badge:",
      e instanceof Error ? `${e.name}: ${e.message}` : e,
    );
    return null;
  }
}
