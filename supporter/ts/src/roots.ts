import {
  chooseWebCrypto,
  supporterCrypto,
  type SupporterCrypto,
} from "./crypto.ts";
import { isCanonicalEd25519Key } from "./ed25519.ts";
import { base64Decode, hex } from "./encoding.ts";
import { trimWhitespace } from "./whitespace.ts";

/**
 * The root public keys an app trusts, the keys of mogh.tech which
 * sign its supporter keys: each the Ed25519 public key as base64
 * SPKI DER (60 characters starting `MCowBQYDK2VwAyEA`). The id of a
 * key, the `k` of the payloads it signed, is never declared: it is
 * derived from the key (`rootKeyId`).
 *
 * Each app has its own, hardcoded in its UI and, the same ones, on
 * its server (the Rust crate's `supporter_root_keys`), which serves
 * a key only when it verifies under them: the browser verifies it
 * again. Rotation adds an entry, and an old entry is removed a few
 * releases later: several may be trusted at once. `checkRootKeys`
 * checks a list, for a test of the app.
 */
export type RootKeys = readonly string[];

/**
 * The id of the test root of the fixture (the tests of this package,
 * `mogh_supporter::fixture` in Rust). Its key is public: a release
 * never trusts it.
 */
export const FIXTURE_ROOT_KEY_ID = "fe812c12f3ab4ce6";

/**
 * Supporter keys which show no badge anymore: their ids (`i`) as
 * lowercase hyphenated UUIDs.
 */
export const REVOKED: readonly string[] = Object.freeze([]);

/**
 * The SPKI DER of an Ed25519 public key is this, then the 32 raw key
 * bytes (RFC 8410).
 */
const ED25519_SPKI_PREFIX = [
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/**
 * The SPKI DER of a root key: its 32 raw bytes after a fixed prefix.
 * Surrounding whitespace is ignored (Rust's `str::trim`). Throws, with
 * the message of the Rust crate's `RootKeyError`, what its
 * `root_key_bytes` refuses: text which is not base64, DER which is not
 * of an Ed25519 public key, and key bytes which are no canonical
 * encoding of a point of the curve, or of a point of small order,
 * which has signatures verifying for any message. WebCrypto's import
 * checks none of the latter.
 */
export function rootKeyDer(spki: string): Uint8Array<ArrayBuffer> {
  let der: Uint8Array<ArrayBuffer>;
  try {
    der = base64Decode(trimWhitespace(spki));
  } catch {
    throw new Error("The root key is not base64");
  }
  if (
    der.length !== ED25519_SPKI_PREFIX.length + 32 ||
    ED25519_SPKI_PREFIX.some((byte, i) => der[i] !== byte)
  ) {
    throw new Error("The root key is not the SPKI DER of an Ed25519 key");
  }
  if (!isCanonicalEd25519Key(der.subarray(ED25519_SPKI_PREFIX.length))) {
    throw new Error("The root key is not a canonical Ed25519 public key");
  }
  return der;
}

/** The id of a root key's SPKI DER (`rootKeyDer`). */
async function derKeyId(
  der: Uint8Array<ArrayBuffer>,
  { sha256 }: SupporterCrypto,
): Promise<string> {
  const digest = await sha256(der.slice(ED25519_SPKI_PREFIX.length));
  return hex(digest.subarray(0, 8));
}

/**
 * The id of a root key: lowercase hex of the first 8 bytes of the
 * SHA-256 of its raw 32 bytes. The `k` of the payloads the key
 * signed, and what the platform publishes next to the key.
 *
 * `subtle` as for `checkSupporterKey`: the page's WebCrypto by default,
 * else (and for `null`) the JavaScript SHA-256 this package ships.
 */
export async function rootKeyId(
  spki: string,
  subtle?: SubtleCrypto | null,
): Promise<string> {
  const der = rootKeyDer(spki);
  return await derKeyId(der, supporterCrypto(await chooseWebCrypto(subtle)));
}

/**
 * The key among `rootKeys` which has the id `kid`, as its SPKI DER.
 * An entry which is no key (`rootKeyDer` refuses it) has no id, and is
 * passed over. Nothing else is: a failure of a WebCrypto given
 * rejects, rather than reading as a root which is not trusted.
 * `subtle` as for `rootKeyId`.
 */
export async function findRootKey(
  rootKeys: RootKeys,
  kid: string,
  subtle?: SubtleCrypto | null,
): Promise<Uint8Array<ArrayBuffer> | undefined> {
  const chosen = supporterCrypto(await chooseWebCrypto(subtle));
  for (const rootKey of rootKeys) {
    if (typeof rootKey !== "string") continue;
    let der: Uint8Array<ArrayBuffer>;
    try {
      der = rootKeyDer(rootKey);
    } catch {
      // Not a key.
      continue;
    }
    if ((await derKeyId(der, chosen)) === kid) return der;
  }
  return undefined;
}

/**
 * Checks the root keys an app hardcodes, for a test of the app: every
 * entry is an Ed25519 public key, listed once, and none is the test
 * root of the fixture, whose key anyone can sign with. Throws with
 * the reason. Resolves to their ids, in order, to compare with what
 * the platform published. An empty list is fine: no key verifies then.
 * `subtle` as for `rootKeyId`.
 */
export async function checkRootKeys(
  rootKeys: RootKeys,
  subtle?: SubtleCrypto | null,
): Promise<string[]> {
  const chosen = supporterCrypto(await chooseWebCrypto(subtle));
  const ids: string[] = [];
  for (const [i, rootKey] of rootKeys.entries()) {
    let id: string;
    try {
      id = await derKeyId(rootKeyDer(rootKey), chosen);
    } catch (e) {
      throw new Error(
        `The root key at position ${i + 1} is not valid | ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    if (ids.includes(id)) {
      throw new Error(`The root key ${id} is listed twice`);
    }
    if (id === FIXTURE_ROOT_KEY_ID) {
      throw new Error(
        `The root key ${id} is the test root of the fixture, which is public: a release never trusts it`,
      );
    }
    ids.push(id);
  }
  return ids;
}
