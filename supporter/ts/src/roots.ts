import { base64Decode, hex } from "./encoding.ts";

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
 * The SPKI DER of a root key, for `crypto.subtle.importKey("spki", ..)`.
 * Surrounding whitespace is ignored. Throws when it is not the DER of
 * an Ed25519 public key.
 */
export function rootKeyDer(spki: string): Uint8Array<ArrayBuffer> {
  const der = base64Decode(spki.trim());
  if (
    der.length !== ED25519_SPKI_PREFIX.length + 32 ||
    ED25519_SPKI_PREFIX.some((byte, i) => der[i] !== byte)
  ) {
    throw new Error("The root key is not the SPKI DER of an Ed25519 key");
  }
  return der;
}

/**
 * The id of a root key: lowercase hex of the first 8 bytes of the
 * SHA-256 of its raw 32 bytes. The `k` of the payloads the key
 * signed, and what the platform publishes next to the key.
 */
export async function rootKeyId(
  spki: string,
  subtle: SubtleCrypto = crypto.subtle,
): Promise<string> {
  const der = rootKeyDer(spki);
  const digest = await subtle.digest("SHA-256", der.slice(ED25519_SPKI_PREFIX.length));
  return hex(new Uint8Array(digest, 0, 8));
}

/**
 * The key among `rootKeys` which has the id `kid`, as its SPKI DER.
 * An entry which is no key has no id, and is passed over.
 */
export async function findRootKey(
  rootKeys: RootKeys,
  kid: string,
  subtle: SubtleCrypto = crypto.subtle,
): Promise<Uint8Array<ArrayBuffer> | undefined> {
  for (const rootKey of rootKeys) {
    if (typeof rootKey !== "string") continue;
    try {
      if ((await rootKeyId(rootKey, subtle)) === kid) return rootKeyDer(rootKey);
    } catch {
      // Not a key.
    }
  }
  return undefined;
}

/**
 * Checks the root keys an app hardcodes, for a test of the app: every
 * entry is an Ed25519 public key, listed once, and none is the test
 * root of the fixture, whose key anyone can sign with. Throws with
 * the reason. Resolves to their ids, in order, to compare with what
 * the platform published. An empty list is fine: no key verifies then.
 */
export async function checkRootKeys(
  rootKeys: RootKeys,
  subtle: SubtleCrypto = crypto.subtle,
): Promise<string[]> {
  const ids: string[] = [];
  for (const [i, rootKey] of rootKeys.entries()) {
    let id: string;
    try {
      id = await rootKeyId(rootKey, subtle);
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
