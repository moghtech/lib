// What a UI knows about signing keys (Ed25519 key pairs a user signs
// requests with, mogh_auth's signed requests): telling public keys
// apart in a table, and checking a pasted public key before it is
// sent. No React: the node tests load this file directly.

/** The base64 SPKI DER header of every Ed25519 public key (the
 * algorithm identifier and the bit string header): the 32 key
 * bytes follow it. Core takes and lists signing keys in this form
 * (`openssl pkey -pubout` prints it inside a PEM). */
export const ED25519_SPKI_PREFIX = "MCowBQYDK2VwAyEA";

/** The same header of an X25519 public key (a key agreement key,
 * eg. of a mutual TLS style pairing), which a server refuses:
 * requests are signed with Ed25519 keys. */
export const X25519_SPKI_PREFIX = "MCowBQYDK2VuAyEA";

/** An excerpt of a public key telling signing keys apart in a
 * table. Every Ed25519 key shares its first 16 characters (the SPKI
 * header), so the excerpt skips them. A key of another algorithm
 * keeps its header, and so stands apart. */
export function publicKeyExcerpt(publicKey: string, length = 12): string {
  const key = publicKey.startsWith(ED25519_SPKI_PREFIX)
    ? publicKey.slice(ED25519_SPKI_PREFIX.length)
    : publicKey;
  const lead = key === publicKey ? "" : "…";
  return key.length > length
    ? `${lead}${key.slice(0, length)}…`
    : `${lead}${key}`;
}

/** Whether `value` is a private key: a PEM `PRIVATE KEY`, or base64
 * PKCS#8 DER (a sequence opening with its version integer, where a
 * public key's SPKI opens with the algorithm sequence). */
export function isPrivateKey(value: string): boolean {
  const trimmed = value.trim();
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(trimmed)) return true;
  if (trimmed.startsWith("-----BEGIN")) return false;
  let der: string;
  try {
    der = atob(trimmed);
  } catch {
    return false;
  }
  return (
    der.length > 3 && der.charCodeAt(0) === 0x30 && der.charCodeAt(2) === 0x02
  );
}

/** The line a PEM public key (SPKI) opens with. */
const PEM_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";

/** A pasted public key as it is sent to Core: the base64 SPKI. A
 * PEM is reduced to its body, also one whose line breaks were lost
 * (a `.pub` file pasted into a single line field). */
export function publicKeyValue(value: string): string {
  const trimmed = value.trim();
  if (!trimmed.startsWith(PEM_PUBLIC_KEY)) return trimmed;
  return trimmed
    .slice(PEM_PUBLIC_KEY.length)
    .split("-----END")[0]
    .replace(/\s+/g, "");
}

/** What [publicKeyError] tells about a key which can't be used:
 * who holds the private key of a pair, and so what to do. */
export interface PublicKeyHints {
  /** A private key was pasted in place of the public key. */
  privateKey: string;
  /** An X25519 key was pasted: signing keys are Ed25519 keys. */
  x25519: string;
}

/** The hints of a user's own signing key, whose pair the user
 * generates with openssl into `keyFile` (eg. `komodo.key`). */
export function publicKeyHints(keyFile: string): PublicKeyHints {
  return {
    privateKey: `This is a private key, which never leaves your machine. Paste its public key: openssl pkey -in ${keyFile} -pubout`,
    x25519: `This is an X25519 key: signing keys are Ed25519 keys. Generate a new pair: openssl genpkey -algorithm ed25519 -out ${keyFile}`,
  };
}

/** A form's check of a pasted public key: `null` when it can be
 * sent, as [publicKeyValue] (empty is for the form to decide: a
 * signing key form may have Core generate the pair). A private key
 * is refused before it leaves the browser, and so is anything which
 * can't be an Ed25519 public key (a short value could be a raw
 * private key). An X25519 key is refused saying so, with the app's
 * `hints` on what to do. Core validates the rest. */
export function publicKeyError(
  value: string,
  hints: PublicKeyHints = publicKeyHints("signing.key"),
): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (isPrivateKey(trimmed)) return hints.privateKey;
  if (trimmed.startsWith("-----BEGIN") && !trimmed.startsWith(PEM_PUBLIC_KEY)) {
    return "Expected a PEM PUBLIC KEY";
  }
  // The base64 SPKI: the body of a PEM, or the value itself.
  const spki = publicKeyValue(trimmed);
  if (spki.startsWith(X25519_SPKI_PREFIX)) return hints.x25519;
  return spki.startsWith(ED25519_SPKI_PREFIX)
    ? null
    : `Not an Ed25519 public key: base64 SPKI starts with ${ED25519_SPKI_PREFIX}, or paste the PEM`;
}
