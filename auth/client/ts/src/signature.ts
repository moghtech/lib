// Signed requests: the scheme mogh_auth_server verifies, as
// mogh_auth_client's `signature` module signs it in Rust. A request is
// authenticated by an Ed25519 signature over its host, method, path,
// a timestamp, a nonce and the sha256 of its body, made with a signing
// key whose public half the server knows. The private key is never
// sent. Everything here runs on WebCrypto (`crypto.subtle`), so it
// works the same in node, Deno, Bun and the browser.
//
// Sign every attempt anew, right before sending: the server refuses a
// signature it has seen, and one older than its tolerance (about a
// second by default), see `fetchSignedJson` in `request.ts`.

/** The public key of the signing key, base64 spki der. */
export const API_PUBLIC_KEY_HEADER = "x-api-public-key";
/**
 * The host the request is signed for (`urlHost` of the server's
 * address). The server verifies the signature for it, once it is one of
 * the hosts the server is configured with.
 */
export const API_HOST_HEADER = "x-api-host";
/** Unix milliseconds, when the request was signed. */
export const API_TIMESTAMP_HEADER = "x-api-timestamp";
/** A random value making every signature unique. */
export const API_NONCE_HEADER = "x-api-nonce";
/** The base64 of the 64 byte Ed25519 signature. */
export const API_SIGNATURE_HEADER = "x-api-signature";

/**
 * The first line of every signed message: the format (`MOGH1`) and the
 * signature primitive. A signature made with the same key for anything
 * else never verifies as a request, and a later format or another
 * primitive gets another first line.
 */
export const SIGNED_REQUEST_VERSION = "MOGH1-ED25519";

/**
 * How the error starts (`401`) which a server answers a request with
 * that is signed for a host (`X-API-HOST`) it is not configured with.
 * It is the server which has to change (the address the client uses
 * belongs in its hosts), or the address of the client: no other key
 * would get through.
 */
export const SIGNED_FOR_ANOTHER_HOST =
  "Signed for a host this server is not configured as";

/**
 * How the error starts (`401`) which a server answers a request with
 * whose timestamp is further from its clock than it tolerates. The
 * clocks have to agree (or the request took too long to arrive): a
 * request signed anew may get through, see `fetchSignedJson`.
 */
export const SIGNED_AT_ANOTHER_TIME =
  "Signed at a time too far from the clock of this server";

/**
 * The key pair requests are signed with, parsed once (`signingKeys`)
 * rather than for every request.
 */
export type SigningKeys = {
  /** The private key, usable for `crypto.subtle.sign` only. */
  readonly privateKey: CryptoKey;
  /**
   * The public key, base64 spki der: the form the server stores, sent
   * in `X-API-PUBLIC-KEY`.
   */
  readonly publicKey: string;
};

/** What a request signature covers. Every field is signed as it is given. */
export type SignedRequest = {
  /**
   * The host of the server the request is for (`urlHost`): its
   * lowercase `host[:port]`.
   */
  host: string;
  /** The request method exactly as it is sent (`POST`). */
  method: string;
  /**
   * The path and query the server receives (eg. `/read?x=1`), never
   * the scheme and host.
   */
  pathAndQuery: string;
  /** Unix milliseconds. */
  timestamp: number;
  /** A random value, see `validNonce` and `randomNonce`. */
  nonce: string;
  /** The request body exactly as sent, empty for none. */
  body: Uint8Array | string;
};

const ENCODER = new TextEncoder();

/**
 * The accepted forms of a private key, as the errors name them. A key
 * is never repeated in an error.
 */
const INLINE_KEY_FORMS =
  "a private key given inline must be pkcs8 encoded (pem, or base64 der) or exactly 32 raw bytes";
const NOT_A_PRIVATE_KEY =
  "Private key must be 32 characters or less, or pkcs8 encoded.";

/** The Ed25519 algorithm identifier's OID (RFC 8410), as DER encodes it. */
const ED25519_OID = [0x2b, 0x65, 0x70];
/** The X25519 OID: a key of the other algorithm, refused saying so. */
const X25519_OID = [0x2b, 0x65, 0x6e];
/** A pkcs8 v1 PrivateKeyInfo of an Ed25519 key, up to its 32 byte seed. */
const PKCS8_V1_PREFIX = hexBytes("302e020100300506032b657004220420");
/** A SubjectPublicKeyInfo of an Ed25519 key, up to its 32 raw bytes. */
const SPKI_PREFIX = hexBytes("302a300506032b6570032100");

/**
 * Parses the private key of a signing key, deriving its public key,
 * for `signedRequestHeaders` and `requestSigner`. The key is taken as
 * mogh_pki takes it:
 * - pkcs8 pem (rfc7468, openssl, `-----BEGIN PRIVATE KEY-----`),
 * - pkcs8 base64 der (the pem body), v1 or v2 (whose embedded public
 *   key is dropped, the key derives it),
 * - raw key bytes: a value of 32 characters or fewer (its UTF-8 bytes,
 *   exactly as given) is the Ed25519 seed itself, zero padded to 32.
 *   That is how the random keys a server hands out (an onboarding or
 *   recovery key of exactly 32 characters) are used. With
 *   `inline: true`, for a key a person writes down, a shorter raw
 *   value is refused instead: `changeme` would be a key anybody finds
 *   from its public key.
 *
 * A value which reads like the path of a key file (`file:...`, `./`,
 * `~/`, a `.key` / `.pem` ending) is refused: it is no key, and taken
 * as raw bytes the path would be the key. A key of another algorithm
 * (an X25519 key), the all zero seed, and an empty value are refused.
 * The errors name the accepted forms, never the value.
 */
export async function signingKeys(
  privateKey: string,
  options?: { inline?: boolean },
): Promise<SigningKeys> {
  const seed = parseSeed(privateKey, options?.inline === true);
  const der = concatBytes(PKCS8_V1_PREFIX, seed);
  seed.fill(0);
  const subtle = webCrypto().subtle;
  // The public half of an Ed25519 key is derived, not stored: the jwk
  // of the private key carries it (`x`).
  const extractable = await subtle.importKey(
    "pkcs8",
    der,
    { name: "Ed25519" },
    true,
    ["sign"],
  );
  const jwk = await subtle.exportKey("jwk", extractable);
  if (typeof jwk.x !== "string") {
    throw new Error("Failed to derive the public key of the private key");
  }
  const publicKey = base64Encode(
    concatBytes(SPKI_PREFIX, base64UrlDecode(jwk.x)),
  );
  // What is kept can sign and nothing else.
  const signing = await subtle.importKey(
    "pkcs8",
    der,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  der.fill(0);
  return { privateKey: signing, publicKey };
}

/**
 * A new Ed25519 key pair: the private key as base64 pkcs8 der (the
 * form `signingKeys` takes, and the one a server's `CreateSigningKey`
 * returns), and the public key as base64 spki der, to register with
 * the server.
 */
export async function generateSigningKey(): Promise<{
  privateKey: string;
  publicKey: string;
}> {
  const subtle = webCrypto().subtle;
  const pair = (await subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const privateKey = base64Encode(
    new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey)),
  );
  const publicKey = base64Encode(
    new Uint8Array(await subtle.exportKey("spki", pair.publicKey)),
  );
  return { privateKey, publicKey };
}

/**
 * The host a request to `url` (an `http(s)` or `ws(s)` url) is signed
 * for: its lowercase `host[:port]`, without the port when it is the
 * default of the scheme. `https://Example.com/auth` is `example.com`,
 * `http://10.0.0.5:9120` is `10.0.0.5:9120`, and `http://[::1]:80` is
 * `[::1]`. The server derives the hosts it accepts signatures for the
 * same way, from the origins it is configured with.
 *
 * A url with credentials (`https://user:password@example.com`) is an
 * error, which doesn't repeat them: a client sends those as
 * `Authorization`, which a server takes over the signature.
 */
export function urlHost(url: string | URL): string {
  return urlOriginHost(parseUrl(url));
}

function parseUrl(url: string | URL): URL {
  if (url instanceof URL) return url;
  try {
    return new URL(url.trim());
  } catch {
    throw new Error("Invalid url, expected eg. https://example.com");
  }
}

function urlOriginHost(url: URL): string {
  if (!["http:", "https:", "ws:", "wss:"].includes(url.protocol)) {
    throw new Error(
      "The url is not an http(s) url, expected eg. https://example.com",
    );
  }
  if (url.username || url.password) {
    throw new Error(
      "The url carries credentials (user:password@), expected eg. https://example.com",
    );
  }
  if (!url.hostname) {
    throw new Error("The url has no host, expected eg. https://example.com");
  }
  const hostname = url.hostname.toLowerCase();
  const host = url.port ? `${hostname}:${url.port}` : hostname;
  if (!validHost(host)) {
    throw new Error(
      "The host of the url is not a host name or ip address, expected eg. https://example.com",
    );
  }
  return host;
}

/**
 * The path and query of `url` as a request to it carries them: percent
 * encoded, without the fragment.
 */
export function urlPathAndQuery(url: string | URL): string {
  const parsed = parseUrl(url);
  return parsed.pathname + parsed.search;
}

/** The longest host: a name of 253 characters, a trailing dot and a port. */
const MAX_HOST_LEN = 260;

/**
 * Whether `host` has the form a request is signed for and `X-API-HOST`
 * names: what `urlHost` makes of an address, a lowercase `host[:port]`.
 */
export function validHost(host: string): boolean {
  return (
    host.length >= 1 &&
    host.length <= MAX_HOST_LEN &&
    /^[a-z0-9.\-_:[\]]+$/.test(host)
  );
}

/**
 * Whether the server accepts `nonce`: 16 to 64 characters of `A-Z`,
 * `a-z`, `0-9`, `-` and `_` (hex and base64url both fit).
 */
export function validNonce(nonce: string): boolean {
  return /^[A-Za-z0-9_-]{16,64}$/.test(nonce);
}

/** A nonce for a signed request: 16 random bytes as 32 hex characters. */
export function randomNonce(): string {
  const bytes = new Uint8Array(16);
  webCrypto().getRandomValues(bytes);
  return hex(bytes);
}

/** The sha256 of a request body as the signature covers it: lowercase hex. */
export async function bodySha256(body: Uint8Array | string): Promise<string> {
  const bytes = typeof body === "string" ? ENCODER.encode(body) : body;
  return hex(
    new Uint8Array(
      await webCrypto().subtle.digest("SHA-256", bufferSource(bytes)),
    ),
  );
}

/**
 * Whether `request` is one a server could accept: a host as `urlHost`
 * gives it, a method as one is sent, a path and query as a server
 * receives them (visible ASCII, starting with `/`, without a fragment)
 * and a valid nonce. Throws otherwise, so what a client signs by
 * mistake (a url or a key for the host) is an error here rather than
 * a `401`.
 */
export function checkSignedRequest(request: SignedRequest): void {
  if (!validHost(request.host)) {
    throw new Error(
      "Invalid host to sign the request for, expected the lowercase host[:port] of the server address (eg. example.com)",
    );
  }
  // RFC 9110 5.6.2.
  if (!/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(request.method)) {
    throw new Error(
      "Invalid method to sign the request for, expected it as it is sent (eg. POST)",
    );
  }
  if (
    !request.pathAndQuery.startsWith("/") ||
    !/^[\x21-\x7e]+$/.test(request.pathAndQuery) ||
    request.pathAndQuery.includes("#")
  ) {
    throw new Error(
      "Invalid path to sign the request for, expected the path and query the server receives (eg. /read?x=1)",
    );
  }
  if (!validNonce(request.nonce)) {
    throw new Error(
      "Invalid nonce, expected 16 to 64 characters of A-Z a-z 0-9 - _",
    );
  }
}

/**
 * The message which is signed: one line each, joined by `\n` without a
 * trailing one.
 *
 * ```text
 * MOGH1-ED25519
 * {host}
 * {method}
 * {pathAndQuery}
 * {timestamp}
 * {nonce}
 * {sha256(body) hex}
 * ```
 */
export async function signedMessage(request: SignedRequest): Promise<string> {
  return [
    SIGNED_REQUEST_VERSION,
    request.host,
    request.method,
    request.pathAndQuery,
    String(request.timestamp),
    request.nonce,
    await bodySha256(request.body),
  ].join("\n");
}

/**
 * The signature of `request`: 64 bytes, base64, sent in
 * `X-API-SIGNATURE`. A request no server could accept
 * (`checkSignedRequest`) is an error.
 */
export async function signRequest(
  keys: SigningKeys,
  request: SignedRequest,
): Promise<string> {
  checkSignedRequest(request);
  const message = ENCODER.encode(await signedMessage(request));
  const signature = await webCrypto().subtle.sign(
    "Ed25519",
    keys.privateKey,
    message,
  );
  return base64Encode(new Uint8Array(signature));
}

/**
 * The headers authenticating a request made right now to the server at
 * `host` (`urlHost` of its address, never the address itself): the
 * public key, host, timestamp, nonce and signature, a new timestamp
 * and nonce every call. `pathAndQuery` is the path the server receives
 * (where a proxy in front of it strips a prefix, not the one of the
 * url), and `body` exactly the bytes sent (empty for none).
 *
 * The server only accepts the signature for about a second by default,
 * so make them right before sending, and keep the clock of the client
 * synchronized.
 */
export async function signedRequestHeaders(
  keys: SigningKeys,
  host: string,
  method: string,
  pathAndQuery: string,
  body: Uint8Array | string,
): Promise<Record<string, string>> {
  const request: SignedRequest = {
    host,
    method,
    pathAndQuery,
    timestamp: Date.now(),
    nonce: randomNonce(),
    body,
  };
  const signature = await signRequest(keys, request);
  return {
    [API_PUBLIC_KEY_HEADER]: keys.publicKey,
    [API_HOST_HEADER]: host,
    [API_TIMESTAMP_HEADER]: String(request.timestamp),
    [API_NONCE_HEADER]: request.nonce,
    [API_SIGNATURE_HEADER]: signature,
  };
}

/**
 * `signedRequestHeaders` for a `method` request with `body` sent to
 * `url`: signed for the host of the url (`urlHost`) and its path and
 * query, as they are sent. Where a proxy in front of the server strips
 * a prefix of the path, sign the path the server receives with
 * `signedRequestHeaders` (or `requestSigner` with an `address`)
 * instead.
 */
export async function signedRequestHeadersForUrl(
  keys: SigningKeys,
  method: string,
  url: string | URL,
  body: Uint8Array | string,
): Promise<Record<string, string>> {
  const parsed = parseUrl(url);
  return await signedRequestHeaders(
    keys,
    urlOriginHost(parsed),
    method,
    parsed.pathname + parsed.search,
    body,
  );
}

/**
 * Signs a request about to be sent: the headers to send it with, made
 * right before each attempt (`fetchSignedJson`). `requestSigner` makes
 * one for a key.
 */
export type RequestSigner = (request: {
  /** The method as it is sent. */
  method: string;
  /** Where the request is sent. */
  url: string;
  /** The body exactly as sent, none for a request without one. */
  body?: Uint8Array | string | undefined;
}) => Promise<Record<string, string>>;

/**
 * A `RequestSigner` signing with `keys`, the key pair of `signingKeys`
 * (or its promise: a key which doesn't parse then rejects every
 * request, nothing else). Every request is signed for the host of its
 * url and its path and query, as they are sent, unless:
 * - `address`: the server's address, which every request url has to
 *   start with. The request is then signed for the host of the address
 *   and the path after it, the one the server receives where a proxy
 *   strips a prefix (`https://example.com/app` makes a request to
 *   `https://example.com/app/read` sign `/read`).
 * - `host`: the host to sign for instead of the url's (or the
 *   address's), one of the hosts the server is configured with: the
 *   server knows itself by another host than the url has.
 * - `headers`: sent along, unsigned, with every request (eg. a client
 *   type the server routes the signer by).
 */
export function requestSigner(
  keys: SigningKeys | Promise<SigningKeys>,
  options?: {
    address?: string;
    host?: string;
    headers?: Record<string, string>;
  },
): RequestSigner {
  const address = options?.address?.trim().replace(/\/+$/, "");
  const fixedHost = options?.host ?? (address ? urlHost(address) : undefined);
  return async ({ method, url, body }) => {
    const pair = await keys;
    let host: string;
    let pathAndQuery: string;
    if (address) {
      if (!url.startsWith(address + "/") && url !== address) {
        throw new Error(
          "The request url is not under the address the signer signs for",
        );
      }
      host = fixedHost ?? urlHost(address);
      pathAndQuery = url.slice(address.length) || "/";
    } else {
      const parsed = parseUrl(url);
      host = fixedHost ?? urlOriginHost(parsed);
      pathAndQuery = parsed.pathname + parsed.search;
    }
    const signed = await signedRequestHeaders(
      pair,
      host,
      method,
      pathAndQuery,
      body ?? "",
    );
    return { ...options?.headers, ...signed };
  };
}

// ---- The private key forms ----

/**
 * The 32 byte Ed25519 seed of a private key in any of the accepted
 * forms, see `signingKeys`. With `inline`, a raw value has to be
 * exactly 32 bytes.
 */
function parseSeed(privateKey: string, inline: boolean): Uint8Array {
  const trimmed = privateKey.trim();
  if (!trimmed) throw new Error("Private key is empty");
  // pem rfc7468 (openssl)
  if (trimmed.startsWith("-----BEGIN")) {
    return seedOfDer(pemBody(trimmed), inline);
  }
  if (looksLikeAPath(privateKey)) {
    throw new Error(
      `The private key looks like a file path, which would be taken for the key itself: ${INLINE_KEY_FORMS}`,
    );
  }
  // Raw input is used exactly as given (its UTF-8 bytes), so a key
  // keeps deriving the same public key however it is passed.
  const bytes = ENCODER.encode(privateKey);
  let raw: boolean;
  if (inline) {
    if (bytes.length < 32) {
      throw new Error(
        `The private key is shorter than 32 bytes: ${INLINE_KEY_FORMS}. A shorter raw value would be used as the key itself, which anybody can find from the public key: generate a key, or keep it in a key file`,
      );
    }
    raw = bytes.length === 32;
  } else {
    raw = bytes.length <= 32;
  }
  if (raw) {
    const seed = new Uint8Array(32);
    seed.set(bytes);
    checkSeed(seed);
    return seed;
  }
  // base64 der
  let der: Uint8Array;
  try {
    der = base64Decode(trimmed);
  } catch {
    throw new Error(
      inline ? `Invalid private key: ${INLINE_KEY_FORMS}` : NOT_A_PRIVATE_KEY,
    );
  }
  return seedOfDer(der, inline);
}

/** The base64 body of a pem, decoded. */
function pemBody(pem: string): Uint8Array {
  const lines = pem.split(/\r?\n/).map((line) => line.trim());
  const begin = lines[0]?.match(/^-----BEGIN ([^-]+)-----$/);
  const end = lines[lines.length - 1]?.match(/^-----END ([^-]+)-----$/);
  if (!begin || !end || begin[1] !== end[1]) {
    throw new Error(
      "Failed to get der from pem: expected a -----BEGIN PRIVATE KEY----- / -----END PRIVATE KEY----- pair",
    );
  }
  if (begin[1] !== "PRIVATE KEY") {
    throw new Error(
      `Failed to get der from pem: expected a PRIVATE KEY (pkcs8), not ${begin[1]}`,
    );
  }
  try {
    return base64Decode(lines.slice(1, -1).join(""));
  } catch {
    throw new Error("Failed to get der from pem: the body is not base64");
  }
}

/**
 * The seed of a pkcs8 PrivateKeyInfo (der): v1 or v2 (whose attributes
 * and public key are skipped). A key of another algorithm is refused,
 * naming X25519 when it is that.
 */
function seedOfDer(der: Uint8Array, inline: boolean): Uint8Array {
  const invalid = (reason: string) =>
    new Error(
      `${inline ? `Invalid private key: ${INLINE_KEY_FORMS}` : NOT_A_PRIVATE_KEY} (${reason})`,
    );
  try {
    const info = readTlv(der, 0);
    if (info.tag !== 0x30) throw new Error("not a PrivateKeyInfo");
    const version = readTlv(der, info.start);
    if (version.tag !== 0x02) throw new Error("no version");
    const algorithm = readTlv(der, version.end);
    if (algorithm.tag !== 0x30) throw new Error("no algorithm");
    const oid = readTlv(der, algorithm.start);
    if (oid.tag !== 0x06) throw new Error("no algorithm oid");
    const oidBytes = Array.from(der.subarray(oid.start, oid.end));
    if (sameBytes(oidBytes, X25519_OID)) {
      throw new WrongKeyAlgorithm();
    }
    if (!sameBytes(oidBytes, ED25519_OID)) {
      throw new Error("not an Ed25519 key");
    }
    const privateKey = readTlv(der, algorithm.end);
    if (privateKey.tag !== 0x04) throw new Error("no private key");
    const curvePrivateKey = readTlv(der, privateKey.start);
    if (curvePrivateKey.tag !== 0x04 || curvePrivateKey.end > privateKey.end) {
      throw new Error("no curve private key");
    }
    const seed = der.slice(curvePrivateKey.start, curvePrivateKey.end);
    if (seed.length !== 32) {
      throw new Error(
        `raw private key length should be 32, got ${seed.length}`,
      );
    }
    checkSeed(seed);
    return seed;
  } catch (e) {
    if (e instanceof WrongKeyAlgorithm) throw e;
    throw invalid(e instanceof Error ? e.message : String(e));
  }
}

/** A pkcs8 key of the other algorithm: its own error says more. */
class WrongKeyAlgorithm extends Error {
  constructor() {
    super(
      "The private key is an X25519 key, requests are signed with an Ed25519 key",
    );
    this.name = "WrongKeyAlgorithm";
  }
}

/** Refuses the all zero seed, which empty or zero input produces. */
function checkSeed(seed: Uint8Array): void {
  let bits = 0;
  for (const byte of seed) bits |= byte;
  if (bits === 0) {
    throw new Error("Private key is all zero, a publicly known key");
  }
}

/** One der TLV at `offset`: its tag and the bounds of its contents. */
function readTlv(
  bytes: Uint8Array,
  offset: number,
): { tag: number; start: number; end: number } {
  if (offset + 2 > bytes.length) throw new Error("truncated der");
  const tag = bytes[offset]!;
  let length = bytes[offset + 1]!;
  let start = offset + 2;
  if (length & 0x80) {
    const lengthBytes = length & 0x7f;
    if (
      lengthBytes === 0 ||
      lengthBytes > 4 ||
      start + lengthBytes > bytes.length
    ) {
      throw new Error("invalid der length");
    }
    length = 0;
    for (let i = 0; i < lengthBytes; i++) {
      length = length * 256 + bytes[start + i]!;
    }
    start += lengthBytes;
  }
  const end = start + length;
  if (end > bytes.length) throw new Error("truncated der");
  return { tag, start, end };
}

/**
 * Whether `privateKey` reads like the path of a key file, which is
 * refused as a key: `file:` specs, relative paths, Windows drives, a
 * key file's ending, and an absolute path which doesn't read as random
 * base64 (as a raw key's length of it does, bar one in thousands).
 */
export function looksLikeAPath(privateKey: string): boolean {
  const spec = privateKey.trim();
  const prefix = spec.slice(0, 5).toLowerCase() === "file:";
  const relative = ["./", "../", "~/", ".\\", "..\\", "~\\"].some((start) =>
    spec.startsWith(start),
  );
  const drive = /^[A-Za-z]:[\\/]/.test(spec);
  const ending = [".key", ".pem", ".der", ".pk8", ".p8", ".priv"].some(
    (end) => spec.length > end.length && spec.toLowerCase().endsWith(end),
  );
  const random = () =>
    spec.length % 4 === 0 &&
    isBase64(spec) &&
    /[A-Z]/.test(spec) &&
    /[a-z]/.test(spec) &&
    /[0-9]/.test(spec);
  return (
    prefix || relative || drive || ending || (spec.startsWith("/") && !random())
  );
}

// ---- Bytes ----

function webCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new Error(
      "WebCrypto (crypto.subtle) is not available: signed requests need it",
    );
  }
  return c;
}

function hexBytes(hexString: string): Uint8Array {
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexString.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * `bytes` as WebCrypto takes them: a view over a plain `ArrayBuffer`
 * (copied when it is over a shared one).
 */
function bufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.buffer instanceof ArrayBuffer
    ? (bytes as Uint8Array<ArrayBuffer>)
    : new Uint8Array(bytes);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function sameBytes(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/** Standard base64, padded, no whitespace: what the server encodes and takes. */
function isBase64(value: string): boolean {
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
    value,
  );
}

function base64Decode(value: string): Uint8Array {
  if (!isBase64(value)) throw new Error("not base64");
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64UrlDecode(value: string): Uint8Array {
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  return base64Decode(standard + "=".repeat((4 - (standard.length % 4)) % 4));
}

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
