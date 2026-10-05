import { type CborMap, decodeCbor } from "./cbor.ts";
import { hex } from "./encoding.ts";

/** The format version this package reads: the `v` of a payload. */
export const FORMAT_VERSION = 1;

/** The most bytes a payload may have. */
export const MAX_PAYLOAD_BYTES = 4096;

/** The `t` of a payload. */
export type SupporterTier = "individual" | "organization" | "sponsor";

const TIERS: readonly SupporterTier[] = ["individual", "organization", "sponsor"];

/**
 * The payload of a supporter key (`P`), read. It is trusted only once
 * the root signature over the payload bytes verifies.
 */
export interface SupporterPayload {
  /** `v`. Only `FORMAT_VERSION` is valid. */
  version: number;
  /** `k`: the id of the root key which signed the key, lowercase hex. */
  rootKeyId: string;
  /**
   * `i`: the id of the key as a lowercase hyphenated UUID, the form
   * the revocation list uses.
   */
  id: string;
  /** `a`: the app the key is for, `komodo` or `cicada`. */
  app: string;
  /** `n`: the name the badge shows. */
  name: string;
  /** `t`. */
  tier: SupporterTier;
  /** `s`: supporter since, `YYYY-MM-DD`. Shown, not checked. */
  since: string;
  /**
   * `c`: the last release date the key covers, `YYYY-MM-DD`. A
   * release published up to this date shows the badge, forever.
   */
  covers: string;
}

/** Why bytes are not a payload. Never echoes them. */
export class PayloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PayloadError";
  }
}

/**
 * Whether `text` has the form `YYYY-MM-DD`: digits and hyphens in
 * their places. Two such dates compare as strings.
 */
export function isDate(text: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(text);
}

/**
 * Decodes the payload bytes as a CBOR map. Nothing in it is trusted
 * yet: read only `k` from it (`payloadRootKeyId`), verify the root
 * signature, then `readPayload`.
 */
export function decodePayloadMap(bytes: Uint8Array): CborMap {
  if (bytes.length > MAX_PAYLOAD_BYTES) {
    throw new PayloadError(
      `The payload is ${bytes.length} bytes, the most is ${MAX_PAYLOAD_BYTES}`,
    );
  }
  const value = decodeCbor(bytes);
  if (!(value instanceof Map)) {
    throw new PayloadError("The payload is not a map");
  }
  return value;
}

/** The `k` of a payload map, lowercase hex: the root to verify under. */
export function payloadRootKeyId(map: CborMap): string {
  return hex(bytesField(map, "k", 8));
}

/** The payload of a decoded map. Keys this version does not know are ignored. */
export function readPayload(map: CborMap): SupporterPayload {
  return {
    version: unsignedField(map, "v"),
    rootKeyId: hex(bytesField(map, "k", 8)),
    id: formatUuid(bytesField(map, "i", 16)),
    app: textField(map, "a"),
    name: textField(map, "n"),
    tier: tierField(map, "t"),
    since: dateField(map, "s"),
    covers: dateField(map, "c"),
  };
}

/** 16 bytes as a lowercase hyphenated UUID (8-4-4-4-12). */
export function formatUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new PayloadError(`A UUID is 16 bytes, got ${bytes.length}`);
  }
  const h = hex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function field(map: CborMap, name: string) {
  if (!map.has(name)) {
    throw new PayloadError(`The payload has no \`${name}\``);
  }
  return map.get(name);
}

function unsignedField(map: CborMap, name: string): number {
  const value = field(map, name);
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new PayloadError(
      `The \`${name}\` of the payload is not an unsigned integer`,
    );
  }
  return value;
}

function bytesField(map: CborMap, name: string, length: number): Uint8Array {
  const value = field(map, name);
  if (!(value instanceof Uint8Array)) {
    throw new PayloadError(`The \`${name}\` of the payload is not a byte string`);
  }
  if (value.length !== length) {
    throw new PayloadError(
      `The \`${name}\` of the payload is ${value.length} bytes, expected ${length}`,
    );
  }
  return value;
}

function textField(map: CborMap, name: string): string {
  const value = field(map, name);
  if (typeof value !== "string") {
    throw new PayloadError(`The \`${name}\` of the payload is not text`);
  }
  return value;
}

function tierField(map: CborMap, name: string): SupporterTier {
  const value = textField(map, name);
  if (!(TIERS as readonly string[]).includes(value)) {
    throw new PayloadError(
      `The \`${name}\` of the payload is not \`individual\`, \`organization\` or \`sponsor\``,
    );
  }
  return value as SupporterTier;
}

function dateField(map: CborMap, name: string): string {
  const value = textField(map, name);
  if (!isDate(value)) {
    throw new PayloadError(
      `The \`${name}\` of the payload is not a \`YYYY-MM-DD\` date`,
    );
  }
  return value;
}
