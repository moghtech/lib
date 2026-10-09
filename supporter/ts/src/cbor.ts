/**
 * The subset of CBOR (RFC 8949) a supporter key payload is encoded
 * in: unsigned and negative integers, byte and text strings, arrays
 * and maps of definite length, `false`, `true` and `null`. Arrays
 * and maps are decoded whole, which is what lets a field this
 * version does not know be skipped. Everything else is refused:
 * indefinite lengths, tags, floats, other simple values, duplicate
 * map keys, map keys which are neither text nor integers, and bytes
 * after the item.
 *
 * The Rust crate's decoder (`decode_cbor`) is the same, error
 * messages included: both run the vectors of
 * `supporter/test_vectors.json`.
 */

/** The most nested arrays / maps `decodeCbor` follows. */
export const CBOR_MAX_DEPTH = 16;

/**
 * An integer is a `number` when it is safe, else a `bigint`, so each
 * value has one representation (a map key is found again).
 */
export type CborValue =
  | number
  | bigint
  | Uint8Array<ArrayBuffer>
  | string
  | CborValue[]
  | CborMap
  | boolean
  | null;

export type CborMap = Map<string | number | bigint, CborValue>;

/**
 * Text strings: utf8, strictly (an invalid sequence is an error), and
 * a leading byte order mark kept as part of the text, as Rust's
 * `str::from_utf8` keeps it. A `TextDecoder` drops it by default.
 */
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Why bytes are not an item of the subset. Never echoes them. */
export class CborError extends Error {
  /** The byte offset of the item. */
  readonly at: number;
  constructor(message: string, at: number) {
    super(`${message} at byte ${at}`);
    this.name = "CborError";
    this.at = at;
  }
}

/** Decodes `bytes` as exactly one item of the subset. */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const decoder = new Decoder(bytes);
  const value = decoder.item(0);
  if (decoder.at < bytes.length) {
    throw new CborError(
      `${bytes.length - decoder.at} bytes follow the item`,
      decoder.at,
    );
  }
  return value;
}

class Decoder {
  at = 0;
  private readonly bytes: Uint8Array;
  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }

  private byte(): number {
    if (this.at >= this.bytes.length) {
      throw new CborError("Unexpected end of input", this.at);
    }
    return this.bytes[this.at++];
  }

  private take(length: number): Uint8Array {
    if (length > this.bytes.length - this.at) {
      throw new CborError("Unexpected end of input", this.at);
    }
    const slice = this.bytes.subarray(this.at, this.at + length);
    this.at += length;
    return slice;
  }

  /**
   * The argument of an item: inline for additional information 0 to
   * 23, else the next 1, 2, 4 or 8 bytes, big endian.
   */
  private argument(major: number, info: number, at: number): number | bigint {
    if (info < 24) return info;
    switch (info) {
      case 24:
        return this.byte();
      case 25: {
        const b = this.take(2);
        return (b[0] << 8) | b[1];
      }
      case 26: {
        const b = this.take(4);
        return b[0] * 0x1000000 + ((b[1] << 16) | (b[2] << 8) | b[3]);
      }
      case 27: {
        let n = 0n;
        for (const byte of this.take(8)) {
          n = (n << 8n) | BigInt(byte);
        }
        return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
      }
      case 31:
        throw new CborError("Indefinite length item", at);
      default:
        throw new CborError(
          `Unsupported item (major type ${major}, additional information ${info})`,
          at,
        );
    }
  }

  /**
   * A length or count. Every byte of a string and every item of an
   * array / map takes at least one byte of input, so a value past
   * the input is refused before anything is read or allocated for it.
   */
  private length(major: number, info: number, at: number): number {
    const n = this.argument(major, info, at);
    if (typeof n === "bigint" || n > this.bytes.length - this.at) {
      throw new CborError("Unexpected end of input", this.at);
    }
    return n;
  }

  item(depth: number): CborValue {
    const at = this.at;
    const initial = this.byte();
    const major = initial >> 5;
    const info = initial & 0x1f;
    switch (major) {
      case 0:
        return this.argument(major, info, at);
      case 1: {
        const n = this.argument(major, info, at);
        return typeof n === "number" && n < Number.MAX_SAFE_INTEGER
          ? -1 - n
          : -1n - BigInt(n);
      }
      case 2:
        return this.take(this.length(major, info, at)).slice();
      case 3: {
        const text = this.take(this.length(major, info, at));
        try {
          return UTF8.decode(text);
        } catch {
          throw new CborError("Text is not utf8", at);
        }
      }
      case 4: {
        if (depth >= CBOR_MAX_DEPTH) {
          throw new CborError(`Nested deeper than ${CBOR_MAX_DEPTH}`, at);
        }
        const count = this.length(major, info, at);
        const items: CborValue[] = [];
        for (let i = 0; i < count; i++) {
          items.push(this.item(depth + 1));
        }
        return items;
      }
      case 5: {
        if (depth >= CBOR_MAX_DEPTH) {
          throw new CborError(`Nested deeper than ${CBOR_MAX_DEPTH}`, at);
        }
        const count = this.length(major, info, at);
        const map: CborMap = new Map();
        for (let i = 0; i < count; i++) {
          const keyAt = this.at;
          const key = this.item(depth + 1);
          if (
            typeof key !== "string" &&
            typeof key !== "number" &&
            typeof key !== "bigint"
          ) {
            throw new CborError("Map key is not text or an integer", keyAt);
          }
          if (map.has(key)) {
            throw new CborError("Duplicate map key", keyAt);
          }
          map.set(key, this.item(depth + 1));
        }
        return map;
      }
      case 6:
        throw new CborError("Tag", at);
      default:
        switch (info) {
          case 20:
            return false;
          case 21:
            return true;
          case 22:
            return null;
          case 25:
          case 26:
          case 27:
            throw new CborError("Float", at);
          case 31:
            throw new CborError("Indefinite length item", at);
          default:
            throw new CborError(
              `Unsupported item (major type ${major}, additional information ${info})`,
              at,
            );
        }
    }
  }
}
