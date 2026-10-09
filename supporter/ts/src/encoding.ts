const BASE64URL =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const BASE64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** The value of each ascii character in `alphabet`, `-1` for none. */
function alphabetIndex(alphabet: string): Int8Array {
  const index = new Int8Array(128).fill(-1);
  for (let i = 0; i < alphabet.length; i++) {
    index[alphabet.charCodeAt(i)] = i;
  }
  return index;
}

const BASE64URL_INDEX = alphabetIndex(BASE64URL);

const BASE64_INDEX = alphabetIndex(BASE64);

/**
 * Decodes the symbols `text[start..end)`, 6 bits each, into `out` from
 * `at`. Any other character is an error, and so are non zero bits left
 * after the last whole byte (another text for the same bytes). Returns
 * where the next byte goes.
 */
function decodeSymbols(
  text: string,
  start: number,
  end: number,
  index: Int8Array,
  name: string,
  out: Uint8Array,
  at: number,
): number {
  let acc = 0;
  let bits = 0;
  let o = at;
  for (let i = start; i < end; i++) {
    const code = text.charCodeAt(i);
    const value = code < 128 ? index[code] : -1;
    if (value < 0) {
      throw new Error(`${name}: invalid character at ${i}`);
    }
    acc = (acc << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0) {
    throw new Error(`${name}: non canonical trailing bits`);
  }
  return o;
}

/**
 * Decodes base64url without padding (RFC 4648 §5), strictly: padding,
 * any other character, a length of 1 mod 4 and non zero trailing bits
 * (another text for the same bytes) are errors, as for the Rust
 * crate's `BASE64URL_NOPAD` of data_encoding. Every value of a
 * supporter key is encoded this way.
 */
export function base64urlDecode(text: string): Uint8Array<ArrayBuffer> {
  if (text.length % 4 === 1) {
    throw new Error("base64url: invalid length");
  }
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  decodeSymbols(text, 0, text.length, BASE64URL_INDEX, "base64url", out, 0);
  return out;
}

function encode(bytes: Uint8Array, alphabet: string, pad: boolean): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      alphabet[n >> 18] +
      alphabet[(n >> 12) & 63] +
      alphabet[(n >> 6) & 63] +
      alphabet[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += alphabet[n >> 18] + alphabet[(n >> 12) & 63] + (pad ? "==" : "");
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out +=
      alphabet[n >> 18] +
      alphabet[(n >> 12) & 63] +
      alphabet[(n >> 6) & 63] +
      (pad ? "=" : "");
  }
  return out;
}

/** Encodes base64url without padding. */
export function base64urlEncode(bytes: Uint8Array): string {
  return encode(bytes, BASE64URL, false);
}

/** Encodes standard base64 with padding: the form of a `data:` url. */
export function base64Encode(bytes: Uint8Array): string {
  return encode(bytes, BASE64, true);
}

/**
 * Decodes standard base64 with padding (RFC 4648 §4), the form of a
 * root key's SPKI DER and of an uploaded icon, strictly, as the Rust
 * crate's `BASE64` of data_encoding does: a length which is no
 * multiple of 4, padding anywhere but at the end of a block of 4 (2
 * or 3 symbols, then `==` or `=`), any other character, and non zero
 * trailing bits (another text for the same bytes) are errors. Padded
 * blocks can follow each other (`AQ==AQ==`), as in Rust.
 */
export function base64Decode(text: string): Uint8Array<ArrayBuffer> {
  if (text.length % 4 !== 0) {
    throw new Error("base64: invalid length");
  }
  const out = new Uint8Array((text.length / 4) * 3);
  let o = 0;
  for (let block = 0; block < text.length; block += 4) {
    let end = block + 4;
    while (end > block && text[end - 1] === "=") end--;
    if (end - block < 2) {
      throw new Error(`base64: invalid padding at ${end}`);
    }
    o = decodeSymbols(text, block, end, BASE64_INDEX, "base64", out, o);
  }
  return out.slice(0, o);
}

/** Lowercase hex. */
export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(
    parts.reduce((length, part) => length + part.length, 0),
  );
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return concatBytes(new TextEncoder().encode(text));
}
