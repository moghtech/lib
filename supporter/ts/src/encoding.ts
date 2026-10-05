const BASE64URL =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const BASE64 =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const BASE64URL_INDEX = new Int8Array(128).fill(-1);
for (let i = 0; i < BASE64URL.length; i++) {
  BASE64URL_INDEX[BASE64URL.charCodeAt(i)] = i;
}

/**
 * Decodes base64url without padding (RFC 4648 §5), strictly: padding,
 * any other character, a length of 1 mod 4 and non zero trailing bits
 * (another text for the same bytes) are errors. Every value of a
 * supporter key is encoded this way.
 */
export function base64urlDecode(text: string): Uint8Array<ArrayBuffer> {
  if (text.length % 4 === 1) {
    throw new Error("base64url: invalid length");
  }
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const value = code < 128 ? BASE64URL_INDEX[code] : -1;
    if (value < 0) {
      throw new Error(`base64url: invalid character at ${i}`);
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
    throw new Error("base64url: non canonical trailing bits");
  }
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
 * root key's SPKI DER. Other characters are an error.
 */
export function base64Decode(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) {
    throw new Error("base64: invalid text");
  }
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
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
