/**
 * The check of an Ed25519 public key the Rust crate makes with
 * curve25519-dalek (`root_key_bytes`), which WebCrypto doesn't: the
 * 32 bytes are the canonical encoding of a point of the curve
 * (RFC 8032 §5.1.3), and the point is not of small order. A small
 * order (weak) key has signatures which verify for any message.
 *
 * Plain arithmetic on `bigint`, for public keys only (the root keys an
 * app hardcodes): nothing here is constant time, and nothing secret
 * goes in.
 */

/** The field prime, `2^255 - 19`. */
const P = 2n ** 255n - 19n;

/** The constant `d` of the curve, `-121665 / 121666`. */
const D =
  37095705934669439343138083508754565189542113879843219016388785533085940283555n;

/** A square root of `-1`, `2^((p - 1) / 4)`. */
const SQRT_M1 =
  19681161376707505956807079304988542015446066515923890162744021073123829784752n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r < 0n ? r + P : r;
}

function pow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
  }
  return result;
}

interface Point {
  x: bigint;
  y: bigint;
}

/**
 * The point 32 bytes encode, or `undefined`: no point of the curve, or
 * not its canonical encoding (a `y` of `p` or more, or the sign bit set
 * for an `x` of `0`).
 */
function decodePoint(bytes: Uint8Array): Point | undefined {
  // `y` little endian, the top bit is the sign of `x`.
  let y = 0n;
  for (let i = 31; i >= 0; i--) {
    y = (y << 8n) | BigInt(i === 31 ? bytes[i] & 0x7f : bytes[i]);
  }
  const sign = bytes[31] >> 7;
  if (y >= P) return undefined;
  // x^2 = u / v = (y^2 - 1) / (d y^2 + 1)
  const yy = (y * y) % P;
  const u = mod(yy - 1n);
  const v = mod(D * yy + 1n);
  const v3 = (((v * v) % P) * v) % P;
  const v7 = (((v3 * v3) % P) * v) % P;
  let x = (((u * v3) % P) * pow((u * v7) % P, (P - 5n) / 8n)) % P;
  const vxx = (v * ((x * x) % P)) % P;
  if (vxx !== u) {
    if (vxx !== mod(-u)) return undefined;
    x = (x * SQRT_M1) % P;
  }
  if (x === 0n && sign === 1) return undefined;
  if (Number(x & 1n) !== sign) x = P - x;
  return { x, y };
}

/** `p + q` on the curve (`a = -1`), whose addition law is complete. */
function add(p: Point, q: Point): Point {
  const xx = (p.x * q.x) % P;
  const yy = (p.y * q.y) % P;
  const dxxyy = (D * ((xx * yy) % P)) % P;
  return {
    x: (mod(p.x * q.y + p.y * q.x) * pow(mod(1n + dxxyy), P - 2n)) % P,
    y: (mod(yy + xx) * pow(mod(1n - dxxyy), P - 2n)) % P,
  };
}

/**
 * Whether 32 bytes are an Ed25519 public key the Rust crate takes: the
 * canonical encoding of a point of the curve, which is not of small
 * order (8 times the point, the cofactor, is not the identity).
 */
export function isCanonicalEd25519Key(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return false;
  const point = decodePoint(bytes);
  if (point === undefined) return false;
  let q = point;
  for (let i = 0; i < 3; i++) q = add(q, q);
  return !(q.x === 0n && q.y === 1n);
}
