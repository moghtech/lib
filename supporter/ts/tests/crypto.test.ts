// The two implementations the badge verifies with, side by side: the
// page's WebCrypto and the JavaScript one of `@noble/ed25519` and
// `@noble/hashes` (src/crypto.ts). verify.test.ts runs every verdict
// through both; this checks them on crafted signatures too.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { supporterCrypto } from "../src/crypto.ts";
import { hexToBytes } from "./fixture.ts";

const IMPLEMENTATIONS = [
  supporterCrypto(crypto.subtle),
  supporterCrypto(null),
];

function bytes(hex: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(hexToBytes(hex));
}

/** RFC 8032 §7.1 TEST 1 to 3: public key, message, signature. */
const RFC_8032 = [
  [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "",
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  ],
  [
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "72",
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  ],
  [
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "af82",
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  ],
].map(([key, message, signature]) => ({
  key: bytes(key),
  message: bytes(message),
  signature: bytes(signature),
}));

/** The group order, little endian. */
const ORDER = bytes(
  "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
);

/** `signature` with the order added to its S: the same point, refused. */
function plusOrder(signature: Uint8Array<ArrayBuffer>) {
  const out = signature.slice();
  let carry = 0;
  for (let i = 0; i < 32; i++) {
    const sum = out[32 + i] + ORDER[i] + carry;
    out[32 + i] = sum & 0xff;
    carry = sum >> 8;
  }
  return out;
}

test("both are named", () => {
  assert.deepEqual(
    IMPLEMENTATIONS.map(({ name }) => name),
    ["WebCrypto", "JavaScript"],
  );
});

test("both verify the signatures of RFC 8032, and nothing else", async () => {
  for (const { name, verifyEd25519 } of IMPLEMENTATIONS) {
    for (const [i, { key, message, signature }] of RFC_8032.entries()) {
      const at = `${name}, test ${i + 1}`;
      assert.equal(await verifyEd25519(key, signature, message), true, at);
      // Another message, signature or key.
      const other = new Uint8Array([...message, 0]);
      assert.equal(await verifyEd25519(key, signature, other), false, at);
      const flipped = signature.slice();
      flipped[10] ^= 1;
      assert.equal(await verifyEd25519(key, flipped, message), false, at);
      const next = RFC_8032[(i + 1) % RFC_8032.length].key;
      assert.equal(await verifyEd25519(next, signature, message), false, at);
      // No second encoding of a signature: S of the order or more.
      assert.equal(await verifyEd25519(key, plusOrder(signature), message), false, at);
    }
  }
});

test("both refuse a small order key, whose signatures verify for anything", async () => {
  // The identity as the public key, R the identity and S 0: valid for
  // every message under ZIP-215 (noble's default), refused by WebCrypto
  // and by RFC 8032's rules, which the JavaScript one follows.
  const identity = new Uint8Array(32);
  identity[0] = 1;
  const signature = new Uint8Array(64);
  signature.set(identity);
  for (const { name, verifyEd25519 } of IMPLEMENTATIONS) {
    for (const message of [new Uint8Array(0), bytes("616e797468696e67")]) {
      assert.equal(await verifyEd25519(identity, signature, message), false, name);
    }
  }
});

test("both hash with SHA-256", async () => {
  for (const data of [new Uint8Array(0), bytes("616263"), new Uint8Array(1000).fill(7)]) {
    const expected = createHash("sha256").update(data).digest("hex");
    for (const { name, sha256 } of IMPLEMENTATIONS) {
      assert.equal(Buffer.from(await sha256(data)).toString("hex"), expected, name);
    }
  }
});
