import { test } from "node:test";
import assert from "node:assert/strict";
import {
  base64Decode,
  base64urlDecode,
  base64urlEncode,
  concatBytes,
  hex,
  utf8,
} from "../src/index.ts";
import * as fixture from "./fixture.ts";

test("base64url round trips, like node's", () => {
  for (const length of [0, 1, 2, 3, 4, 31, 32, 33, 63, 64, 65, 96, 100]) {
    for (let round = 0; round < 5; round++) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      const encoded = base64urlEncode(bytes);
      assert.equal(encoded, Buffer.from(bytes).toString("base64url"));
      assert.deepEqual(base64urlDecode(encoded), bytes);
    }
  }
  assert.equal(base64urlEncode(fixture.NONCE_BYTES), fixture.NONCE);
  assert.equal(hex(base64urlDecode(fixture.RESPONSE.payload)), fixture.PAYLOAD_HEX);
});

test("base64url is strict", () => {
  assert.throws(() => base64urlDecode("AQ=="), /invalid character at 2/);
  assert.throws(() => base64urlDecode("A"), /invalid length/);
  assert.throws(() => base64urlDecode("AQEBA"), /invalid length/);
  assert.throws(() => base64urlDecode("A+"), /invalid character at 1/);
  assert.throws(() => base64urlDecode("A/"), /invalid character at 1/);
  assert.throws(() => base64urlDecode(" AQ"), /invalid character at 0/);
  assert.throws(() => base64urlDecode("AQ\n"), /invalid character at 2/);
  assert.throws(() => base64urlDecode("A€"), /invalid character at 1/);
  // `AR` decodes to 0x01 with a trailing bit set: not what `AQ` encodes.
  assert.throws(() => base64urlDecode("AR"), /non canonical trailing bits/);
  assert.throws(() => base64urlDecode("AQF"), /non canonical trailing bits/);
  assert.deepEqual(base64urlDecode("AQ"), new Uint8Array([1]));
  assert.deepEqual(base64urlDecode("AQE"), new Uint8Array([1, 1]));
  assert.deepEqual(base64urlDecode(""), new Uint8Array());
});

test("base64 decodes a root key", () => {
  const der = base64Decode(fixture.ROOT_SPKI);
  assert.equal(der.length, 44);
  assert.equal(hex(der.subarray(0, 12)), "302a300506032b6570032100");
  assert.throws(() => base64Decode(fixture.ROOT_SPKI.replace("+", "-")), /invalid text/);
  assert.throws(() => base64Decode(fixture.ROOT_SPKI.slice(0, -1)), /invalid text/);
  assert.throws(() => base64Decode(" " + fixture.ROOT_SPKI), /invalid text/);
});

test("hex, concat, utf8", () => {
  assert.equal(hex(new Uint8Array([0, 1, 0xab, 0xff])), "0001abff");
  assert.equal(hex(new Uint8Array()), "");
  assert.deepEqual(concatBytes(new Uint8Array([1]), new Uint8Array(), new Uint8Array([2, 3])), new Uint8Array([1, 2, 3]));
  assert.deepEqual(utf8("komodo-supporter-v1"), new Uint8Array(Buffer.from("komodo-supporter-v1")));
  assert.deepEqual(utf8("€"), new Uint8Array([0xe2, 0x82, 0xac]));
});
