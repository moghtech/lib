import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CborError,
  decodeCbor,
  decodePayloadMap,
  formatUuid,
  payloadRootKeyId,
  readPayload,
  type CborMap,
} from "../src/index.ts";
import * as fixture from "./fixture.ts";

const bytes = (...values: number[]) => new Uint8Array(values);

function reason(input: Uint8Array): string {
  try {
    decodeCbor(input);
  } catch (e) {
    assert.ok(e instanceof CborError, String(e));
    return e.message;
  }
  assert.fail("decoded");
}

test("the fixture payload decodes to its fields", () => {
  const payload = fixture.hexToBytes(fixture.PAYLOAD_HEX);
  const map = decodePayloadMap(payload);
  assert.equal(map.size, 8);
  assert.deepEqual([...map.keys()], ["v", "k", "i", "a", "n", "t", "s", "c"]);
  assert.equal(map.get("v"), 1);
  assert.equal(payloadRootKeyId(map), fixture.ROOT_KID);
  assert.deepEqual(readPayload(map), fixture.SUPPORTER);
});

test("decodes the subset", () => {
  assert.equal(decodeCbor(bytes(0x17)), 23);
  assert.equal(decodeCbor(bytes(0x18, 0x18)), 24);
  assert.equal(decodeCbor(bytes(0x19, 0x01, 0x00)), 256);
  assert.equal(decodeCbor(bytes(0x1a, 0xff, 0xff, 0xff, 0xff)), 0xffffffff);
  assert.equal(decodeCbor(bytes(0x1b, 0, 0, 0, 1, 0, 0, 0, 0)), 2 ** 32);
  assert.equal(decodeCbor(bytes(0x1b, 0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), Number.MAX_SAFE_INTEGER);
  assert.equal(decodeCbor(bytes(0x1b, 0, 0x20, 0, 0, 0, 0, 0, 0)), 2n ** 53n);
  assert.equal(decodeCbor(bytes(0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), 2n ** 64n - 1n);
  assert.equal(decodeCbor(bytes(0x20)), -1);
  assert.equal(decodeCbor(bytes(0x38, 0x63)), -100);
  assert.equal(decodeCbor(bytes(0x3b, 0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe)), Number.MIN_SAFE_INTEGER);
  assert.equal(decodeCbor(bytes(0x3b, 0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), -(2n ** 53n));
  assert.equal(decodeCbor(bytes(0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), -(2n ** 64n));
  assert.deepEqual(decodeCbor(bytes(0x42, 1, 2)), bytes(1, 2));
  assert.deepEqual(decodeCbor(bytes(0x40)), bytes());
  assert.equal(decodeCbor(bytes(0x60)), "");
  assert.equal(decodeCbor(bytes(0x63, 0xe2, 0x82, 0xac)), "€");
  assert.deepEqual(decodeCbor(bytes(0x82, 0x01, 0xf6)), [1, null]);
  assert.deepEqual(decodeCbor(bytes(0x80)), []);
  const map = decodeCbor(bytes(0xa2, 0x01, 0xf4, 0x61, 0x61, 0xf5)) as CborMap;
  assert.deepEqual([...map.entries()], [[1, false], ["a", true]]);
  assert.deepEqual([...(decodeCbor(bytes(0xa0)) as CborMap).entries()], []);
  // A nested map value, and a bigint key.
  const nested = decodeCbor(bytes(0xa1, 0x61, 0x78, 0xa1, 0x1b, 0, 0x20, 0, 0, 0, 0, 0, 0, 0x01)) as CborMap;
  assert.deepEqual([...(nested.get("x") as CborMap).entries()], [[2n ** 53n, 1]]);
  // The byte string is a copy, not a view of the input.
  const input = bytes(0x41, 0x07);
  const decoded = decodeCbor(input) as Uint8Array;
  input[1] = 0;
  assert.equal(decoded[0], 7);
});

test("rejects the rest", () => {
  assert.equal(reason(bytes()), "Unexpected end of input at byte 0");
  assert.equal(reason(bytes(0x18)), "Unexpected end of input at byte 1");
  assert.equal(reason(bytes(0x42, 1)), "Unexpected end of input at byte 1");
  // Two items can't fit in one byte: refused before the first is read.
  assert.equal(reason(bytes(0x82, 1)), "Unexpected end of input at byte 1");
  assert.equal(reason(bytes(0x83, 1, 2)), "Unexpected end of input at byte 1");
  assert.equal(reason(bytes(0xa1, 1)), "Unexpected end of input at byte 2");
  // A claimed length past the input, 8 bytes long: refused before anything is allocated.
  assert.equal(reason(bytes(0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), "Unexpected end of input at byte 9");
  assert.equal(reason(bytes(0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)), "Unexpected end of input at byte 9");
  assert.equal(reason(bytes(0x9f, 0x01, 0xff)), "Indefinite length item at byte 0");
  assert.equal(reason(bytes(0x5f, 0x41, 0x01, 0xff)), "Indefinite length item at byte 0");
  assert.equal(reason(bytes(0x7f, 0x61, 0x61, 0xff)), "Indefinite length item at byte 0");
  assert.equal(reason(bytes(0xbf, 0xff)), "Indefinite length item at byte 0");
  assert.equal(reason(bytes(0x81, 0xff)), "Indefinite length item at byte 1");
  assert.equal(reason(bytes(0xc0, 0x61, 0x61)), "Tag at byte 0");
  assert.equal(reason(bytes(0xd8, 0x18, 0x01)), "Tag at byte 0");
  assert.equal(reason(bytes(0xf9, 0x3c, 0x00)), "Float at byte 0");
  assert.equal(reason(bytes(0xfa, 0, 0, 0, 0)), "Float at byte 0");
  assert.equal(reason(bytes(0xfb, 0, 0, 0, 0, 0, 0, 0, 0)), "Float at byte 0");
  assert.equal(reason(bytes(0xf7)), "Unsupported item (major type 7, additional information 23) at byte 0");
  assert.equal(reason(bytes(0xf8, 0x20)), "Unsupported item (major type 7, additional information 24) at byte 0");
  assert.equal(reason(bytes(0x1c)), "Unsupported item (major type 0, additional information 28) at byte 0");
  assert.equal(reason(bytes(0x61, 0xff)), "Text is not utf8 at byte 0");
  assert.equal(reason(bytes(0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02)), "Duplicate map key at byte 4");
  assert.equal(reason(bytes(0xa2, 0x01, 0x01, 0x01, 0x02)), "Duplicate map key at byte 3");
  // 1 as a number and as an 8 byte integer are the same key.
  assert.equal(reason(bytes(0xa2, 0x01, 0x01, 0x1b, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02)), "Duplicate map key at byte 3");
  assert.equal(reason(bytes(0xa1, 0x41, 0x01, 0x01)), "Map key is not text or an integer at byte 1");
  assert.equal(reason(bytes(0xa1, 0x80, 0x01)), "Map key is not text or an integer at byte 1");
  assert.equal(reason(bytes(0xa1, 0xf6, 0x01)), "Map key is not text or an integer at byte 1");
  assert.equal(reason(bytes(0x01, 0x02)), "1 bytes follow the item at byte 1");
  assert.equal(reason(bytes(0xa0, 0x00, 0x00)), "2 bytes follow the item at byte 1");
  // 16 nested arrays decode, 17 don't.
  const nested = new Uint8Array(16).fill(0x81);
  nested[15] = 0x80;
  decodeCbor(nested);
  assert.equal(reason(bytes(0x81, ...nested)), "Nested deeper than 16 at byte 16");
  // The error never echoes the input.
  assert.ok(!reason(bytes(0x61, 0xff)).includes("ff"));
});

test("the payload fields are checked", () => {
  // The fixture map with one entry replaced, in its order.
  const withField = (name: string, value: unknown): CborMap => {
    const map = decodePayloadMap(fixture.hexToBytes(fixture.PAYLOAD_HEX));
    map.set(name, value as never);
    return map;
  };
  const reason = (map: CborMap) => {
    try {
      readPayload(map);
    } catch (e) {
      assert.ok(e instanceof Error);
      return `${e.name}: ${e.message}`;
    }
    assert.fail("read");
  };
  assert.match(reason(withField("v", "1")), /PayloadError: The `v` of the payload is not an unsigned integer/);
  assert.match(reason(withField("v", -1)), /`v` of the payload is not an unsigned integer/);
  assert.match(reason(withField("v", 2n ** 60n)), /`v` of the payload is not an unsigned integer/);
  assert.match(reason(withField("k", new Uint8Array(7))), /`k` of the payload is 7 bytes, expected 8/);
  assert.match(reason(withField("k", "fe812c12f3ab4ce6")), /`k` of the payload is not a byte string/);
  assert.match(reason(withField("i", new Uint8Array(0))), /`i` of the payload is 0 bytes, expected 16/);
  assert.match(reason(withField("a", 1)), /`a` of the payload is not text/);
  assert.match(reason(withField("n", null)), /`n` of the payload is not text/);
  assert.match(reason(withField("t", "patron")), /`t` of the payload is not `individual`, `organization` or `sponsor`/);
  assert.match(reason(withField("t", "Organization")), /`t` of the payload is not/);
  assert.match(reason(withField("c", "2027/09/30")), /`c` of the payload is not a `YYYY-MM-DD` date/);
  assert.match(reason(withField("c", "2027-9-30")), /`c` of the payload is not a `YYYY-MM-DD` date/);
  assert.match(reason(withField("s", "2025-01-1x")), /`s` of the payload is not a `YYYY-MM-DD` date/);
  const missing = withField("", 0);
  missing.delete("c");
  assert.match(reason(missing), /payload has no `c`/);
  // Unknown fields are ignored.
  const extended = withField("x", [1, new Map([[1, true]])]);
  extended.set(1, new Uint8Array());
  assert.deepEqual(readPayload(extended), fixture.SUPPORTER);
  // Not a map, too long.
  assert.throws(() => decodePayloadMap(bytes(0x80)), /payload is not a map/);
  assert.throws(() => decodePayloadMap(bytes(0x01)), /payload is not a map/);
  assert.throws(() => decodePayloadMap(new Uint8Array(4097)), /payload is 4097 bytes, the most is 4096/);
  assert.throws(() => decodePayloadMap(bytes()), CborError);
  // The root key id before anything else is read.
  assert.match((() => { try { payloadRootKeyId(withField("k", 1)); return ""; } catch (e) { return String(e); } })(), /`k` of the payload is not a byte string/);
});

test("uuids are formatted 8-4-4-4-12", () => {
  assert.equal(formatUuid(fixture.hexToBytes("0190a3c27b6a7cc2b1f04a5d9e3c8f21")), fixture.ID);
  assert.equal(formatUuid(new Uint8Array(16)), "00000000-0000-0000-0000-000000000000");
  assert.equal(formatUuid(new Uint8Array(16).fill(0xff)), "ffffffff-ffff-ffff-ffff-ffffffffffff");
  assert.throws(() => formatUuid(new Uint8Array(15)), /16 bytes/);
});
