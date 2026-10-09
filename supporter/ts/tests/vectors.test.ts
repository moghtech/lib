// The vectors the Rust crate runs too (`supporter/test_vectors.json`,
// see its description, and `shared_vectors` in supporter/rs/src/tests.rs):
// the two decoders and checks give the same verdict, and the same
// reason, on the same input.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CborError,
  base64Decode,
  base64urlDecode,
  brandingProblem,
  decodeCbor,
  hex,
  normalizeBranding,
  rootKeyId,
  type CborValue,
} from "../src/index.ts";
import { hexToBytes } from "./fixture.ts";

type Entry = Record<string, unknown>;

const vectors: Record<string, Entry[]> = JSON.parse(
  readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), "../../test_vectors.json"),
    "utf8",
  ),
);

function entries(name: string): Entry[] {
  const list = vectors[name];
  assert.ok(Array.isArray(list) && list.length > 0, `no ${name} vectors`);
  return list;
}

/** The expected error of an entry, `undefined` for one which passes. */
function expectedError(entry: Entry, okField: string): string | undefined {
  assert.notEqual("error" in entry, okField in entry, `${JSON.stringify(entry)} needs either \`error\` or \`${okField}\``);
  return entry.error as string | undefined;
}

/** A decoded value as the vectors write it. */
function toJson(value: CborValue): unknown {
  if (typeof value === "number" || typeof value === "bigint") return { int: String(value) };
  if (typeof value === "string") return { text: value };
  if (value instanceof Uint8Array) return { bytes: hex(value) };
  if (Array.isArray(value)) return { array: value.map(toJson) };
  if (value instanceof Map) return { map: [...value].map(([k, v]) => [toJson(k), toJson(v)]) };
  return value;
}

test("cbor", () => {
  for (const entry of entries("cbor")) {
    const bytes = hexToBytes(entry.hex as string);
    const error = expectedError(entry, "value");
    if (error === undefined) {
      assert.deepEqual(toJson(decodeCbor(bytes)), entry.value, JSON.stringify(entry));
    } else {
      assert.throws(
        () => decodeCbor(bytes),
        (e: unknown) => e instanceof CborError && e.message === error,
        JSON.stringify(entry),
      );
    }
  }
});

test("base64 and base64url", () => {
  for (const [name, decode] of [
    ["base64", base64Decode],
    ["base64url", base64urlDecode],
  ] as const) {
    for (const entry of entries(name)) {
      const text = entry.text as string;
      if (expectedError(entry, "hex") === undefined) {
        assert.equal(hex(decode(text)), entry.hex, `${name} ${JSON.stringify(entry)}`);
      } else {
        assert.throws(() => decode(text), `${name} ${JSON.stringify(entry)}`);
      }
    }
  }
});

test("root keys", async () => {
  // With the page's WebCrypto, and with the JavaScript SHA-256 a page
  // without it gets (`null`).
  for (const subtle of [undefined, null]) {
    for (const entry of entries("root_keys")) {
      const error = expectedError(entry, "id");
      if (error === undefined) {
        assert.equal(await rootKeyId(entry.key as string, subtle), entry.id, JSON.stringify(entry));
      } else {
        await assert.rejects(
          rootKeyId(entry.key as string, subtle),
          (e: unknown) => e instanceof Error && e.message === error,
          JSON.stringify(entry),
        );
      }
    }
  }
});

test("branding icons and links", () => {
  for (const [name, field] of [
    ["icons", "icon"],
    ["links", "link"],
  ] as const) {
    for (const entry of entries(name)) {
      const branding = {
        replace_home: false,
        hide_name: false,
        uppercase_name: false,
        [field]: entry[field] as string,
      };
      const error = expectedError(entry, "kept");
      assert.equal(brandingProblem(branding), error ?? null, JSON.stringify(entry));
      if (error === undefined) {
        assert.equal(normalizeBranding(branding)[field] ?? null, entry.kept, JSON.stringify(entry));
      }
    }
  }
});
