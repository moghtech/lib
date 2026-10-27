import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_CREDENTIAL_NAME_LENGTH,
  credentialNameError,
  expiryMs,
  timestampMs,
} from "../src/credential-key.ts";

test("timestamps are read as unix ms or ISO 8601, none as null", () => {
  const iso = Date.UTC(2026, 8, 25, 10);
  assert.equal(timestampMs(1_760_000_000_000), 1_760_000_000_000);
  assert.equal(timestampMs("2026-09-25T10:00:00Z"), iso);
  assert.equal(timestampMs(0), null);
  assert.equal(timestampMs(null), null);
  assert.equal(timestampMs(undefined), null);
  assert.equal(timestampMs(""), null);
  assert.equal(timestampMs("soon"), null);
  // The same reading for expiries: 0 and null are "never".
  assert.equal(expiryMs(0), null);
  assert.equal(expiryMs("2026-09-25T10:00:00Z"), iso);
});

test("key names are at most 200 characters, and not blank by default", () => {
  assert.equal(credentialNameError("ci"), null);
  assert.equal(
    credentialNameError("n".repeat(MAX_CREDENTIAL_NAME_LENGTH)),
    null,
  );
  assert.match(credentialNameError("n".repeat(201))!, /at most 200/);
  assert.match(credentialNameError("")!, /empty/);
  assert.match(credentialNameError("   ")!, /empty/);
  // An app whose keys may go unnamed.
  assert.equal(credentialNameError("", { required: false }), null);
  assert.match(
    credentialNameError("n".repeat(201), { required: false })!,
    /at most 200/,
  );
});
