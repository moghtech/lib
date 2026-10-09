import { test } from "node:test";
import assert from "node:assert/strict";
import {
  fmtDuration,
  fmtSnakeCaseToUpperSpaceCase,
  fmtUpperCamelcase,
} from "../src/formatting.ts";

test("fmtSnakeCaseToUpperSpaceCase skips empty parts", () => {
  // These used to throw during render.
  assert.equal(fmtSnakeCaseToUpperSpaceCase("_"), "");
  assert.equal(fmtSnakeCaseToUpperSpaceCase("exited_"), "Exited");
  assert.equal(fmtSnakeCaseToUpperSpaceCase("_id"), "Id");
  assert.equal(fmtSnakeCaseToUpperSpaceCase("a__b"), "A B");
  assert.equal(fmtSnakeCaseToUpperSpaceCase(""), "");
  assert.equal(
    fmtSnakeCaseToUpperSpaceCase("list_all_items"),
    "List All Items",
  );
});

test("fmtUpperCamelcase keeps what it can't split", () => {
  assert.equal(fmtUpperCamelcase("RunBuild"), "Run Build");
  assert.equal(fmtUpperCamelcase("Aes256Gcm"), "Aes 256 Gcm");
  assert.equal(fmtUpperCamelcase("Server_Unreachable"), "Server Unreachable");
  assert.equal(fmtUpperCamelcase("running"), "running");
  // These used to lose parts: "KILLED", "ERROR", "1", "Up 5".
  assert.equal(fmtUpperCamelcase("OOMKilled"), "OOMKilled");
  assert.equal(fmtUpperCamelcase("HTTPError"), "HTTPError");
  assert.equal(fmtUpperCamelcase("exited_1"), "exited_1");
  assert.equal(fmtUpperCamelcase("Up 5 minutes"), "Up 5 minutes");
});

test("fmtDuration rounds once, with hours and singular units", () => {
  const cases: [number, string][] = [
    [0, "0.0 seconds"],
    [1_000, "1.0 seconds"],
    [59_940, "59.9 seconds"],
    // These read "60.0 seconds", "1 minute 60 seconds" and "59 minutes
    // 60 seconds": the seconds were rounded after the minutes were split
    // off.
    [59_960, "1 minute 0 seconds"],
    [119_600, "2 minutes 0 seconds"],
    [3_599_400, "59 minutes 59 seconds"],
    [3_599_500, "1 hour 0 minutes"],
    // Singular: was "1 minute 1 seconds".
    [61_000, "1 minute 1 second"],
    [62_000, "1 minute 2 seconds"],
    // Hours: a two hour build was "120 minutes 0 seconds".
    [2 * 3_600_000, "2 hours 0 minutes"],
    [2 * 3_600_000 + 3 * 60_000, "2 hours 3 minutes"],
    [3_600_000 + 60_000 + 29_000, "1 hour 1 minute"],
    [3_600_000 + 60_000 + 30_000, "1 hour 2 minutes"],
  ];
  const start = Date.UTC(2026, 9, 8);
  for (const [ms, expected] of cases) {
    assert.equal(fmtDuration(start, start + ms), expected, `${ms} ms`);
  }
  // An end before the start (clock skew) is no time.
  assert.equal(fmtDuration(start, start - 1_500), "0.0 seconds");
});
