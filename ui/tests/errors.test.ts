import { test } from "node:test";
import assert from "node:assert/strict";
import { errorNotificationMessage } from "../src/errors.ts";

test("the server's error, then the causes it doesn't show yet", () => {
  assert.equal(
    errorNotificationMessage({
      status: 401,
      result: {
        error: "invalid login credentials | You have 4 attempts remaining",
        trace: ["invalid login credentials", "user not found"],
      },
    }),
    "Invalid login credentials | You have 4 attempts remaining | User not found | See console for details",
  );
  assert.equal(
    errorNotificationMessage({ result: { error: "denied" } }),
    "Denied | See console for details",
  );
});

test("an empty error or empty trace lines don't throw", () => {
  // The supporter hooks' own copy threw a TypeError here, so a write
  // answered with `{ "error": "" }` showed no notification at all.
  assert.equal(
    errorNotificationMessage({ result: { error: "", trace: [] } }),
    "Unknown error | See console for details",
  );
  assert.equal(
    errorNotificationMessage({ result: { error: "", trace: ["", "cause"] } }),
    "Cause | See console for details",
  );
  assert.equal(
    errorNotificationMessage({ result: { error: "failed", trace: ["", " "] } }),
    "Failed | See console for details",
  );
  assert.equal(
    errorNotificationMessage({ result: { error: "  ", trace: [""] } }),
    "Unknown error | See console for details",
  );
});

test("anything that was caught has a message", () => {
  for (const caught of [
    undefined,
    null,
    "a string",
    42,
    new TypeError("Failed to fetch"),
    { status: 1 },
    { result: null },
    { result: "not an object" },
    { result: { error: 7, trace: "not a list" } },
    { result: { trace: [null, 3, {}] } },
  ]) {
    assert.equal(
      errorNotificationMessage(caught),
      "Unknown error | See console for details",
      String(caught),
    );
  }
});
