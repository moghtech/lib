import { test } from "node:test";
import assert from "node:assert/strict";
import { releaseDate } from "../src/vite.ts";

const APP = { name: "komodo-ui", version: "2.4.0" };

/** Today in UTC, as the dev server's fallback has it. */
function today() {
  return new Date().toISOString().slice(0, 10);
}

test("the release date is the one in package.json, in every mode", () => {
  for (const mode of ["production", "development", "test", "staging"]) {
    assert.equal(
      releaseDate({ mode, packageJson: { ...APP, releaseDate: "2026-10-09" } }),
      "2026-10-09",
      mode,
    );
  }
  // A leap day where there is one.
  assert.equal(
    releaseDate({ mode: "production", packageJson: { releaseDate: "2028-02-29" } }),
    "2028-02-29",
  );
});

test("a production build without one fails, rather than take the day of the build", () => {
  for (const packageJson of [APP, {}, { name: 5 }]) {
    assert.throws(
      () => releaseDate({ mode: "production", packageJson }),
      (e: unknown) =>
        e instanceof Error &&
        /^No "releaseDate" in /.test(e.message) &&
        /"releaseDate": "YYYY-MM-DD"/.test(e.message),
    );
  }
  // Named by the package which lacks it.
  assert.throws(() => releaseDate({ mode: "production", packageJson: APP }), /^Error: No "releaseDate" in the package\.json of komodo-ui: /);
  assert.throws(() => releaseDate({ mode: "production", packageJson: {} }), /^Error: No "releaseDate" in the app's package\.json: /);
});

test("the dev server, tests and other modes fall back to today", () => {
  for (const mode of ["development", "test", "staging"]) {
    const before = today();
    const date = releaseDate({ mode, packageJson: APP });
    assert.ok(date === before || date === today(), `${mode}: ${date}`);
  }
});

test("a release date which is no date fails in every mode", () => {
  for (const mode of ["production", "development"]) {
    for (const value of [
      "",
      "2026-1-09",
      "2026-10-9",
      "26-10-09",
      " 2026-10-09",
      "2026-10-09 ",
      "2026/10/09",
      "2026-10-09T00:00:00Z",
      "2026-13-01",
      "2026-00-10",
      "2026-02-30",
      "2027-02-29",
      "2026-04-31",
      "2026-10-00",
      "0099-01-01",
      "２０２６-10-09",
      20261009,
      null,
      ["2026-10-09"],
      { date: "2026-10-09" },
    ]) {
      assert.throws(
        () => releaseDate({ mode, packageJson: { ...APP, releaseDate: value } }),
        (e: unknown) =>
          e instanceof Error &&
          e.message ===
            `The "releaseDate" of the package.json of komodo-ui is not a YYYY-MM-DD calendar date: ${JSON.stringify(value)}`,
        `${mode}: ${JSON.stringify(value)}`,
      );
    }
  }
});

test("no package.json is no release date", () => {
  assert.throws(() => releaseDate({ mode: "production", packageJson: undefined }), /No "releaseDate" in the app's package\.json/);
  assert.throws(() => releaseDate({ mode: "production", packageJson: null }), /No "releaseDate" in the app's package\.json/);
});
