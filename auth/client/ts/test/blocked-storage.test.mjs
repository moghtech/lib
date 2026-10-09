import assert from "node:assert/strict";
import { beforeEach, describe, it, mock } from "node:test";
import { jwtFor, setLocalStorage } from "./helpers.mjs";

const KEY = "mogh-auth-tokens-v1";

/** Reads of the `localStorage` global. */
let reads = 0;
// Browsers blocking site data throw on reading `localStorage`.
setLocalStorage({
  get: () => {
    reads++;
    throw new DOMException("The operation is insecure.", "SecurityError");
  },
});

let warn;
// Expected: the "localStorage is unavailable" warning.
beforeEach(() => {
  warn = mock.method(console, "warn", () => {});
});

/** The tokens module of a page of its own (fresh module state). */
let pages = 0;
const newPage = () => import(`../dist/tokens.js?page=${++pages}`);

it("importing the package touches no storage", async () => {
  const MoghAuth = await import("../dist/lib.js");
  assert.equal(reads, 0);
  assert.equal(typeof MoghAuth.MoghAuthClient, "function");
  // Always a store.
  assert.equal(MoghAuth.LOGIN_TOKENS.jwt(), "");
  assert.ok(reads > 0);
});

describe("storage blocked", () => {
  it("keeps the tokens for the page", async () => {
    const { LOGIN_TOKENS, createLoginTokens } = await newPage();
    let calls = 0;
    LOGIN_TOKENS.subscribe(() => calls++);
    LOGIN_TOKENS.add_and_change(jwtFor("x"));
    LOGIN_TOKENS.add_and_change(jwtFor("y"));
    assert.equal(LOGIN_TOKENS.jwt(), jwtFor("y"));
    assert.deepEqual(
      LOGIN_TOKENS.accounts().map((t) => t.user_id),
      ["y", "x"],
    );
    assert.equal(calls, 2);
    // The page's stores share them, as they would `localStorage`.
    const other = createLoginTokens();
    assert.equal(other.jwt(), jwtFor("y"));
    other.remove("y");
    assert.equal(LOGIN_TOKENS.jwt(), "");
    assert.deepEqual(
      LOGIN_TOKENS.accounts().map((t) => t.user_id),
      ["x"],
    );
    // Under their own key.
    const app = createLoginTokens({ key: "other-app-tokens" });
    assert.deepEqual(app.accounts(), []);
    // Warned once, not for each store.
    assert.equal(warn.mock.callCount(), 1);
    assert.match(
      String(warn.mock.calls[0].arguments[0]),
      /localStorage is unavailable/,
    );
  });

  it("another page doesn't see them", async () => {
    const a = (await newPage()).LOGIN_TOKENS;
    const b = (await newPage()).LOGIN_TOKENS;
    a.add_and_change(jwtFor("x"));
    assert.equal(b.jwt(), "");
    assert.deepEqual(b.accounts(), []);
  });

  it("storage which throws on use is unavailable too", async () => {
    const { createLoginTokens } = await newPage();
    const getItem = mock.fn(() => {
      throw new DOMException("denied", "SecurityError");
    });
    setLocalStorage({ value: { getItem, setItem: getItem } });
    const store = createLoginTokens();
    store.add_and_change(jwtFor("x"));
    assert.equal(store.jwt(), jwtFor("x"));
    // Tried once, then the page's memory.
    assert.equal(getItem.mock.callCount(), 1);
    assert.equal(warn.mock.callCount(), 1);
  });

  it("in node there is nothing to warn about", async () => {
    const { createLoginTokens } = await newPage();
    setLocalStorage({ value: undefined });
    const store = createLoginTokens({ key: KEY });
    store.add_and_change(jwtFor("x"));
    assert.equal(store.jwt(), jwtFor("x"));
    assert.equal(warn.mock.callCount(), 0);
  });
});
