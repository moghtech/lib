import { test } from "node:test";
import assert from "node:assert/strict";

// The browser's localStorage, where the store keeps the tokens. Node's
// own warns when it is read without `--localstorage-file`.
const stored = new Map<string, string>();
Object.defineProperty(globalThis, "localStorage", {
  configurable: true,
  value: {
    getItem: (key: string) => stored.get(key) ?? null,
    setItem: (key: string, value: string) => void stored.set(key, value),
  },
});
const { LOGIN_TOKENS } = await import("mogh_auth_client");
const { addAccountPath, currentUserId } =
  await import("../src/auth/accounts.ts");

const base64Url = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (sub: string) =>
  `${base64Url({ alg: "none" })}.${base64Url({ sub })}.sig`;

test("adding an account comes back here, without the auto redirect", () => {
  (globalThis as { location?: unknown }).location = {
    pathname: "/servers/abc",
    search: "?tab=logs&x=1",
    hash: "#top",
  };
  const path = addAccountPath();
  assert.ok(path.startsWith("/login?"), path);
  const params = new URL(path, "http://app.example").searchParams;
  assert.equal(params.get("backto"), "/servers/abc?tab=logs&x=1#top");
  // An auto redirect provider would answer for the account already
  // signed in at the provider: the login page must stay.
  assert.equal(params.get("disableAutoLogin"), "true");
});

test("the current user id is the one stored with this tab's token", () => {
  assert.equal(currentUserId(), undefined);
  LOGIN_TOKENS.add_and_change(jwt("alice"));
  assert.equal(currentUserId(), "alice");
  LOGIN_TOKENS.add_and_change(jwt("bob"));
  assert.equal(currentUserId(), "bob");
  LOGIN_TOKENS.change("alice");
  assert.equal(currentUserId(), "alice");
  LOGIN_TOKENS.remove("alice");
  // Another signed in account becomes this tab's.
  assert.equal(currentUserId(), "bob");
  LOGIN_TOKENS.remove_all();
  assert.equal(currentUserId(), undefined);
});
