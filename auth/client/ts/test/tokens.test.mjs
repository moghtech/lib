import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import {
  MemoryStorage,
  jwtFor,
  setLocalStorage,
  storageEvent,
} from "./helpers.mjs";

const KEY = "mogh-auth-tokens-v1";

let storage;
setLocalStorage({ get: () => storage });
// The `storage` events of other tabs are dispatched on `window`.
globalThis.window = new EventTarget();

const { createLoginTokens } = await import("../dist/tokens.js");

const stored = () => JSON.parse(storage.getItem(KEY));

describe("login tokens shared by tabs", () => {
  beforeEach(() => {
    storage = new MemoryStorage();
  });

  it("a logout is not undone by another tab", () => {
    const a = createLoginTokens();
    a.add_and_change(jwtFor("x"));
    // Opened after the login.
    const b = createLoginTokens();
    assert.equal(b.jwt(), jwtFor("x"));

    a.remove("x");
    // The logout reaches the other tab.
    assert.equal(b.jwt(), "");

    b.add_and_change(jwtFor("y"));
    assert.deepEqual(stored().tokens, [{ user_id: "y", jwt: jwtFor("y") }]);
    // After a reload.
    assert.deepEqual(
      createLoginTokens()
        .accounts()
        .map((t) => t.user_id),
      ["y"],
    );
  });

  it("the default store shares the tokens with other tabs", async () => {
    // Each tab evaluates the module on its own.
    const tab_a = (await import("../dist/tokens.js?tab=a")).LOGIN_TOKENS;
    const tab_b = (await import("../dist/tokens.js?tab=b")).LOGIN_TOKENS;
    tab_a.add_and_change(jwtFor("x"));
    tab_a.remove("x");
    tab_b.add_and_change(jwtFor("y"));
    assert.deepEqual(
      tab_a.accounts().map((t) => t.user_id),
      ["y"],
    );
  });

  it("a login is kept when a stale tab changes the tokens", () => {
    const a = createLoginTokens();
    const b = createLoginTokens();
    a.add_and_change(jwtFor("x"));
    a.add_and_change(jwtFor("y"));

    b.change("x");
    assert.deepEqual(stored(), {
      current: "x",
      tokens: [
        { user_id: "x", jwt: jwtFor("x") },
        { user_id: "y", jwt: jwtFor("y") },
      ],
    });

    b.remove("z");
    assert.equal(stored().tokens.length, 2);
    assert.deepEqual(
      a.accounts().map((t) => t.user_id),
      ["y", "x"],
    );

    b.remove("y");
    assert.deepEqual(stored(), {
      current: "x",
      tokens: [{ user_id: "x", jwt: jwtFor("x") }],
    });
    assert.equal(b.jwt(), jwtFor("x"));

    b.remove_all();
    assert.equal(a.jwt(), "");
    assert.deepEqual(a.accounts(), []);
  });

  it("each tab keeps its own current user", () => {
    const a = createLoginTokens();
    a.add_and_change(jwtFor("x"));
    const b = createLoginTokens();
    assert.equal(b.jwt(), jwtFor("x"));

    // Signing in another user in one tab.
    b.add_and_change(jwtFor("y"));
    assert.equal(b.jwt(), jwtFor("y"));
    assert.equal(a.jwt(), jwtFor("x"));
    assert.deepEqual(
      a.accounts().map((t) => t.user_id),
      ["x", "y"],
    );
    assert.deepEqual(
      b.accounts().map((t) => t.user_id),
      ["y", "x"],
    );

    // Switching the user in one tab.
    a.change("y");
    b.change("x");
    assert.equal(a.jwt(), jwtFor("y"));
    assert.equal(b.jwt(), jwtFor("x"));

    // A new tab (or a reload) starts with the user chosen last.
    assert.equal(createLoginTokens().jwt(), jwtFor("x"));

    // A new token of the tab's user is used.
    const refreshed = jwtFor("y") + "2";
    b.add_and_change(refreshed);
    assert.equal(a.jwt(), refreshed);
  });

  it("a tab whose user signs out elsewhere is signed out", () => {
    const a = createLoginTokens();
    a.add_and_change(jwtFor("x"));
    const b = createLoginTokens();
    b.add_and_change(jwtFor("y"));
    b.change("x");
    a.change("y");

    // `a` signs out its user `y`, and switches to `x`.
    a.remove("y");
    assert.equal(a.jwt(), jwtFor("x"));
    // `b` signs out `x`: `a` is signed out, not switched to another user.
    b.add_and_change(jwtFor("z"));
    b.remove("x");
    assert.equal(a.jwt(), "");
    assert.deepEqual(
      a.accounts().map((t) => t.user_id),
      ["z"],
    );
    assert.equal(b.jwt(), jwtFor("z"));
    assert.equal(stored().current, "z");

    // `x` signs in again.
    b.add_and_change(jwtFor("x"));
    assert.equal(a.jwt(), jwtFor("x"));
  });

  it("notifies subscribers of changes in this and other tabs", () => {
    const a = createLoginTokens();
    const b = createLoginTokens();
    let calls = 0;
    const unsubscribe = a.subscribe(() => calls++);

    a.add_and_change(jwtFor("x"));
    assert.equal(calls, 1);

    b.add_and_change(jwtFor("y"));
    assert.equal(calls, 1);
    // The browser fires `storage` in the other tabs.
    window.dispatchEvent(storageEvent(KEY));
    assert.equal(calls, 2);
    assert.equal(a.jwt(), jwtFor("x"));
    assert.equal(a.accounts().length, 2);

    // Other keys, and events without a change, are ignored.
    window.dispatchEvent(storageEvent("other-key"));
    window.dispatchEvent(storageEvent(KEY));
    assert.equal(calls, 2);

    // `localStorage.clear()` in another tab.
    storage.clear();
    window.dispatchEvent(storageEvent(null));
    assert.equal(calls, 3);
    assert.equal(a.jwt(), "");

    unsubscribe();
    a.add_and_change(jwtFor("x"));
    b.remove_all();
    window.dispatchEvent(storageEvent(KEY));
    assert.equal(calls, 3);
  });

  // The browser updates a tab's `localStorage` as soon as another tab
  // changes it, and fires `storage` in a later task: a read in between
  // (a render, a polling request) already sees the change.
  it("notifies of another tab's change read before its storage event", () => {
    const a = createLoginTokens();
    a.add_and_change(jwtFor("x"));
    const b = createLoginTokens();
    let calls = 0;
    const unsubscribe = a.subscribe(() => calls++);

    // `x` signs out in the other tab.
    b.remove("x");
    assert.equal(a.jwt(), "");
    window.dispatchEvent(storageEvent(KEY));
    assert.equal(calls, 1);
    // Once.
    window.dispatchEvent(storageEvent(KEY));
    assert.equal(calls, 1);

    b.add_and_change(jwtFor("y"));
    assert.equal(a.accounts().length, 1);
    window.dispatchEvent(storageEvent(KEY));
    assert.equal(calls, 2);

    // `localStorage.clear()` in another tab.
    storage.clear();
    assert.deepEqual(a.accounts(), []);
    window.dispatchEvent(storageEvent(null));
    assert.equal(calls, 3);

    // A change undone before the event: nothing to tell.
    b.add_and_change(jwtFor("z"));
    assert.equal(a.accounts().length, 1);
    b.remove_all();
    storage.removeItem(KEY);
    assert.deepEqual(a.accounts(), []);
    window.dispatchEvent(storageEvent(KEY));
    window.dispatchEvent(storageEvent(KEY));
    assert.equal(calls, 3);

    unsubscribe();
  });

  it("stores under another key are separate", () => {
    const a = createLoginTokens();
    const other = createLoginTokens({ key: "other-app-tokens" });
    a.add_and_change(jwtFor("x"));
    other.add_and_change(jwtFor("y"));
    assert.equal(a.jwt(), jwtFor("x"));
    assert.equal(other.jwt(), jwtFor("y"));
    assert.deepEqual(
      JSON.parse(storage.getItem("other-app-tokens")).tokens,
      [{ user_id: "y", jwt: jwtFor("y") }],
    );
  });

  it("drops invalid stored tokens", (t) => {
    const warn = t.mock.method(console, "warn", () => {});
    storage.setItem(
      KEY,
      JSON.stringify({ current: 1, tokens: [{ user_id: "x" }, null] }),
    );
    const a = createLoginTokens();
    assert.equal(a.jwt(), "");
    assert.deepEqual(a.accounts(), []);
    storage.setItem(KEY, "not json");
    assert.deepEqual(a.accounts(), []);
    assert.equal(warn.mock.callCount(), 1);
  });

  it("keeps the known state when reading fails", (t) => {
    const warn = t.mock.method(console, "warn", () => {});
    const a = createLoginTokens();
    a.add_and_change(jwtFor("x"));
    const getItem = storage.getItem;
    storage.getItem = () => {
      throw new DOMException("denied", "SecurityError");
    };
    assert.equal(a.jwt(), jwtFor("x"));
    assert.equal(a.accounts().length, 1);
    // Warned once, not on every call.
    assert.equal(warn.mock.callCount(), 1);
    storage.getItem = getItem;
    assert.equal(a.jwt(), jwtFor("x"));
  });

  it("keeps a login for the page when storing it fails", (t) => {
    const warn = t.mock.method(console, "warn", () => {});
    const a = createLoginTokens();
    storage.setItem = () => {
      throw new DOMException("full", "QuotaExceededError");
    };
    assert.doesNotThrow(() => a.add_and_change(jwtFor("x")));
    assert.equal(a.jwt(), jwtFor("x"));
    assert.equal(storage.getItem(KEY), null);
    assert.equal(warn.mock.callCount(), 1);
  });
});

describe("refused tokens", () => {
  beforeEach(() => {
    storage = new MemoryStorage();
  });

  it("a refused token isn't sendable, a new login's is", () => {
    const store = createLoginTokens();
    store.add_and_change(jwtFor("x"));
    const refused = store.jwt();
    assert.equal(store.sendableJwt(), refused);

    store.refuse(refused);
    assert.equal(store.isRefused(refused), true);
    assert.equal(store.sendableJwt(), "");
    // Still the tab's token: the app shows the login page for it.
    assert.equal(store.jwt(), refused);

    // Logging in again gives a new token.
    store.add_and_change(jwtFor("x") + "2");
    assert.equal(store.sendableJwt(), jwtFor("x") + "2");
    assert.equal(store.isRefused(refused), true);
  });

  it("stays refused across account switches", () => {
    const store = createLoginTokens();
    store.add_and_change(jwtFor("x"));
    store.refuse(jwtFor("x"));
    store.add_and_change(jwtFor("y"));
    assert.equal(store.sendableJwt(), jwtFor("y"));
    store.change("x");
    assert.equal(store.sendableJwt(), "");
  });

  it("is kept per tab", () => {
    const a = createLoginTokens();
    a.add_and_change(jwtFor("x"));
    const b = createLoginTokens();
    a.refuse(jwtFor("x"));
    // The other tab still sends it, once, until refused there too.
    assert.equal(b.sendableJwt(), jwtFor("x"));
    assert.equal(b.isRefused(jwtFor("x")), false);
  });

  it("notifies of each new refusal", (t) => {
    const error = t.mock.method(console, "error", () => {});
    const store = createLoginTokens();
    store.add_and_change(jwtFor("x"));
    let refusals = 0;
    let changes = 0;
    const unsubscribe = store.subscribeRefusals(() => refusals++);
    store.subscribe(() => changes++);
    // A failing listener doesn't keep the others from it.
    store.subscribeRefusals(() => {
      throw new Error("listener");
    });

    store.refuse(jwtFor("x"));
    assert.equal(refusals, 1);
    // `sendableJwt()` changed, for `useSyncExternalStore`.
    assert.equal(changes, 1);
    assert.equal(error.mock.callCount(), 1);

    // Once per token.
    store.refuse(jwtFor("x"));
    store.refuse("");
    assert.equal(refusals, 1);
    assert.equal(changes, 1);

    unsubscribe();
    store.refuse(jwtFor("y"));
    assert.equal(refusals, 1);
    assert.equal(changes, 2);
  });

  it("the latch doesn't swallow another tab's change", () => {
    const a = createLoginTokens();
    a.add_and_change(jwtFor("x"));
    const b = createLoginTokens();
    let calls = 0;
    a.subscribe(() => calls++);
    // Read by `a` before its storage event arrives.
    b.add_and_change(jwtFor("y"));
    assert.equal(a.accounts().length, 2);
    a.refuse(jwtFor("x"));
    assert.equal(calls, 1);
    window.dispatchEvent(storageEvent(KEY));
    assert.equal(calls, 2);
  });
});
