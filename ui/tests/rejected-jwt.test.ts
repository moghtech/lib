import { test } from "node:test";
import assert from "node:assert/strict";
import { LOGIN_TOKENS } from "mogh_auth_client";
import { SEND_REJECTED_ONCE, sendWithJwt } from "../src/auth/rejected-jwt.ts";

// React Query behaves like in a browser (it retries 3 times by
// default), not like on a server (no retries).
(globalThis as { window?: unknown }).window = {};
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
const { QueryClient, QueryObserver, focusManager } =
  await import("@tanstack/query-core");

type Options = ConstructorParameters<typeof QueryObserver>[1];

/**
 * Runs a query until it settles, then focuses the window again.
 * Returns how often the request was sent.
 */
async function sendCount(
  request: () => Promise<unknown>,
  options: Partial<Options>,
) {
  const client = new QueryClient();
  client.mount();
  let sent = 0;
  const observer = new QueryObserver(client, {
    queryKey: ["GetUserId"],
    queryFn: () => {
      sent++;
      return request();
    },
    retryDelay: 0,
    ...options,
  });
  const settled = new Promise<void>((resolve) =>
    observer.subscribe((result) => {
      if (result.status !== "pending" && result.fetchStatus === "idle") {
        resolve();
      }
    }),
  );
  await settled;
  // The user comes back to the tab
  focusManager.setFocused(false);
  focusManager.setFocused(true);
  // Long enough for a refetch and its retries (no delay between them)
  await new Promise((resolve) => setTimeout(resolve, 100));
  focusManager.setFocused(undefined);
  observer.destroy();
  client.unmount();
  // Drops the queries with their timers, which keep node running
  client.clear();
  return sent;
}

const base64Url = (value: unknown) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

let logins = 0;
/** Logs `user` in in this tab with a new token, which is returned. */
function login(user: string) {
  logins++;
  const jwt = `${base64Url({ alg: "none" })}.${base64Url({ sub: user, n: logins })}.sig`;
  LOGIN_TOKENS.add_and_change(jwt);
  return jwt;
}

/** The server's own answer (`RequestError.server`) with `status`. */
const refused = (status: number) => () =>
  Promise.reject({
    status,
    result: { error: "refused", trace: [] },
    server: true,
  });

test("without the options, a refused token is sent again and again", async () => {
  // What the query did before, with the defaults of the host app:
  // 3 retries, and the same again when the window is focused.
  assert.equal(await sendCount(refused(401), {}), 8);
});

test("a token the server refused is only sent once", async () => {
  const jwt = login("expired");
  const sent = await sendCount(
    () => sendWithJwt([401, 403], refused(401)),
    SEND_REJECTED_ONCE,
  );
  assert.equal(sent, 1);
  // Noted in the store, which the app's own client reads too: the
  // queries aren't enabled again for it, only for another token.
  assert.equal(LOGIN_TOKENS.isRefused(jwt), true);
  assert.equal(LOGIN_TOKENS.sendableJwt(), "");
  const fresh = login("expired");
  assert.equal(LOGIN_TOKENS.sendableJwt(), fresh);
});

test("the token latched is the one sent", async () => {
  const sent = login("sender");
  await assert.rejects(
    sendWithJwt([401], (jwt) => {
      assert.equal(jwt, sent);
      // Another user logs in while the request is in flight.
      login("other");
      return refused(401)();
    }),
  );
  assert.equal(LOGIN_TOKENS.isRefused(sent), true);
  assert.notEqual(LOGIN_TOKENS.sendableJwt(), "");
});

test("only the listed statuses of the server mark a token as refused", async () => {
  const jwt = login("not-an-admin");
  await assert.rejects(sendWithJwt([401], refused(403)));
  assert.equal(LOGIN_TOKENS.isRefused(jwt), false);
  // A proxy's or an auth gateway's 401 says nothing about the token.
  await assert.rejects(
    sendWithJwt([401], () =>
      Promise.reject({ status: 401, result: { error: "Unauthorized" } }),
    ),
  );
  assert.equal(LOGIN_TOKENS.isRefused(jwt), false);
  await assert.rejects(sendWithJwt([401], refused(401)));
  assert.equal(LOGIN_TOKENS.isRefused(jwt), true);
});

test("a token another user of the store saw refused isn't sent", async () => {
  const jwt = login("app-refused");
  let changes = 0;
  const unsubscribe = LOGIN_TOKENS.subscribe(() => changes++);
  // The app's own client got the refusal, eg. to its GetUser.
  LOGIN_TOKENS.refuse(jwt);
  unsubscribe();
  // What `useSendableJwt` renders again on.
  assert.equal(changes, 1);
  let sent = 0;
  const error = await sendWithJwt([401], async () => {
    sent++;
  }).catch((e) => e);
  assert.equal(sent, 0);
  // Like the server's 401, but not its answer: not latched again.
  assert.equal(error.status, 401);
  assert.equal(error.server, undefined);
  assert.match(error.result.error, /log in again/);
});

test("nothing is sent without a token", async () => {
  LOGIN_TOKENS.remove_all();
  let sent = 0;
  await assert.rejects(
    sendWithJwt([401], async () => {
      sent++;
    }),
    { status: 401 },
  );
  assert.equal(sent, 0);
});

test("a request which never reached the server is retried", async () => {
  const jwt = login("flaky");
  let attempts = 0;
  const flaky = async () => {
    attempts++;
    if (attempts < 3) throw { status: 1 };
    return { user_id: "user" };
  };
  const sent = await sendCount(
    () => sendWithJwt([401, 403], flaky),
    SEND_REJECTED_ONCE,
  );
  assert.equal(sent, 3);
  assert.equal(LOGIN_TOKENS.isRefused(jwt), false);

  // At most 3 times
  const unreachable = await sendCount(
    () => Promise.reject({ status: 1 }),
    SEND_REJECTED_ONCE,
  );
  assert.equal(unreachable, 4);
});
