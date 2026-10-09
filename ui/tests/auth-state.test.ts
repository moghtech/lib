import { test } from "node:test";
import assert from "node:assert/strict";
import { registerHooks } from "node:module";

// Runs `useAuthState` / `externalLogin` of src/auth/hooks.ts in Node, as
// a plain function: react, react-query, the notifications and the auth
// client are stubs recording what the hook does with them. The hooks
// import no page (tsx, left for the bundler). Each `pageLoad` gets its
// own copy of the auth modules (and so of their page load state).

interface Recorder {
  mutations: Record<string, MutationOptions>;
  sent: [string, unknown][];
  notifications: { title: string; message: string }[];
  tokens: string[];
  /** The stored token of the user logged in, `""` for none. */
  jwt: string;
  /** What the page logged with `console.warn`. */
  warnings: unknown[][];
}
interface MutationOptions {
  onSuccess?: (data: unknown) => void;
  onError?: (error: unknown) => void;
}
const recorder: Recorder = {
  mutations: {},
  sent: [],
  notifications: [],
  tokens: [],
  jwt: "",
  warnings: [],
};
(globalThis as { __moghAuthTest?: unknown }).__moghAuthTest = recorder;

// The hook logs what it ignores and why, expected here.
console.log = () => {};
console.error = () => {};
console.warn = (...args: unknown[]) => void recorder.warnings.push(args);

const STUBS: Record<string, string> = {
  react: `
export const useState = (init) =>
  [typeof init === "function" ? init() : init, () => {}];
export const useSyncExternalStore = (_subscribe, snapshot) => snapshot();
export const useRef = (current) => ({ current });
`,
  "@tanstack/react-query": `
const recorder = globalThis.__moghAuthTest;
export const UseMutationOptions = undefined;
export const useQuery = () => ({});
export const useMutation = (options) => {
  const type = options.mutationKey[0];
  recorder.mutations[type] = options;
  return { mutate: (params) => recorder.sent.push([type, params]) };
};
`,
  "@mantine/notifications": `
export const notifications = {
  show: (n) => globalThis.__moghAuthTest.notifications.push(n),
};
`,
  mogh_auth_client: `
const recorder = globalThis.__moghAuthTest;
export const LOGIN_TOKENS = {
  jwt: () => recorder.jwt,
  add_and_change: (jwt) => recorder.tokens.push(jwt),
};
export const Passkey = {
  base64UrlDecode: (value) => value,
  prepareRequestChallengeResponse: (value) => value,
};
export const MoghAuthClient = () => ({
  externalLogin: (slug) => recorder.sent.push(["externalLogin", slug]),
});
export const isReauthenticationRequired = () => false;
`,
};
/** The sources: their relative imports load the page load's copies. */
const SRC = new URL("../src/", import.meta.url).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (STUBS[specifier] !== undefined) {
      return {
        url: "data:text/javascript," + encodeURIComponent(STUBS[specifier]),
        shortCircuit: true,
      };
    }
    const parent = context.parentURL ?? "";
    const parentPath = parent.split("?")[0];
    if (
      specifier.startsWith(".") &&
      parentPath.startsWith(SRC) &&
      parentPath.endsWith(".ts")
    ) {
      // The page load's copy of the module.
      const query = parent.includes("?")
        ? parent.slice(parent.indexOf("?"))
        : "";
      const resolved = nextResolve(
        /\.[cm]?[jt]sx?$/.test(specifier) ? specifier : specifier + ".ts",
        context,
      );
      return { ...resolved, url: resolved.url.split("?")[0] + query };
    }
    return nextResolve(specifier, context);
  },
});

const ORIGIN = "http://app.example";

/** The tab's url, changed by `history.replaceState`. */
let current = new URL(ORIGIN);
/** Where `location.replace` / `reload` were asked to go. */
let navigations: string[] = [];

(globalThis as { location?: unknown }).location = {
  get href() {
    return current.href;
  },
  get origin() {
    return current.origin;
  },
  get pathname() {
    return current.pathname;
  },
  get search() {
    return current.search;
  },
  get hash() {
    return current.hash;
  },
  replace: (url: string) => void navigations.push(url),
  reload: () => void navigations.push("reload"),
};
(globalThis as { history?: unknown }).history = {
  state: null,
  // Like a browser: relative to the page, and only on its origin.
  replaceState(_state: unknown, _unused: string, url: string) {
    const next = new URL(url, current.href);
    if (next.origin !== current.origin) {
      throw new DOMException(
        `A history state object with URL '${next.href}' cannot be created ` +
          `in a document with origin '${current.origin}'`,
        "SecurityError",
      );
    }
    current = next;
  },
};
const storage = new Map<string, string>();
/** Whether `sessionStorage` throws, like when the browser blocks it. */
let storageBlocked = false;
function sessionStore<T>(use: () => T): T {
  if (storageBlocked) {
    throw new DOMException("The operation is insecure.", "SecurityError");
  }
  return use();
}
(globalThis as { sessionStorage?: unknown }).sessionStorage = {
  getItem: (key: string) => sessionStore(() => storage.get(key) ?? null),
  setItem: (key: string, value: string) =>
    sessionStore(() => void storage.set(key, value)),
  removeItem: (key: string) => sessionStore(() => void storage.delete(key)),
};

type Auth = typeof import("../src/auth/hooks.ts");
type ExternalFlow = typeof import("../src/auth/external-flow.ts");
type Utils = typeof import("../src/auth/utils.ts");

let loads = 0;
/** A new page load of the app at `path`. */
async function pageLoad(path: string) {
  loads += 1;
  current = new URL(ORIGIN + path);
  navigations = [];
  recorder.mutations = {};
  recorder.sent = [];
  recorder.notifications = [];
  recorder.tokens = [];
  recorder.jwt = "";
  recorder.warnings = [];
  const auth: Auth = await import(`../src/auth/hooks.ts?load=${loads}`);
  const flow: ExternalFlow = await import(
    `../src/auth/external-flow.ts?load=${loads}`
  );
  return { auth, flow };
}

/** The tab leaves for an external login started through mogh_ui. */
async function startExternalLogin() {
  const { auth } = await pageLoad("/login");
  auth.externalLogin("oidc");
  assert.deepEqual(recorder.sent, [["externalLogin", "oidc"]]);
}

/** Redeeming failed: the server refused `ExchangeForJwt`. */
function redeemFails(error = "Session has no completed login") {
  recorder.mutations.ExchangeForJwt.onError!({ result: { error } });
}

test("a redeem_ready link is redeemed, but its failure isn't shown", async () => {
  // Nobody logged in in this tab. The login would wait in the visitor's
  // own session: a link can only complete a login of their own.
  const { auth, flow } = await pageLoad("/tools?tab=a&redeem_ready=true#b");
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  assert.deepEqual(recorder.sent, [["ExchangeForJwt", undefined]]);
  // Nor again on the next render
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  assert.equal(recorder.sent.length, 1);
  assert.equal(flow.externalLoginState.failed, false);

  redeemFails("A reason anyone could have planted");
  // Only logged: nothing alarming, the user just logs in.
  assert.deepEqual(recorder.notifications, []);
  assert.equal(recorder.warnings.length, 1);
  assert.equal(current.href, `${ORIGIN}/tools?tab=a#b`);
  assert.equal(auth.useAuthState().jwt_redeem_ready, false);
  assert.equal(recorder.sent.length, 1);
  // The login page doesn't auto redirect to a provider.
  assert.equal(flow.externalLoginState.failed, true);
  assert.deepEqual(navigations, []);
});

test("a redeem_ready link doesn't bother a user who is logged in", async () => {
  const { auth } = await pageLoad("/tools?redeem_ready=true");
  recorder.jwt = "token";
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  assert.deepEqual(recorder.sent, [["ExchangeForJwt", undefined]]);
  redeemFails();
  assert.deepEqual(recorder.notifications, []);
  assert.deepEqual(recorder.tokens, []);
  assert.equal(current.href, `${ORIGIN}/tools`);
  assert.equal(auth.useAuthState().jwt_redeem_ready, false);
});

test("a login which returns to another tab is redeemed there", async () => {
  // Eg. from a link in an email the provider sent to finish the login:
  // the tab which left for the provider holds the mark, not this one.
  const { auth, flow } = await pageLoad("/tools?tab=a&redeem_ready=true#b");
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  assert.deepEqual(recorder.sent, [["ExchangeForJwt", undefined]]);
  recorder.mutations.ExchangeForJwt.onSuccess!({ jwt: "token" });
  assert.deepEqual(recorder.tokens, ["token"]);
  // Loads the page again without the param, fragment kept.
  assert.deepEqual(navigations, [`${ORIGIN}/tools?tab=a#b`]);
  assert.deepEqual(recorder.notifications, []);
  assert.equal(flow.externalLoginState.failed, false);
});

test("a login is redeemed with sessionStorage blocked", async () => {
  storageBlocked = true;
  try {
    const { auth } = await pageLoad("/login");
    auth.externalLogin("oidc");
    assert.deepEqual(recorder.sent, [["externalLogin", "oidc"]]);
    const back = await pageLoad("/?redeem_ready=true");
    assert.equal(back.auth.useAuthState().jwt_redeem_ready, true);
    assert.deepEqual(recorder.sent, [["ExchangeForJwt", undefined]]);
    recorder.mutations.ExchangeForJwt.onSuccess!({ jwt: "token" });
    assert.deepEqual(recorder.tokens, ["token"]);
  } finally {
    storageBlocked = false;
  }
});

test("a login returning after 30 minutes is redeemed, its failure not shown", async () => {
  await startExternalLogin();
  // The mark the tab left with, 31 minutes ago.
  assert.equal(storage.size, 1);
  const [key] = storage.keys();
  storage.set(key, String(Date.now() - 31 * 60_000));
  const { auth } = await pageLoad("/?redeem_ready=true");
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  assert.deepEqual(recorder.sent, [["ExchangeForJwt", undefined]]);
  assert.equal(storage.size, 0);
  redeemFails();
  assert.deepEqual(recorder.notifications, []);
  assert.equal(recorder.warnings.length, 1);
  assert.equal(current.href, `${ORIGIN}/`);
});

test("the return from the tab's own external login is redeemed, once", async () => {
  await startExternalLogin();
  const { auth, flow } = await pageLoad("/tools?tab=a&redeem_ready=true#b");
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  assert.deepEqual(recorder.sent, [["ExchangeForJwt", undefined]]);
  // Renders again while redeeming
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  assert.deepEqual(recorder.sent, [["ExchangeForJwt", undefined]]);
  assert.equal(flow.externalLoginState.failed, false);

  // Redeemed: loads the page again without the param, fragment kept.
  recorder.mutations.ExchangeForJwt.onSuccess!({ jwt: "token" });
  assert.deepEqual(recorder.tokens, ["token"]);
  assert.deepEqual(navigations, [`${ORIGIN}/tools?tab=a#b`]);
  assert.deepEqual(recorder.notifications, []);
});

test("the tab's own external login shows the server's error redeeming it", async () => {
  await startExternalLogin();
  const { auth, flow } = await pageLoad("/tools?redeem_ready=true#b");
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  redeemFails("Login is not allowed from this ip");
  assert.equal(recorder.notifications.length, 1);
  const [shown] = recorder.notifications;
  assert.equal(shown.title, "Login request ExchangeForJwt failed");
  assert.match(shown.message, /^Login is not allowed from this ip \| /);
  assert.equal(current.href, `${ORIGIN}/tools#b`);
  assert.equal(auth.useAuthState().jwt_redeem_ready, false);
  assert.equal(flow.externalLoginState.failed, true);
  assert.equal(recorder.sent.length, 1);

  // The mark vouched for that one return only.
  const later = await pageLoad("/?redeem_ready=true");
  assert.equal(later.auth.useAuthState().jwt_redeem_ready, true);
  assert.equal(recorder.sent.length, 1);
  redeemFails();
  assert.deepEqual(recorder.notifications, []);
});

test("the reason in a login_error is only shown after the tab's own login", async () => {
  // Anyone can put text in a link.
  const planted = await pageLoad("/?login_error=Call%20555-0100");
  planted.auth.useAuthState();
  assert.deepEqual(
    recorder.notifications.map((n) => [n.title, n.message]),
    [["Login failed", "The external login didn't complete."]],
  );
  assert.equal(current.href, `${ORIGIN}/`);
  assert.equal(planted.flow.externalLoginState.failed, true);

  await startExternalLogin();
  const back = await pageLoad("/?login_error=Denied%20at%20the%20provider");
  back.auth.useAuthState();
  assert.deepEqual(
    recorder.notifications.map((n) => [n.title, n.message]),
    [["Login failed", "Denied at the provider"]],
  );
  assert.deepEqual(recorder.sent, []);
});

test("a link to a path starting with // doesn't crash the app", async () => {
  // `https://app//x/` has the path `//x/`, which as a relative url is
  // another host: `replaceState` would throw while rendering.
  for (const query of ["passkey=garbage", "login_error=hi", "link_error=hi"]) {
    const { auth } = await pageLoad(`//x/?${query}&keep=1#h`);
    const state = auth.useAuthState();
    assert.equal(current.origin, ORIGIN, query);
    assert.equal(current.href, `${ORIGIN}//x/?keep=1#h`, query);
    assert.equal(state.jwt_redeem_ready, false, query);
    assert.equal(state.passkey_pending, false, query);
    assert.deepEqual(recorder.sent, [], query);
  }
  const { auth } = await pageLoad(`//x/?redeem_ready=true&keep=1#h`);
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  redeemFails();
  assert.equal(current.href, `${ORIGIN}//x/?keep=1#h`);
  assert.equal(auth.useAuthState().jwt_redeem_ready, false);
});

test("a failed redeem on a path starting with // falls back to the app", async () => {
  await startExternalLogin();
  const { auth } = await pageLoad("//x/?redeem_ready=true#h");
  assert.equal(auth.useAuthState().jwt_redeem_ready, true);
  redeemFails();
  assert.equal(current.href, `${ORIGIN}//x/#h`);
});

test("externalLogin on a path starting with // tidies the url", async () => {
  const { auth } = await pageLoad("//x/?totp=true&keep=1#h");
  auth.externalLogin("oidc");
  assert.equal(current.href, `${ORIGIN}//x/?keep=1#h`);
  assert.deepEqual(recorder.sent, [["externalLogin", "oidc"]]);
});

test("the url is only tidied up: a refused replaceState doesn't throw", async () => {
  const { auth } = await pageLoad("/x?login_error=hi");
  const history = globalThis.history as { replaceState: unknown };
  const replaceState = history.replaceState;
  history.replaceState = () => {
    throw new DOMException("Too many calls", "SecurityError");
  };
  try {
    auth.useAuthState();
    auth.externalLogin("oidc");
  } finally {
    history.replaceState = replaceState;
  }
});

test("the second factor's end keeps the fragment", async () => {
  await pageLoad("/docs?a=1&totp=true#install");
  const { sanitizeQuery }: Utils = await import("../src/auth/utils.ts");
  sanitizeQuery();
  assert.deepEqual(navigations, [`${ORIGIN}/docs?a=1#install`]);

  // A path starting with `//` stays on this origin.
  await pageLoad("//x/?passkey=e30#h");
  sanitizeQuery();
  assert.deepEqual(navigations, [`${ORIGIN}//x/#h`]);

  // Nothing to remove (eg. after a local login's second factor): the page
  // is still loaded again, `replace` would only scroll to the fragment.
  await pageLoad("/notes#frag");
  sanitizeQuery();
  assert.deepEqual(navigations, ["reload"]);
  await pageLoad("/notes");
  sanitizeQuery();
  assert.deepEqual(navigations, [`${ORIGIN}/notes`]);
});

test("only the login route itself is the login page", async () => {
  const { flow } = await pageLoad("/");
  for (const path of ["/login", "/login/"]) {
    assert.equal(flow.isLoginPath(path), true, path);
  }
  for (const path of [
    "/",
    "/login-providers/abc",
    "/loginx",
    "/login/x",
    "/settings/login",
    "//login",
  ]) {
    assert.equal(flow.isLoginPath(path), false, path);
  }
});
