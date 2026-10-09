import { jwtDecode } from "jwt-decode";
import type { RequestError } from "./request.js";

export const extractUserIdFromJwt = (jwt: string) => {
  return jwtDecode<{ sub: string | undefined }>(jwt).sub;
};

export type LoginToken = { user_id: string; jwt: string };

type LoginTokens = {
  /** The user chosen last, in any tab. New tabs (and reloads) start with it. */
  current: string | undefined;
  /** Array of logged in user ids / tokens */
  tokens: Array<LoginToken>;
};

/**
 * The login tokens of the signed in users, kept in `localStorage` (or
 * in the page's memory where that is unavailable).
 */
export type LoginTokensStore = {
  /** The token of this tab's current user, or `""` when signed out. */
  jwt: () => string;
  /** The signed in users, this tab's current one first. */
  accounts: () => Array<LoginToken>;
  /**
   * Add (or replace) the token's user, and make it the current one
   * of this tab, and of the tabs opened next.
   */
  add_and_change: (jwt: string) => void;
  /**
   * Sign out a user, in every tab. When it is this tab's current one,
   * another signed in user (if any) becomes current here. Other tabs
   * with that user are signed out.
   */
  remove: (user_id: string) => void;
  /** Sign out every user, in every tab. */
  remove_all: () => void;
  /**
   * Make another signed in user the current one of this tab, and of
   * the tabs opened next.
   */
  change: (to_id: string) => void;
  /**
   * Call `listener` after the login tokens change, in this tab or in
   * another one (the browser's `storage` event), and after a token is
   * refused in this tab (`refuse`). When this tab's user signs out in
   * another tab, `jwt()` gives `""` from then on: use it to show the
   * login page and drop the data cached for the user. Another tab's
   * change is notified when its `storage` event arrives, even when this
   * tab already read it (eg. `jwt()` in a render). Returns the function
   * to unsubscribe.
   *
   * Fits React's `useSyncExternalStore(store.subscribe, store.jwt)`,
   * and `store.sendableJwt` alike.
   */
  subscribe: (listener: () => void) => () => void;
  /**
   * Note that the server refused `jwt`: it answered a request made with
   * it as a session which is over (see `isTokenRefusal`). Every request
   * with a token the server refuses counts against its per IP auth rate
   * limit, which logging in shares, so a refused token is never sent
   * again, by any caller using this store, until the page is reloaded:
   * `sendableJwt()` gives `""` while it is this tab's token. A new login
   * gives a new token, which is sent. Calls the `subscribeRefusals` (and
   * `subscribe`) listeners when `jwt` wasn't refused yet.
   */
  refuse: (jwt: string) => void;
  /** Whether the server refused `jwt` (`refuse`), in this tab. */
  isRefused: (jwt: string) => boolean;
  /**
   * The token to send: this tab's token (`jwt()`) unless the server
   * refused it (`refuse`), otherwise `""`.
   */
  sendableJwt: () => string;
  /**
   * Call `listener` after the server refused a token, in this tab
   * (`refuse`), eg. to send the user to the login page. Returns the
   * function to unsubscribe.
   */
  subscribeRefusals: (listener: () => void) => () => void;
};

/** The `localStorage` key used by `LOGIN_TOKENS`. */
const LOGIN_TOKENS_KEY = "mogh-auth-tokens-v1";

/** The part of a `Storage` the stores use. */
type TokenStorage = Pick<Storage, "getItem" | "setItem">;

/**
 * Keep the login tokens in `localStorage` under `key`.
 *
 * The stored tokens are shared by every tab of the origin: a login or
 * logout in one tab applies to all of them. Each call reads the latest
 * stored value and each change is applied onto it, so tabs never undo
 * each other's changes.
 *
 * The current user is kept per tab (per store). A tab starts with the
 * user chosen last in any tab, and only its own `add_and_change`,
 * `change` and `remove` change it: signing in another user or
 * switching the user in one tab leaves the other tabs with their user.
 * So a tab never starts sending the token of another user than the one
 * it shows. When a tab's user signs out in another tab, the tab is
 * signed out (`jwt()` gives `""`), use `subscribe` to react to that.
 *
 * Every app on the same origin (eg. several apps behind one host with
 * path routing, or on `localhost` in development) shares the default
 * key, and so one token list and the user chosen last. Such apps
 * should each pass their own `key`. Create one store per key, eg. at
 * module level. Apps using the auth pages and hooks of `mogh_ui` can't:
 * those always use the default `LOGIN_TOKENS`.
 *
 * Where `localStorage` is unavailable (in node, or in a browser
 * blocking site data for the origin, which throws on reading it), the
 * tokens are kept in the page's memory instead, shared by its stores
 * like `localStorage` would be: a login then lasts until the page is
 * closed or reloaded, and other tabs don't see it. A blocked
 * `localStorage` is warned about once.
 *
 * The storage is first read when the store is first used, not when it
 * is created: importing the package (eg. for the client, in node,
 * where reading `localStorage` warns) touches no storage.
 *
 * The tokens the server refused (`refuse`) are kept by the store, in
 * this tab: every caller using the store (the app's client, the auth
 * and supporter hooks of `mogh_ui`) stops sending a token once any of
 * them saw it refused.
 */
export function createLoginTokens(options?: {
  /** The `localStorage` key. Default: `mogh-auth-tokens-v1`. */
  key?: string;
}): LoginTokensStore {
  const key = options?.key ?? LOGIN_TOKENS_KEY;

  // Set on first use (`ready`).
  let storage: TokenStorage | undefined;

  let read_failed = false;
  const read = (from: TokenStorage) => {
    try {
      const stored = from.getItem(key);
      read_failed = false;
      return stored;
    } catch (error) {
      // Once, not on every call while it keeps failing.
      if (!read_failed) {
        console.warn("Failed to read the stored login tokens.", error);
      }
      read_failed = true;
      return undefined;
    }
  };

  // The stored value last seen, and its parsed state.
  let raw: string | null = null;
  let state: LoginTokens = { current: undefined, tokens: [] };

  // This tab's current user. It stays set when the user signs out in
  // another tab, which signs out this tab rather than switching it to
  // another user, and resumes when the user signs in again.
  let selected: string | undefined;

  // The stored value listeners were last notified of. Kept apart from
  // `raw`, which every read updates: the browser updates this tab's
  // `localStorage` as soon as another tab changes it, and fires the
  // `storage` event in a later task, so a read in between (a render, a
  // polling request) already sees the change.
  let notified_raw: string | null = null;

  /**
   * The storage, read for the first time on the first call: the tab
   * starts with the user chosen last (in any tab) by then.
   */
  const ready = (): TokenStorage => {
    if (storage) return storage;
    const resolved = resolveStorage(key);
    raw = read(resolved) ?? null;
    state = parseLoginTokens(raw);
    selected = state.current;
    notified_raw = raw;
    storage = resolved;
    return resolved;
  };

  /** The latest stored state. Only parsed again after it changed. */
  const load = () => {
    if (!storage) {
      ready();
      return state;
    }
    const stored = read(storage);
    // Keep the state known to this page when reading fails.
    if (stored !== undefined && stored !== raw) {
      raw = stored;
      state = parseLoginTokens(stored);
    }
    return state;
  };

  const listeners = new Set<() => void>();

  const notify = () => {
    notified_raw = raw;
    callListeners(listeners);
  };

  const save = (next: LoginTokens) => {
    const to = ready();
    state = next;
    const json = JSON.stringify(next);
    try {
      to.setItem(key, json);
      raw = json;
    } catch (error) {
      // Eg. QuotaExceededError. The login still works for this page.
      console.warn(
        "Failed to store the login tokens, they are lost when the page is closed.",
        error,
      );
    }
    notify();
  };

  // Changes made by other tabs. `key` is null after `localStorage.clear()`.
  const onStorage = (event: StorageEvent) => {
    if (event.key !== null && event.key !== key) return;
    load();
    if (raw !== notified_raw) notify();
  };

  const subscribe = (listener: () => void) => {
    listeners.add(listener);
    if (listeners.size === 1 && typeof window !== "undefined") {
      window.addEventListener?.("storage", onStorage);
    }
    return () => {
      if (
        listeners.delete(listener) &&
        listeners.size === 0 &&
        typeof window !== "undefined"
      ) {
        window.removeEventListener?.("storage", onStorage);
      }
    };
  };

  const jwt = () => {
    const { tokens } = load();
    return selected
      ? (tokens.find((t) => t.user_id === selected)?.jwt ?? "")
      : "";
  };

  const accounts = () => {
    const { tokens } = load();
    const current_token = tokens.find((t) => t.user_id === selected);
    const filtered = tokens.filter((t) => t.user_id !== selected);
    return current_token ? [current_token, ...filtered] : filtered;
  };

  const add_and_change = (jwt: string) => {
    const user_id = extractUserIdFromJwt(jwt);
    if (!user_id) return;
    const filtered = load().tokens.filter((t) => t.user_id !== user_id);
    filtered.push({ user_id, jwt });
    filtered.sort((a, b) => a.user_id.localeCompare(b.user_id));
    selected = user_id;
    save({
      current: user_id,
      tokens: filtered,
    });
  };

  const remove = (user_id: string) => {
    const { current, tokens } = load();
    const filtered = tokens.filter((t) => t.user_id !== user_id);
    if (selected === user_id) selected = filtered[0]?.user_id;
    // The user chosen last, unless that is the one signing out.
    let next = current;
    if (current === user_id) {
      next = filtered.some((t) => t.user_id === selected)
        ? selected
        : filtered[0]?.user_id;
    }
    save({
      current: next,
      tokens: filtered,
    });
  };

  const remove_all = () => {
    // Before setting `selected`, which the first read sets.
    ready();
    selected = undefined;
    save({
      current: undefined,
      tokens: [],
    });
  };

  const change = (to_id: string) => {
    const { tokens } = load();
    selected = to_id;
    save({
      current: to_id,
      tokens,
    });
  };

  // The tokens the server refused, in this tab. Each is a session
  // which is over: kept until the page is reloaded.
  const refused = new Set<string>();
  const refusal_listeners = new Set<() => void>();

  const refuse = (jwt: string) => {
    if (!jwt || refused.has(jwt)) return;
    refused.add(jwt);
    // `sendableJwt()` may have changed. Leaves `notified_raw` alone:
    // the stored tokens didn't change.
    callListeners(listeners);
    callListeners(refusal_listeners);
  };

  const isRefused = (jwt: string) => refused.has(jwt);

  const sendableJwt = () => {
    const current = jwt();
    return current && !refused.has(current) ? current : "";
  };

  const subscribeRefusals = (listener: () => void) => {
    refusal_listeners.add(listener);
    return () => {
      refusal_listeners.delete(listener);
    };
  };

  return {
    jwt,
    accounts,
    add_and_change,
    remove,
    remove_all,
    change,
    subscribe,
    refuse,
    isRefused,
    sendableJwt,
    subscribeRefusals,
  };
}

/** Calls each listener, one failing doesn't keep the others from it. */
function callListeners(listeners: Set<() => void>) {
  for (const listener of [...listeners]) {
    try {
      listener();
    } catch (error) {
      console.error("Login tokens listener failed.", error);
    }
  }
}

/**
 * Whether a failed request means the server refused the token it was
 * sent with, which then isn't to be sent again
 * (`LoginTokensStore.refuse`): a status of `refusedOn` answered by the
 * server itself (`RequestError.server`), not by a proxy or an auth
 * gateway in front of it, whose `401` / `403` says nothing about the
 * token.
 *
 * The default, `[401]`, is a token the server doesn't take: expired,
 * invalidated, or its user deleted. Pass `[401, 403]` for a request
 * whose `403` also means that the session is over (eg. `GetUserId`, or
 * an app's `GetUser`: a disabled user), rather than that the user lacks
 * a permission. Takes anything that was caught: it never throws, and
 * is `false` for any other value.
 */
export function isTokenRefusal(
  e: unknown,
  refusedOn: readonly number[] = [401],
): boolean {
  try {
    if (!e || typeof e !== "object") return false;
    const { status, server } = e as Partial<RequestError>;
    return (
      server === true &&
      typeof status === "number" &&
      refusedOn.includes(status)
    );
  } catch {
    // Eg. a getter which throws.
    return false;
  }
}

/**
 * The login tokens kept in `localStorage`, under `mogh-auth-tokens-v1`,
 * or in the page's memory where that is unavailable. See
 * `createLoginTokens`.
 */
export const LOGIN_TOKENS: LoginTokensStore = createLoginTokens();

/**
 * The page's stand-in for `localStorage` where that is unavailable,
 * shared by its stores (each under its key) like `localStorage` is.
 */
let memoryStorage: TokenStorage | undefined;
/** Whether a blocked `localStorage` was warned about. */
let warnedUnavailable = false;

/** `localStorage` when it can be read, otherwise the page's memory. */
function resolveStorage(key: string): TokenStorage {
  try {
    // An undeclared global has to be checked with `typeof`, using it
    // directly throws a ReferenceError. When the browser blocks site
    // data, even reading `localStorage` (and so `typeof`) throws a
    // SecurityError, and some browsers only throw on use.
    if (typeof localStorage !== "undefined" && localStorage) {
      localStorage.getItem(key);
      return localStorage;
    }
    // Eg. node: there is no page to keep the tokens across anyway.
  } catch (error) {
    // Once, not for each store.
    if (!warnedUnavailable) {
      warnedUnavailable = true;
      console.warn(
        "localStorage is unavailable, the login tokens are only kept until the page is closed.",
        error,
      );
    }
  }
  memoryStorage ??= createMemoryStorage();
  return memoryStorage;
}

function createMemoryStorage(): TokenStorage {
  const items = new Map<string, string>();
  return {
    getItem: (key) => items.get(key) ?? null,
    setItem: (key, value) => {
      items.set(key, String(value));
    },
  };
}

function parseLoginTokens(stored: string | null): LoginTokens {
  try {
    const parsed = stored ? JSON.parse(stored) : undefined;
    // Anything else than what this module stored is dropped,
    // rather than failing every page load until it is cleared.
    if (parsed && Array.isArray(parsed.tokens)) {
      return {
        current:
          typeof parsed.current === "string" ? parsed.current : undefined,
        tokens: parsed.tokens.filter(
          (token: Partial<LoginToken> | undefined) =>
            typeof token?.user_id === "string" &&
            typeof token?.jwt === "string",
        ),
      };
    }
  } catch (error) {
    console.warn("Invalid stored login tokens, starting without any.", error);
  }
  return { current: undefined, tokens: [] };
}
