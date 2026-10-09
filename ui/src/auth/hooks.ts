// The auth hooks and the session state of the page: the api's url,
// the clients, login / manage requests with their notifications, the
// admin listings, and the return from an external login. Re-exported
// by ./index.ts with the pages, which import from here (not the
// package barrel).

import { notifications } from "@mantine/notifications";
import {
  useMutation,
  UseMutationOptions,
  useQuery,
} from "@tanstack/react-query";
import * as MoghAuth from "mogh_auth_client";
import { useRef, useState } from "react";
import {
  externalLoginState,
  flowReturnError,
  flowReturnParam,
  markExternalFlow,
  removeQueryParams,
  replaceUrl,
  takeExternalFlowReturn,
  withoutFlowReturnParams,
} from "./external-flow";
import { errorNotificationMessage } from "../errors";
import { type PasskeyRequest, passkeyRequestFromParam } from "./passkey-login";
import {
  SEND_REJECTED_ONCE,
  sendWithJwt,
  useSendableJwt,
} from "./rejected-jwt";
import { backtoPath, sanitizeQueryInner } from "./utils";

export let AUTH_URL: string;

/**
 * Set the global auth url.
 * Make sure to call this before first render.
 * @param url The global url
 */
export function setAuthUrl(url: string) {
  AUTH_URL = url;
}

export function authClient() {
  return MoghAuth.MoghAuthClient(AUTH_URL, MoghAuth.LOGIN_TOKENS.jwt());
}

/**
 * Log in with an external login provider: redirects to it, like
 * `authClient().externalLogin`. From the login page the provider
 * sends the user back to [backtoPath], which never leaves the app,
 * from anywhere else back to the current page. Either way without the
 * query params the login returns with (see [useAuthState]), which only
 * the server adds.
 *
 * Also notes that this tab started the login: [useAuthState] only
 * shows the server's reason a failed login comes back with (or its
 * error redeeming one) after a login this tab started. Start external
 * logins through this (or `LoginPage`), not the client's
 * `externalLogin`, which would have such failures only logged.
 *
 * @param providerSlug The provider `slug` from `GetLoginOptions`.
 */
export function externalLogin(providerSlug: string) {
  // The client builds the redirect from the url (on the login page
  // from its `backto`), only hand it a checked one.
  const current = location.pathname + location.search + location.hash;
  let url = current;
  const search = new URLSearchParams(location.search);
  if (search.has("backto")) {
    search.set("backto", backtoPath());
    url = `${location.pathname}?${search}${location.hash}`;
  }
  url = withoutFlowReturnParams(url);
  if (url !== current) {
    // Absolute: a path starting with `//` would be read as another host.
    replaceUrl(location.origin + url);
  }
  markExternalFlow();
  authClient().externalLogin(providerSlug);
}

/**
 * Called when a manage request is refused because it needs a recent login
 * (`MoghAuth.isReauthenticationRequired`). By default the user is sent to
 * `/login`, and comes back to the current page after logging in.
 */
let onReauthenticationRequired = () => {
  const backto = encodeURIComponent(
    location.pathname + location.search + location.hash,
  );
  // Leaves time to read the notification.
  setTimeout(() => location.assign(`/login?backto=${backto}`), 2_000);
};

/** Replace what happens when a change needs the user to log in again. */
export function setOnReauthenticationRequired(handler: () => void) {
  onReauthenticationRequired = handler;
}

/**
 * Handles a request refused because it needs a recent login
 * (`MoghAuth.isReauthenticationRequired`): notifies the user and runs
 * the `setOnReauthenticationRequired` handler (by default, to the login
 * page and back). Returns whether `e` was such a refusal, so an app's
 * own write hook can do the same as `useManageAuth` for the writes its
 * server gates behind a recent login:
 *
 * ```ts
 * onError: (e) => {
 *   if (handleReauthenticationRequired(e)) return;
 *   notifications.show({ title: "Write failed", message: errorNotificationMessage(e), color: "red" });
 * },
 * ```
 */
export function handleReauthenticationRequired(e: unknown): boolean {
  if (!MoghAuth.isReauthenticationRequired(e)) return false;
  notifications.show({
    title: "Log in again to continue",
    message:
      "For your security this change needs a recent login. Taking you to the login page...",
    color: "yellow",
  });
  onReauthenticationRequired();
  return true;
}

export function useLoginOptions() {
  return useQuery({
    queryKey: ["GetLoginOptions"],
    queryFn: () => authClient().login("GetLoginOptions", {}),
  });
}

/**
 * Runs a manage query with this tab's token. A token the server
 * refuses with one of `refusedOn` is noted in `LOGIN_TOKENS`
 * (`refuse`), and then isn't sent again, by these queries nor by the
 * app's own client: every request with a token the server refuses
 * counts against its per IP auth rate limit, which logging in shares.
 */
function manageQuery<T>(
  refusedOn: readonly number[],
  query: (client: ReturnType<typeof authClient>) => Promise<T>,
): Promise<T> {
  return sendWithJwt(refusedOn, (jwt) =>
    query(MoghAuth.MoghAuthClient(AUTH_URL, jwt)),
  );
}

/**
 * List all the external login providers, including disabled ones.
 * Only available to admin users.
 */
export function useExternalLoginProviders(options?: { enabled?: boolean }) {
  const jwt = useSendableJwt();
  return useQuery({
    queryKey: ["ListExternalLoginProviders"],
    queryFn: () =>
      manageQuery([401], (client) =>
        client.manage("ListExternalLoginProviders", {}),
      ),
    enabled: (options?.enabled ?? true) && !!jwt,
    // A user who isn't an admin gets the same answer every time
    retry: false,
  });
}

/**
 * List the token issuers trusted for workload
 * identity. Only available to admin users.
 */
export function useTrustedIssuers(options?: { enabled?: boolean }) {
  const jwt = useSendableJwt();
  return useQuery({
    queryKey: ["ListTrustedIssuers"],
    queryFn: () =>
      manageQuery([401], (client) => client.manage("ListTrustedIssuers", {})),
    enabled: (options?.enabled ?? true) && !!jwt,
    // A user who isn't an admin gets the same answer every time
    retry: false,
  });
}

/**
 * `useMutation` for the auth requests, which forgets each request once
 * it settled and the caller's callbacks ran: its params (a password, a
 * code, a credential) and its answer (a token, TOTP recovery codes, a
 * new key's secret, a passkey challenge). React-query keeps both in the
 * hook's state, and keeps a finished mutation in the query client's
 * cache for 5 minutes by default, where anything running on the page
 * could still read them after the dialog showing them closed. So the
 * hook resets once its last request in flight settled, and its
 * mutations have `gcTime: 0`: unobserved, the cache drops them at once,
 * whatever the app's query client defaults.
 *
 * What a caller does with the answer (or the failure) goes in the
 * hook's callbacks (`onSuccess`, `onError`, `onSettled`), or after the
 * `mutateAsync` promise: `data`, `error` and `variables` are gone by
 * then, and a callback passed to `mutate` itself doesn't run.
 */
function useForgetfulMutation<TData, TError, TVariables, TOnMutateResult>(
  options: UseMutationOptions<TData, TError, TVariables, TOnMutateResult>,
) {
  // Overlapping requests (eg. a second click before the first
  // answered) are a mutation each, and the hook observes the latest:
  // reset once the last one settled, so it stays pending while any is.
  const forget = useRef({ inFlight: 0, reset: () => {} });
  const mutation = useMutation({
    ...options,
    gcTime: 0,
    onMutate: (variables, context) => {
      forget.current.inFlight++;
      return options.onMutate?.(variables, context) as
        TOnMutateResult | Promise<TOnMutateResult>;
    },
    onSettled: async (...args) => {
      try {
        await options.onSettled?.(...args);
      } finally {
        const settled = forget.current;
        settled.inFlight = Math.max(0, settled.inFlight - 1);
        if (settled.inFlight === 0) settled.reset();
      }
    },
  });
  forget.current.reset = mutation.reset;
  return mutation;
}

/**
 * A login request, its failure notified. Forgotten once it settled (see
 * `useForgetfulMutation`): use the answer in `onSuccess` or from the
 * `mutateAsync` promise, not from `data`.
 */
export function useLogin<
  T extends MoghAuth.Types.LoginRequest["type"],
  R extends Extract<MoghAuth.Types.LoginRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseMutationOptions<MoghAuth.LoginResponses[T], unknown, P, unknown>,
    "mutationKey" | "mutationFn"
  >,
>(type: T, config?: C) {
  return useForgetfulMutation({
    // Spread first: a caller's `onError` extends the
    // notification below instead of replacing it.
    ...config,
    mutationKey: [type],
    mutationFn: (params: P) => authClient().login<T, R>(type, params),
    onError: (e: LoginError, ...args) => {
      showLoginError(type, e);
      config?.onError && config.onError(e, ...args);
    },
  });
}

/** What a failed login request rejects with. */
type LoginError = { result?: { error?: string; trace?: string[] } };

/** Logs a failed login request, and shows the server's error. */
function showLoginError(
  type: MoghAuth.Types.LoginRequest["type"],
  e: LoginError,
) {
  console.log("Login error:", e);
  notifications.show({
    title: `Login request ${type} failed`,
    message: errorNotificationMessage(e),
    color: "red",
  });
}

/**
 * Look up the signed in user's id.
 *
 * Pass `enabled: false` where the host app already knows the answer
 * from its own session query. Every request with a token the server
 * refuses counts against its per IP auth rate limit, so a token the
 * server rejects is only ever sent once: it isn't retried or refetched
 * (whatever the host's query client defaults), and the query stays
 * disabled until there is another token. Also when the app's own
 * client saw the refusal (`LOGIN_TOKENS.refuse`).
 */
export function useUserId(options?: { enabled?: boolean }) {
  const jwt = useSendableJwt();
  return useQuery({
    queryKey: ["GetUserId"],
    queryFn: () =>
      manageQuery([401, 403], (client) => client.manage("GetUserId", {})),
    enabled: (options?.enabled ?? true) && !!jwt,
    // The server would refuse the token again
    ...SEND_REJECTED_ONCE,
  });
}

/**
 * A manage request (with the signed in user's token), its failure
 * notified; one refused for an old login sends the user to log in
 * again (`setOnReauthenticationRequired`). Forgotten once it settled
 * (see `useForgetfulMutation`): use the answer in `onSuccess` or from
 * the `mutateAsync` promise, not from `data` / `error`.
 */
export function useManageAuth<
  T extends MoghAuth.Types.ManageRequest["type"],
  R extends Extract<MoghAuth.Types.ManageRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseMutationOptions<MoghAuth.ManageResponses[T], unknown, P, unknown>,
    "mutationKey" | "mutationFn"
  >,
>(type: T, config?: C) {
  return useForgetfulMutation({
    // Spread first: a caller's `onError` extends the
    // notification below instead of replacing it.
    ...config,
    mutationKey: [type],
    mutationFn: (params: P) => authClient().manage<T, R>(type, params),
    onError: (
      e: { result?: { error?: string; trace?: string[] } },
      ...args
    ) => {
      console.log("Manage auth error:", e);
      // Not a failure of the request itself: changes to how the
      // user logs in are only accepted shortly after logging in.
      if (handleReauthenticationRequired(e)) {
        config?.onError && config.onError(e, ...args);
        return;
      }
      notifications.show({
        title: `Manage auth request ${type} failed`,
        message: errorNotificationMessage(e),
        color: "red",
      });
      config?.onError && config.onError(e, ...args);
    },
  });
}

/**
 * The redeem of this page load's `redeem_ready`: `sent` once, and
 * `failed` when it didn't log in.
 */
let jwt_redeem: "sent" | "failed" | undefined;
/**
 * Whether the page load which redeemed is the return from an external
 * login this tab started ([takeExternalFlowReturn]): only then is the
 * server's error shown when the redeem fails.
 */
let jwt_redeem_vouched = false;
let passkey_sent = false;
let external_error_shown = false;

/** The longest reason from the url shown in the notification. */
const MAX_EXTERNAL_ERROR_LENGTH = 300;

/**
 * Handles what an external login redirects back to the app with.
 * Call it at the top of the app, before (outside) its router:
 * - `redeem_ready`: redeems the login for a token, once per page load.
 *   The login it redeems waits in the visitor's own session, so it
 *   works wherever the login returns: also to another tab (eg. from a
 *   link in an email the provider sent), a reload while redeeming, or
 *   a login started with the client's `externalLogin`. Anyone can put
 *   it in a link, which can only complete a login of the visitor's
 *   own, and otherwise fails. The server's error is only shown on the
 *   page load which returns from an external login this tab started
 *   through mogh_ui ([externalLogin], `LoginPage`) within 30 minutes.
 *   Otherwise the failure is only logged to the console. Either way
 *   the param is removed from the url, and the login page doesn't
 *   auto redirect, which could loop.
 * - `passkey`: asks for the passkey, the login's second factor.
 * - `login_error` / `link_error`: shows why an external login / link
 *   failed (`AuthImpl::external_login_error_redirect` on the server).
 *   Anyone can put text in a link, so the server's reason is only
 *   shown after an external login / link this tab started through
 *   mogh_ui ([externalLogin], `LoginPage`, `LinkedLogins`), on the
 *   page load it came back to, when the url carries only the one reason
 *   the server adds. Otherwise the notification says the login didn't
 *   complete, and the text is only logged to the console. Next to what
 *   a login which went through returns with (`redeem_ready`, `totp`,
 *   `passkey`) it isn't the server's at all, and is only logged.
 *
 * The server adds its params after the query already in the url, so
 * `redeem_ready`, `totp` and `passkey` are read from their last value.
 *
 * The first page load after leaving for the provider ends the flow,
 * whatever it came back with (also a successful login or link, or a
 * second factor to ask for). So call this on every page of the app.
 *
 * Returns whether to show a loader while the token is redeemed
 * (`jwt_redeem_ready`, false again if that fails), or the login page
 * for the second factor (`passkey_pending`, `totp`).
 */
export function useAuthState() {
  // A failed redeem falls back to the app, eg. its login page.
  const [redeemFailed, setRedeemFailed] = useState(false);
  const onSuccess = ({ jwt }: MoghAuth.Types.JwtResponse) => {
    MoghAuth.LOGIN_TOKENS.add_and_change(jwt);
    sanitizeQueryInner(search);
  };
  const { mutate: redeemJwt } = useForgetfulMutation({
    mutationKey: ["ExchangeForJwt"],
    mutationFn: () => authClient().login("ExchangeForJwt", {}),
    onSuccess,
    onError: (e: LoginError) => {
      if (jwt_redeem_vouched) {
        showLoginError("ExchangeForJwt", e);
      } else {
        // Eg. a link carrying it, with no login to redeem: nothing
        // alarming to show, the user can just log in.
        console.warn(
          "Couldn't redeem the redeem_ready in the url, which isn't the return from an external login this tab started:",
          e,
        );
      }
      // Retrying can't help, the server has ended the login (or there
      // was none). Nor can the provider: the login page doesn't auto
      // redirect to it, which could loop.
      jwt_redeem = "failed";
      externalLoginState.failed = true;
      setRedeemFailed(true);
      removeQueryParams("redeem_ready");
    },
  });
  const { mutate: completePasskeyLogin } = useLogin("CompletePasskeyLogin", {
    onSuccess,
  });
  const search = new URLSearchParams(location.search);
  // Whether the tab is back from an external login / link it started.
  const external_flow_return = takeExternalFlowReturn();
  // Judged on the url as it loaded, before any of it is removed.
  const external_error = flowReturnError(search, external_flow_return);

  // A link can carry anything here: a challenge which can't be
  // read must not crash the app, which renders this on every page.
  const _passkey = flowReturnParam(search, "passkey");
  let passkeyRequest: PasskeyRequest | undefined;
  if (_passkey) {
    try {
      passkeyRequest = passkeyRequestFromParam(_passkey);
    } catch (e) {
      console.error("Invalid passkey challenge:", e);
      search.delete("passkey");
      if (!passkey_sent) {
        passkey_sent = true;
        notifications.show({
          title: "Invalid passkey challenge",
          message: "Log in again to continue.",
          color: "red",
        });
      }
      removeQueryParams("passkey");
    }
  }

  // guard against multiple reqs sent
  // maybe isPending would do this but not sure about with render loop, this for sure will.
  if (passkeyRequest && !passkey_sent) {
    passkey_sent = true;
    navigator.credentials
      .get(passkeyRequest)
      .then((credential) => completePasskeyLogin({ credential }))
      .catch((e) => {
        console.error(e);
        notifications.show({
          title: "Failed to select passkey",
          message: "See console for details",
          color: "red",
        });
      });
  }

  // An external login / link which failed comes back with the reason
  // (`AuthImpl::external_login_error_redirect` on the server).
  if (external_error && !external_error_shown) {
    external_error_shown = true;
    const { link, text, source } = external_error;
    const param = link ? "link_error" : "login_error";
    if (source === "stray") {
      // Next to a login which went through: not the server's.
      console.warn(`Ignored ${param} in the url:`, text);
    } else {
      if (!link) {
        // Don't auto redirect to the provider again, it would loop.
        externalLoginState.failed = true;
      }
      let message: string;
      if (source === "server") {
        message =
          text.length > MAX_EXTERNAL_ERROR_LENGTH
            ? text.slice(0, MAX_EXTERNAL_ERROR_LENGTH) + "..."
            : text;
      } else {
        // Not a flow started here, the text may come from anyone.
        console.warn(`Unverified ${param} in the url:`, text);
        message = link
          ? "Linking the external login didn't complete."
          : "The external login didn't complete.";
      }
      notifications.show({
        title: link ? "Failed to link login" : "Login failed",
        message,
        color: "red",
        autoClose: 10_000,
      });
    }
    search.delete("login_error");
    search.delete("link_error");
    removeQueryParams("login_error", "link_error");
  }

  const redeem_ready = flowReturnParam(search, "redeem_ready") === "true";

  // Once per page load: guards against multiple requests sent. Whether
  // the page load returns from the tab's flow is only known on the
  // first render.
  if (redeem_ready && jwt_redeem === undefined) {
    jwt_redeem = "sent";
    jwt_redeem_vouched = external_flow_return;
    redeemJwt();
  }

  return {
    jwt_redeem_ready: redeem_ready && jwt_redeem === "sent" && !redeemFailed,
    passkey_pending: !!passkeyRequest,
    totp: flowReturnParam(search, "totp") === "true",
  };
}
