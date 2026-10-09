import { useQueryClient } from "@tanstack/react-query";
import * as MoghAuth from "mogh_auth_client";
import { useEffect, useMemo, useRef, useSyncExternalStore } from "react";

// The signed in accounts of the browser (`MoghAuth.LOGIN_TOKENS`), for
// the app's account menu (`AccountsMenu`) and its session handling.

/**
 * The signed in users, this tab's current one first. Renders again on
 * sign ins / outs, in this tab or in another one: the tokens are shared
 * by the tabs.
 */
export function useAccounts(): MoghAuth.LoginToken[] {
  const tokens = MoghAuth.LOGIN_TOKENS;
  // `accounts()` gives a new array per call, which can't be a
  // `useSyncExternalStore` snapshot: its content can.
  const snapshot = useSyncExternalStore(tokens.subscribe, accountsSnapshot);
  return useMemo(
    () => JSON.parse(snapshot) as MoghAuth.LoginToken[],
    [snapshot],
  );
}

function accountsSnapshot() {
  return JSON.stringify(MoghAuth.LOGIN_TOKENS.accounts());
}

/**
 * The user id of this tab's current token (the id the store keeps
 * next to it), `undefined` while signed out. Renders again when it
 * changes, in this tab or by a sign out in another one.
 */
export function useCurrentUserId(): string | undefined {
  return useSyncExternalStore(
    MoghAuth.LOGIN_TOKENS.subscribe,
    currentUserId,
    () => undefined,
  );
}

/** See `useCurrentUserId`. */
export function currentUserId(): string | undefined {
  const tokens = MoghAuth.LOGIN_TOKENS;
  const jwt = tokens.jwt();
  return jwt
    ? tokens.accounts().find((account) => account.jwt === jwt)?.user_id
    : undefined;
}

/**
 * Drops the cached queries (and the variables of past mutations, eg.
 * a password) when this tab's user changes: signed out, here or in
 * another tab, or signed in as another user. They hold the previous
 * user's data, which must neither outlive the session nor show for the
 * next user until the refetch.
 *
 * Call it once, at the top of the app (inside the query client
 * provider).
 */
export function useResetOnUserChange() {
  const qc = useQueryClient();
  const userId = useCurrentUserId();
  const previous = useRef(userId);
  useEffect(() => {
    if (previous.current === userId) return;
    const signedIn = previous.current !== undefined;
    previous.current = userId;
    // Nothing is cached for a user while signed out.
    if (!signedIn) return;
    qc.getMutationCache().clear();
    // Refetches what is still mounted, with the new token.
    qc.resetQueries();
  }, [qc, userId]);
}

/**
 * The login page for signing in another account, coming back to the
 * current page after: `/login?backto=<current>&disableAutoLogin=true`.
 * Without `disableAutoLogin` a login provider set to `auto_redirect`
 * would take the user straight to the provider, which (signed in there
 * already) answers for the same account, and the login form and the
 * other providers could never be reached.
 */
export function addAccountPath(): string {
  const params = new URLSearchParams({
    backto: location.pathname + location.search + location.hash,
    disableAutoLogin: "true",
  });
  return `/login?${params}`;
}
