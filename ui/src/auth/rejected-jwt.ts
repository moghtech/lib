import * as MoghAuth from "mogh_auth_client";
import { useSyncExternalStore } from "react";

// How the auth and supporter queries send this tab's token: through
// the refused token latch of mogh_auth_client's store
// (`LOGIN_TOKENS.refuse` / `sendableJwt`), which the app's own client
// shares. Every request with a token the server refuses counts against
// its per IP auth rate limit, which logging in shares, so a token which
// any user of the store saw refused isn't sent again by the others.
// Not exported from the package.

/**
 * This tab's token unless the server refused it, else `""`
 * (`LOGIN_TOKENS.sendableJwt`). Renders again after a login change and
 * after a refusal seen by any user of the store, so a query it enables
 * stops at once, also when the app's own request saw the refusal.
 */
export function useSendableJwt(): string {
  return useSyncExternalStore(
    MoghAuth.LOGIN_TOKENS.subscribe,
    MoghAuth.LOGIN_TOKENS.sendableJwt,
    () => "",
  );
}

/**
 * What a request fails with, unsent, when there is no token to send
 * (none, or the server refused it): a `401` like the server's, but not
 * the server's own body (no `server` mark), so nobody latches it again.
 */
export function notSent(): MoghAuth.RequestError {
  return {
    status: 401,
    result: {
      error: "Not sent: the session has ended, log in again",
      trace: [],
    },
  };
}

/**
 * Sends `request` with this tab's token as it is when sent, unless the
 * server refused that token: then fails at once (`notSent`). When the
 * server refuses it with a status of `refusedOn`
 * (`MoghAuth.isTokenRefusal`: the server's own answer, never a proxy's)
 * the store notes the token refused, for every user of the store.
 */
export async function sendWithJwt<T>(
  refusedOn: readonly number[],
  request: (jwt: string) => Promise<T>,
): Promise<T> {
  const jwt = MoghAuth.LOGIN_TOKENS.sendableJwt();
  if (!jwt) throw notSent();
  try {
    return await request(jwt);
  } catch (e) {
    if (MoghAuth.isTokenRefusal(e, refusedOn)) {
      MoghAuth.LOGIN_TOKENS.refuse(jwt);
    }
    throw e;
  }
}

/**
 * Query options which keep a query from sending a token the server
 * refused again, whatever the host's query client defaults: only a
 * request which never reached the server (the client's status 1) is
 * retried, and an error isn't refetched when the window is focused.
 */
export const SEND_REJECTED_ONCE = {
  retry: (failures: number, e: unknown) =>
    (e as { status?: number } | undefined)?.status === 1 && failures < 3,
  refetchOnWindowFocus: false,
} as const;
