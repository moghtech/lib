import { useMutation } from "@tanstack/react-query";
import type { DefaultError, UseMutationOptions } from "@tanstack/react-query";
import { useRef } from "react";

// A module of its own: the auth hooks build on it, and are run in
// node by tests/auth-state.test.ts with react and react-query stubbed,
// so it imports nothing else.

/**
 * `useMutation` for a request whose params or answer carry a
 * credential (a password, a code, a token, a new key's secret or
 * private key, a pasted private key), which forgets each request once
 * it settled and the caller's callbacks ran. React-query keeps both in
 * the hook's state, and keeps a finished mutation in the query
 * client's cache for 5 minutes by default, where anything running on
 * the page could still read them after the dialog showing them closed
 * (`queryClient.getMutationCache()`). So the hook resets once its last
 * request in flight settled, and its mutations have `gcTime: 0`:
 * unobserved, the cache drops them at once, whatever the app's query
 * client defaults. The auth requests (`useLogin`, `useManageAuth`) and
 * the supporter key's (`useManageSupporter`) are made with it; an app
 * makes its own writes carrying a credential with it too.
 *
 * What a caller does with the answer (or the failure) goes in the
 * hook's callbacks (`onSuccess`, `onError`, `onSettled`), or after the
 * `mutateAsync` promise: `data`, `error` and `variables` are gone by
 * then, and a callback passed to `mutate` itself doesn't run.
 */
export function useSecretMutation<
  TData = unknown,
  TError = DefaultError,
  TVariables = void,
  TOnMutateResult = unknown,
>(options: UseMutationOptions<TData, TError, TVariables, TOnMutateResult>) {
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
