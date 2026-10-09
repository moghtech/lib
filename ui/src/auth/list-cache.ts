import type { QueryClient, QueryKey } from "@tanstack/react-query";

/**
 * After a save answered with the saved list item (eg.
 * `UpdateTrustedIssuer`): writes it into the cached list (`queryKey`) in
 * place of the item with the same `id`, so a page showing it is current
 * right away, not after the refetch (or never, when the refetch fails).
 * Then refetches (`invalidate`, the list and what else shows it), and
 * resolves once that settled: returned from the save's `onSuccess`, it
 * makes an awaited save (`mutateAsync`) resolve with the cache current.
 */
export function savedListItem<T>(
  queryClient: QueryClient,
  queryKey: QueryKey,
  saved: T,
  id: (item: T) => string,
  invalidate: () => Promise<unknown>,
): Promise<unknown> {
  queryClient.setQueryData<T[]>(queryKey, (list) =>
    list?.map((item) => (id(item) === id(saved) ? saved : item)),
  );
  return invalidate();
}
