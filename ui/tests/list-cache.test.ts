import { test } from "node:test";
import assert from "node:assert/strict";
import { MutationObserver, QueryClient } from "@tanstack/query-core";
import { savedListItem } from "../src/auth/list-cache.ts";

type Item = { issuer: { id: string; name: string } };
const item = (id: string, name: string): Item => ({ issuer: { id, name } });
const KEY = ["ListTrustedIssuers"];

test("a save shows at once, and resolves once the list is refetched", async () => {
  const client = new QueryClient();
  client.setQueryData<Item[]>(KEY, [item("a", "A"), item("b", "B")]);
  let release!: () => void;
  const refetched = new Promise<void>((resolve) => (release = resolve));
  // What the page's update does: the save answers with the saved item.
  const save = new MutationObserver(client, {
    mutationFn: async (name: string) => item("b", name),
    onSuccess: (saved: Item) =>
      savedListItem(
        client,
        KEY,
        saved,
        (i) => i.issuer.id,
        () => refetched,
      ),
  });
  let resolved = false;
  const done = save.mutate("Renamed").then(() => (resolved = true));
  await new Promise((resolve) => setTimeout(resolve, 10));
  // The page (and its config's original) show the saved values right
  // away, before the refetch landed: the draft can be dropped.
  assert.deepEqual(client.getQueryData(KEY), [
    item("a", "A"),
    item("b", "Renamed"),
  ]);
  // The save itself waits for the refetch.
  assert.equal(resolved, false);
  release();
  await done;
  assert.equal(resolved, true);
});

test("the saved item stays until a refetch replaces it", async () => {
  const client = new QueryClient();
  client.setQueryData<Item[]>(KEY, [item("a", "A")]);
  // Eg. the refetch failed (invalidateQueries resolves either way).
  await savedListItem(
    client,
    KEY,
    item("a", "Saved"),
    (i) => i.issuer.id,
    () => Promise.resolve(),
  );
  assert.deepEqual(client.getQueryData(KEY), [item("a", "Saved")]);
  // No list loaded yet: nothing is made up.
  const empty = new QueryClient();
  await savedListItem(
    empty,
    KEY,
    item("a", "Saved"),
    (i) => i.issuer.id,
    () => Promise.resolve(),
  );
  assert.equal(empty.getQueryData(KEY), undefined);
});
