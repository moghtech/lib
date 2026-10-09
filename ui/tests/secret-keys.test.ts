import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type SecretKey,
  secretKeyOf,
  secretWasSet,
} from "../src/components/config/secret-keys.ts";

type Draft = { client_secret: string; token: string; name: string };

test("a stored secret the draft can't show reads as set before", () => {
  // The provider page's client secret: never sent to the browser, so
  // the draft's original is "" whether a secret is stored or not. The
  // dialog read a replaced stored secret as "None -> ••••••••".
  const original: Draft = { client_secret: "", token: "t", name: "n" };
  const keys: SecretKey<Draft>[] = [
    { key: "client_secret", stored: true },
    "token",
  ];
  const secret = secretKeyOf(keys, "client_secret")!;
  assert.equal(secretWasSet(secret, original, "client_secret"), true);
  const none = secretKeyOf<Draft>(
    [{ key: "client_secret", stored: false }],
    "client_secret",
  )!;
  assert.equal(secretWasSet(none, original, "client_secret"), false);
  // A plain key: set before when the draft's original is.
  assert.equal(
    secretWasSet(secretKeyOf(keys, "token")!, original, "token"),
    true,
  );
  assert.equal(
    secretWasSet("token", { ...original, token: "" }, "token"),
    false,
  );
  // Not a secret at all.
  assert.equal(secretKeyOf(keys, "name"), undefined);
  assert.equal(secretKeyOf(undefined, "name"), undefined);
});
