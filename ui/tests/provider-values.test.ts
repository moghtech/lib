import { test } from "node:test";
import assert from "node:assert/strict";
import type * as MoghAuth from "mogh_auth_client";
import {
  providerFormErrors,
  providerFormValues,
  providerUpdate,
} from "../src/auth/providers/values.ts";

type ListItem = MoghAuth.Types.ExternalLoginProviderListItem;

/** A stored OIDC provider with a client secret. */
const oidc: ListItem = {
  provider: {
    id: "p1",
    name: "Company SSO",
    slug: "sso",
    registration_disabled: false,
    token_exchange: {
      enabled: true,
      audiences: ["cli"],
      max_token_age_secs: 300,
    },
    config: {
      kind: "Oidc",
      params: {
        enabled: true,
        provider: "https://idp.example.com",
        client_id: "app",
        // What the list returns for a stored secret: never the secret.
        client_secret: "##############",
        groups_claim: "groups",
        admin_groups: ["admins"],
      },
    },
  },
  read_only: false,
  redirect_uri: "https://app.example.com/auth/external/sso/callback",
};

/** A stored Github provider without a secret yet. */
const github: ListItem = {
  provider: {
    id: "p2",
    name: "Github",
    config: { kind: "Github", params: { enabled: false, client_id: "gh" } },
  },
  read_only: false,
  redirect_uri: "https://app.example.com/auth/external/p2/callback",
};

test("a stored provider's values pass", () => {
  for (const item of [oidc, github]) {
    assert.deepEqual(providerFormErrors(item, providerFormValues(item)), {});
  }
  const values = providerFormValues(oidc);
  // The secret is never sent to the browser, nor shown.
  assert.equal(values.client_secret, "");
  assert.equal(values.token_exchange_max_age_secs, 300);
});

test("an emptied maximum token age is an error, not 0", () => {
  // 0 is no limit at all, the loosest setting: never what an emptied
  // field saves.
  const values = {
    ...providerFormValues(oidc),
    token_exchange_max_age_secs: "" as const,
  };
  assert.deepEqual(Object.keys(providerFormErrors(oidc, values)), [
    "token_exchange_max_age_secs",
  ]);
  assert.throws(() => providerUpdate(oidc, values));
  for (const age of [1.5, -1, NaN]) {
    const errors = providerFormErrors(oidc, {
      ...providerFormValues(oidc),
      token_exchange_max_age_secs: age,
    });
    assert.ok(errors.token_exchange_max_age_secs, String(age));
  }
  const unlimited = {
    ...providerFormValues(oidc),
    token_exchange_max_age_secs: 0,
  };
  assert.deepEqual(providerFormErrors(oidc, unlimited), {});
  assert.equal(
    providerUpdate(oidc, unlimited).token_exchange?.max_token_age_secs,
    0,
  );
});

test("the name, slug and urls are checked like the server does", () => {
  const values = providerFormValues(oidc);
  const errors = (changes: object) =>
    providerFormErrors(oidc, { ...values, ...changes });
  assert.ok(errors({ name: "  " }).name);
  for (const slug of ["Bad", "a--b", "-a", "a-", "a_b", "a".repeat(65)]) {
    assert.ok(errors({ slug }).slug, slug);
  }
  for (const slug of ["", "sso", "my-sso-2", "a".repeat(64)]) {
    assert.equal(errors({ slug }).slug, undefined, slug);
  }
  // Changing the address needs the secret again (below), typed here.
  const secret = { client_secret: "s" };
  assert.ok(errors({ ...secret, provider: "ftp://idp" }).provider);
  assert.ok(errors({ ...secret, provider: "idp.example.com" }).provider);
  assert.equal(errors({ ...secret, provider: "" }).provider, undefined);
  assert.ok(errors({ redirect_host: "not a url" }).redirect_host);
  assert.equal(
    errors({ redirect_host: " https://login.example.com " }).redirect_host,
    undefined,
  );
});

test("the client secret rules", () => {
  const values = providerFormValues(oidc);
  // The server won't send the stored secret to another address.
  const moved = { ...values, provider: "https://other.example.com" };
  assert.ok(providerFormErrors(oidc, moved).client_secret);
  assert.deepEqual(
    providerFormErrors(oidc, { ...moved, client_secret: "new" }),
    {},
  );
  assert.deepEqual(
    providerFormErrors(oidc, { ...moved, clear_client_secret: true }),
    {},
  );
  // Only OIDC works without a secret.
  const enabled = { ...providerFormValues(github), enabled: true };
  assert.ok(providerFormErrors(github, enabled).client_secret);
  assert.deepEqual(
    providerFormErrors(github, { ...enabled, client_secret: "s" }),
    {},
  );
  const stored: ListItem = {
    ...github,
    provider: {
      ...github.provider,
      config: {
        kind: "Github",
        params: {
          enabled: true,
          client_id: "gh",
          client_secret: "##############",
        },
      },
    },
  };
  assert.ok(
    providerFormErrors(stored, {
      ...providerFormValues(stored),
      clear_client_secret: true,
    }).clear_client_secret,
  );
});

test("the update request the values make", () => {
  const update = providerUpdate(oidc, {
    ...providerFormValues(oidc),
    name: " Renamed ",
    slug: " sso-2 ",
    client_id: " app-2 ",
    provider: " https://idp.example.com/o/app ",
    client_secret: "secret",
    token_exchange_max_age_secs: 600,
  });
  assert.equal(update.id, "p1");
  assert.equal(update.name, "Renamed");
  assert.equal(update.slug, "sso-2");
  assert.deepEqual(update.token_exchange, {
    enabled: true,
    audiences: ["cli"],
    max_token_age_secs: 600,
  });
  assert.equal(update.config.kind, "Oidc");
  assert.deepEqual(update.config.params, {
    enabled: true,
    client_id: "app-2",
    client_secret: "secret",
    provider: "https://idp.example.com/o/app",
    redirect_host: "",
    use_full_email: false,
    auto_redirect: false,
    additional_audiences: [],
    additional_scopes: [],
    groups_claim: "groups",
    allowed_groups: [],
    admin_groups: ["admins"],
  });
  assert.equal(update.clear_client_secret, false);

  // An empty secret keeps the stored one, removing it is explicit.
  const cleared = providerUpdate(oidc, {
    ...providerFormValues(oidc),
    client_secret: "typed before the switch",
    clear_client_secret: true,
  });
  assert.equal(cleared.config.params.client_secret, "");
  assert.equal(cleared.clear_client_secret, true);

  // Github has no signed tokens to exchange.
  const gh = providerUpdate(github, {
    ...providerFormValues(github),
    token_exchange_enabled: true,
  });
  assert.equal(gh.token_exchange?.enabled, false);
  assert.deepEqual(gh.config, {
    kind: "Github",
    params: { enabled: false, client_id: "gh", client_secret: "" },
  });
});
