import { test } from "node:test";
import assert from "node:assert/strict";
import type * as MoghAuth from "mogh_auth_client";
import {
  issuerFormErrors,
  issuerFormValues,
  newRule,
  trustedIssuer,
  type IssuerFormContext,
  type IssuerFormValues,
} from "../src/auth/issuers/values.ts";

const stored: MoghAuth.Types.TrustedIssuer = {
  id: "i1",
  name: "Github Actions",
  enabled: true,
  issuer: "https://token.actions.githubusercontent.com",
  keys: { source: "Discovery", params: {} },
  audiences: ["https://app.example.com"],
  max_token_age_secs: 300,
  rules: [
    {
      id: "r1",
      name: "Deploy",
      enabled: true,
      claims: [{ claim: "repository_id", pattern: "12345" }],
      groups: ["deployers"],
      admin: false,
      token_ttl_secs: 900,
    },
  ],
};

const values = (changes: Partial<IssuerFormValues> = {}): IssuerFormValues => ({
  ...issuerFormValues(stored),
  ...changes,
});

/**
 * The errors on a page which shows the review device field, of values
 * edited from `stored` unless given another.
 */
const errorsOf = (
  values: IssuerFormValues,
  context: Partial<IssuerFormContext> = {},
) => issuerFormErrors(values, { stored, device: true, ...context });

/** Stored reviewing at a url, with a credential (listed redacted). */
const reviewing: MoghAuth.Types.TrustedIssuer = {
  id: "i3",
  name: "Cluster",
  enabled: true,
  issuer: "https://kubernetes.default.svc.cluster.local",
  keys: {
    source: "TokenReview",
    params: {
      url: "https://10.0.0.1:6443",
      ca: "",
      token: "##############",
      device: "",
    },
  },
  audiences: ["https://cicada.example.com"],
};

test("a stored issuer's values pass, and make the same issuer", () => {
  assert.deepEqual(errorsOf(values()), {});
  assert.deepEqual(trustedIssuer("i1", values()), stored);
  // A field the server left out has its serde default.
  assert.deepEqual(
    issuerFormValues({ id: "i2", name: "n", issuer: "https://x" }),
    {
      name: "n",
      enabled: false,
      issuer: "https://x",
      keys_source: "Discovery",
      keys_url: "",
      keys_static: "",
      review_url: "",
      review_ca: "",
      review_token: "",
      review_token_stored: false,
      review_device: "",
      review_in_cluster: false,
      audiences: [],
      max_token_age_secs: 0,
      rules: [],
    },
  );
});

test("a token review issuer round-trips, its credential write-only", () => {
  // Stored with a credential: listed redacted, the form starts empty
  // and knows one is stored.
  const read = issuerFormValues(reviewing);
  assert.equal(read.keys_source, "TokenReview");
  assert.equal(read.review_url, "https://10.0.0.1:6443");
  assert.equal(read.review_token, "");
  assert.equal(read.review_token_stored, true);

  // An empty credential saves as empty, which keeps the stored one.
  const kept = trustedIssuer("i3", { ...read, rules: [] });
  assert.deepEqual(kept.keys, {
    source: "TokenReview",
    params: {
      url: "https://10.0.0.1:6443",
      ca: "",
      token: "",
      device: "",
    },
  });
  assert.deepEqual(errorsOf({ ...read, rules: [] }, { stored: reviewing }), {});

  // Fresh direct setup: the credential is required with a url.
  const direct = values({
    keys_source: "TokenReview",
    review_url: "https://10.0.0.1:6443",
  });
  assert.deepEqual(Object.keys(errorsOf(direct)), ["review_token"]);
  assert.deepEqual(
    errorsOf(values({ ...direct, review_token: "reviewer" })),
    {},
  );

  // Through a device: no url beside it. The credential and CA fields
  // are hidden while a device is set, so they aren't checked.
  const device = values({
    keys_source: "TokenReview",
    review_device: "dev_123",
  });
  assert.deepEqual(errorsOf(device), {});
  assert.deepEqual(
    Object.keys(
      errorsOf(
        values({
          ...device,
          review_url: "https://10.0.0.1:6443",
          review_token: "reviewer",
          review_ca: "pem",
        }),
      ),
    ),
    ["review_device"],
  );
  // Neither target is an error too, naming what the page offers.
  const neither = values({ keys_source: "TokenReview" });
  assert.deepEqual(errorsOf(neither), {
    review_url:
      "A token review needs the cluster api server URL, a device to review through, or this cluster",
  });
  assert.deepEqual(errorsOf(neither, { device: false }), {
    review_url:
      "A token review needs the cluster api server URL, or this cluster",
  });
});

test("an in-cluster review stores nothing and quiets the hidden fields", () => {
  // Stored: the toggle reads back, no credential is stored.
  const read = issuerFormValues({
    id: "i4",
    name: "Cluster",
    enabled: true,
    issuer: "https://kubernetes.default.svc.cluster.local",
    keys: { source: "TokenReview", params: { in_cluster: true } },
    audiences: ["https://cicada.example.com"],
  });
  assert.equal(read.review_in_cluster, true);
  assert.equal(read.review_token_stored, false);

  // Saved: only the toggle goes out, whatever lingers in the hidden
  // fields, and none of their checks fire.
  const lingering = values({
    keys_source: "TokenReview",
    review_in_cluster: true,
    review_url: "not a url",
    review_token: "pasted",
    review_ca: "pem",
    review_device: "dev_123",
  });
  assert.deepEqual(errorsOf(lingering), {});
  assert.deepEqual(trustedIssuer("i4", lingering).keys, {
    source: "TokenReview",
    params: { in_cluster: true },
  });
});

test("a url issuer with a CA switched to a device saves", () => {
  // Stored reviewing at a url, with a CA and a credential.
  const withCa: MoghAuth.Types.TrustedIssuer = {
    id: "i5",
    name: "Cluster",
    enabled: true,
    issuer: "https://kubernetes.default.svc.cluster.local",
    keys: {
      source: "TokenReview",
      params: {
        url: "https://10.0.0.1:6443",
        ca: "-----BEGIN CERTIFICATE-----",
        token: "##############",
        device: "",
      },
    },
    audiences: ["https://app.example.com"],
  };
  const read = issuerFormValues(withCa);
  // The url emptied and a device typed: the CA (and a credential typed
  // before) are hidden now, neither checked nor sent, as the server
  // drops them for a device anyway.
  for (const review_token of ["", "typed before the device"]) {
    const switched = {
      ...read,
      review_url: "",
      review_device: "dev_123",
      review_token,
    };
    assert.deepEqual(errorsOf(switched, { stored: withCa }), {});
    assert.deepEqual(trustedIssuer("i5", switched).keys, {
      source: "TokenReview",
      params: { url: "", ca: "", token: "", device: "dev_123" },
    });
  }
});

test("a changed url needs the reviewer credential again", () => {
  // As the server: the stored credential is only kept for the url it
  // was entered for.
  const read = issuerFormValues(reviewing);
  const moved = { ...read, review_url: "https://10.0.0.2:6443" };
  assert.deepEqual(errorsOf(moved, { stored: reviewing }), {
    review_token: "Enter the reviewer credential again when changing the URL",
  });
  // With a new credential, or at the stored url (spaces aside), it saves.
  assert.deepEqual(
    errorsOf({ ...moved, review_token: "new" }, { stored: reviewing }),
    {},
  );
  assert.deepEqual(
    errorsOf(
      { ...read, review_url: " https://10.0.0.1:6443 " },
      { stored: reviewing },
    ),
    {},
  );
});

test("emptied number fields are errors, not 0", () => {
  const emptied = values({
    max_token_age_secs: "",
    rules: [{ ...values().rules[0], token_ttl_secs: "" }],
  });
  assert.deepEqual(Object.keys(errorsOf(emptied)), [
    "max_token_age_secs",
    "rules.0.token_ttl_secs",
  ]);
  assert.throws(() => trustedIssuer("i1", emptied));
  assert.throws(() => trustedIssuer("i1", values({ max_token_age_secs: 1.5 })));
  assert.equal(
    trustedIssuer("i1", values({ max_token_age_secs: 0 })).max_token_age_secs,
    0,
  );
});

test("errors are keyed by the path of their field", () => {
  const errors = errorsOf(
    values({
      name: " ",
      issuer: "token.actions.githubusercontent.com",
      keys_source: "JwksUri",
      keys_url: "ftp://keys",
      audiences: [],
      rules: [
        {
          ...newRule(),
          claims: [
            { claim: "", pattern: "x" },
            { claim: "sub", pattern: "" },
            { claim: "aud", pattern: "**" },
          ],
        },
        { ...newRule(), name: "Empty", claims: [] },
      ],
    }),
  );
  assert.deepEqual(errors, {
    name: "Name cannot be empty",
    issuer: "The issuer must be an http(s) URL",
    keys_url: "The keys URL must be an http(s) URL",
    audiences: "At least one audience is required",
    "rules.0.name": "A rule has no name",
    "rules.0.claims.0.claim": "Rule '(unnamed)': a claim has no name",
    "rules.0.claims.1.pattern": "Rule '(unnamed)': claim 'sub' has no value",
    "rules.0.claims.2.pattern":
      "Rule '(unnamed)': claim 'aud' matches any value, which restricts nothing",
    "rules.1.claims": "Rule 'Empty' needs at least one claim to match",
  });
});

test("static keys have to be a key set", () => {
  const keys = (keys_static: string) =>
    errorsOf(values({ keys_source: "Static", keys_static })).keys_static;
  assert.equal(keys("{ not json"), "The static keys must be valid JSON");
  assert.match(keys('{ "kid": "a" }') ?? "", /must be a key set/);
  assert.equal(keys('{ "keys": [] }'), undefined);
  // Only the source in use is checked.
  assert.deepEqual(
    errorsOf(values({ keys_source: "Discovery", keys_static: "x" })),
    {},
  );
});

test("the issuer the values make", () => {
  const issuer = trustedIssuer(
    "i1",
    values({
      name: " CI ",
      issuer: " https://gitlab.example.com ",
      keys_source: "JwksUri",
      keys_url: " https://gitlab.example.com/oauth/discovery/keys ",
      rules: [
        {
          ...newRule(),
          name: " Build ",
          claims: [{ claim: " project_id ", pattern: " 7 " }],
        },
      ],
    }),
  );
  assert.equal(issuer.name, "CI");
  assert.equal(issuer.issuer, "https://gitlab.example.com");
  assert.deepEqual(issuer.keys, {
    source: "JwksUri",
    params: "https://gitlab.example.com/oauth/discovery/keys",
  });
  assert.deepEqual(issuer.rules, [
    {
      // A new rule: the server gives it its id.
      id: "",
      name: "Build",
      enabled: true,
      // The claim's name is trimmed, its pattern kept as typed.
      claims: [{ claim: "project_id", pattern: " 7 " }],
      groups: [],
      admin: false,
      token_ttl_secs: 900,
    },
  ]);
  assert.deepEqual(
    trustedIssuer(
      "i1",
      values({ keys_source: "Static", keys_static: '{"keys":[]}' }),
    ).keys,
    { source: "Static", params: '{"keys":[]}' },
  );
});
