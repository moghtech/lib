import { test } from "node:test";
import assert from "node:assert/strict";
import type * as MoghAuth from "mogh_auth_client";
import {
  issuerFormErrors,
  issuerFormValues,
  newRule,
  trustedIssuer,
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

test("a stored issuer's values pass, and make the same issuer", () => {
  assert.deepEqual(issuerFormErrors(values()), {});
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
  const read = issuerFormValues({
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
  });
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
  assert.deepEqual(issuerFormErrors({ ...read, rules: [] }), {});

  // Fresh direct setup: the credential is required with a url.
  const direct = values({
    keys_source: "TokenReview",
    review_url: "https://10.0.0.1:6443",
  });
  assert.deepEqual(Object.keys(issuerFormErrors(direct)), [
    "review_token",
  ]);
  assert.deepEqual(
    issuerFormErrors(values({ ...direct, review_token: "reviewer" })),
    {},
  );

  // Through a device: no url, credential or CA beside it.
  const device = values({
    keys_source: "TokenReview",
    review_device: "dev_123",
  });
  assert.deepEqual(issuerFormErrors(device), {});
  assert.deepEqual(
    Object.keys(
      issuerFormErrors(
        values({
          ...device,
          review_url: "https://10.0.0.1:6443",
          review_token: "reviewer",
          review_ca: "pem",
        }),
      ),
    ),
    ["review_device", "review_token", "review_ca"],
  );
  // Neither target is an error too.
  assert.deepEqual(
    Object.keys(issuerFormErrors(values({ keys_source: "TokenReview" }))),
    ["review_url"],
  );
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
  assert.deepEqual(issuerFormErrors(lingering), {});
  assert.deepEqual(trustedIssuer("i4", lingering).keys, {
    source: "TokenReview",
    params: { in_cluster: true },
  });
});

test("emptied number fields are errors, not 0", () => {
  const emptied = values({
    max_token_age_secs: "",
    rules: [{ ...values().rules[0], token_ttl_secs: "" }],
  });
  assert.deepEqual(Object.keys(issuerFormErrors(emptied)), [
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
  const errors = issuerFormErrors(
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
    issuerFormErrors(values({ keys_source: "Static", keys_static }))
      .keys_static;
  assert.equal(keys("{ not json"), "The static keys must be valid JSON");
  assert.match(keys('{ "kid": "a" }') ?? "", /must be a key set/);
  assert.equal(keys('{ "keys": [] }'), undefined);
  // Only the source in use is checked.
  assert.deepEqual(
    issuerFormErrors(values({ keys_source: "Discovery", keys_static: "x" })),
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
