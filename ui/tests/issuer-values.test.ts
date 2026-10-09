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
      audiences: [],
      max_token_age_secs: 0,
      rules: [],
    },
  );
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
