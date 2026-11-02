import type * as MoghAuth from "mogh_auth_client";

// The values a trusted issuer's page edits, the checks the server
// would refuse them for, and the issuer they make. Plain functions,
// apart from the page (`TrustedIssuerConfig`) which renders the fields.

type TrustedIssuer = MoghAuth.Types.TrustedIssuer;
type KeysSource = MoghAuth.Types.TrustedIssuerKeys["source"];

export interface RuleFormValues {
  /** Empty for rules which don't exist yet. */
  id: string;
  name: string;
  enabled: boolean;
  claims: { claim: string; pattern: string }[];
  groups: string[];
  admin: boolean;
  /** `""` while the field is emptied, which is no value to save. */
  token_ttl_secs: number | "";
}

export interface IssuerFormValues {
  name: string;
  enabled: boolean;
  issuer: string;
  keys_source: KeysSource;
  /** The url / key set json, depending on the source. */
  keys_url: string;
  keys_static: string;
  /** The cluster api server url of a TokenReview source. */
  review_url: string;
  /** The PEM bundle the api server's certificate is verified against. */
  review_ca: string;
  /**
   * The reviewer credential to store. Always starts empty: an empty
   * save keeps the stored one (`review_token_stored` says whether one
   * is stored, the server redacts it).
   */
  review_token: string;
  review_token_stored: boolean;
  /** The device (periphery) a TokenReview source reviews through. */
  review_device: string;
  /**
   * Review with the cluster the app itself runs in: its own service
   * account posts the reviews, nothing is stored. The other review
   * fields are hidden and left out of the save while this is on.
   */
  review_in_cluster: boolean;
  audiences: string[];
  /**
   * 0 for no limit. `""` while the field is emptied, which is no value
   * to save (`issuerFormErrors`), rather than 0: no limit at all is the
   * loosest setting.
   */
  max_token_age_secs: number | "";
  rules: RuleFormValues[];
}

export const KEYS_SOURCES: { value: KeysSource; label: string }[] = [
  { value: "Discovery", label: "Discovery" },
  { value: "JwksUri", label: "Keys URL" },
  { value: "Static", label: "Static keys" },
  { value: "TokenReview", label: "Token review" },
];

/** The redacted credential the server lists in place of a stored one. */
const REDACTED = "##############";

export const newRule = (): RuleFormValues => ({
  id: "",
  name: "",
  enabled: true,
  claims: [{ claim: "", pattern: "" }],
  groups: [],
  admin: false,
  // Workloads should get short lived tokens
  token_ttl_secs: 900,
});

/**
 * The values of a stored issuer. A field the server left out has its
 * default there (`#[serde(default)]`).
 */
export function issuerFormValues(issuer: TrustedIssuer): IssuerFormValues {
  const keys = issuer.keys;
  return {
    name: issuer.name,
    enabled: issuer.enabled ?? false,
    issuer: issuer.issuer,
    keys_source: keys?.source ?? "Discovery",
    keys_url: keys?.source === "JwksUri" ? keys.params : "",
    keys_static: keys?.source === "Static" ? keys.params : "",
    review_url:
      keys?.source === "TokenReview" ? (keys.params.url ?? "") : "",
    review_ca:
      keys?.source === "TokenReview" ? (keys.params.ca ?? "") : "",
    review_token: "",
    review_token_stored:
      keys?.source === "TokenReview" && !!keys.params.token,
    review_device:
      keys?.source === "TokenReview" ? (keys.params.device ?? "") : "",
    review_in_cluster:
      keys?.source === "TokenReview" && (keys.params.in_cluster ?? false),
    audiences: issuer.audiences ?? [],
    max_token_age_secs: issuer.max_token_age_secs ?? 0,
    rules: (issuer.rules ?? []).map((rule) => ({
      id: rule.id ?? "",
      name: rule.name,
      enabled: rule.enabled ?? false,
      claims: (rule.claims ?? []).map((c) => ({ ...c })),
      groups: rule.groups ?? [],
      admin: rule.admin ?? false,
      token_ttl_secs: rule.token_ttl_secs ?? 0,
    })),
  };
}

/**
 * The issuer the values make, with its `id`. Check the values with
 * `issuerFormErrors` first: an emptied number throws.
 */
export function trustedIssuer(
  id: string,
  values: IssuerFormValues,
): TrustedIssuer {
  const keys: MoghAuth.Types.TrustedIssuerKeys =
    values.keys_source === "JwksUri"
      ? { source: "JwksUri", params: values.keys_url.trim() }
      : values.keys_source === "Static"
        ? { source: "Static", params: values.keys_static }
        : values.keys_source === "TokenReview"
          ? {
              source: "TokenReview",
              // The other review fields are hidden while the app's
              // own cluster reviews: they are not sent either.
              params: values.review_in_cluster
                ? { in_cluster: true }
                : {
                    url: values.review_url.trim(),
                    ca: values.review_ca.trim(),
                    // Empty (or the redacted listing) keeps the stored one
                    token: values.review_token,
                    device: values.review_device.trim(),
                  },
            }
          : { source: "Discovery", params: {} };
  return {
    id,
    name: values.name.trim(),
    enabled: values.enabled,
    issuer: values.issuer.trim(),
    keys,
    audiences: values.audiences,
    max_token_age_secs: seconds(values.max_token_age_secs),
    rules: values.rules.map((rule) => ({
      ...rule,
      name: rule.name.trim(),
      claims: rule.claims.map(({ claim, pattern }) => ({
        claim: claim.trim(),
        pattern,
      })),
      token_ttl_secs: seconds(rule.token_ttl_secs),
    })),
  };
}

/** A whole number of seconds as sent, never an emptied field as 0. */
function seconds(value: number | ""): number {
  const problem = wholeSeconds(value);
  if (problem) throw new Error(problem);
  return value as number;
}

function validHttpUrl(value: string) {
  try {
    return ["http:", "https:"].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

/** Why `value` is no whole number of seconds (0 included), if it isn't. */
export const wholeSeconds = (value: unknown) =>
  typeof value === "number" && Number.isInteger(value) && value >= 0
    ? null
    : "Must be a whole number of seconds";

/**
 * What the server would refuse, checked before a save: by the path of
 * the field (`issuer`, `max_token_age_secs`, `rules.0.name`,
 * `rules.0.claims.1.pattern`, ...), each message readable on its own,
 * in the order of the fields.
 */
export function issuerFormErrors(
  values: IssuerFormValues,
): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!values.name.trim().length) errors.name = "Name cannot be empty";
  if (!validHttpUrl(values.issuer.trim())) {
    errors.issuer = "The issuer must be an http(s) URL";
  }
  if (
    values.keys_source === "JwksUri" &&
    !validHttpUrl(values.keys_url.trim())
  ) {
    errors.keys_url = "The keys URL must be an http(s) URL";
  }
  if (values.keys_source === "Static") {
    try {
      if (!Array.isArray(JSON.parse(values.keys_static).keys)) {
        errors.keys_static =
          'The static keys must be a key set: { "keys": [...] }';
      }
    } catch {
      errors.keys_static = "The static keys must be valid JSON";
    }
  }
  // With the app's own cluster reviewing, the other review fields
  // are hidden and not saved: nothing of theirs to check.
  if (values.keys_source === "TokenReview" && !values.review_in_cluster) {
    const url = values.review_url.trim();
    const device = values.review_device.trim();
    if (!url && !device) {
      errors.review_url =
        "A token review needs the cluster api server URL, a device to review through, or this cluster";
    } else if (url && device) {
      errors.review_device =
        "A token review goes to the URL or through the device, not both";
    }
    if (url && !validHttpUrl(url)) {
      errors.review_url = "The api server must be an http(s) URL";
    }
    if (
      url &&
      !values.review_token &&
      !values.review_token_stored
    ) {
      errors.review_token = "A reviewer credential is required with a URL";
    }
    if (values.review_token === REDACTED) {
      errors.review_token =
        "The redacted credential cannot be used as the credential";
    }
    if (device && values.review_token) {
      errors.review_token =
        "A device reviews with its own credentials: no credential here";
    }
    if (device && values.review_ca.trim()) {
      errors.review_ca =
        "A device reviews with its own cluster CA: no CA here";
    }
  }
  // What ties a token to this app
  if (!values.audiences.length) {
    errors.audiences = "At least one audience is required";
  }
  const age = wholeSeconds(values.max_token_age_secs);
  if (age)
    errors.max_token_age_secs = `Maximum token age: ${age.toLowerCase()}`;
  values.rules.forEach((rule, r) => {
    const name = rule.name.trim() || "(unnamed)";
    if (!rule.name.trim().length)
      errors[`rules.${r}.name`] = "A rule has no name";
    // A rule without claims would accept every token of the issuer
    if (!rule.claims.length) {
      errors[`rules.${r}.claims`] =
        `Rule '${name}' needs at least one claim to match`;
    }
    rule.claims.forEach(({ claim, pattern }, c) => {
      const at = `rules.${r}.claims.${c}`;
      if (!claim.trim().length) {
        errors[`${at}.claim`] = `Rule '${name}': a claim has no name`;
      }
      // The server refuses patterns which match anything
      if (!pattern.length) {
        errors[`${at}.pattern`] =
          `Rule '${name}': claim '${claim}' has no value`;
      } else if (/^\*+$/.test(pattern)) {
        errors[`${at}.pattern`] =
          `Rule '${name}': claim '${claim}' matches any value, which restricts nothing`;
      }
    });
    const ttl = wholeSeconds(rule.token_ttl_secs);
    if (ttl) {
      errors[`rules.${r}.token_ttl_secs`] =
        `Rule '${name}': token lifetime ${ttl.toLowerCase()}`;
    }
  });
  return errors;
}
