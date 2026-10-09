import type * as MoghAuth from "mogh_auth_client";

// The values a provider's page edits, the checks the server would
// refuse them for, and the update request they make. Plain functions,
// apart from the page (`LoginProviderConfig`) which renders the fields.

type ListItem = MoghAuth.Types.ExternalLoginProviderListItem;
type ProviderConfig = MoghAuth.Types.ExternalLoginProviderConfig;
type ProviderKind = ProviderConfig["kind"];

/** Flat form values covering every kind of provider. */
export interface ProviderFormValues {
  name: string;
  /** Names the provider in its urls. Empty keeps the stored one. */
  slug: string;
  registration_disabled: boolean;
  enabled: boolean;
  client_id: string;
  /** Left empty, the stored secret is kept. */
  client_secret: string;
  /** Remove the stored secret. Not part of the provider config. */
  clear_client_secret: boolean;
  // Token exchange
  token_exchange_enabled: boolean;
  token_exchange_audiences: string[];
  /**
   * 0 for no limit. `""` while the field is emptied, which is no
   * value to save (`providerFormErrors`), rather than 0: no limit at
   * all is the loosest setting.
   */
  token_exchange_max_age_secs: number | "";
  // OIDC
  provider: string;
  redirect_host: string;
  use_full_email: boolean;
  auto_redirect: boolean;
  additional_audiences: string[];
  additional_scopes: string[];
  groups_claim: string;
  allowed_groups: string[];
  admin_groups: string[];
}

/** The values of a stored provider. */
export function providerFormValues(item: ListItem): ProviderFormValues {
  const { kind, params } = item.provider.config;
  const oidc = kind === "Oidc" ? params : undefined;
  return {
    name: item.provider.name,
    slug: item.provider.slug ?? "",
    registration_disabled: item.provider.registration_disabled ?? false,
    enabled: params.enabled ?? false,
    client_id: params.client_id ?? "",
    // The secret is never sent to the client.
    client_secret: "",
    clear_client_secret: false,
    token_exchange_enabled: item.provider.token_exchange?.enabled ?? false,
    token_exchange_audiences: item.provider.token_exchange?.audiences ?? [],
    token_exchange_max_age_secs:
      item.provider.token_exchange?.max_token_age_secs ?? 0,
    provider: oidc?.provider ?? "",
    redirect_host: oidc?.redirect_host ?? "",
    use_full_email: oidc?.use_full_email ?? false,
    auto_redirect: oidc?.auto_redirect ?? false,
    additional_audiences: oidc?.additional_audiences ?? [],
    additional_scopes: oidc?.additional_scopes ?? [],
    groups_claim: oidc?.groups_claim ?? "",
    allowed_groups: oidc?.allowed_groups ?? [],
    admin_groups: oidc?.admin_groups ?? [],
  };
}

/** The provider config of `kind` the values make. */
export function providerConfig(
  kind: ProviderKind,
  values: ProviderFormValues,
): ProviderConfig {
  const named = {
    enabled: values.enabled,
    client_id: values.client_id.trim(),
    client_secret: values.clear_client_secret ? "" : values.client_secret,
  };
  if (kind !== "Oidc") {
    return { kind, params: named } as ProviderConfig;
  }
  return {
    kind: "Oidc",
    params: {
      ...named,
      provider: values.provider.trim(),
      redirect_host: values.redirect_host.trim(),
      use_full_email: values.use_full_email,
      auto_redirect: values.auto_redirect,
      additional_audiences: values.additional_audiences,
      additional_scopes: values.additional_scopes,
      groups_claim: values.groups_claim.trim(),
      allowed_groups: values.allowed_groups,
      admin_groups: values.admin_groups,
    },
  };
}

export function validHttpUrl(value: string) {
  try {
    return ["http:", "https:"].includes(new URL(value).protocol);
  } catch {
    return false;
  }
}

/** Whether `value` is a whole number of seconds (0 included). */
export function isWholeSeconds(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

/** What the server would refuse, by field, checked before a save. */
export function providerFormErrors(
  item: ListItem,
  values: ProviderFormValues,
): Partial<Record<keyof ProviderFormValues, string>> {
  const kind = item.provider.config.kind;
  const hasSecret = !!item.provider.config.params.client_secret;
  const existingProviderUrl =
    item.provider.config.kind === "Oidc"
      ? (item.provider.config.params.provider ?? "")
      : "";
  const errors: Partial<Record<keyof ProviderFormValues, string>> = {};
  if (!values.name.trim().length) {
    errors.name = "Name cannot be empty";
  }
  const slug = values.slug.trim();
  if (slug.length && !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug)) {
    errors.slug =
      "Only lowercase letters, digits and single hyphens between them";
  } else if (slug.length > 64) {
    errors.slug = "At most 64 characters";
  }
  if (
    kind === "Oidc" &&
    values.provider.trim().length &&
    !validHttpUrl(values.provider.trim())
  ) {
    errors.provider = "Must be an http(s) URL";
  }
  if (
    kind === "Oidc" &&
    values.redirect_host.trim().length &&
    !validHttpUrl(values.redirect_host.trim())
  ) {
    errors.redirect_host = "Must be an http(s) URL";
  }
  if (!values.clear_client_secret) {
    // The server won't send the stored secret to another address
    if (
      kind === "Oidc" &&
      hasSecret &&
      !values.client_secret.length &&
      values.provider.trim() !== existingProviderUrl
    ) {
      errors.client_secret =
        "Enter the client secret again when changing the provider URL";
    }
    // Only OIDC works without a secret (public clients using PKCE)
    if (
      kind !== "Oidc" &&
      values.enabled &&
      !hasSecret &&
      !values.client_secret.length
    ) {
      errors.client_secret =
        "A client secret is required to enable this provider";
    }
  }
  if (!isWholeSeconds(values.token_exchange_max_age_secs)) {
    errors.token_exchange_max_age_secs =
      "Must be a whole number of seconds, 0 for no limit";
  }
  if (values.clear_client_secret && kind !== "Oidc" && values.enabled) {
    errors.clear_client_secret =
      "Disable the provider to remove its secret, it can't work without one";
  }
  return errors;
}

/**
 * The update request a provider's values make. Check the values with
 * `providerFormErrors` first: an emptied maximum token age throws.
 */
export function providerUpdate(
  item: ListItem,
  values: ProviderFormValues,
): MoghAuth.Types.UpdateExternalLoginProvider {
  const kind = item.provider.config.kind;
  const max_token_age_secs = values.token_exchange_max_age_secs;
  if (!isWholeSeconds(max_token_age_secs)) {
    // Never sent as 0: that would be no limit at all.
    throw new Error("The maximum token age is no whole number of seconds");
  }
  return {
    id: item.provider.id,
    name: values.name.trim(),
    slug: values.slug.trim(),
    registration_disabled: values.registration_disabled,
    // Github has no signed tokens to exchange
    token_exchange: {
      enabled: kind !== "Github" && values.token_exchange_enabled,
      audiences: values.token_exchange_audiences,
      max_token_age_secs,
    },
    config: providerConfig(kind, values),
    clear_client_secret: values.clear_client_secret,
  };
}
