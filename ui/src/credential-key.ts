// The credentials a user owns and manages from their profile page:
// api keys and signing keys, as the apps' records carry them. The
// rules and conversions `CredentialKeysTable` works with, without
// React: the node tests load this file directly.

/** A timestamp as the apps' records carry it: unix milliseconds, or
 * ISO 8601. */
export type Timestamp = string | number;

/** When a credential expires: a [Timestamp], or never (`0`, `null`,
 * `undefined`). */
export type Expiry = Timestamp | null | undefined;

/** The timestamp as unix milliseconds, `null` for none (`0`, `null`,
 * `undefined`, an empty string, or a string which isn't a date). */
export function timestampMs(value: Expiry): number | null {
  if (!value) return null;
  const ms = typeof value === "number" ? value : Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/** The expiry as unix milliseconds, `null` for never. */
export const expiryMs = timestampMs;

/** The longest api key / signing key name mogh_auth_server takes
 * (its `validate_api_key_name`). */
export const MAX_CREDENTIAL_NAME_LENGTH = 200;

/** The name rule of a new or renamed key, as the server checks it:
 * at most 200 characters, and (unless `required` is off, for an app
 * whose keys may go unnamed) not blank. `null` when the name
 * passes. */
export function credentialNameError(
  name: string,
  { required = true }: { required?: boolean } = {},
): string | null {
  if (required && !name.trim().length) return "Name cannot be empty";
  return name.length > MAX_CREDENTIAL_NAME_LENGTH
    ? `Name can be at most ${MAX_CREDENTIAL_NAME_LENGTH} characters`
    : null;
}

/** What the api key and signing key tables list: a credential a
 * user owns. `id` is what an update or delete names: the api key
 * itself, a signing key's public key, or a record id. */
export interface CredentialKey {
  id: string;
  /** May be empty, for an app whose keys go unnamed. */
  name: string;
  /** A disabled key is refused like an unknown one, until enabled
   * again. */
  enabled: boolean;
  expires_at?: Expiry;
  /** Source ips the key is accepted from. Empty: every ip. */
  cidr_whitelist?: string[];
  created_at: Timestamp;
  /** Missing or `0`: never updated (a record from before it was
   * kept). */
  updated_at?: Timestamp | null;
}

/** The update the table makes inline, one field at a time: the
 * name, the enabled switch, the source ips. */
export interface CredentialKeyUpdate {
  id: string;
  name?: string;
  enabled?: boolean;
  cidr_whitelist?: string[];
}

/** The ids of the table's sortable columns. An app sorting server
 * side names its request's sort keys here (`Types.ApiKeySortBy`),
 * which the table then reports through the DataTable's
 * `onSortingStateChange`. */
export interface CredentialKeySortBy {
  Name: string;
  Enabled: string;
  ExpiresAt: string;
  CreatedAt: string;
  UpdatedAt: string;
}

/** The column ids when the table sorts its rows itself. */
export const CREDENTIAL_KEY_SORT_BY: CredentialKeySortBy = {
  Name: "name",
  Enabled: "enabled",
  ExpiresAt: "expires_at",
  CreatedAt: "created_at",
  UpdatedAt: "updated_at",
};
