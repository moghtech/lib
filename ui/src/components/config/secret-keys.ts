/**
 * A field holding a secret (a credential being set): the confirm
 * dialog shows that it changes, never its value. As an object with
 * `stored` for a secret the draft can't show (the api never returns
 * it, so the draft starts empty): whether one is stored, which the
 * dialog shows as its previous value.
 */
export type SecretKey<T> = keyof T | { key: keyof T; stored: boolean };

/** The `SecretKey` entry of `key` in `secretKeys`, if any. */
export function secretKeyOf<T>(
  secretKeys: SecretKey<T>[] | undefined,
  key: keyof T,
): SecretKey<T> | undefined {
  return secretKeys?.find((secret) =>
    typeof secret === "object" ? secret.key === key : secret === key,
  );
}

/**
 * Whether a secret was set before the change, as the confirm dialog
 * shows it: what its `stored` says, else whether the draft's original
 * value is set.
 */
export function secretWasSet<T>(
  secret: SecretKey<T>,
  previous: T,
  key: keyof T,
): boolean {
  return typeof secret === "object" ? secret.stored : !!previous[key];
}
