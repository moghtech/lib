// Internal (not exported from the package): the stat components' rule
// for a value which isn't known.

/** `value` when it is a finite number, else `undefined`. */
export function knownNumber(value: number | undefined) {
  return value !== undefined && Number.isFinite(value) ? value : undefined;
}
