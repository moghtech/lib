// Internal (not exported from the package): what a number input's
// change commits, see `ConfigNumberInput`.

/**
 * The number `input` (a NumberInput's change) commits: a complete
 * number in `min` .. `max`, a whole one unless `allowDecimal`, else
 * `undefined`. NumberInput passes a string for partial input ('' while
 * retyping, '-'), which is no number (`Number("")` would be 0), and for
 * text it keeps as typed ('1.', '0.10', many digits), which is.
 */
export function committedNumber(
  input: number | string,
  {
    min,
    max,
    allowDecimal = true,
  }: { min?: number; max?: number; allowDecimal?: boolean },
): number | undefined {
  const number =
    typeof input === "number"
      ? input
      : input.trim() === ""
        ? NaN
        : Number(input);
  if (!Number.isFinite(number)) return undefined;
  // Past 2^53 a whole number isn't exact any more.
  if (!allowDecimal && !Number.isSafeInteger(number)) return undefined;
  if (min !== undefined && number < min) return undefined;
  if (max !== undefined && number > max) return undefined;
  return number;
}
