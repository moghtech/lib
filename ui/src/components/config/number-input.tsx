import { NumberInput, NumberInputProps } from "@mantine/core";
import { useState } from "react";
import { committedNumber } from "./number-commit";

export interface ConfigNumberInputProps extends Omit<
  NumberInputProps,
  | "value"
  | "onChange"
  | "onValueChange"
  | "min"
  | "max"
  | "allowDecimal"
  | "allowNegative"
> {
  value: number | undefined;
  /**
   * Called with a complete number in `min` .. `max` (a whole one unless
   * `allowDecimal`), and only when it differs from `value`.
   */
  onValueChange: (value: number) => void;
  /** Default: no bound. Negative numbers can be typed only below 0. */
  min?: number;
  /** Default: no bound. */
  max?: number;
  /** Default: true. */
  allowDecimal?: boolean;
}

/**
 * A config's number input. Only a complete number in range reaches
 * `onValueChange`: partial input ('' or '-') stays in the input
 * instead of becoming 0, and nothing is written for a focus / blur
 * alone or the same number (which would mark the config changed). On
 * blur, the input shows the stored value again, so it never disagrees
 * with what Save sends. With `min` / `max` a number out of range can't
 * be typed. Takes NumberInput's other props (`rightSection` for a
 * unit, its accessible name as `aria-label`: a `ConfigItem`'s label is
 * no `<label>`).
 */
export function ConfigNumberInput({
  value,
  onValueChange,
  min,
  max,
  allowDecimal = true,
  onBlur,
  ...props
}: ConfigNumberInputProps) {
  // The text while it isn't the stored number. NumberInput passes
  // strings for partial input, and for text it keeps as typed
  // ('1.', '0.10', 14+ digits).
  const [draft, setDraft] = useState<string>();
  return (
    <NumberInput
      w={{ base: "85%", lg: 400 }}
      {...props}
      value={draft ?? value ?? ""}
      onChange={(input) => {
        setDraft(typeof input === "string" ? input : undefined);
        const number = committedNumber(input, { min, max, allowDecimal });
        if (number !== undefined && number !== value) onValueChange(number);
      }}
      onBlur={(e) => {
        setDraft(undefined);
        onBlur?.(e);
      }}
      min={min}
      max={max}
      allowDecimal={allowDecimal}
      allowNegative={min === undefined || min < 0}
      clampBehavior={
        min === undefined && max === undefined ? undefined : "strict"
      }
    />
  );
}
