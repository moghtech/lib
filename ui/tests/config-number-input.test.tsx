import { fireEvent, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { ConfigNumberInput } from "../src/components/config";
import { committedNumber } from "../src/components/config/number-commit";
import { renderWithProviders } from "./render";

describe("committedNumber", () => {
  it("commits complete numbers in range, whole ones unless decimals are allowed", () => {
    const whole = { min: 0, max: 2_147_483_647, allowDecimal: false };
    expect(committedNumber(30, whole)).toBe(30);
    expect(committedNumber(0, whole)).toBe(0);
    // Partial input is a string ('' while retyping, '-'): no number.
    expect(committedNumber("", whole)).toBeUndefined();
    expect(committedNumber("-", whole)).toBeUndefined();
    expect(committedNumber(1.5, whole)).toBeUndefined();
    expect(committedNumber(-1, whole)).toBeUndefined();
    expect(committedNumber(2_147_483_648, whole)).toBeUndefined();
    // Past 2^53 a whole number isn't exact any more.
    expect(
      committedNumber("90071992547409930", { allowDecimal: false }),
    ).toBeUndefined();

    const any = { allowDecimal: true };
    expect(committedNumber(1.5, any)).toBe(1.5);
    // Text NumberInput keeps as typed.
    expect(committedNumber("0.10", any)).toBe(0.1);
    expect(committedNumber("1.", any)).toBe(1);
    expect(committedNumber(" ", any)).toBeUndefined();
    expect(committedNumber(NaN, any)).toBeUndefined();
  });
});

function Field({
  initial,
  onValueChange,
  ...props
}: {
  initial: number | undefined;
  onValueChange: (value: number) => void;
  min?: number;
  max?: number;
  allowDecimal?: boolean;
}) {
  const [value, setValue] = useState(initial);
  return (
    <ConfigNumberInput
      aria-label="Timeout"
      value={value}
      onValueChange={(v) => {
        onValueChange(v);
        setValue(v);
      }}
      rightSection="seconds"
      {...props}
    />
  );
}

const input = () =>
  screen.getByRole("textbox", { name: "Timeout" }) as HTMLInputElement;

describe("ConfigNumberInput", () => {
  it("commits a typed number, not partial input, and shows the stored value on blur", () => {
    const onValueChange = vi.fn();
    renderWithProviders(<Field initial={30} onValueChange={onValueChange} />);
    screen.getByText("seconds");
    fireEvent.change(input(), { target: { value: "" } });
    expect(onValueChange).not.toHaveBeenCalled();
    fireEvent.blur(input());
    expect(input().value).toBe("30");

    fireEvent.change(input(), { target: { value: "45" } });
    expect(onValueChange).toHaveBeenLastCalledWith(45);
  });

  it("writes nothing on a focus and blur alone, or for the same number", () => {
    const onValueChange = vi.fn();
    renderWithProviders(<Field initial={30} onValueChange={onValueChange} />);
    fireEvent.focus(input());
    fireEvent.blur(input());
    fireEvent.change(input(), { target: { value: "30" } });
    expect(onValueChange).not.toHaveBeenCalled();
  });

  it("keeps whole numbers in min .. max", () => {
    const onValueChange = vi.fn();
    renderWithProviders(
      <Field
        initial={30}
        onValueChange={onValueChange}
        min={0}
        max={100}
        allowDecimal={false}
      />,
    );
    fireEvent.change(input(), { target: { value: "-5" } });
    fireEvent.change(input(), { target: { value: "500" } });
    for (const [value] of onValueChange.mock.calls) {
      expect(Number.isInteger(value) && value >= 0 && value <= 100).toBe(true);
    }
    fireEvent.change(input(), { target: { value: "60" } });
    expect(onValueChange).toHaveBeenLastCalledWith(60);
  });
});
