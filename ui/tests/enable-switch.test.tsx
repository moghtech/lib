import { useForm, type UseFormReturnType } from "@mantine/form";
import { fireEvent, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { EnableSwitch } from "../src/components/enable-switch";
import { renderWithProviders } from "./render";

function Controlled({
  onSubmit,
  toggleOnEnter,
}: {
  onSubmit: () => void;
  toggleOnEnter?: boolean;
}) {
  const [admin, setAdmin] = useState(false);
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
    >
      <EnableSwitch
        label="Admin"
        checked={admin}
        onCheckedChange={setAdmin}
        toggleOnEnter={toggleOnEnter}
      />
    </form>
  );
}

const adminSwitch = () =>
  screen.getByRole("switch", { name: /Admin/ }) as HTMLInputElement;

describe("EnableSwitch toggleOnEnter", () => {
  it("toggles on Enter through its own change, instead of submitting", () => {
    const onSubmit = vi.fn();
    renderWithProviders(<Controlled onSubmit={onSubmit} toggleOnEnter />);
    // fireEvent returns false when the default (the submit) was prevented.
    expect(fireEvent.keyDown(adminSwitch(), { key: "Enter" })).toBe(false);
    expect(adminSwitch().checked).toBe(true);
    screen.getByText("Enabled");
    fireEvent.keyDown(adminSwitch(), { key: "Enter" });
    expect(adminSwitch().checked).toBe(false);
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("toggles once per press: a held Enter repeats", () => {
    renderWithProviders(<Controlled onSubmit={() => {}} toggleOnEnter />);
    fireEvent.keyDown(adminSwitch(), { key: "Enter" });
    expect(
      fireEvent.keyDown(adminSwitch(), { key: "Enter", repeat: true }),
    ).toBe(false);
    expect(adminSwitch().checked).toBe(true);
  });

  it("toggles a field of an uncontrolled form (its getInputProps)", () => {
    let form!: UseFormReturnType<{ admin: boolean }>;
    function Uncontrolled() {
      form = useForm({ mode: "uncontrolled", initialValues: { admin: false } });
      return (
        <EnableSwitch
          label="Admin"
          {...form.getInputProps("admin", { type: "checkbox" })}
          key={form.key("admin")}
          toggleOnEnter
        />
      );
    }
    renderWithProviders(<Uncontrolled />);
    fireEvent.keyDown(adminSwitch(), { key: "Enter" });
    expect(form.getValues().admin).toBe(true);
    fireEvent.keyDown(adminSwitch(), { key: "Enter" });
    expect(form.getValues().admin).toBe(false);
  });

  it("leaves Enter alone without it, and other keys always", () => {
    renderWithProviders(<Controlled onSubmit={() => {}} />);
    expect(fireEvent.keyDown(adminSwitch(), { key: "Enter" })).toBe(true);
    expect(adminSwitch().checked).toBe(false);
    renderWithProviders(<Controlled onSubmit={() => {}} toggleOnEnter />);
    const [, other] = screen.getAllByRole("switch", { name: /Admin/ });
    expect(fireEvent.keyDown(other, { key: "a" })).toBe(true);
    expect((other as HTMLInputElement).checked).toBe(false);
  });
});
