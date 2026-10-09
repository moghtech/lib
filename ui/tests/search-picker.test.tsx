import { Button, Combobox } from "@mantine/core";
import { fireEvent, renderHook, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import {
  pickerTargetProps,
  SearchPicker,
  usePickFirst,
} from "../src/components/search-picker";
import { useSearchCombobox } from "../src/hooks";
import { renderWithProviders } from "./render";

const TAGS = ["prod", "staging", "dev"];

function TagPicker({
  onPick,
  clearable,
}: {
  onPick: (tag: string) => void;
  clearable?: boolean;
}) {
  const picker = useSearchCombobox();
  const [picked, setPicked] = useState<string>();
  const shown = TAGS.filter((tag) => tag.includes(picker.search));
  return (
    <SearchPicker
      picker={picker}
      onOptionSubmit={(tag) => {
        setPicked(tag);
        onPick(tag);
        picker.combobox.closeDropdown();
      }}
      empty={shown.length === 0}
      emptyText="No tags."
      onClear={clearable ? () => setPicked(undefined) : undefined}
      canClear={!!picked}
      clearLabel="Clear the tag"
      target={
        <Button {...pickerTargetProps(picker.combobox)}>
          {picked ?? "Select tag"}
        </Button>
      }
    >
      {shown.map((tag) => (
        <Combobox.Option key={tag} value={tag}>
          {tag}
        </Combobox.Option>
      ))}
    </SearchPicker>
  );
}

describe("SearchPicker", () => {
  it("searches, picks, and says when nothing matches", () => {
    const onPick = vi.fn();
    renderWithProviders(<TagPicker onPick={onPick} />);
    fireEvent.click(screen.getByRole("button", { name: "Select tag" }));
    const search = screen.getByRole("textbox", { name: "Search" });
    fireEvent.change(search, { target: { value: "sta" } });
    expect(screen.getAllByRole("option").map((o) => o.textContent)).toEqual([
      "staging",
    ]);
    fireEvent.click(screen.getByRole("option", { name: "staging" }));
    expect(onPick).toHaveBeenCalledWith("staging");
    screen.getByRole("button", { name: "staging" });

    fireEvent.click(screen.getByRole("button", { name: "staging" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search" }), {
      target: { value: "nope" },
    });
    screen.getByText("No tags.");
  });

  it("clears with a named button of its own, next to the target", () => {
    renderWithProviders(<TagPicker onPick={() => {}} clearable />);
    const clear = screen.getByRole("button", { name: "Clear the tag" });
    expect(clear.hasAttribute("disabled")).toBe(true);
    const target = screen.getByRole("button", { name: "Select tag" });
    // Not nested in the target: a button inside a button is invalid.
    expect(target.contains(clear)).toBe(false);

    fireEvent.click(target);
    fireEvent.click(screen.getByRole("option", { name: "dev" }));
    fireEvent.click(screen.getByRole("button", { name: "Clear the tag" }));
    screen.getByRole("button", { name: "Select tag" });
  });
});

describe("usePickFirst", () => {
  it("picks the first option once loaded, while nothing is picked", () => {
    const onSelect = vi.fn();
    const { rerender } = renderHook(
      ({ first }: { first?: string }) =>
        usePickFirst(first, undefined, onSelect, false),
      { initialProps: { first: undefined as string | undefined } },
    );
    expect(onSelect).not.toHaveBeenCalled();
    rerender({ first: "prod" });
    expect(onSelect).toHaveBeenCalledWith("prod");
  });

  it("not when something is picked, or nothing is a choice", () => {
    const onSelect = vi.fn();
    renderHook(() => usePickFirst("prod", "dev", onSelect, false));
    renderHook(() => usePickFirst("prod", undefined, onSelect, true));
    expect(onSelect).not.toHaveBeenCalled();
  });
});
