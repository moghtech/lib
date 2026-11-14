import { act, fireEvent, screen } from "@testing-library/react";
import { X } from "lucide-react";
import { describe, expect, it, vi } from "vitest";
import { ConfirmButton } from "../src/components/confirm-button";
import { ConfirmIcon } from "../src/components/confirm-icon";
import { renderWithProviders } from "./render";

/**
 * Clicks `button` twice in one tick, before React renders what the
 * first click changed (eg. a double click landing on the confirm).
 */
function clickTwiceInOneTick(button: HTMLElement) {
  act(() => {
    button.click();
    button.click();
  });
}

describe("ConfirmButton", () => {
  it("runs onClick once for a click in the same tick as the confirming one", () => {
    const onClick = vi.fn();
    renderWithProviders(
      <ConfirmButton onClick={onClick}>Delete</ConfirmButton>,
    );
    const button = screen.getByRole("button", { name: "Delete" });
    fireEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
    clickTwiceInOneTick(button);
    expect(onClick).toHaveBeenCalledOnce();
    // Back to asking first.
    expect(button.textContent).toBe("Delete");
  });

  it("holds while an onClick returning a promise is in flight", async () => {
    let finish!: () => void;
    const onClick = vi.fn(
      () => new Promise<void>((resolve) => (finish = resolve)),
    );
    renderWithProviders(
      <ConfirmButton onClick={onClick}>Delete</ConfirmButton>,
    );
    const button = screen.getByRole("button", { name: "Delete" });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledOnce();
    // Asked and confirmed again while the first still runs.
    fireEvent.click(button);
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledOnce();
    await act(async () => finish());
    fireEvent.click(button);
    fireEvent.click(button);
    expect(onClick).toHaveBeenCalledTimes(2);
  });
});

describe("ConfirmIcon", () => {
  it("runs onClick once for a click in the same tick as the confirming one", () => {
    const onClick = vi.fn();
    renderWithProviders(
      <ConfirmIcon label="Remove" onClick={onClick}>
        <X size="1rem" />
      </ConfirmIcon>,
    );
    const button = screen.getByRole("button", { name: "Remove" });
    fireEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
    clickTwiceInOneTick(button);
    expect(onClick).toHaveBeenCalledOnce();
    expect(button.getAttribute("aria-label")).toBe("Remove");
  });
});
