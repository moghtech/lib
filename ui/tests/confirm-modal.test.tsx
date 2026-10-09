import {
  act,
  fireEvent,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConfirmModal } from "../src/components/confirm-modal";
import { renderWithProviders } from "./render";

/** A promise the test settles. */
function deferred() {
  let resolve!: () => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<void>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** The dialog's confirm button. */
const confirmButton = () =>
  within(screen.getByRole("dialog")).getByRole("button", {
    name: "Restart",
  }) as HTMLButtonElement;

describe("ConfirmModal", () => {
  it("runs one confirm at a time: a double click sends once", async () => {
    const run = deferred();
    const onConfirm = vi.fn(() => run.promise);
    renderWithProviders(
      <ConfirmModal confirmText="web" onConfirm={onConfirm}>
        Restart
      </ConfirmModal>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Restart" }));
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "web" },
    });
    const confirm = confirmButton();
    // In one tick: before React rendered the first click's state.
    act(() => {
      confirm.click();
      confirm.click();
    });
    expect(onConfirm).toHaveBeenCalledOnce();
    await act(async () => run.resolve());
  });

  it("controlled: opened by the caller, pending until the confirm settled", async () => {
    const run = deferred();
    const onConfirm = vi.fn(() => run.promise);
    const onClose = vi.fn();
    renderWithProviders(
      <ConfirmModal
        opened
        onClose={onClose}
        title="Group Execute - Restart"
        confirmText="Restart"
        confirmButtonContent="Restart"
        topAdditonal={<span>web, api</span>}
        onConfirm={onConfirm}
      />,
    );
    // No button of its own: the caller opens it (eg. from a menu item).
    screen.getByText("web, api");
    expect(screen.getAllByRole("button", { name: "Restart" })).toHaveLength(1);
    expect(confirmButton().disabled).toBe(true);
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "Restart" },
    });
    fireEvent.click(confirmButton());
    expect(onConfirm).toHaveBeenCalledOnce();
    // While it runs: the button waits, and the dialog stays.
    expect(confirmButton().disabled).toBe(true);
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Escape" });
    expect(onClose).not.toHaveBeenCalled();

    await act(async () => run.resolve());
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("stays open to retry a failed confirm", async () => {
    const onConfirm = vi.fn(() => Promise.reject(new Error("refused")));
    const onClose = vi.fn();
    renderWithProviders(
      <ConfirmModal
        opened
        onClose={onClose}
        confirmButtonContent="Restart"
        onConfirm={onConfirm}
      />,
    );
    fireEvent.click(confirmButton());
    await waitFor(() => expect(confirmButton().disabled).toBe(false));
    expect(onClose).not.toHaveBeenCalled();
    // Escape closes it again once nothing runs.
    fireEvent.keyDown(confirmButton(), { key: "Escape" });
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("without confirmText, the click alone confirms", () => {
    const onConfirm = vi.fn(async () => {});
    renderWithProviders(
      <ConfirmModal
        opened
        onClose={() => {}}
        confirmButtonContent="Restart"
        onConfirm={onConfirm}
      />,
    );
    expect(screen.queryByRole("textbox")).toBeNull();
    fireEvent.click(confirmButton());
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("starts every open with an empty input, controlled too", () => {
    const { rerender } = renderWithProviders(
      <ConfirmModal opened onClose={() => {}} confirmText="web">
        Restart
      </ConfirmModal>,
    );
    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "we" },
    });
    rerender(
      <ConfirmModal opened={false} onClose={() => {}} confirmText="web">
        Restart
      </ConfirmModal>,
    );
    rerender(
      <ConfirmModal opened onClose={() => {}} confirmText="web">
        Restart
      </ConfirmModal>,
    );
    expect((screen.getByRole("textbox") as HTMLInputElement).value).toBe("");
  });
});
