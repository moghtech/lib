import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { CidrWhitelistCell } from "../src/components/cidr-whitelist-input";
import { renderWithProviders } from "./render";

/** Opens the editor, adds `entry` and saves. */
async function save(entry: string) {
  fireEvent.click(screen.getByRole("button", { name: /All ips/ }));
  const input = await screen.findByPlaceholderText("All ips allowed");
  fireEvent.change(input, { target: { value: entry } });
  fireEvent.keyDown(input, { key: "Enter" });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
}

describe("CidrWhitelistCell", () => {
  it("keeps the editor open when the save is refused", async () => {
    const onSave = vi.fn(() => Promise.reject({ status: 400 }));
    renderWithProviders(<CidrWhitelistCell value={[]} onSave={onSave} />);
    await save("10.0.0.300/8");
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(["10.0.0.300/8"]));
    // The list is still there to fix.
    await waitFor(() =>
      expect(
        (screen.getByRole("button", { name: "Save" }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    expect(screen.getByText("10.0.0.300/8")).toBeTruthy();
  });

  it("closes once the save went through", async () => {
    const onSave = vi.fn(() => Promise.resolve());
    renderWithProviders(<CidrWhitelistCell value={[]} onSave={onSave} />);
    await save("10.0.0.0/8");
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Save" })).toBeNull(),
    );
  });

  it("adds to a stored list, trimming the entries", async () => {
    const onSave = vi.fn(() => Promise.resolve());
    renderWithProviders(
      <CidrWhitelistCell value={["10.0.0.0/8"]} onSave={onSave} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /10\.0\.0\.0\/8/ }));
    const input = await screen.findByPlaceholderText("Add ip or CIDR");
    fireEvent.change(input, { target: { value: " 192.168.1.1 " } });
    fireEvent.keyDown(input, { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith(["10.0.0.0/8", "192.168.1.1"]),
    );
  });
});
