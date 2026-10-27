import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { CredentialKeysTable } from "../src/components/credential-keys-table";
import { type CredentialKey, credentialNameError } from "../src/credential-key";
import { renderWithProviders } from "./render";

const DAY_MS = 24 * 60 * 60 * 1000;

/** An app's record mapped into the table's shape, keeping its own
 * key field for the key column. */
type ApiKeyRow = CredentialKey & { key: string };

const KEYS: ApiKeyRow[] = [
  {
    id: "K-ci",
    key: "K-ci",
    name: "ci",
    enabled: true,
    // A minute past the 30 days: the test takes less to get there.
    expires_at: Date.now() + 30 * DAY_MS + 60_000,
    cidr_whitelist: ["10.0.0.0/8"],
    created_at: 1_760_000_000_000,
    updated_at: 1_760_000_000_000,
  },
  {
    id: "K-old",
    key: "K-old",
    name: "laptop",
    enabled: false,
    expires_at: Date.now() - DAY_MS,
    cidr_whitelist: [],
    created_at: 1_750_000_000_000,
    // A record from before the timestamp was kept.
    updated_at: 0,
  },
  {
    id: "K-unnamed",
    key: "K-unnamed",
    name: "",
    enabled: true,
    expires_at: 0,
    created_at: 1_740_000_000_000,
  },
];

function Table({
  update = vi.fn(async () => {}),
  onDelete = vi.fn(async () => {}),
  unnamed,
}: {
  update?: (update: unknown) => Promise<unknown>;
  onDelete?: (ids: string[]) => Promise<unknown>;
  /** The app lets keys go unnamed. */
  unnamed?: boolean;
}) {
  return (
    <CredentialKeysTable
      entity="Api Key"
      tableKey="test-api-keys"
      data={KEYS}
      keyColumn={{ header: "Key", id: "key", accessorKey: "key" }}
      nameError={
        unnamed
          ? (name) => credentialNameError(name, { required: false })
          : undefined
      }
      update={update}
      onDelete={onDelete}
    />
  );
}

const row = (name: string) => screen.getByText(name).closest("tr")!;

describe("CredentialKeysTable", () => {
  it("lists the keys with their status", () => {
    renderWithProviders(<Table />);
    const ci = row("ci");
    expect(within(ci).getByText("30 days")).toBeTruthy();
    expect(within(ci).getByText("10.0.0.0/8")).toBeTruthy();
    expect((within(ci).getByRole("switch") as HTMLInputElement).checked).toBe(
      true,
    );
    const laptop = row("laptop");
    expect(within(laptop).getByText("EXPIRED")).toBeTruthy();
    expect(within(laptop).getByText("All ips")).toBeTruthy();
    expect(
      (within(laptop).getByRole("switch") as HTMLInputElement).checked,
    ).toBe(false);
    // Never updated, never expires, no name.
    expect(within(laptop).getByText("—")).toBeTruthy();
    const unnamed = row("No name");
    expect(within(unnamed).getByText("Never")).toBeTruthy();
  });

  it("renames a key, by the name rule", async () => {
    const update = vi.fn(async () => {});
    renderWithProviders(<Table update={update} />);
    fireEvent.click(screen.getByRole("button", { name: "ci" }));
    const input = await screen.findByRole("textbox", { name: "Name" });
    // A blank name is refused before sending.
    fireEvent.change(input, { target: { value: "  " } });
    expect(await screen.findByText("Name cannot be empty")).toBeTruthy();
    fireEvent.keyDown(input, { key: "Enter" });
    expect(update).not.toHaveBeenCalled();

    fireEvent.change(input, { target: { value: "ci deploys" } });
    fireEvent.click(screen.getByTitle("Save name"));
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith({ id: "K-ci", name: "ci deploys" }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("textbox", { name: "Name" })).toBeNull(),
    );
  });

  it("keeps the rename open when it fails", async () => {
    const update = vi.fn(() => Promise.reject({ status: 400 }));
    renderWithProviders(<Table update={update} />);
    fireEvent.click(screen.getByRole("button", { name: "ci" }));
    const input = (await screen.findByRole("textbox", {
      name: "Name",
    })) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "taken" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(update).toHaveBeenCalled());
    await waitFor(() => expect(input.disabled).toBe(false));
    expect(input.value).toBe("taken");
  });

  it("names an unnamed key, where the app allows none", async () => {
    const update = vi.fn(async () => {});
    renderWithProviders(<Table update={update} unnamed />);
    fireEvent.click(screen.getByRole("button", { name: "No name" }));
    const input = await screen.findByRole("textbox", { name: "Name" });
    expect(screen.queryByText("Name cannot be empty")).toBeNull();
    fireEvent.change(input, { target: { value: "laptop 2" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith({
        id: "K-unnamed",
        name: "laptop 2",
      }),
    );
  });

  it("disables and enables a key", async () => {
    const update = vi.fn(async () => {});
    renderWithProviders(<Table update={update} />);
    fireEvent.click(within(row("ci")).getByRole("switch"));
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith({ id: "K-ci", enabled: false }),
    );
    fireEvent.click(within(row("laptop")).getByRole("switch"));
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith({ id: "K-old", enabled: true }),
    );
  });

  it("edits the source ips", async () => {
    const update = vi.fn(async () => {});
    renderWithProviders(<Table update={update} />);
    fireEvent.click(within(row("ci")).getByRole("button", { name: /10\.0/ }));
    const input = await screen.findByPlaceholderText("Add ip or CIDR");
    fireEvent.change(input, { target: { value: "192.168.1.1" } });
    fireEvent.keyDown(input, { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(update).toHaveBeenCalledWith({
        id: "K-ci",
        cidr_whitelist: ["10.0.0.0/8", "192.168.1.1"],
      }),
    );
  });

  it("deletes the selected keys after a confirm", async () => {
    const onDelete = vi.fn(async () => {});
    renderWithProviders(<Table onDelete={onDelete} />);
    const button = () =>
      screen.getByRole("button", { name: /^Delete/ }) as HTMLButtonElement;
    expect(button().disabled).toBe(true);
    fireEvent.click(within(row("ci")).getByRole("checkbox"));
    fireEvent.click(within(row("laptop")).getByRole("checkbox"));
    expect(button().textContent).toBe("Delete (2)");
    fireEvent.click(button());
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Delete 2 Api Keys")).toBeTruthy();
    expect(within(dialog).getByText("ci")).toBeTruthy();
    expect(within(dialog).getByText("laptop")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete (2)" }));
    await waitFor(() =>
      expect(onDelete).toHaveBeenCalledWith(["K-ci", "K-old"]),
    );
    // The selection is cleared once deleted.
    await waitFor(() => expect(button().disabled).toBe(true));
  });

  it("searches the keys by name", () => {
    renderWithProviders(<Table />);
    fireEvent.change(screen.getByPlaceholderText("search..."), {
      target: { value: "LAP" },
    });
    expect(screen.getByText("laptop")).toBeTruthy();
    expect(screen.queryByText("ci")).toBeNull();
    expect(screen.queryByText("No name")).toBeNull();
  });
});
