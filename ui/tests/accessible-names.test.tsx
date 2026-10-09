import { Modal } from "@mantine/core";
import { fireEvent, screen } from "@testing-library/react";
import { Box, X } from "lucide-react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { setAuthUrl } from "../src/auth/hooks";
import { TrustedIssuerPage } from "../src/auth/issuers/page";
import { AuthProfileSections } from "../src/auth/profile/sections";
import { ConfirmIcon } from "../src/components/confirm-icon";
import { DataTable } from "../src/components/data-table";
import { EntityHeader } from "../src/components/entity-header";
import { InputList } from "../src/components/input-list";
import { ListPagination } from "../src/components/list-pagination";
import { StatCell } from "../src/components/stat-cell";
import { ThemeToggle } from "../src/components/theme-toggle";
import { ThemeProvider } from "../src/theme";
import { renderWithProviders } from "./render";

// The page's diff editor (Monaco) isn't what these tests look at.
vi.mock("../src/components/monaco", () => ({
  MonacoDiffEditor: () => null,
  MonacoEditor: () => null,
}));

// The issuer list the page reads, set by a test.
const issuers = vi.hoisted(() => ({ data: [] as unknown[] }));
vi.mock("../src/auth/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/auth/hooks")>()),
  useTrustedIssuers: () => ({
    data: issuers.data,
    isPending: false,
    error: null,
  }),
}));

describe("mogh_ui's icon-only buttons have names", () => {
  it("EntityHeader: rename, its input, save and cancel", () => {
    renderWithProviders(
      <EntityHeader
        name="prod"
        icon={Box}
        intent="Good"
        onRename={async () => {}}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    screen.getByRole("textbox", { name: "Name" });
    screen.getByRole("button", { name: "Save name" });
    fireEvent.click(screen.getByRole("button", { name: "Cancel rename" }));
    screen.getByRole("button", { name: "Rename" });
  });

  it("InputList: remove, by value or position", () => {
    renderWithProviders(
      <InputList<{ args: string[] }>
        field="args"
        values={["--quiet", ""]}
        disabled={false}
        set={() => {}}
      />,
    );
    screen.getByRole("button", { name: "Remove --quiet" });
    screen.getByRole("button", { name: "Remove item 2" });
  });

  it("StatCell: the details", () => {
    renderWithProviders(
      <StatCell value={42} intent="Good" info="4 of 8 cores" />,
    );
    screen.getByRole("button", { name: "Details" });
  });

  it("ConfirmIcon: its label, then confirming it", () => {
    const onClick = vi.fn();
    renderWithProviders(
      <ConfirmIcon label="Remove from group" onClick={onClick}>
        <X size="1rem" />
      </ConfirmIcon>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Remove from group" }));
    expect(onClick).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm: Remove from group" }),
    );
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("ListPagination: first, previous, next", () => {
    renderWithProviders(
      <ListPagination page={1} setPage={() => {}} count={10} pageSize={10} />,
    );
    screen.getByRole("button", { name: "First page" });
    screen.getByRole("button", { name: "Previous page" });
    screen.getByRole("button", { name: "Next page" });
  });

  it("ThemeToggle", () => {
    renderWithProviders(<ThemeToggle />);
    screen.getByRole("button", { name: "Color scheme" });
  });

  it("DataTable: the select all checkbox", () => {
    renderWithProviders(
      <DataTable
        tableKey="names-test"
        data={[{ id: "a" }, { id: "b" }]}
        columns={[{ header: "Id", accessorKey: "id" }]}
        selectOptions={{ selectKey: (row) => row.id }}
      />,
    );
    screen.getByRole("checkbox", { name: "Select all rows" });
    expect(
      screen.getAllByRole("checkbox", { name: "Select row" }),
    ).toHaveLength(2);
  });

  it("dialogs' close buttons (the theme of ThemeProvider)", async () => {
    renderWithProviders(
      <ThemeProvider>
        <Modal opened onClose={() => {}} title="Dialog">
          Content
        </Modal>
      </ThemeProvider>,
    );
    await screen.findByRole("button", { name: "Close" });
  });
});

describe("the auth pages' icon-only buttons have names", () => {
  beforeEach(() => setAuthUrl("http://auth.test"));

  it("AuthProfileSections: saving the username and the password", async () => {
    vi.stubGlobal("fetch", async () =>
      Response.json({
        local: true,
        registration_disabled: false,
        providers: [],
      }),
    );
    renderWithProviders(
      <AuthProfileSections
        user={{
          username: "max",
          passwordSet: true,
          totpEnrolled: false,
          passkeyEnrolled: false,
          externalSkip2fa: false,
          linkedLogins: [],
        }}
        refetchUser={() => {}}
      />,
    );
    screen.getByRole("button", { name: "Update Username" });
    await screen.findByRole("button", { name: "Update Password" });
  });

  it("TrustedIssuerPage: removing a rule and a claim", async () => {
    issuers.data = [
      {
        read_only: false,
        issuer: {
          id: "github",
          name: "GitHub Actions",
          enabled: true,
          issuer: "https://token.actions.githubusercontent.com",
          keys: { source: "Discovery", params: {} },
          audiences: ["mogh"],
          max_token_age_secs: 0,
          rules: [
            {
              id: "deploy",
              name: "deploy",
              enabled: true,
              claims: [{ claim: "repository_id", pattern: "42" }],
              groups: [],
            },
          ],
        },
      },
    ];
    renderWithProviders(<TrustedIssuerPage id="github" backTo="/" />);
    await screen.findByRole("button", { name: "Remove rule" });
    screen.getByRole("button", { name: "Remove claim" });
    screen.getByRole("button", { name: "Rename" });
  });
});
