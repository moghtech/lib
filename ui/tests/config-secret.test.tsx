import { fireEvent, screen, within } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { Config } from "../src/components/config";
import { renderWithProviders } from "./render";

// The dialog's diff editor (Monaco) isn't what this test looks at.
vi.mock("../src/components/monaco", () => ({
  MonacoDiffEditor: () => null,
  MonacoEditor: () => null,
}));

type Repo = { webhook_secret: string; branch: string };

function RepoConfig({ original }: { original: Repo }) {
  const [update, setUpdate] = useState<Partial<Repo>>({});
  return (
    <Config<Repo>
      original={original}
      update={update}
      setUpdate={setUpdate}
      disabled={false}
      onSave={async () => {}}
      disableSidebar
      groups={{
        "": [
          {
            label: "Webhook",
            fields: {
              webhook_secret: {
                secret: true,
                description: "The secret webhooks are signed with.",
              },
              branch: true,
            },
          },
        ],
      }}
    />
  );
}

describe("Config secret fields", () => {
  it("mask the value, and the confirm dialog doesn't print it", () => {
    renderWithProviders(
      <RepoConfig original={{ webhook_secret: "S_old", branch: "main" }} />,
    );
    const input = screen.getByLabelText("Webhook Secret") as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(input.value).toBe("S_old");
    // Other strings are plain text inputs.
    expect(
      (screen.getByRole("textbox", { name: "Branch" }) as HTMLInputElement)
        .value,
    ).toBe("main");

    fireEvent.change(input, { target: { value: "S_new" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Save" })[0]);
    const dialog = screen.getByRole("dialog");
    within(dialog).getByText("Webhook Secret");
    expect(within(dialog).getAllByText("••••••••")).toHaveLength(2);
    expect(within(dialog).queryByText("S_old")).toBeNull();
    expect(within(dialog).queryByText("S_new")).toBeNull();
  });

  it("an unset secret is a masked input too", () => {
    renderWithProviders(
      <RepoConfig
        original={{ webhook_secret: undefined as never, branch: "main" }}
      />,
    );
    expect(
      (screen.getByLabelText("Webhook Secret") as HTMLInputElement).type,
    ).toBe("password");
  });
});
