import { QueryClient } from "@tanstack/react-query";
import { fireEvent, screen } from "@testing-library/react";
import type { Types } from "mogh_supporter";
import { describe, expect, it, vi } from "vitest";
import { SupporterKeyConfig } from "../src/supporter";
import { renderWithProviders } from "./render";

// The confirm dialog's diff editor (Monaco) isn't what this test
// looks at.
vi.mock("../src/components/monaco", () => ({
  MonacoDiffEditor: () => null,
  MonacoEditor: () => null,
}));

const organization: Types.SupporterKeyInfo = {
  source: "Stored",
  config_key: false,
  supporter: {
    version: 1,
    root_key_id: "00",
    id: "00000000-0000-0000-0000-000000000000",
    app: "cicada",
    name: "Acme Corp",
    tier: "organization",
    since: "2026-01-01",
    covers: "2027-01-01",
  },
};

/**
 * The settings of an organization's key, without branding yet: the
 * answers in the query client (without a login the queries don't run).
 */
function renderBranding() {
  const client = new QueryClient();
  client.setQueryData(["GetSupporterKeyInfo"], organization);
  client.setQueryData(["GetSupporterBranding"], {});
  renderWithProviders(<SupporterKeyConfig />, client);
  return screen.getByRole("textbox", { name: "Icon" }) as HTMLInputElement;
}

describe("SupporterKeyConfig's branding", () => {
  // The uploaded images are looked up by the text typed: names of
  // Object.prototype's members are icon text like any other.
  it.each(["constructor", "toString", "__proto__", "hasOwnProperty"])(
    "takes %s as icon text",
    (text) => {
      const icon = renderBranding();
      fireEvent.change(icon, { target: { value: text } });
      const typed = screen.getByRole("textbox", {
        name: "Icon",
      }) as HTMLInputElement;
      expect(typed.value).toBe(text);
      // Text, not an upload: it stays editable.
      expect(typed.disabled).toBe(false);
    },
  );
});
