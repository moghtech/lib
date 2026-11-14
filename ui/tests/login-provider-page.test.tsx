import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import type * as MoghAuth from "mogh_auth_client";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { setAuthUrl } from "../src/auth/hooks";
import { LoginProviderPage } from "../src/auth/providers/page";
import { answering, renderWithProviders } from "./render";

// The confirm dialog's diff editor (Monaco) isn't what these tests
// look at.
vi.mock("../src/components/monaco", () => ({
  MonacoDiffEditor: () => null,
  MonacoEditor: () => null,
}));

// The provider list the page reads, set by a test.
const providers = vi.hoisted(() => ({ data: [] as unknown[] }));
vi.mock("../src/auth/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/auth/hooks")>()),
  useExternalLoginProviders: () => ({
    data: providers.data,
    isPending: false,
    error: null,
  }),
}));

/** An OIDC provider making the members of "admins" admins. */
const item: MoghAuth.Types.ExternalLoginProviderListItem = {
  read_only: false,
  redirect_uri: "https://app.example.com/auth/external/idp/callback",
  provider: {
    id: "idp",
    name: "Company IdP",
    slug: "idp",
    registration_disabled: false,
    token_exchange: { enabled: false, audiences: [], max_token_age_secs: 300 },
    config: {
      kind: "Oidc",
      params: {
        enabled: true,
        client_id: "app",
        client_secret: "##############",
        provider: "https://idp.example.com",
        redirect_host: "",
        use_full_email: false,
        auto_redirect: false,
        additional_audiences: [],
        additional_scopes: [],
        groups_claim: "groups",
        allowed_groups: ["staff"],
        admin_groups: ["admins"],
      },
    },
  },
};

beforeEach(() => {
  setAuthUrl("http://auth.test");
  providers.data = [item];
});

describe("LoginProviderPage with adminGroups={false}", () => {
  it("offers no admin groups, and sends the stored ones back unchanged", async () => {
    renderWithProviders(
      <LoginProviderPage id="idp" backTo="/" adminGroups={false} />,
    );
    const clientId = await screen.findByRole("textbox", { name: "Client ID" });
    expect(screen.queryByRole("combobox", { name: "Admin Groups" })).toBeNull();
    screen.getByRole("combobox", { name: "Allowed Groups" });

    fireEvent.change(clientId, { target: { value: "app-2" } });
    const { fetch, requests } = answering(item);
    vi.stubGlobal("fetch", fetch);
    fireEvent.click(screen.getAllByRole("button", { name: "Save" })[0]);
    fireEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Save" }),
    );
    await waitFor(() => expect(requests).toHaveLength(1));
    expect(requests[0].url).toBe(
      "http://auth.test/manage/UpdateExternalLoginProvider",
    );
    const sent = requests[0].body as MoghAuth.Types.UpdateExternalLoginProvider;
    expect(sent.config).toEqual({
      kind: "Oidc",
      params: {
        ...item.provider.config.params,
        client_id: "app-2",
        // Empty keeps the stored secret.
        client_secret: "",
        admin_groups: ["admins"],
      },
    });
  });

  it("offers them by default", async () => {
    renderWithProviders(<LoginProviderPage id="idp" backTo="/" />);
    await screen.findByRole("combobox", { name: "Admin Groups" });
  });
});
