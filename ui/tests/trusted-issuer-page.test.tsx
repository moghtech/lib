import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import type * as MoghAuth from "mogh_auth_client";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { setAuthUrl } from "../src/auth/hooks";
import { TrustedIssuerPage } from "../src/auth/issuers/page";
import { answering, renderWithProviders } from "./render";

// The confirm dialog's diff editor (Monaco) isn't what these tests
// look at.
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

type Keys = MoghAuth.Types.TrustedIssuerKeys;

/** A managed issuer with `keys` and one rule, listed for the page. */
function storedIssuer(
  keys: Keys,
  rule: Partial<MoghAuth.Types.WorkloadRule> = {},
): MoghAuth.Types.TrustedIssuer {
  const issuer: MoghAuth.Types.TrustedIssuer = {
    id: "cluster",
    name: "Cluster",
    enabled: true,
    issuer: "https://kubernetes.default.svc.cluster.local",
    keys,
    audiences: ["https://app.example.com"],
    max_token_age_secs: 300,
    rules: [
      {
        id: "deploy",
        name: "Deploy",
        enabled: true,
        claims: [{ claim: "sub", pattern: "system:serviceaccount:ci:deploy" }],
        groups: [],
        admin: false,
        token_ttl_secs: 900,
        ...rule,
      },
    ],
  };
  issuers.data = [{ read_only: false, issuer }];
  return issuer;
}

const URL_REVIEW: Keys = {
  source: "TokenReview",
  params: {
    url: "https://10.0.0.1:6443",
    ca: "",
    token: "##############",
    device: "",
  },
};

const DEVICE_REVIEW: Keys = {
  source: "TokenReview",
  params: { url: "", ca: "", token: "", device: "dev_123" },
};

/** The options of the "Signing Keys" selector. */
function keysSources() {
  fireEvent.click(screen.getByRole("combobox", { name: "Signing Keys" }));
  return screen.getAllByRole("option").map((option) => option.textContent);
}

/** Types `value` into the input labelled `label`. */
function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

/** Opens the config's confirm dialog. */
function openConfirm() {
  fireEvent.click(screen.getAllByRole("button", { name: "Save" })[0]);
  return screen.getByRole("dialog");
}

/**
 * Saves through the confirm dialog (`dialog`, opened by `openConfirm`),
 * returning the issuer the update sent. `fetch` answers with `stored`.
 */
async function confirmSave(
  dialog: HTMLElement,
  stored: MoghAuth.Types.TrustedIssuer,
) {
  const { fetch, requests } = answering({ read_only: false, issuer: stored });
  vi.stubGlobal("fetch", fetch);
  fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
  await waitFor(() => expect(requests).toHaveLength(1));
  expect(requests[0].url).toBe("http://auth.test/manage/UpdateTrustedIssuer");
  return (requests[0].body as { issuer: MoghAuth.Types.TrustedIssuer }).issuer;
}

/** The text of the confirm dialog's line of `field`, if it lists it. */
function confirmLine(dialog: HTMLElement, field: string) {
  return within(dialog)
    .queryByText(field)
    ?.parentElement?.querySelector("pre")
    ?.textContent?.replace(/\s+/g, " ");
}

/** The review fields shown, by label. */
function reviewFields() {
  return [
    "API Server URL",
    "Reviewer Credential",
    "API Server CA",
    "Review Device",
  ].filter((label) => screen.queryByLabelText(label));
}

beforeEach(() => {
  setAuthUrl("http://auth.test");
  // A refused save is logged by the confirm dialog.
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("TrustedIssuerPage's token review", () => {
  it("offers the url and the app's own cluster by default, in the app's neutral words", async () => {
    storedIssuer(URL_REVIEW);
    renderWithProviders(<TrustedIssuerPage id="cluster" backTo="/" />);
    await screen.findByRole("textbox", { name: "API Server URL" });
    screen.getByRole("switch", { name: "Review with this cluster" });
    screen.getByLabelText("Reviewer Credential");
    expect(screen.queryByRole("textbox", { name: "Review Device" })).toBeNull();
    expect(document.body.textContent).not.toMatch(/cicada|periphery/i);
    expect(document.body.textContent).not.toMatch(/through a device/);
    expect(keysSources()).toContain("Token review");
  });

  it("adds the device field with { device: true }, in the app's words when given", async () => {
    storedIssuer(URL_REVIEW);
    const { unmount } = renderWithProviders(
      <TrustedIssuerPage
        id="cluster"
        backTo="/"
        tokenReview={{ device: true }}
      />,
    );
    const device = await screen.findByRole("textbox", {
      name: "Review Device",
    });
    expect(device.getAttribute("placeholder")).toBe("Device id");
    screen.getByText(/Leave empty to review through a device instead/);
    expect(screen.queryByTestId("review-device-not-offered")).toBeNull();
    unmount();

    renderWithProviders(
      <TrustedIssuerPage
        id="cluster"
        backTo="/"
        tokenReview={{
          device: true,
          deviceField: {
            label: "Review Agent",
            description: "The agent in the cluster which reviews the tokens.",
            placeholder: "agent_...",
          },
        }}
      />,
    );
    const agent = await screen.findByRole("textbox", { name: "Review Agent" });
    expect(agent.getAttribute("placeholder")).toBe("agent_...");
    screen.getByText("The agent in the cluster which reviews the tokens.");
  });

  it("isn't offered with tokenReview={false}", async () => {
    storedIssuer({ source: "Discovery", params: {} });
    renderWithProviders(
      <TrustedIssuerPage id="cluster" backTo="/" tokenReview={false} />,
    );
    await screen.findByRole("combobox", { name: "Signing Keys" });
    expect(keysSources()).toEqual(["Discovery", "Keys URL", "Static keys"]);
    expect(document.body.textContent).not.toMatch(/Token review asks/);
  });

  it("still shows an issuer stored with it where it isn't offered, to move it off", async () => {
    storedIssuer(URL_REVIEW);
    renderWithProviders(
      <TrustedIssuerPage id="cluster" backTo="/" tokenReview={false} />,
    );
    await screen.findByTestId("token-review-not-offered");
    // As stored, editable.
    const url = screen.getByRole("textbox", {
      name: "API Server URL",
    }) as HTMLInputElement;
    expect(url.value).toBe("https://10.0.0.1:6443");
    expect(keysSources()).toContain("Token review");
    // Moved to another source: the notice and the review fields go.
    fireEvent.click(screen.getByRole("option", { name: "Discovery" }));
    expect(screen.queryByTestId("token-review-not-offered")).toBeNull();
    expect(
      screen.queryByRole("textbox", { name: "API Server URL" }),
    ).toBeNull();
  });

  it("still shows a device an issuer is stored with where devices aren't offered, to empty it", async () => {
    storedIssuer(DEVICE_REVIEW);
    renderWithProviders(<TrustedIssuerPage id="cluster" backTo="/" />);
    const device = (await screen.findByRole("textbox", {
      name: "Review Device",
    })) as HTMLInputElement;
    expect(device.value).toBe("dev_123");
    screen.getByTestId("review-device-not-offered");
    fireEvent.change(device, { target: { value: "" } });
    expect(screen.queryByTestId("review-device-not-offered")).toBeNull();
    // Still there to type one again (the stored issuer has one).
    screen.getByRole("textbox", { name: "Review Device" });
  });
});

describe("TrustedIssuerPage's reviewer credential", () => {
  it("shows as stored in the confirm dialog when replaced, never its value", async () => {
    storedIssuer(URL_REVIEW);
    renderWithProviders(<TrustedIssuerPage id="cluster" backTo="/" />);
    await screen.findByLabelText("Reviewer Credential");
    type("Reviewer Credential", "new-reviewer");
    const dialog = openConfirm();
    within(dialog).getByText("Review Token");
    expect(within(dialog).getAllByText("••••••••")).toHaveLength(2);
    expect(within(dialog).queryByText("None")).toBeNull();
    expect(within(dialog).queryByText("new-reviewer")).toBeNull();
  });

  it("has to be entered again for a changed url, refused before anything is sent", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    storedIssuer(URL_REVIEW);
    renderWithProviders(<TrustedIssuerPage id="cluster" backTo="/" />);
    await screen.findByLabelText("API Server URL");
    type("API Server URL", "https://10.0.0.2:6443");
    const dialog = openConfirm();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await screen.findByText(
      "Enter the reviewer credential again when changing the URL",
    );
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("TrustedIssuerPage saves each review mode", () => {
  it("at a url: the stored credential is kept by an empty one, a new one is sent", async () => {
    const stored = storedIssuer(URL_REVIEW);
    renderWithProviders(
      <TrustedIssuerPage
        id="cluster"
        backTo="/"
        tokenReview={{ device: true }}
      />,
    );
    await screen.findByLabelText("API Server URL");
    expect(reviewFields()).toEqual([
      "API Server URL",
      "Reviewer Credential",
      "API Server CA",
      "Review Device",
    ]);
    // Something else changed: the credential isn't listed, and goes
    // out empty, which keeps the stored one.
    type("Rule Name", "Deploy prod");
    let dialog = openConfirm();
    expect(confirmLine(dialog, "Review Token")).toBeUndefined();
    expect((await confirmSave(dialog, stored)).keys).toEqual({
      source: "TokenReview",
      params: { url: "https://10.0.0.1:6443", ca: "", token: "", device: "" },
    });

    type("Reviewer Credential", "new-reviewer");
    dialog = openConfirm();
    expect(confirmLine(dialog, "Review Token")).toBe("•••••••• -> ••••••••");
    expect((await confirmSave(dialog, stored)).keys).toEqual({
      source: "TokenReview",
      params: {
        url: "https://10.0.0.1:6443",
        ca: "",
        token: "new-reviewer",
        device: "",
      },
    });
  });

  it("at a url of an issuer storing no credential: it reads None before", async () => {
    const stored = storedIssuer({ source: "Discovery", params: {} });
    renderWithProviders(<TrustedIssuerPage id="cluster" backTo="/" />);
    fireEvent.click(
      await screen.findByRole("combobox", { name: "Signing Keys" }),
    );
    fireEvent.click(screen.getByRole("option", { name: "Token review" }));
    type("API Server URL", "https://10.0.0.1:6443");
    type("Reviewer Credential", "reviewer");
    const dialog = openConfirm();
    expect(confirmLine(dialog, "Review Token")).toBe("None -> ••••••••");
    expect((await confirmSave(dialog, stored)).keys).toEqual({
      source: "TokenReview",
      params: {
        url: "https://10.0.0.1:6443",
        ca: "",
        token: "reviewer",
        device: "",
      },
    });
  });

  it("through a device: no credential or CA shown or sent", async () => {
    const stored = storedIssuer(DEVICE_REVIEW);
    renderWithProviders(
      <TrustedIssuerPage
        id="cluster"
        backTo="/"
        tokenReview={{ device: true }}
      />,
    );
    await screen.findByLabelText("Review Device");
    expect(reviewFields()).toEqual(["API Server URL", "Review Device"]);
    type("Rule Name", "Deploy prod");
    const dialog = openConfirm();
    expect(confirmLine(dialog, "Review Token")).toBeUndefined();
    expect((await confirmSave(dialog, stored)).keys).toEqual({
      source: "TokenReview",
      params: { url: "", ca: "", token: "", device: "dev_123" },
    });
  });

  it("a url issuer with a CA and a typed credential switched to a device", async () => {
    const stored = storedIssuer({
      source: "TokenReview",
      params: { ...URL_REVIEW.params, ca: "-----BEGIN CERTIFICATE-----" },
    });
    renderWithProviders(
      <TrustedIssuerPage
        id="cluster"
        backTo="/"
        tokenReview={{ device: true }}
      />,
    );
    await screen.findByLabelText("API Server CA");
    type("Reviewer Credential", "typed before the device");
    type("API Server URL", "");
    type("Review Device", "dev_456");
    expect(reviewFields()).toEqual(["API Server URL", "Review Device"]);
    const dialog = openConfirm();
    expect((await confirmSave(dialog, stored)).keys).toEqual({
      source: "TokenReview",
      params: { url: "", ca: "", token: "", device: "dev_456" },
    });
  });

  it("with this cluster: only the switch shown and sent", async () => {
    const stored = storedIssuer({
      source: "TokenReview",
      params: { in_cluster: true },
    });
    renderWithProviders(
      <TrustedIssuerPage
        id="cluster"
        backTo="/"
        tokenReview={{ device: true }}
      />,
    );
    const inCluster = (await screen.findByRole("switch", {
      name: "Review with this cluster",
    })) as HTMLInputElement;
    expect(inCluster.checked).toBe(true);
    expect(reviewFields()).toEqual([]);
    type("Rule Name", "Deploy prod");
    const dialog = openConfirm();
    expect(confirmLine(dialog, "Review Token")).toBeUndefined();
    expect((await confirmSave(dialog, stored)).keys).toEqual({
      source: "TokenReview",
      params: { in_cluster: true },
    });
  });
});

describe("TrustedIssuerPage with ruleAdmin={false}", () => {
  it("offers no admin switch, and sends a rule's stored admin back unchanged", async () => {
    const stored = storedIssuer(
      { source: "Discovery", params: {} },
      {
        admin: true,
      },
    );
    renderWithProviders(
      <TrustedIssuerPage id="cluster" backTo="/" ruleAdmin={false} />,
    );
    await screen.findByLabelText("Rule Name");
    expect(screen.queryByRole("switch", { name: /^Admin/ })).toBeNull();
    // Nor the badge of a rule granting admin.
    expect(screen.queryByTitle("A rule grants admin")).toBeNull();
    type("Rule Name", "Deploy prod");
    const sent = await confirmSave(openConfirm(), stored);
    expect(sent.rules).toEqual([
      { ...stored.rules![0], name: "Deploy prod", admin: true },
    ]);
  });

  it("offers it by default", async () => {
    storedIssuer({ source: "Discovery", params: {} }, { admin: true });
    renderWithProviders(<TrustedIssuerPage id="cluster" backTo="/" />);
    await screen.findByRole("switch", { name: /^Admin/ });
    screen.getByTitle("A rule grants admin");
  });
});
