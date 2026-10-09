import { expect, test, type Page } from "@playwright/test";
import {
  expectLoggedInAs,
  logIn,
  logOut,
  notification,
  signUp,
  uniqueName,
} from "./helpers";
import { ADMIN, ADMIN_PASSWORD } from "./global-setup";
import { IDP_URL } from "../playwright.config";

test("settings are for admins", async ({ page }) => {
  await signUp(page, uniqueName("plain"));
  await expect(page.getByRole("link", { name: "Settings" })).toHaveCount(0);
  await page.goto("/settings");
  await expect(
    page.getByText("Only admins can change the settings."),
  ).toBeVisible();
});

test("admin enables and disables users", async ({ page, browser }) => {
  // Another browser (own storage) for the user being managed.
  const username = uniqueName("managed");
  const userContext = await browser.newContext();
  const userPage = await userContext.newPage();
  await signUp(userPage, username);

  await logIn(page, ADMIN, ADMIN_PASSWORD);
  await expectLoggedInAs(page, ADMIN);
  await page.goto("/settings");
  const row = page.getByTestId(`user-row-${username}`);
  await expect(row).toBeVisible();
  // The switch reflects the server state, which changes after the write.
  const enabled = row.getByRole("switch", { name: `${username} enabled` });
  await expect(enabled).toBeChecked();
  await enabled.click({ force: true });
  await expect(enabled).not.toBeChecked();

  await userPage.reload();
  await expect(userPage.getByText("User not enabled")).toBeVisible();

  await enabled.click({ force: true });
  await expect(enabled).toBeChecked();
  await userPage.reload();
  await expectLoggedInAs(userPage, username);
  await userContext.close();
});

test("admin adds a login provider, which users can use to log in", async ({
  page,
}) => {
  const providerName = uniqueName("SSO");
  const idpUser = uniqueName("sso-user");
  await page.request.post(`${IDP_URL}/control/users`, {
    data: { sub: `${idpUser}-sub`, preferred_username: idpUser },
  });

  await logIn(page, ADMIN, ADMIN_PASSWORD);
  await expectLoggedInAs(page, ADMIN);
  await page.goto("/settings");

  // The provider from the server config is listed, read only.
  await expect(page.getByRole("row", { name: /OIDC/ }).first()).toBeVisible();

  await page.getByRole("button", { name: "New Login Provider" }).click();
  await page
    .getByRole("dialog")
    .getByRole("textbox", { name: "Name" })
    .fill(providerName);
  await page.getByRole("dialog").getByRole("button", { name: "Create" }).click();

  // Continues on the page of the new provider, with its configuration.
  await expect(page).toHaveURL(/\/login-providers\/[^/]+$/);
  const providerUrl = page.url();
  await expect(page.getByText("Provider created.")).toBeVisible();
  await expect(
    page.getByText(/\/auth\/external\/.+\/callback/).first(),
  ).toBeVisible();
  await page.getByRole("textbox", { name: "Provider URL" }).fill(IDP_URL);
  await page.getByRole("textbox", { name: "Client ID" }).fill("example-client-id");
  await page
    .getByRole("textbox", { name: "Client Secret" })
    .fill("example-client-secret");
  await page
    .getByRole("switch", { name: "Enabled", exact: true })
    .check({ force: true });
  await saveConfig(page);
  await expect(notification(page, "Saved login provider.")).toBeVisible();

  // The secret is never sent back to the browser.
  await page.goto(providerUrl);
  const secret = page.getByRole("textbox", { name: "Client Secret" });
  await expect(secret).toHaveValue("");
  await expect(page.locator("body")).not.toContainText("example-client-secret");
  // Replacing it: the confirm dialog says one is stored (not "None"),
  // and shows neither value.
  await secret.fill("another-secret");
  await page.getByRole("button", { name: "Save", exact: true }).first().click();
  const confirm = page.getByRole("dialog");
  await expect(confirm).toContainText("•••••••• -> ••••••••");
  await expect(confirm).not.toContainText("another-secret");
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Reset" }).first().click();

  // A provider's row opens its page from the keyboard too.
  await page.goto("/settings");
  await page.getByRole("row", { name: new RegExp(providerName) }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(providerUrl);

  await page.goto("/settings");
  await logOut(page);
  await page.getByRole("button", { name: new RegExp(providerName) }).click();
  await page.getByTestId(`idp-user-${idpUser}-sub`).click();
  await expectLoggedInAs(page, idpUser);
});

test("admin adds a workload identity issuer, a job exchanges its token", async ({
  page,
  request,
}) => {
  const issuerName = uniqueName("CI");
  const audience = `https://example-app.test/${issuerName}`;

  await logIn(page, ADMIN, ADMIN_PASSWORD);
  await expectLoggedInAs(page, ADMIN);
  await page.goto("/settings");
  await page.getByRole("button", { name: "New Trusted Issuer" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill(issuerName);
  await dialog.getByRole("textbox", { name: "Issuer", exact: true }).fill(IDP_URL);
  // One audience: the app's origin by default, replaced by this test's.
  await dialog.getByRole("textbox", { name: "Audience" }).fill(audience);
  await dialog.getByRole("button", { name: "Create" }).click();

  // Created disabled, without rules: the page continues with them.
  await expect(page).toHaveURL(/\/trusted-issuers\/[^/]+$/);
  const issuerUrl = page.url();

  await page
    .getByRole("switch", { name: "Enabled", exact: true })
    .check({ force: true });
  await page.getByRole("button", { name: "Add rule" }).click();
  await page.getByRole("textbox", { name: "Rule Name" }).fill("Deploy");
  await page.getByRole("textbox", { name: "Claim", exact: true }).fill("repository_id");
  await page.getByRole("textbox", { name: "Claim Value" }).fill("12345");
  await saveConfig(page);
  await expect(notification(page, "Saved trusted issuer.")).toBeVisible();

  // An emptied number is refused, not saved as 0 (no age limit).
  await page.goto(issuerUrl);
  const maxAge = page.getByRole("textbox", { name: "Maximum Token Age" });
  await expect(maxAge).toHaveValue("300 seconds");
  await maxAge.fill("");
  await saveConfig(page);
  await expect(
    notification(page, "Maximum token age: must be a whole number of seconds"),
  ).toBeVisible();
  await page.keyboard.press("Escape");

  await page.goto("/settings");
  await expect(
    page.getByRole("row", { name: new RegExp(issuerName) }),
  ).toContainText("Enabled");

  // The job gets a token from its platform (the mock idp) ...
  const minted = await request.post(`${IDP_URL}/control/mint`, {
    data: {
      sub: "repo:my-org/my-repo",
      aud: [audience],
      claims: { repository_id: "12345" },
    },
  });
  const { token } = await minted.json();
  // ... and exchanges it for an app token.
  const exchanged = await request.post("/auth/token", {
    form: {
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: token,
      subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
    },
  });
  expect(exchanged.status(), await exchanged.text()).toBe(200);
  const { access_token } = await exchanged.json();
  const info = await request.post("/read/GetRequestInfo", {
    headers: { authorization: `Bearer ${access_token}` },
    data: {},
  });
  expect(info.status()).toBe(200);

  // Its user shows up for the admin, marked as a workload.
  await page.reload();
  await expect(
    page.getByTestId("user-row-workload-deploy").first(),
  ).toContainText("Workload");
});

/** Saves a page's Config: its Save button, then the confirm dialog's. */
async function saveConfig(page: Page) {
  await page.getByRole("button", { name: "Save", exact: true }).first().click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Save", exact: true })
    .click();
}
