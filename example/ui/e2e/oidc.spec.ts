import { expect, test, type Page } from "@playwright/test";
import {
  enrollTotp,
  expectLoggedInAs,
  freshCode,
  logOut,
  notification,
  signUp,
  uniqueName,
} from "./helpers";
import { IDP_URL } from "../playwright.config";

/** Adds a user who can log in at the mock identity provider. */
async function addIdpUser(page: Page, username: string, groups: string[] = []) {
  const res = await page.request.post(`${IDP_URL}/control/users`, {
    data: {
      sub: `${username}-sub`,
      preferred_username: username,
      email: `${username}@example.com`,
      groups,
    },
  });
  expect(res.ok()).toBeTruthy();
}

/** The mock provider shows a page to pick who to log in as. */
async function pickIdpUser(page: Page, username: string) {
  await expect(page.getByText("Mock Identity Provider")).toBeVisible();
  await page.getByTestId(`idp-user-${username}-sub`).click();
}

test("sign up and log in through the provider", async ({ page }) => {
  const username = uniqueName("oidc");
  await addIdpUser(page, username);

  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  // Back at the app, which redeems the session for a token.
  await expectLoggedInAs(page, username);
  await expect(page).not.toHaveURL(/redeem_ready/);

  await page.goto("/profile");
  await expect(page.getByRole("row", { name: /OIDC/ })).toContainText(
    `${username}-sub`,
  );
  // Without a password this is the only login, it can't be unlinked.
  await expect(page.getByRole("row", { name: /OIDC/ })).toContainText(
    "Your only login",
  );

  await logOut(page);
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expectLoggedInAs(page, username);
});

test("a login the provider finishes in another tab is redeemed there", async ({
  page,
  context,
}) => {
  const username = uniqueName("othertab");
  await addIdpUser(page, username);
  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await expect(page.getByText("Mock Identity Provider")).toBeVisible();

  // Eg. a link in an email: the same browser (session cookie), but not
  // the tab which left for the provider.
  const other = await context.newPage();
  const redeems: string[] = [];
  other.on("request", (request) => {
    if (request.url().includes("/ExchangeForJwt")) redeems.push(request.url());
  });
  await other.goto(page.url());
  await pickIdpUser(other, username);
  // The login waits in the browser's session, not in the tab.
  await expectLoggedInAs(other, username);
  await expect(other).not.toHaveURL(/redeem_ready/);
  await expect(other.locator(".mantine-Notification-root")).toHaveCount(0);
  expect(redeems).toHaveLength(1);
});

test("denying the login at the provider", async ({ page }) => {
  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await page.getByTestId("idp-deny").click();
  // Back at the login page with the reason, not on a page of JSON.
  await expect(page).toHaveURL(/\/login$/);
  await expect(
    notification(page, /Login was denied at the provider/),
  ).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
});

test("a login which is already linked can't be linked again", async ({
  page,
}) => {
  const idpUser = uniqueName("taken");
  await addIdpUser(page, idpUser);
  // The provider login belongs to its own user already.
  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, idpUser);
  await expectLoggedInAs(page, idpUser);
  await logOut(page);

  await signUp(page, uniqueName("linker"));
  await page.goto("/profile");
  await page.getByRole("button", { name: "Link OIDC" }).click();
  await pickIdpUser(page, idpUser);
  await expect(page).toHaveURL(/\/profile$/);
  await expect(notification(page, /already linked/)).toBeVisible();
  await expect(page.getByRole("row", { name: /OIDC/ })).toContainText(
    "Unlinked",
  );
});

test("link a provider login to a local user, then unlink the password", async ({
  page,
}) => {
  const username = uniqueName("link");
  const idpUser = uniqueName("idp");
  await addIdpUser(page, idpUser);
  await signUp(page, username);

  await page.goto("/profile");
  await page.getByRole("button", { name: "Link OIDC" }).click();
  await pickIdpUser(page, idpUser);
  await expect(page).toHaveURL(/\/profile$/);
  await expect(page.getByRole("row", { name: /OIDC/ })).toContainText(
    `${idpUser}-sub`,
  );

  // The provider now logs in the local user.
  await logOut(page);
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, idpUser);
  await expectLoggedInAs(page, username);

  // With two logins either can be removed, but not the last one.
  await page.goto("/profile");
  const local = page.getByRole("row", { name: /Local/ });
  await local.getByRole("button", { name: "Unlink" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox").fill("Unlink");
  await dialog.getByRole("button", { name: "Unlink" }).click();
  await expect(page.getByRole("row", { name: /OIDC/ })).toContainText(
    "Your only login",
  );
});

test("second factor after an external login", async ({ page }) => {
  const username = uniqueName("oidc2fa");
  await addIdpUser(page, username);
  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expectLoggedInAs(page, username);
  const { totp } = await enrollTotp(page);
  await logOut(page);

  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  // The provider vouched for the first factor only.
  await expect(page).toHaveURL(/totp=true/);
  await page
    .getByRole("textbox", { name: "2FA Code" })
    .fill(freshCode(totp, "next"));
  await page.getByRole("button", { name: "Log In" }).click();
  await expectLoggedInAs(page, username);
  await expect(page).not.toHaveURL(/totp=true/);
});
