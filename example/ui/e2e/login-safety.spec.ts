import {
  expect,
  test,
  type APIRequestContext,
  type Page,
} from "@playwright/test";
import {
  enrollTotp,
  expectLoggedInAs,
  freshCode,
  logOut,
  notification,
  PASSWORD,
  signUp,
  uniqueName,
} from "./helpers";
import { ADMIN, ADMIN_PASSWORD } from "./global-setup";
import { APP_URL, IDP_URL } from "../playwright.config";

/**
 * What the login flows do with input anyone can put in a link:
 * `backto`, `login_error`, `passkey` and `redeem_ready`.
 */

async function logInAt(page: Page, url: string, username: string) {
  await page.goto(url);
  await page.getByRole("textbox", { name: "Username" }).fill(username);
  await page
    .getByRole("textbox", { name: "Password", exact: true })
    .fill(PASSWORD);
  await page.getByRole("button", { name: "Log In" }).click();
}

test("login only returns to pages of the app", async ({ page }) => {
  const username = uniqueName("backto-safe");
  await signUp(page, username);
  await logOut(page);

  // Scripts, other sites and what only becomes one once parsed.
  for (const backto of [
    "javascript:window.__pwned=1",
    "//evil.example/login",
    "/\\evil.example/login",
    "/\t/evil.example/login",
    "https://evil.example/login",
    `${APP_URL}@evil.example/login`,
  ]) {
    await logInAt(
      page,
      `/login?backto=${encodeURIComponent(backto)}`,
      username,
    );
    await expect(page, backto).toHaveURL(`${APP_URL}/`);
    await expectLoggedInAs(page, username);
    expect(
      await page.evaluate(
        () => (window as unknown as { __pwned?: number }).__pwned,
      ),
      backto,
    ).toBeUndefined();
  }

  // A path which resolves to `//host` stays a path.
  await logInAt(
    page,
    `/login?backto=${encodeURIComponent("/.//evil.example")}`,
    username,
  );
  await expect(page).toHaveURL(`${APP_URL}/evil.example`);

  // Pages of the app keep their query.
  await logInAt(
    page,
    `/login?backto=${encodeURIComponent("/tools?tab=a#b")}`,
    username,
  );
  await expect(page).toHaveURL(`${APP_URL}/tools?tab=a#b`);
});

test("the back button of the login page stays in the app", async ({ page }) => {
  await signUp(page, uniqueName("back"));
  await page.goto(
    `/login?backto=${encodeURIComponent("https://evil.example/login")}`,
  );
  await expect(page.getByRole("link", { name: "Back" })).toHaveAttribute(
    "href",
    "/",
  );
  await page.goto(`/login?backto=${encodeURIComponent("/tools")}`);
  await expect(page.getByRole("link", { name: "Back" })).toHaveAttribute(
    "href",
    "/tools",
  );
});

async function addIdpUser(page: Page, username: string) {
  const res = await page.request.post(`${IDP_URL}/control/users`, {
    data: { sub: `${username}-sub`, preferred_username: username },
  });
  expect(res.ok()).toBeTruthy();
}

async function pickIdpUser(page: Page, username: string) {
  await expect(page.getByText("Mock Identity Provider")).toBeVisible();
  await page.getByTestId(`idp-user-${username}-sub`).click();
}

test("second factor of an external login while still signed in", async ({
  page,
}) => {
  const username = uniqueName("oidc2fa-again");
  await addIdpUser(page, username);
  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expectLoggedInAs(page, username);
  const { totp } = await enrollTotp(page);

  // Logging in again (eg. to reauthenticate) without logging out.
  // The second factor is shown outside the app's router, and the
  // old token still says somebody is signed in.
  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expect(page).toHaveURL(/totp=true/);
  await page
    .getByRole("textbox", { name: "2FA Code" })
    .fill(freshCode(totp, "next"));
  await page.getByRole("button", { name: "Log In" }).click();
  await expectLoggedInAs(page, username);
  await expect(page).not.toHaveURL(/totp=true/);
});

test("the second factor on a page whose path starts with /login stays there", async ({
  page,
}) => {
  const username = uniqueName("oidc2fa-login-prefix");
  await addIdpUser(page, username);
  await page.goto("/login");
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expectLoggedInAs(page, username);
  const { totp } = await enrollTotp(page);
  await logOut(page);

  // Like an app's `/login-providers/:id`: not the login route, the login
  // page is only shown there for the second factor. The fragment comes
  // back too.
  const backto = "/login-x?tab=a#frag";
  await page.goto(`/login?backto=${encodeURIComponent(backto)}`);
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expect(page).toHaveURL(/\/login-x\?tab=a&totp=true#frag$/);
  await page
    .getByRole("textbox", { name: "2FA Code" })
    .fill(freshCode(totp, "next"));
  await page.getByRole("button", { name: "Log In" }).click();
  await expect(page).toHaveURL(`${APP_URL}${backto}`);
  await expect(page.getByText("Page not found")).toBeVisible();
});

test("a passkey challenge which can't be read doesn't crash the app", async ({
  page,
}) => {
  for (const passkey of ["x", "e30", "bnVsbA"]) {
    await page.goto(`/?passkey=${passkey}`);
    await expect(
      notification(page, "Invalid passkey challenge").first(),
    ).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
    await expect(page).not.toHaveURL(/passkey=/);
  }
});

/** The `ExchangeForJwt` requests the page sends. */
function redeemRequests(page: Page) {
  const sent: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/ExchangeForJwt")) sent.push(request.url());
  });
  return sent;
}

/** The warnings the page logs to the console. */
function consoleWarnings(page: Page) {
  const warnings: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "warning") warnings.push(message.text());
  });
  return warnings;
}

/**
 * Opens `url` carrying a `redeem_ready` nobody's login is waiting for,
 * and expects its redeem refused, without counting against the ip.
 */
async function openPlantedRedeem(page: Page, url: string) {
  const refused = page.waitForResponse((response) =>
    response.url().includes("/ExchangeForJwt"),
  );
  await page.goto(url);
  const response = await refused;
  expect(response.status()).toBe(401);
  expect(await response.text()).not.toContain("attempts remaining");
}

test("a redeem_ready link shows nothing alarming", async ({ page }) => {
  // No external login was started: the session has nothing to redeem.
  // It is asked all the same (a login may have returned to another
  // tab), and the failure is only logged.
  const redeems = redeemRequests(page);
  const warnings = consoleWarnings(page);
  await openPlantedRedeem(page, "/?redeem_ready=true");
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
  await expect(page).not.toHaveURL(/redeem_ready/);
  await expect(page.locator(".mantine-Notification-root")).toHaveCount(0);
  expect(redeems).toHaveLength(1);
  expect(warnings.some((warning) => warning.includes("redeem_ready"))).toBe(
    true,
  );
});

test("a redeem_ready link doesn't bother a user who is logged in", async ({
  page,
}) => {
  const username = uniqueName("redeem-link");
  await signUp(page, username);
  const redeems = redeemRequests(page);
  await openPlantedRedeem(page, "/tools?redeem_ready=true");
  await expect(page).toHaveURL(`${APP_URL}/tools`);
  await expectLoggedInAs(page, username);
  await expect(page.locator(".mantine-Notification-root")).toHaveCount(0);
  expect(redeems).toHaveLength(1);
});

/** Notes in the tab that it left for an external login (`externalLogin`). */
async function markExternalFlow(page: Page) {
  await page.goto("/login");
  await page.evaluate(() =>
    sessionStorage.setItem("mogh-ui-external-flow-v1", String(Date.now())),
  );
}

test("a failed redeem falls back to the login page", async ({ page }) => {
  // The tab's own external login, but the session has nothing to redeem.
  const redeems = redeemRequests(page);
  await markExternalFlow(page);
  await page.goto("/?redeem_ready=true");
  await expect(notification(page, /ExchangeForJwt failed/)).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
  await expect(page).not.toHaveURL(/redeem_ready/);
  expect(redeems).toHaveLength(1);
});

test("a link to a path starting with // doesn't crash the app", async ({
  page,
}) => {
  // `//x/` as a relative url is another host.
  await page.goto(`${APP_URL}//x/?passkey=garbage`);
  await expect(
    notification(page, "Invalid passkey challenge").first(),
  ).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();

  await page.goto(`${APP_URL}//x/?login_error=hi`);
  await expect(
    notification(page, "The external login didn't complete."),
  ).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();

  await markExternalFlow(page);
  await page.goto(`${APP_URL}//x/?redeem_ready=true`);
  await expect(notification(page, /ExchangeForJwt failed/)).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
});

test("a login error in a link isn't shown as the app's message", async ({
  page,
}) => {
  const spoofed = "Your account is locked. Call support at +1-555-0100";
  await page.goto(`/login?login_error=${encodeURIComponent(spoofed)}`);
  await expect(
    notification(page, "The external login didn't complete."),
  ).toBeVisible();
  await expect(page.locator("body")).not.toContainText("+1-555-0100");
  await expect(page).toHaveURL(/\/login$/);
});

test("a finished external login or link doesn't vouch for a later login error", async ({
  page,
}) => {
  const spoofed = "Your account is locked. Call support at +1-555-0100";
  async function expectNotVouched() {
    await page.goto(`/login?login_error=${encodeURIComponent(spoofed)}`);
    await expect(
      notification(page, "The external login didn't complete."),
    ).toBeVisible();
    await expect(page.locator("body")).not.toContainText("+1-555-0100");
  }

  // A link which succeeded comes back without any query.
  const idpUser = uniqueName("vouch-link-idp");
  await addIdpUser(page, idpUser);
  await signUp(page, uniqueName("vouch-link"));
  await page.goto("/profile");
  await page.getByRole("button", { name: "Link OIDC" }).click();
  await pickIdpUser(page, idpUser);
  await expect(page).toHaveURL(/\/profile$/);
  await expect(page.getByRole("row", { name: /OIDC/ })).toContainText(
    `${idpUser}-sub`,
  );
  await expectNotVouched();

  // A login which comes back for the second factor.
  const username = uniqueName("vouch-2fa");
  await addIdpUser(page, username);
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expectLoggedInAs(page, username);
  await enrollTotp(page);
  await logOut(page);
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expect(page).toHaveURL(/totp=true/);
  await expectNotVouched();
});

test("a login error planted in backto doesn't come back with the login", async ({
  page,
}) => {
  const spoofed = "Your account is locked. Call support at +1-555-0100";
  const username = uniqueName("planted-backto");
  await addIdpUser(page, username);
  // The provider sends the tab back to `backto`, and the server adds
  // its `redeem_ready=true` after the query already there.
  const backto =
    `/tools?tab=a&login_error=${encodeURIComponent(spoofed)}` +
    "&redeem_ready=0";
  await page.goto(`/login?backto=${encodeURIComponent(backto)}`);
  await page.getByRole("button", { name: /OIDC/ }).click();
  await pickIdpUser(page, username);
  await expectLoggedInAs(page, username);
  await expect(page).toHaveURL(`${APP_URL}/tools?tab=a`);
  await expect(page.locator("body")).not.toContainText("+1-555-0100");
  await expect(notification(page, "Login failed")).toHaveCount(0);
});

/** A fresh admin token, manage requests need a recent login. */
async function adminJwt(request: APIRequestContext): Promise<string> {
  const login = await request.post("/auth/login/LoginLocalUser", {
    data: { username: ADMIN, password: ADMIN_PASSWORD },
  });
  expect(login.ok(), await login.text()).toBeTruthy();
  return (await login.json()).data.jwt;
}

/**
 * Runs `test` with a provider the login page auto redirects to, deleted
 * after it.
 */
async function withAutoRedirect(
  request: APIRequestContext,
  test: () => Promise<void>,
) {
  const created = await request.post(
    "/auth/manage/CreateExternalLoginProvider",
    {
      headers: { authorization: await adminJwt(request) },
      data: {
        name: uniqueName("Auto SSO"),
        registration_disabled: false,
        config: {
          kind: "Oidc",
          params: {
            enabled: true,
            provider: IDP_URL,
            client_id: "example-client-id",
            client_secret: "example-client-secret",
            auto_redirect: true,
          },
        },
      },
    },
  );
  expect(created.ok(), await created.text()).toBeTruthy();
  const providerId: string = (await created.json()).provider.id;

  try {
    await test();
  } finally {
    // Every other test expects the login page.
    const deleted = await request.post(
      "/auth/manage/DeleteExternalLoginProvider",
      {
        headers: { authorization: await adminJwt(request) },
        data: { id: providerId },
      },
    );
    expect(deleted.ok(), await deleted.text()).toBeTruthy();
  }
}

/** Counts the page's visits to a provider. */
function providerVisits(page: Page) {
  const visits = { count: 0 };
  page.on("request", (req) => {
    if (/\/auth\/external\/[^/]+\/login/.test(req.url())) visits.count++;
  });
  return visits;
}

test("auto redirect to a provider stops when the login fails", async ({
  page,
  request,
}) => {
  await withAutoRedirect(request, async () => {
    const visits = providerVisits(page);
    // Straight to the provider, where the user says no.
    await page.goto("/login");
    await expect(page.getByText("Mock Identity Provider")).toBeVisible();
    await page.getByTestId("idp-deny").click();

    // Back on the login page with the reason, which stays.
    await expect(
      notification(page, /Login was denied at the provider/),
    ).toBeVisible();
    await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
    await page.waitForTimeout(2_000);
    await expect(page).toHaveURL(new RegExp(`^${APP_URL}/login`));
    await expect(page.getByText("Mock Identity Provider")).toHaveCount(0);
    expect(visits.count).toBe(1);
  });
});

test("a failed redeem doesn't auto redirect to the provider", async ({
  page,
  request,
}) => {
  await withAutoRedirect(request, async () => {
    // Without the tab's mark, eg. a login started with sessionStorage
    // blocked: the provider would send it back to fail again, in a loop.
    const visits = providerVisits(page);
    await openPlantedRedeem(page, "/?redeem_ready=true");
    await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
    await page.waitForTimeout(2_000);
    await expect(page).not.toHaveURL(/redeem_ready/);
    await expect(page.getByText("Mock Identity Provider")).toHaveCount(0);
    await expect(page.locator(".mantine-Notification-root")).toHaveCount(0);
    expect(visits.count).toBe(0);
  });
});
