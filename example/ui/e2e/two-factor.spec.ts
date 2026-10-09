import { expect, test } from "@playwright/test";
import {
  enrollTotp,
  expectLoggedInAs,
  freshCode,
  logIn,
  logOut,
  notification,
  signUp,
  uniqueName,
} from "./helpers";

test("totp: a mistyped code can be retried", async ({ page }) => {
  const username = uniqueName("totp");
  await signUp(page, username);
  const { totp } = await enrollTotp(page);
  await logOut(page);

  await logIn(page, username);
  const code = page.getByRole("textbox", { name: "2FA Code" });
  await expect(code).toBeVisible();

  await code.fill("000000");
  await page.getByRole("button", { name: "Log In" }).click();
  await expect(notification(page, /Invalid TOTP code/)).toBeVisible();

  // Still the same login: the right code finishes it.
  await code.fill(freshCode(totp, "next"));
  await page.getByRole("button", { name: "Log In" }).click();
  await expectLoggedInAs(page, username);
});

test("totp: recovery code, and cancelling the second factor", async ({
  page,
}) => {
  const username = uniqueName("recovery");
  await signUp(page, username);
  const { recoveryCodes } = await enrollTotp(page);
  await logOut(page);

  await logIn(page, username);
  await expect(page.getByRole("textbox", { name: "2FA Code" })).toBeVisible();
  // Back to the first factor, eg. to log in as somebody else.
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();

  await logIn(page, username);
  await page.getByRole("button", { name: "Use a recovery code" }).click();
  await page
    .getByRole("textbox", { name: "Recovery Code" })
    .fill(recoveryCodes[0]);
  await page.getByRole("button", { name: "Log In" }).click();
  await expectLoggedInAs(page, username);

  // Each recovery code only works once.
  await logOut(page);
  await logIn(page, username);
  await page.getByRole("button", { name: "Use a recovery code" }).click();
  await page
    .getByRole("textbox", { name: "Recovery Code" })
    .fill(recoveryCodes[0]);
  await page.getByRole("button", { name: "Log In" }).click();
  await expect(notification(page, /Invalid recovery code/)).toBeVisible();
});

test("totp: unenroll goes back to password only", async ({ page }) => {
  const username = uniqueName("unenroll");
  await signUp(page, username);
  await enrollTotp(page);
  await page.getByRole("button", { name: "Unenroll TOTP 2FA" }).click();
  // Destructive actions are confirmed by typing a word.
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox").fill("Unenroll");
  await dialog.getByRole("button", { name: "Unenroll TOTP 2FA" }).click();
  await expect(
    page.getByRole("button", { name: "Enroll TOTP 2FA", exact: true }),
  ).toBeVisible();
  await logOut(page);
  await logIn(page, username);
  await expectLoggedInAs(page, username);
});

test("a confirm dialog starts over on every open", async ({ page }) => {
  await signUp(page, uniqueName("confirm-again"));
  await enrollTotp(page);
  const dialog = page.getByRole("dialog");
  const confirm = dialog.getByRole("button", { name: "Unenroll TOTP 2FA" });
  await page.getByRole("button", { name: "Unenroll TOTP 2FA" }).click();
  await dialog.getByRole("textbox").fill("Unenroll");
  await expect(confirm).toBeEnabled();
  // Typed, then cancelled: the text doesn't confirm the next open.
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await page.getByRole("button", { name: "Unenroll TOTP 2FA" }).click();
  await expect(dialog.getByRole("textbox")).toHaveValue("");
  await expect(confirm).toBeDisabled();
});

test("passkey: enroll and log in with a virtual authenticator", async ({
  page,
}) => {
  // A software authenticator inside the browser, which
  // answers webauthn requests without any user interaction.
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    },
  );

  const username = uniqueName("passkey");
  await signUp(page, username);
  await page.goto("/profile");
  // A double click begins one enrollment: a second begin would replace
  // the first one's challenge, and its passkey would fail to confirm.
  await page.getByRole("button", { name: "Enroll Passkey 2FA" }).dblclick();
  await expect(
    page.getByRole("button", { name: "Unenroll Passkey 2FA" }),
  ).toBeVisible();
  await expect(notification(page, /failed/i)).toHaveCount(0);
  const { credentials } = await cdp.send("WebAuthn.getCredentials", {
    authenticatorId,
  });
  expect(credentials).toHaveLength(1);

  await logOut(page);
  await logIn(page, username);
  // The password asks for the passkey, which the authenticator provides.
  await expectLoggedInAs(page, username);

  // A prompt which failed (here: no user verification) can be tried
  // again, without starting the login over.
  await logOut(page);
  await cdp.send("WebAuthn.setUserVerified", {
    authenticatorId,
    isUserVerified: false,
  });
  await logIn(page, username);
  await expect(notification(page, "Failed to select passkey")).toBeVisible();
  await cdp.send("WebAuthn.setUserVerified", {
    authenticatorId,
    isUserVerified: true,
  });
  await page.getByRole("button", { name: "Try Again" }).click();
  await expectLoggedInAs(page, username);

  // Without the authenticator the password isn't enough.
  await logOut(page);
  await cdp.send("WebAuthn.disable");
  await logIn(page, username);
  await expect(
    page.getByText("Provide your passkey to finish login"),
  ).toBeVisible();
  await expect(page.getByTestId("current-user")).toHaveCount(0);
});
