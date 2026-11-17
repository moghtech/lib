import { expect, type Locator, type Page } from "@playwright/test";
import * as OTPAuth from "otpauth";

export const PASSWORD = "correct-horse-battery";

let counter = 0;
/** Usernames are unique per test, the tests share one server. */
export function uniqueName(prefix: string) {
  counter += 1;
  return `${prefix}-${Date.now().toString(36)}-${counter}`;
}

export async function signUp(page: Page, username: string) {
  await page.goto("/login");
  await page.getByRole("textbox", { name: "Username" }).fill(username);
  await page.getByRole("textbox", { name: "Password", exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Sign Up" }).click();
  await expectLoggedInAs(page, username);
}

export async function logIn(page: Page, username: string, password = PASSWORD) {
  await page.goto("/login");
  await page.getByRole("textbox", { name: "Username" }).fill(username);
  await page.getByRole("textbox", { name: "Password", exact: true }).fill(password);
  await page.getByRole("button", { name: "Log In" }).click();
}

export async function logOut(page: Page) {
  await page.getByRole("button", { name: "Log Out" }).click();
  await expect(page.getByRole("textbox", { name: "Username" })).toBeVisible();
}

export async function expectLoggedInAs(page: Page, username: string) {
  await expect(page.getByTestId("current-user")).toHaveText(username);
}

/**
 * Sets a Mantine switch. The input of a switch is invisible (its
 * track is drawn over it), so the click is forced, and a forced click
 * does not check what lies at its point: when the input sits under
 * the fixed header, the header is clicked and the switch stays as it
 * was. The app keeps its scroll position across a route change, so
 * where a switch sits depends on how long the pages before have grown
 * in this run (the settings page gets a row for each provider the
 * tests add). So the switch is first brought to the middle of the
 * viewport, at once: the page scrolls smoothly by default, and the
 * click would not wait for that.
 */
export async function setSwitch(toggle: Locator, checked: boolean) {
  await toMiddle(toggle);
  await toggle.setChecked(checked, { force: true });
}

/**
 * Clicks a switch which shows the state of the server: it changes
 * when the write is answered, so the caller waits for the new state
 * (see [setSwitch] for the scroll).
 */
export async function clickSwitch(toggle: Locator) {
  await toMiddle(toggle);
  await toggle.click({ force: true });
}

async function toMiddle(toggle: Locator) {
  await toggle.evaluate((input) =>
    input.scrollIntoView({ block: "center", behavior: "instant" }),
  );
}

/** The error notification mogh_ui / the app show for failed requests. */
export function notification(page: Page, text: string | RegExp) {
  return page.locator(".mantine-Notification-root").filter({ hasText: text });
}

/** Enrolls TOTP on the profile page. Returns the authenticator and the recovery codes. */
export async function enrollTotp(page: Page) {
  await page.goto("/profile");
  await page.getByRole("button", { name: "Enroll TOTP 2FA" }).click();
  const dialog = page.getByRole("dialog");
  // Read only, not disabled: selectable where the clipboard can't be
  // written.
  const uriInput = dialog.getByRole("textbox", { name: "URI" });
  await expect(uriInput).toHaveValue(/^otpauth:\/\//);
  await expect(uriInput).not.toBeEditable();
  const totp = OTPAuth.URI.parse(await uriInput.inputValue()) as OTPAuth.TOTP;
  await dialog
    .getByRole("textbox", { name: "Confirm Code" })
    .fill(totp.generate());
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(page.getByText("Save recovery keys")).toBeVisible();
  const codes = dialog.getByRole("textbox", { name: /^Code \d+$/ });
  await expect(codes.first()).not.toBeEditable();
  const recoveryCodes = await codes.evaluateAll((inputs) =>
    inputs.map((input) => (input as HTMLInputElement).value),
  );
  expect(recoveryCodes).toHaveLength(10);
  // Held open while the codes show: Escape doesn't lose them.
  await page.keyboard.press("Escape");
  await expect(codes.first()).toBeVisible();
  // Done asks whether they were saved first.
  await dialog.getByRole("button", { name: "Done" }).click();
  await dialog.getByRole("button", { name: "Saved, close" }).click();
  await expect(
    page.getByRole("button", { name: "Unenroll TOTP 2FA" }),
  ).toBeVisible();
  return { totp, recoveryCodes };
}

/**
 * A code the server didn't accept yet. Codes only work once and the
 * enrollment used the current one, but the server also accepts the
 * steps next to it (clock skew of one step).
 */
export function freshCode(totp: OTPAuth.TOTP, step: "next" | "previous") {
  return totp.generate({
    timestamp: Date.now() + (step === "next" ? 30_000 : -30_000),
  });
}
