import { readFileSync } from "fs";
import path from "path";
import { expect, test, type Page } from "@playwright/test";
import {
  expectLoggedInAs,
  logIn,
  notification,
  signUp,
  uniqueName,
} from "./helpers";
import { ADMIN, ADMIN_PASSWORD } from "./global-setup";
import { SUPPORTER_KEY } from "../playwright.config";

// The first test sets the key in the settings, the next ones rely on
// it (and on the branding set along the way), and the last removes
// it: in this order, one after the other.
test.describe.configure({ mode: "serial" });

/**
 * The key covers releases up to this date, and the ui is built with
 * the release date of its package.json (vite.config.ts), whatever the
 * day of the build: with a later one the badge rightly stays away,
 * while the settings still show the key.
 */
const COVERS = "2027-09-30";
const RELEASE_DATE: string = JSON.parse(
  readFileSync(path.join(import.meta.dirname, "../package.json"), "utf8"),
).releaseDate;
const covered = RELEASE_DATE <= COVERS;

/** The instance private key: the only secret in the key. */
const SECRET = SUPPORTER_KEY.replace(/\s/g, "").split(".")[2];

/** A 1x1 png, to upload as the icon. */
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

/** The supporter section of the settings, as the admin. */
async function openSettings(page: Page) {
  await logIn(page, ADMIN, ADMIN_PASSWORD);
  await expectLoggedInAs(page, ADMIN);
  await page.goto("/settings");
  return page.getByTestId("supporter-key-config");
}

/** The branding config, a section of its own under the key's. */
const brandingConfig = (page: Page) =>
  page.getByTestId("supporter-branding-config");

/** Its Save buttons: there while something changed. */
const brandingSave = (page: Page) =>
  brandingConfig(page).getByRole("button", { name: "Save", exact: true });

/** The dialog which lists the changes before they are saved. */
const confirmDialog = (page: Page) =>
  page.getByRole("dialog", { name: "Confirm Update" });

/** Saves the branding through the config's confirm dialog. */
async function saveBranding(page: Page) {
  await brandingSave(page).first().click();
  await confirmDialog(page)
    .getByRole("button", { name: "Save", exact: true })
    .click();
  await expect(confirmDialog(page)).toHaveCount(0);
  // Saved: nothing is left to save.
  await expect(brandingSave(page)).toHaveCount(0);
}

/** Answers `GetSupporterKey` with another instance public key. */
async function tamperWithTheKey(page: Page) {
  await page.route("**/supporter/read/GetSupporterKey", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    expect(body?.instance_public_key).toBeTruthy();
    body.instance_public_key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    await route.fulfill({ response, json: body });
  });
}

test("an admin sets the key in the settings, the badge appears", async ({
  page,
}) => {
  const section = await openSettings(page);
  const become = page.getByTestId("become-supporter");
  await expect(become).toBeVisible();
  await expect(page.getByTestId("home-button")).toHaveText("Mogh Example");
  // The offer is quiet, leads to mogh.tech, and says in the app's
  // words what supporting means when hovered.
  await expect(become).toHaveAttribute("data-variant", "subtle");
  await expect(become).toHaveAttribute("href", "https://mogh.tech/supporter");
  await become.hover();
  await expect(page.getByTestId("supporter-hover-card")).toHaveText(
    /The Mogh apps are free and open source.*Supporters fund their development/,
  );
  await page.mouse.move(0, 400);
  await expect(page.getByTestId("supporter-hover-card")).toHaveCount(0);

  const status = section.getByTestId("supporter-key-status");
  await expect(status).toContainText("No supporter key");
  // The branding is an organization key's.
  await expect(brandingConfig(page)).toHaveCount(0);
  const input = section.getByLabel("Supporter key", { exact: true });
  const save = section.getByRole("button", { name: "Save", exact: true });
  await expect(save).toBeDisabled();

  // A key which does not parse is refused with the reason.
  await input.fill("not.a.key");
  await save.click();
  await expect(notification(page, /Invalid supporter key/)).toBeVisible();
  await expect(status).toContainText("No supporter key");

  // So is a key which parses but does not verify: here, the key with
  // another instance key than the root signed. Nothing is saved.
  const [payload, signature] = SUPPORTER_KEY.replace(/\s/g, "").split(".");
  await input.fill(
    `${payload}.${signature}.BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc`,
  );
  await save.click();
  await expect(
    notification(page, /root signature does not verify/),
  ).toBeVisible();
  await expect(status).toContainText("No supporter key");
  await expect(page.getByTestId("become-supporter")).toBeVisible();

  // The key as pasted, wrapped.
  await input.fill(SUPPORTER_KEY);
  await save.click();
  await expect(notification(page, "Supporter key saved.")).toBeVisible();
  await expect(status).toContainText("Acme Corp");
  await expect(status).toContainText("organization");
  await expect(status).toContainText("Stored");
  await expect(status).toContainText("Covers releases until 2027-09-30.");
  // The key itself never comes back.
  await expect(input).toHaveValue("");
  await expect(page.locator("body")).not.toContainText(SECRET);
  await expect(brandingConfig(page)).toBeVisible();

  // The topbar badge appears without a reload, with the heart.
  if (covered) {
    const badge = page.getByTestId("supporter-badge");
    await expect(badge).toHaveText("Acme Corp");
    await expect(badge.locator("img")).toHaveCount(0);
    await expect(page.getByTestId("become-supporter")).toHaveCount(0);
  } else {
    await expect(page.getByTestId("become-supporter")).toBeVisible();
  }
});

test("an admin gives the badge the organization's icon and size", async ({
  page,
}) => {
  await openSettings(page);
  const branding = brandingConfig(page);
  const icon = branding.getByLabel("Icon", { exact: true });
  // Nothing changed: nothing to save.
  await expect(brandingSave(page)).toHaveCount(0);

  // Not an icon: said under the field, and not saved. The confirm
  // dialog stays open with the reason.
  await icon.fill("logo.png");
  await expect(branding.getByText(/is not an image url/)).toBeVisible();
  await brandingSave(page).first().click();
  await expect(confirmDialog(page)).toContainText("logo.png");
  await confirmDialog(page)
    .getByRole("button", { name: "Save", exact: true })
    .click();
  await expect(notification(page, /is not an image url/)).toBeVisible();
  await expect(confirmDialog(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(confirmDialog(page)).toHaveCount(0);
  // Reset drops the change.
  await branding.getByRole("button", { name: "Reset" }).first().click();
  await expect(icon).toHaveValue("");
  await expect(brandingSave(page)).toHaveCount(0);

  await icon.fill("/mogh-512x512.png");
  const preview = branding
    .getByTestId("supporter-branding-preview")
    .locator("img");
  await expect(preview).toHaveAttribute("src", "/mogh-512x512.png");
  // The badge's default height, and as wide as the (square) image
  // is at it.
  await expect(preview).toHaveCSS("height", "20px");
  await expect(preview).toHaveCSS("width", "20px");
  // The height alone scales the image.
  await branding.getByLabel("Icon height").fill("24");
  await expect(preview).toHaveCSS("height", "24px");
  await expect(preview).toHaveCSS("width", "24px");
  // Out of range: said under the field.
  await branding.getByLabel("Icon height").fill("57");
  await expect(branding.getByText(/icon height is 57 pixels/)).toBeVisible();
  await branding.getByLabel("Icon height").fill("24");
  await branding.getByLabel("Icon width").fill("40");
  await expect(preview).toHaveCSS("width", "40px");
  // The confirm dialog lists what changes.
  await brandingSave(page).first().click();
  await expect(confirmDialog(page)).toContainText("Icon Height");
  await expect(confirmDialog(page)).toContainText("Icon Width");
  await confirmDialog(page)
    .getByRole("button", { name: "Save", exact: true })
    .click();
  await expect(notification(page, "Supporter branding saved.")).toBeVisible();
  await expect(confirmDialog(page)).toHaveCount(0);
  await expect(brandingSave(page)).toHaveCount(0);

  // The badge follows without a reload.
  if (covered) {
    const image = page.getByTestId("supporter-badge").locator("img");
    await expect(image).toHaveAttribute("src", "/mogh-512x512.png");
    // An admin set url on any host learns nothing of the instance.
    await expect(image).toHaveAttribute("referrerpolicy", "no-referrer");
    await expect(image).toHaveCSS("width", "40px");
    await expect(image).toHaveCSS("height", "24px");
  }
  await expect(page.getByTestId("home-button")).toHaveText("Mogh Example");

  // Kept: the form shows it again after a reload.
  await page.reload();
  await expect(icon).toHaveValue("/mogh-512x512.png");
  await expect(branding.getByLabel("Icon width")).toHaveValue("40");
  await expect(branding.getByLabel("Icon height")).toHaveValue("24");
  await expect(brandingSave(page)).toHaveCount(0);
});

test("an icon which includes the name shows alone", async ({ page }) => {
  await openSettings(page);
  const branding = brandingConfig(page);
  const icon = branding.getByLabel("Icon", { exact: true });
  const hide = branding.getByRole("switch", { name: "Hide the name" });
  const preview = branding.getByTestId("supporter-branding-preview");
  const badge = page.getByTestId("supporter-badge");

  await expect(hide).not.toBeChecked();
  await expect(preview).toHaveText("Acme Corp");
  await hide.check({ force: true });
  await expect(preview).toHaveText("");
  await saveBranding(page);
  if (covered) {
    // The icon alone, named for those who can't see it, and on hover.
    await expect(badge).toHaveText("");
    await expect(badge.locator("img")).toHaveAttribute("alt", "Acme Corp");
    await expect(badge).toHaveAttribute("aria-label", "Acme Corp, supporter");
    await badge.hover();
    await expect(page.getByTestId("supporter-hover-card")).toContainText(
      "Organization supporter",
    );
  }
  await page.reload();
  await expect(hide).toBeChecked();

  // An icon which does not load stands for nothing: the name is back.
  await icon.fill("/no-such-icon.png");
  await expect(preview).toHaveText("Acme Corp");
  await saveBranding(page);
  if (covered) {
    await expect(badge).toHaveText("Acme Corp");
    await expect(badge.locator("img")).toHaveCount(0);
  }

  // Without an icon there is nothing to hide the name behind.
  await branding.getByRole("button", { name: "Clear icon" }).click();
  await expect(hide).toBeDisabled();
  await expect(hide).not.toBeChecked();
  await expect(preview).toHaveText("Acme Corp");

  // As it was, for the next tests: the icon with the name.
  await icon.fill("/mogh-512x512.png");
  await expect(hide).toBeEnabled();
  await hide.uncheck({ force: true });
  await saveBranding(page);
  if (covered) {
    await expect(badge).toHaveText("Acme Corp");
    await expect(badge.locator("img")).toHaveAttribute("src", "/mogh-512x512.png");
  }
});

test("the badge opens the organization's own link", async ({ page }) => {
  await openSettings(page);
  const branding = brandingConfig(page);
  const link = branding.getByLabel("Link", { exact: true });
  const badge = page.getByTestId("supporter-badge");
  // Without one it leads to the Mogh supporter page, like the offer.
  if (covered) {
    await expect(badge).toHaveAttribute("href", "https://mogh.tech/supporter");
  }

  // Nothing but a web address: said under the field, and refused.
  await link.fill("javascript:alert(1)");
  await expect(branding.getByText(/not a web address/)).toBeVisible();
  await brandingSave(page).first().click();
  await confirmDialog(page)
    .getByRole("button", { name: "Save", exact: true })
    .click();
  await expect(notification(page, /not a web address/)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(confirmDialog(page)).toHaveCount(0);
  if (covered) {
    await expect(badge).toHaveAttribute("href", "https://mogh.tech/supporter");
  }

  // The organization's site: the badge leads there, in a new tab,
  // without a reload.
  await link.fill("https://acme.example/about");
  await saveBranding(page);
  if (covered) {
    await expect(badge).toHaveAttribute("href", "https://acme.example/about");
    await expect(badge).toHaveAttribute("target", "_blank");
    await expect(badge).toHaveAttribute("rel", "noopener noreferrer");
  }
  await page.reload();
  await expect(link).toHaveValue("https://acme.example/about");
});

test("the name shows in capitals when the branding says so", async ({
  page,
}) => {
  await openSettings(page);
  const branding = brandingConfig(page);
  const caps = branding.getByRole("switch", { name: "All caps name" });
  const preview = branding.getByTestId("supporter-branding-preview");
  const badge = page.getByTestId("supporter-badge");
  await expect(caps).not.toBeChecked();
  await expect(preview.getByText("Acme Corp")).toHaveCSS(
    "text-transform",
    "none",
  );

  await caps.check({ force: true });
  await expect(preview.getByText("Acme Corp")).toHaveCSS(
    "text-transform",
    "uppercase",
  );
  await saveBranding(page);
  if (covered) {
    // Shown in capitals, while the name itself stays as the key has it.
    await expect(badge).toHaveText("Acme Corp");
    await expect(badge.getByText("Acme Corp")).toHaveCSS(
      "text-transform",
      "uppercase",
    );
    await expect(badge).toHaveAttribute("aria-label", "Acme Corp, supporter");
  }
  await page.reload();
  await expect(caps).toBeChecked();
});

test("the topbar shows the badge for the stored key", async ({ page }) => {
  await signUp(page, uniqueName("supporter"));
  if (!covered) {
    await expect(page.getByTestId("become-supporter")).toBeVisible();
    await expect(page.getByTestId("supporter-badge")).toHaveCount(0);
    return;
  }
  const badge = page.getByTestId("supporter-badge");
  await expect(badge).toBeVisible();
  await expect(badge).toHaveText("Acme Corp");
  // The organization's own link, opened in a new tab, and its icon, as
  // the admin set them: for every user.
  await expect(badge).toHaveAttribute("href", "https://acme.example/about");
  await expect(badge).toHaveAttribute("target", "_blank");
  await expect(badge.locator("img")).toHaveAttribute("src", "/mogh-512x512.png");
  await expect(badge.locator("img")).toHaveCSS("width", "40px");
  // The thanks, and under it the app's words.
  await badge.hover();
  const card = page.getByTestId("supporter-hover-card");
  await expect(card).toContainText("Organization supporter");
  await expect(card).toContainText(
    "Supporters fund the development of the Mogh apps",
  );
  await expect(page.getByTestId("become-supporter")).toHaveCount(0);

  // Once per page load: a navigation within the app sends no new request.
  let requests = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/supporter/read/GetSupporterKey")) requests += 1;
  });
  await page.getByRole("link", { name: "Notes" }).click();
  await expect(page.getByText("No notes yet.")).toBeVisible();
  await page.getByRole("link", { name: "Home" }).click();
  await expect(page.getByTestId("welcome")).toBeVisible();
  await expect(badge).toBeVisible();
  expect(requests).toBe(0);
});

test("a page without WebCrypto verifies the key in JavaScript", async ({
  page,
}) => {
  // A page served over plain http from another host than localhost,
  // eg. a LAN install reached at http://192.168.1.10:9120, has no
  // `crypto.subtle` and is no secure context. The suite runs on
  // localhost, which is one: the page is made one which isn't.
  await page.addInitScript(() => {
    Object.defineProperty(Crypto.prototype, "subtle", {
      get: () => undefined,
    });
    Object.defineProperty(globalThis, "isSecureContext", { value: false });
  });
  const section = await openSettings(page);
  expect(
    await page.evaluate(() => [typeof crypto.subtle, isSecureContext]),
  ).toEqual(["undefined", false]);
  const status = section.getByTestId("supporter-key-status");
  await expect(status).toContainText("Acme Corp");
  const browserProblem = section.getByTestId("supporter-key-browser-problem");
  if (!covered) {
    await expect(page.getByTestId("become-supporter")).toBeVisible();
    return;
  }
  // The badge as on a secure page, and no word of the browser refusing
  // the key.
  await expect(page.getByTestId("supporter-badge")).toHaveText("Acme Corp");
  await expect(browserProblem).toHaveCount(0);

  // It verifies, so it refuses too: an answer changed on the way is no
  // badge, and the admin reads why next to the server's verdict.
  await tamperWithTheKey(page);
  await page.reload();
  await expect(page.getByTestId("become-supporter")).toBeVisible();
  await expect(page.getByTestId("supporter-badge")).toHaveCount(0);
  await expect(browserProblem).toContainText(
    "The root signature does not verify",
  );
});

test("a WebCrypto without Ed25519 leaves the key to JavaScript", async ({
  page,
}) => {
  // Browsers before Chrome 137, Safari 17 and Firefox 130 have
  // WebCrypto, and refuse Ed25519 keys.
  await page.addInitScript(() => {
    const importKey = SubtleCrypto.prototype.importKey;
    Object.defineProperty(SubtleCrypto.prototype, "importKey", {
      value(this: SubtleCrypto, ...args: unknown[]) {
        const algorithm = args[2] as string | { name?: string };
        const name =
          typeof algorithm === "string" ? algorithm : algorithm?.name;
        if (name === "Ed25519") {
          return Promise.reject(
            new DOMException(
              "Algorithm: Unrecognized name",
              "NotSupportedError",
            ),
          );
        }
        return Reflect.apply(importKey, this, args);
      },
    });
  });
  await signUp(page, uniqueName("ed25519less"));
  expect(
    await page.evaluate(() =>
      crypto.subtle
        .importKey("raw", new Uint8Array(32), { name: "Ed25519" }, false, [
          "verify",
        ])
        .then(
          () => "imported",
          (e: DOMException) => e.name,
        ),
    ),
  ).toBe("NotSupportedError");
  if (!covered) {
    await expect(page.getByTestId("become-supporter")).toBeVisible();
    return;
  }
  await expect(page.getByTestId("supporter-badge")).toHaveText("Acme Corp");
});

test("an answer changed on the way shows no badge", async ({ page }) => {
  // The browser verifies: a proxy replacing the instance public key
  // (here, with 32 bytes of 0x01) breaks the root signature.
  await tamperWithTheKey(page);
  await signUp(page, uniqueName("tampered"));
  await expect(page.getByTestId("become-supporter")).toBeVisible();
  await expect(page.getByTestId("supporter-badge")).toHaveCount(0);
});

test("the server's answer for another nonce shows no badge", async ({ page }) => {
  // A captured answer: correct, but signed for a nonce this page did
  // not draw. The request's nonce is swapped on the way to the server.
  await page.route("**/supporter/read/GetSupporterKey", async (route) => {
    const body = JSON.parse(route.request().postData() ?? "{}");
    expect(body.nonce).toHaveLength(43);
    body.nonce = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    await route.continue({ postData: JSON.stringify(body) });
  });
  await signUp(page, uniqueName("replayed"));
  await expect(page.getByTestId("become-supporter")).toBeVisible();
  await expect(page.getByTestId("supporter-badge")).toHaveCount(0);
});

test("an uploaded icon and the name take the place of the home button", async ({
  page,
}) => {
  await openSettings(page);
  const branding = brandingConfig(page);
  const file = branding.locator('input[type="file"]');
  const preview = branding.getByTestId("supporter-branding-preview");

  // A file which is no image is refused with the reason.
  await file.setInputFiles({
    name: "page.html",
    mimeType: "text/html",
    buffer: Buffer.from("<html></html>"),
  });
  await expect(notification(page, /has to be a png/)).toBeVisible();
  await expect(preview.locator("img")).toHaveAttribute("src", "/mogh-512x512.png");

  // An image replaces the url.
  await file.setInputFiles({ name: "logo.png", mimeType: "image/png", buffer: PNG });
  await expect(preview.locator("img")).toHaveAttribute(
    "src",
    /^data:image\/png;base64,iVBOR/,
  );
  // The form names the upload: the image itself is no text to show.
  const uploaded = branding.getByLabel("Icon", { exact: true });
  await expect(uploaded).toBeDisabled();
  await expect(uploaded).toHaveValue("logo.png (png, 1 KB)");

  await branding
    .getByRole("switch", { name: "Use as the home button" })
    .check({ force: true });
  // So does the confirm dialog, which never shows the image's bytes.
  await brandingSave(page).first().click();
  await expect(confirmDialog(page)).toContainText("logo.png (png, 1 KB)");
  await expect(confirmDialog(page)).not.toContainText("iVBOR");
  await confirmDialog(page)
    .getByRole("button", { name: "Save", exact: true })
    .click();
  await expect(notification(page, "Supporter branding saved.")).toBeVisible();
  await expect(confirmDialog(page)).toHaveCount(0);
  await expect(brandingSave(page)).toHaveCount(0);
  // Kept as an upload: named as one.
  await expect(uploaded).toHaveValue("Uploaded image (png, 1 KB)");

  const home = page.getByTestId("home-button");
  if (!covered) {
    await expect(home).toHaveText("Mogh Example");
    return;
  }
  // The home button is the organization's now, without a reload, and
  // the badge is not shown a second time. Its name is in capitals
  // there too.
  await expect(home).toHaveText("Acme Corp");
  await expect(home.getByText("Acme Corp")).toHaveCSS(
    "text-transform",
    "uppercase",
  );
  await expect(home.locator("img")).toHaveAttribute(
    "src",
    /^data:image\/png;base64,iVBOR/,
  );
  await expect(home.locator("img")).toHaveCSS("width", "40px");
  await expect(home.locator("img")).toHaveCSS("height", "24px");
  await expect(page.getByTestId("supporter-badge")).toHaveCount(0);
  await expect(page.getByTestId("become-supporter")).toHaveCount(0);

  // An icon which includes the name is the whole home button.
  const hide = branding.getByRole("switch", { name: "Hide the name" });
  await hide.check({ force: true });
  await saveBranding(page);
  await expect(home).toHaveText("");
  await expect(home).toHaveAttribute("aria-label", "Acme Corp");
  await expect(home.locator("img")).toHaveAttribute("alt", "Acme Corp");
  await hide.uncheck({ force: true });
  await saveBranding(page);
  await expect(home).toHaveText("Acme Corp");

  // It still leads home.
  await home.click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByTestId("welcome")).toBeVisible();
});

test("every user sees the brand, but only for a verified key", async ({
  page,
  browser,
}) => {
  await signUp(page, uniqueName("branded"));
  const home = page.getByTestId("home-button");
  if (covered) {
    await expect(home).toHaveText("Acme Corp");
    await expect(home.locator("img")).toHaveAttribute("src", /^data:image\/png/);
    await expect(page.getByTestId("supporter-badge")).toHaveCount(0);
  } else {
    await expect(home).toHaveText("Mogh Example");
  }

  // The branding alone brands nothing: with a key which does not
  // verify the home button stays the app's.
  const context = await browser.newContext();
  const other = await context.newPage();
  await tamperWithTheKey(other);
  await signUp(other, uniqueName("unbranded"));
  await expect(other.getByTestId("become-supporter")).toBeVisible();
  await expect(other.getByTestId("home-button")).toHaveText("Mogh Example");
  await context.close();
});

test("the settings are for admins, and the admin removes the key", async ({
  page,
}) => {
  await signUp(page, uniqueName("plain"));
  await page.goto("/settings");
  await expect(page.getByTestId("supporter-key-config")).toHaveCount(0);

  const section = await openSettings(page);
  await expect(section.getByTestId("supporter-key-status")).toContainText(
    "Acme Corp",
  );
  // Two clicks: the button asks to confirm.
  await section.getByRole("button", { name: "Remove" }).click();
  await section.getByRole("button", { name: "Confirm" }).click();
  await expect(notification(page, "Supporter key removed.")).toBeVisible();
  await expect(section.getByTestId("supporter-key-status")).toContainText(
    "No supporter key",
  );
  await expect(section.getByRole("button", { name: "Remove" })).toHaveCount(0);
  await expect(brandingConfig(page)).toHaveCount(0);
  // The badge and the brand go without a reload.
  await expect(page.getByTestId("become-supporter")).toBeVisible();
  await expect(page.getByTestId("supporter-badge")).toHaveCount(0);
  await expect(page.getByTestId("home-button")).toHaveText("Mogh Example");
});
