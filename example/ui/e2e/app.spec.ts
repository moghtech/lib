import { expect, test } from "@playwright/test";
import { notification, signUp, uniqueName } from "./helpers";

test("notes: create, search, edit, delete", async ({ page }) => {
  await signUp(page, uniqueName("notes"));
  await page.goto("/notes");
  await expect(page.getByText("No notes yet.")).toBeVisible();

  for (const title of ["Shopping", "Work"]) {
    await page.getByRole("button", { name: "New Note" }).click();
    await page.getByLabel("Title").fill(title);
    await page.getByLabel("Content").fill(`Content of ${title}`);
    await page.getByRole("button", { name: "Save" }).click();
    await expect(notification(page, "Note saved.").first()).toBeVisible();
  }
  await expect(page.getByTestId("note-row")).toHaveCount(2);

  // The list is a react-query read keyed by its params.
  await page.getByPlaceholder(/search/i).fill("shop");
  await expect(page.getByTestId("note-row")).toHaveCount(1);
  await page.getByPlaceholder(/search/i).fill("");
  await expect(page.getByTestId("note-row")).toHaveCount(2);

  // The content comes back decrypted.
  await page.getByRole("button", { name: "Edit Shopping" }).click();
  await expect(page.getByLabel("Content")).toHaveValue("Content of Shopping");
  await page.getByLabel("Title").fill("Groceries");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByText("Groceries")).toBeVisible();

  // The server validates too.
  await page.getByRole("button", { name: "New Note" }).click();
  await page.getByLabel("Title").fill("x".repeat(101));
  await page.getByRole("button", { name: "Save" }).click();
  await expect(notification(page, /Input too long/)).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByRole("button", { name: "Delete Work" }).click();
  await expect(page.getByTestId("note-row")).toHaveCount(1);
});

test("tools: key pair, seal / open, validate", async ({ page }) => {
  await signUp(page, uniqueName("tools"));
  await page.goto("/tools");

  await page.getByRole("button", { name: "Generate Key Pair" }).click();
  // An Ed25519 public key (spki), as signing keys are.
  await expect(page.getByTestId("generated-public-key")).toHaveText(
    /^MCowBQYDK2VwAyEA/,
  );

  await page.getByLabel("Text", { exact: true }).fill("for my eyes only");
  await page.getByRole("button", { name: "Seal", exact: true }).click();
  const sealed = page.getByLabel("Sealed");
  await expect(sealed).not.toHaveValue("");
  expect(await sealed.inputValue()).not.toContain("for my eyes only");
  await page.getByRole("button", { name: "Open", exact: true }).click();
  await expect(page.getByTestId("opened-text")).toHaveText("for my eyes only");

  // Tampered input is a failed request, reported as a notification.
  await sealed.fill((await sealed.inputValue()).slice(0, -6) + "AAAAAA");
  await page.getByRole("button", { name: "Open", exact: true }).click();
  await expect(notification(page, /Execute request OpenText failed/)).toBeVisible();

  await page.getByLabel("Input").fill("not a username");
  await page.getByRole("button", { name: "Validate", exact: true }).click();
  await expect(page.getByTestId("validation-result")).toContainText(
    "Only alphanumeric",
  );
  await page.getByLabel("Input").fill("valid.user@example.com");
  await page.getByRole("button", { name: "Validate", exact: true }).click();
  await expect(page.getByTestId("validation-result")).toHaveText("Valid");
});

test("api keys: create in the ui, use against the api", async ({
  page,
  request,
}) => {
  await signUp(page, uniqueName("apikeys"));
  await page.goto("/profile");
  await page.getByRole("button", { name: "New Api Key" }).click();
  await page.getByRole("dialog").getByLabel("Name", { exact: true }).fill("ci");
  await page.getByRole("button", { name: "Create" }).click();
  const key = await page.getByTestId("api-key-key").innerText();
  const secret = await page.getByTestId("api-key-secret").innerText();
  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByTestId("api-key-row")).toHaveCount(1);

  const res = await request.post("/read/GetRequestInfo", {
    headers: { "x-api-key": key, "x-api-secret": secret },
    data: {},
  });
  expect(res.status()).toBe(200);
  expect((await res.json()).auth_method).toBe("ApiKey");

  await page.getByRole("button", { name: "Delete api key ci" }).click();
  await expect(page.getByTestId("api-key-row")).toHaveCount(0);
  const after = await request.post("/read/GetRequestInfo", {
    headers: { "x-api-key": key, "x-api-secret": secret },
    data: {},
  });
  expect(after.status()).toBe(401);
});
