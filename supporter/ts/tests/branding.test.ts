import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  ICON_MEDIA_TYPES,
  MAX_ICON_BYTES,
  DEFAULT_ICON_HEIGHT,
  MAX_ICON_HEIGHT,
  MAX_ICON_URL_LENGTH,
  MAX_ICON_WIDTH,
  MAX_LINK_LENGTH,
  brandingLinkProblem,
  MIN_ICON_SIZE,
  base64Encode,
  brandingIconProblem,
  brandingProblem,
  brandingSizeProblem,
  iconDataUrl,
  normalizeBranding,
  supporterBrand,
  type Supporter,
} from "../src/index.ts";
import * as fixture from "./fixture.ts";

const ORGANIZATION = fixture.SUPPORTER as Supporter;
const INDIVIDUAL: Supporter = { ...ORGANIZATION, name: "Ada", tier: "individual" };
const SPONSOR: Supporter = { ...ORGANIZATION, tier: "sponsor" };

test("the limits are the Rust crate's", () => {
  assert.equal(MAX_ICON_URL_LENGTH, 2048);
  assert.equal(MAX_LINK_LENGTH, 2048);
  assert.equal(MAX_ICON_BYTES, 262144);
  assert.equal(MIN_ICON_SIZE, 8);
  assert.equal(DEFAULT_ICON_HEIGHT, 20);
  assert.equal(MAX_ICON_WIDTH, 240);
  assert.equal(MAX_ICON_HEIGHT, 56);
  assert.deepEqual(
    [...ICON_MEDIA_TYPES],
    ["image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"],
  );
});

describe("icons", () => {
  test("urls, paths and uploaded images are icons", () => {
    for (const icon of [
      "https://example.com/logo.png",
      "http://10.0.0.5:9120/logo.svg?v=2#x",
      "https://example.com",
      "/icons/acme.png",
      "/logo",
      "data:image/png;base64,AQID",
      "data:image/svg+xml;base64,PHN2Zy8+",
      "data:image/jpeg;base64,AQ==",
      "data:image/webp;base64,AQI=",
      "data:image/gif;base64,AQID",
    ]) {
      assert.equal(brandingIconProblem(icon), null, icon);
    }
  });

  test("anything else is not", () => {
    for (const icon of [
      "",
      "logo.png",
      "./logo.png",
      "//evil.example/logo.png",
      "/\\evil.example/logo.png",
      "javascript:alert(1)",
      "ftp://example.com/logo.png",
      "HTTPS://example.com/logo.png",
      "https://",
      "https:///logo.png",
      "https://example.com/a logo.png",
      "https://example.com/logo.png\n",
      "/icons/\u0007.png",
      "data:image/png,AQID",
    ]) {
      assert.match(brandingIconProblem(icon) ?? "", /is not an image url/, JSON.stringify(icon));
    }
    for (const icon of ["data:text/html;base64,AQID", "data:;base64,AQID", "data:IMAGE/PNG;base64,AQID"]) {
      assert.match(brandingIconProblem(icon) ?? "", /not a png, jpeg, gif, webp or svg/, icon);
    }
    assert.match(brandingIconProblem("data:image/png;base64,A-_D") ?? "", /not valid base64/);
    assert.match(brandingIconProblem("data:image/png;base64,AQI") ?? "", /not valid base64/);
    assert.match(brandingIconProblem("data:image/png;base64,") ?? "", /is empty/);
    // The problem never echoes the icon.
    assert.ok(!brandingIconProblem("javascript:alert(1)")?.includes("alert"));
  });

  test("the image is bounded, not its base64", () => {
    const most = base64Encode(new Uint8Array(MAX_ICON_BYTES).fill(7));
    assert.equal(brandingIconProblem(`data:image/png;base64,${most}`), null);
    const over = base64Encode(new Uint8Array(MAX_ICON_BYTES + 1).fill(7));
    assert.equal(
      brandingIconProblem(`data:image/png;base64,${over}`),
      `The uploaded icon is ${MAX_ICON_BYTES + 1} bytes, the most is ${MAX_ICON_BYTES}`,
    );
    assert.match(
      brandingIconProblem(`data:image/png;base64,${"A".repeat(4 * MAX_ICON_BYTES)}`) ?? "",
      /bytes, the most is/,
    );
    const long = "https://example.com/" + "a".repeat(MAX_ICON_URL_LENGTH);
    assert.equal(
      brandingIconProblem(long),
      `The icon url is ${long.length} bytes long, the most is ${MAX_ICON_URL_LENGTH}`,
    );
  });
});

test("sizes are whole pixels within the limits", () => {
  for (const [dimension, size, ok] of [
    ["width", undefined, true],
    ["width", null, true],
    ["width", MIN_ICON_SIZE, true],
    ["width", MAX_ICON_WIDTH, true],
    ["height", MAX_ICON_HEIGHT, true],
    ["width", MIN_ICON_SIZE - 1, false],
    ["width", 0, false],
    ["width", MAX_ICON_WIDTH + 1, false],
    ["height", MAX_ICON_HEIGHT + 1, false],
    ["height", 32.5, false],
    ["height", NaN, false],
  ] as const) {
    assert.equal(brandingSizeProblem(dimension, size) === null, ok, `${dimension} ${size}`);
  }
  assert.equal(
    brandingSizeProblem("height", 57),
    "The icon height is 57 pixels, it has to be 8 to 56",
  );
});

test("links are web addresses", () => {
  for (const link of [
    "https://acme.example",
    "https://acme.example/about?from=komodo#team",
    "http://intranet.acme.example:8080/",
  ]) {
    assert.equal(brandingLinkProblem(link), null, link);
  }
  for (const link of [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD4=",
    "file:///etc/passwd",
    "//acme.example",
    "/settings",
    "acme.example",
    "https://",
    "https:///path",
    "HTTPS://acme.example",
    "https://acme.example/a b",
    " https://acme.example",
    "https://acme.example\u0000",
    "",
  ]) {
    assert.match(brandingLinkProblem(link) ?? "", /not a web address/, JSON.stringify(link));
  }
  const longest = `https://acme.example/${"a".repeat(MAX_LINK_LENGTH - 21)}`;
  assert.equal(brandingLinkProblem(longest), null);
  assert.equal(
    brandingLinkProblem(`${longest}a`),
    `The link is ${MAX_LINK_LENGTH + 1} bytes long, the most is ${MAX_LINK_LENGTH}`,
  );
  // As a whole: checked, trimmed, and left out when empty.
  assert.match(brandingProblem({ link: "javascript:alert(1)" }) ?? "", /not a web address/);
  assert.equal(brandingProblem({ link: " https://acme.example " }), null);
  assert.deepEqual(normalizeBranding({ link: " https://acme.example\n" }), {
    link: "https://acme.example",
    replace_home: false,
    hide_name: false,
    uppercase_name: false,
  });
  assert.deepEqual(normalizeBranding({ link: "  " }), { replace_home: false, hide_name: false, uppercase_name: false });
});

test("a branding is checked and normalized as a whole", () => {
  assert.equal(brandingProblem({ replace_home: false }), null);
  assert.equal(
    brandingProblem({ icon: " /icons/acme.png ", icon_width: 120, icon_height: 32, replace_home: true }),
    null,
  );
  assert.match(brandingProblem({ icon: "logo.png", replace_home: false }) ?? "", /is not an image url/);
  assert.match(brandingProblem({ icon_width: 4, replace_home: false }) ?? "", /icon width is 4 pixels/);
  assert.match(brandingProblem({ icon_height: 400, replace_home: false }) ?? "", /icon height is 400 pixels/);
  // What is unset is left out, like the server answers it.
  assert.deepEqual(normalizeBranding(undefined), { replace_home: false, hide_name: false, uppercase_name: false });
  assert.deepEqual(normalizeBranding({ icon: "  ", replace_home: true }), { replace_home: true, hide_name: false, uppercase_name: false });
  assert.deepEqual(
    normalizeBranding({ icon: " /icons/acme.png\n", icon_width: 120, icon_height: undefined, replace_home: false }),
    { icon: "/icons/acme.png", icon_width: 120, replace_home: false, hide_name: false, uppercase_name: false },
  );
  assert.deepEqual(
    normalizeBranding({ icon: null as never, icon_width: null as never, icon_height: 40 }),
    { icon_height: 40, replace_home: false, hide_name: false, uppercase_name: false },
  );
});

describe("the brand of a verified key", () => {
  test("only organizations and sponsors have one", () => {
    const branding = { icon: "/icons/acme.png", icon_width: 120, icon_height: 32, replace_home: true };
    assert.equal(supporterBrand(undefined, branding), null);
    assert.equal(supporterBrand(null, branding), null);
    assert.equal(supporterBrand(INDIVIDUAL, branding), null);
    assert.deepEqual(supporterBrand(ORGANIZATION, branding), {
      name: "Acme Corp",
      tier: "organization",
      icon: "/icons/acme.png",
      iconWidth: 120,
      iconHeight: 32,
      replaceHome: true,
      hideName: false,
      uppercaseName: false,
    });
    assert.equal(supporterBrand(SPONSOR, branding)?.tier, "sponsor");
  });

  test("without branding it is the name alone, as a badge", () => {
    for (const branding of [undefined, null, {}, { replace_home: false }]) {
      assert.deepEqual(supporterBrand(ORGANIZATION, branding), {
        name: "Acme Corp",
        tier: "organization",
        replaceHome: false,
        hideName: false,
        uppercaseName: false,
      });
    }
  });

  test("what the server sent is checked again", () => {
    const brand = supporterBrand(ORGANIZATION, {
      icon: "javascript:alert(1)",
      icon_width: 4000,
      icon_height: -1,
      replace_home: "yes" as never,
    });
    assert.deepEqual(brand, { name: "Acme Corp", tier: "organization", replaceHome: false, hideName: false, uppercaseName: false });
    assert.deepEqual(
      supporterBrand(ORGANIZATION, { icon: 5 as never, icon_width: "120" as never, replace_home: true }),
      { name: "Acme Corp", tier: "organization", replaceHome: true, hideName: false, uppercaseName: false },
    );
    assert.equal(supporterBrand(ORGANIZATION, { icon: " /logo.svg " })?.icon, "/logo.svg");
  });

  test("the link is a web address, with or without an icon", () => {
    assert.equal(supporterBrand(ORGANIZATION, { link: " https://acme.example/about " })?.link, "https://acme.example/about");
    assert.equal(supporterBrand(SPONSOR, { icon: "/logo.svg", link: "http://intranet.acme.example:8080/" })?.link, "http://intranet.acme.example:8080/");
    // What the server sent is checked again: nothing else becomes an href.
    for (const link of ["javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "/settings", "//acme.example", "acme.example", 5]) {
      assert.equal(supporterBrand(ORGANIZATION, { link: link as never })?.link, undefined, String(link));
    }
    // An individual has no brand, so no link of their own.
    assert.equal(supporterBrand(INDIVIDUAL, { link: "https://acme.example" }), null);
  });

  test("the name shows in capitals when the branding says so, with or without an icon", () => {
    assert.equal(supporterBrand(ORGANIZATION, { uppercase_name: true })?.uppercaseName, true);
    assert.equal(supporterBrand(SPONSOR, { icon: "/logo.svg", uppercase_name: true, replace_home: true })?.uppercaseName, true);
    assert.equal(supporterBrand(ORGANIZATION, { icon: "/logo.svg" })?.uppercaseName, false);
    assert.equal(supporterBrand(ORGANIZATION, { uppercase_name: "yes" as never })?.uppercaseName, false);
    // The name itself stays as the key has it.
    assert.equal(supporterBrand(ORGANIZATION, { uppercase_name: true })?.name, "Acme Corp");
    assert.deepEqual(normalizeBranding({ uppercase_name: true }), {
      replace_home: false,
      hide_name: false,
      uppercase_name: true,
    });
  });

  test("the name is hidden only with an icon to stand for it", () => {
    assert.equal(supporterBrand(ORGANIZATION, { icon: "/logo.svg", hide_name: true, uppercase_name: false })?.hideName, true);
    assert.equal(supporterBrand(SPONSOR, { icon: "/logo.svg", hide_name: true, replace_home: true })?.hideName, true);
    assert.equal(supporterBrand(ORGANIZATION, { icon: "/logo.svg" })?.hideName, false);
    // Without an icon, or with one which is not valid, the name shows.
    assert.equal(supporterBrand(ORGANIZATION, { hide_name: true, uppercase_name: false })?.hideName, false);
    assert.equal(supporterBrand(ORGANIZATION, { icon: "javascript:alert(1)", hide_name: true, uppercase_name: false })?.hideName, false);
    assert.equal(supporterBrand(ORGANIZATION, { icon: "/logo.svg", hide_name: "yes" as never })?.hideName, false);
    // An individual has no brand to hide a name on.
    assert.equal(supporterBrand(INDIVIDUAL, { icon: "/logo.svg", hide_name: true, uppercase_name: false }), null);
    // As it is sent and kept: never without an icon.
    assert.deepEqual(normalizeBranding({ icon: " /logo.svg ", hide_name: true, uppercase_name: false }), {
      icon: "/logo.svg",
      replace_home: false,
      hide_name: true,
      uppercase_name: false,
    });
    assert.deepEqual(normalizeBranding({ hide_name: true, uppercase_name: false }), { replace_home: false, hide_name: false, uppercase_name: false });
    assert.deepEqual(normalizeBranding({ icon: " ", hide_name: true, replace_home: true }), {
      replace_home: true,
      hide_name: false,
      uppercase_name: false,
    });
  });

  test("the size is the icon's", () => {
    // Without an icon there is nothing to size.
    assert.deepEqual(supporterBrand(ORGANIZATION, { icon_width: 120, icon_height: 32, replace_home: true }), {
      name: "Acme Corp",
      tier: "organization",
      replaceHome: true,
      hideName: false,
      uppercaseName: false,
    });
    // One dimension alone is kept as it is: the other follows where it is shown.
    assert.deepEqual(supporterBrand(ORGANIZATION, { icon: "/logo.svg", icon_height: 40 }), {
      name: "Acme Corp",
      tier: "organization",
      icon: "/logo.svg",
      iconHeight: 40,
      replaceHome: false,
      hideName: false,
      uppercaseName: false,
    });
    // A size which is not valid is dropped, the icon stays.
    assert.deepEqual(supporterBrand(ORGANIZATION, { icon: "/logo.svg", icon_width: 241, icon_height: 57 }), {
      name: "Acme Corp",
      tier: "organization",
      icon: "/logo.svg",
      replaceHome: false,
      hideName: false,
      uppercaseName: false,
    });
  });
});

describe("uploads", () => {
  test("an image becomes its data url", async () => {
    const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]);
    const url = await iconDataUrl(new Blob([bytes], { type: "image/png" }));
    assert.equal(url, `data:image/png;base64,${Buffer.from(bytes).toString("base64")}`);
    assert.equal(brandingIconProblem(url), null);
    const svg = await iconDataUrl(new Blob(["<svg/>"], { type: "image/svg+xml" }));
    assert.equal(svg, "data:image/svg+xml;base64,PHN2Zy8+");
    // At the limit.
    const most = await iconDataUrl(
      new Blob([new Uint8Array(MAX_ICON_BYTES)], { type: "image/webp" }),
    );
    assert.equal(brandingIconProblem(most), null);
  });

  test("other files are refused with the reason", async () => {
    await assert.rejects(
      iconDataUrl(new Blob(["<html>"], { type: "text/html" })),
      /has to be a png, jpeg, gif, webp or svg/,
    );
    await assert.rejects(iconDataUrl(new Blob(["x"])), /has to be a png/);
    await assert.rejects(iconDataUrl(new Blob([], { type: "image/png" })), /is empty/);
    await assert.rejects(
      iconDataUrl(new Blob([new Uint8Array(MAX_ICON_BYTES + 1)], { type: "image/png" })),
      /is 257 KB, the most is 256 KB/,
    );
  });
});

test("standard base64 is padded, like node's", () => {
  for (const length of [0, 1, 2, 3, 4, 5, 100, 1000]) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    assert.equal(base64Encode(bytes), Buffer.from(bytes).toString("base64"));
  }
});
