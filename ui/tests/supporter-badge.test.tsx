import { describe, expect, it } from "vitest";
import type { Supporter } from "mogh_supporter";
import { SupporterBadge } from "../src/supporter/badge";
import { renderWithProviders } from "./render";

const individual: Supporter = {
  version: 1,
  rootKeyId: "00",
  id: "00000000-0000-0000-0000-000000000000",
  app: "cicada",
  name: "Maggy Jogging",
  tier: "individual",
  since: "2026-01-01",
  covers: "2027-01-01",
};

/** The span which truncates the text of the badge `testId`. */
function truncatedText(testId: string): HTMLElement {
  const span = document.querySelector(
    `[data-testid="${testId}"] [data-truncate]`,
  );
  expect(span).not.toBeNull();
  return span as HTMLElement;
}

describe("SupporterBadge", () => {
  // A button's line height is 1, and the span which truncates the
  // text clips what overflows it: inherited, it cut the descenders
  // (a g, a p) off the name.
  it.each([
    [
      "a supporter's name",
      <SupporterBadge supporter={individual} />,
      "supporter-badge",
      "Maggy Jogging",
    ],
    [
      "the offer",
      <SupporterBadge supporter={null} />,
      "become-supporter",
      "Become a supporter",
    ],
  ])(
    "gives %s a line height which fits its glyphs",
    (_, badge, testId, text) => {
      renderWithProviders(badge);
      const span = truncatedText(testId);
      expect(span.textContent).toBe(text);
      expect(getComputedStyle(span).lineHeight).toBe("normal");
    },
  );
});
