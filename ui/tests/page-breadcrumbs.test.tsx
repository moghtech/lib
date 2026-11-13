import { describe, expect, it } from "vitest";
import { PageBreadcrumbs } from "../src/components/page-breadcrumbs";
import { renderWithProviders } from "./render";

/** The crumbs, each the element which truncates its label. */
function crumbs(): HTMLElement[] {
  return [...document.querySelectorAll<HTMLElement>("[data-truncate]")];
}

describe("PageBreadcrumbs", () => {
  // `Breadcrumbs` gives each crumb a line height of 1, and a truncated
  // crumb clips what overflows it: that cut the descenders (a g, a p)
  // off the label.
  it("gives a link and the page's own crumb a line height which fits their glyphs", () => {
    renderWithProviders(
      <PageBreadcrumbs
        items={[{ label: "Staging", to: "/staging" }, { label: "Jogging" }]}
      />,
    );
    const [link, page] = crumbs();
    expect(link.tagName).toBe("A");
    expect(link.textContent).toBe("Staging");
    expect(page.textContent).toBe("Jogging");
    for (const crumb of [link, page]) {
      expect(getComputedStyle(crumb).lineHeight).toBe("normal");
    }
  });

  it("leaves the line height to the caller's text props", () => {
    renderWithProviders(
      <PageBreadcrumbs
        commonTextProps={{ lh: 2 }}
        items={[{ label: "Staging", to: "/staging" }, { label: "Jogging" }]}
      />,
    );
    for (const crumb of crumbs()) {
      expect(crumb.style.lineHeight).toBe("2");
    }
  });
});
