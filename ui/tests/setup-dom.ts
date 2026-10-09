// Setup of the jsdom tests (`*.test.tsx`, see vitest.config.ts).

import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

// The browser APIs Mantine uses which jsdom lacks.
window.matchMedia ??= ((query: string) => ({
  matches: false,
  media: query,
  onchange: null,
  addListener: () => {},
  removeListener: () => {},
  addEventListener: () => {},
  removeEventListener: () => {},
  dispatchEvent: () => false,
})) as typeof window.matchMedia;
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};
Element.prototype.scrollIntoView ??= () => {};

afterEach(() => {
  // Not in `globals` mode, so testing-library can't register its own
  // cleanup.
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});
