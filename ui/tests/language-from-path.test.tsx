import { expect, test } from "vitest";
import { languageFromPath } from "../src/components/monaco/common";

// A .tsx test: common.ts imports a Mantine type without `import type`,
// which node's type stripping keeps (vitest drops it).
test("the language of a file name", () => {
  expect(languageFromPath("/etc/caddy/Caddyfile")).toBe("caddyfile");
  expect(languageFromPath("sites/api.caddy")).toBe("caddyfile");
  expect(languageFromPath("dev.caddyfile")).toBe("caddyfile");
  expect(languageFromPath("name.Caddyfile")).toBe("caddyfile");
  expect(languageFromPath("Corefile")).toBe("corefile");
  expect(languageFromPath("name.Corefile")).toBe("corefile");
  expect(languageFromPath("Dockerfile")).toBe("dockerfile");
  expect(languageFromPath("compose.yaml")).toBe("yaml");
  expect(languageFromPath("notes.txt")).toBe(undefined);
});

test("a language's name with a variant after a dot", () => {
  expect(languageFromPath("Caddyfile.dev")).toBe("caddyfile");
  expect(languageFromPath("/srv/dns/Corefile.local")).toBe("corefile");
  expect(languageFromPath("build/Dockerfile.prod")).toBe("dockerfile");
  // Only the base name: the directory doesn't count
  expect(languageFromPath("Caddyfile.d/site")).toBe(undefined);
  // An extension wins over the name
  expect(languageFromPath("Caddyfile.json")).toBe("json");
});

test("file name matching is case sensitive", () => {
  expect(languageFromPath("caddyfile")).toBe(undefined);
  expect(languageFromPath("CADDYFILE.dev")).toBe(undefined);
});
