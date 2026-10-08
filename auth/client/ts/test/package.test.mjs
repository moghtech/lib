import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { it } from "node:test";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

it("relative imports in dist have a .js extension", () => {
  // Required by node16 / nodenext module resolution.
  const dist = path.join(root, "dist");
  const files = readdirSync(dist).filter((file) => !file.endsWith(".map"));
  for (const file of files) {
    const contents = readFileSync(path.join(dist, file), "utf8");
    for (const [, specifier] of contents.matchAll(
      /(?:from|import)\s*\(?\s*"(\.{1,2}\/[^"]*)"/g,
    )) {
      assert.ok(
        specifier.endsWith(".js"),
        `${file} imports "${specifier}" without the .js extension`,
      );
    }
  }
});

it("the source maps resolve in the published package", () => {
  // Vite warns on a map whose sources it can't find, and editors follow
  // the declaration maps to the published src.
  const published = JSON.parse(
    readFileSync(path.join(root, "package.json"), "utf8"),
  ).files;
  const dist = path.join(root, "dist");
  const maps = readdirSync(dist).filter((file) => file.endsWith(".map"));
  assert.ok(maps.includes("lib.js.map"), "build first (npm run build)");
  for (const file of maps) {
    const map = JSON.parse(readFileSync(path.join(dist, file), "utf8"));
    map.sources.forEach((source, i) => {
      const resolved = path.resolve(dist, map.sourceRoot ?? "", source);
      const top = path.relative(root, resolved).split(path.sep)[0];
      assert.ok(
        published.includes(top) && existsSync(resolved),
        `${file} points to ${source}, which isn't published`,
      );
      if (file.endsWith(".js.map")) {
        assert.ok(map.sourcesContent?.[i], `${file} doesn't embed ${source}`);
      }
    });
  }
});

it("generate_types fails when typeshare fails", () => {
  const types = path.join(root, "src/types.ts");
  const before = readFileSync(types, "utf8");
  // Run from the package directory, without typeshare on the PATH.
  const result = spawnSync(
    process.execPath,
    [path.join(root, "generate_types.mjs")],
    { cwd: root, env: { ...process.env, PATH: "" }, encoding: "utf8" },
  );
  assert.notEqual(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stderr, /failed to generate types/);
  assert.equal(readFileSync(types, "utf8"), before);
});
