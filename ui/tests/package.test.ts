import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const dist = path.join(root, "dist");

test(
  "the source maps resolve in the published package",
  // `npm test` doesn't build.
  { skip: !existsSync(dist) && "build first (npm run build)" },
  () => {
    // Vite warns on a map whose sources it can't find, and editors follow
    // the declaration maps to the published src.
    const published: string[] = JSON.parse(
      readFileSync(path.join(root, "package.json"), "utf8"),
    ).files;
    const maps = readdirSync(dist, { recursive: true, encoding: "utf8" })
      .filter((file) => file.endsWith(".map"));
    assert.ok(maps.includes("index.js.map"));
    for (const file of maps) {
      const at = path.dirname(path.join(dist, file));
      const map = JSON.parse(readFileSync(path.join(dist, file), "utf8"));
      map.sources.forEach((source: string, i: number) => {
        const resolved = path.resolve(at, map.sourceRoot ?? "", source);
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
  },
);
