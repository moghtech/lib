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
    const maps = readdirSync(dist, {
      recursive: true,
      encoding: "utf8",
    }).filter((file) => file.endsWith(".map"));
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

/** A version as [major, minor, patch]. */
function version(text: string): number[] {
  const parts = text.split("-")[0].split(".").map(Number);
  assert.ok(parts.length === 3 && parts.every(Number.isInteger), text);
  return parts;
}

function compare(a: number[], b: number[]) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

/**
 * The versions a range allows, as [lowest, above]: `^x.y.z` (npm's
 * caret: up to the next major, or minor / patch for 0.x) or an exact
 * `x.y.z`, `above` excluded.
 */
function bounds(range: string): [number[], number[]] {
  if (!range.startsWith("^")) {
    const exact = version(range);
    return [exact, [exact[0], exact[1], exact[2] + 1]];
  }
  const low = version(range.slice(1));
  const [major, minor, patch] = low;
  const above =
    major > 0
      ? [major + 1, 0, 0]
      : minor > 0
        ? [0, minor + 1, 0]
        : [0, 0, patch + 1];
  return [low, above];
}

/** Whether every version `range` allows is one `peer` allows. */
function within(range: string, peer: string) {
  const [low, above] = bounds(range);
  const [peerLow, peerAbove] = bounds(peer);
  return compare(low, peerLow) >= 0 && compare(above, peerAbove) <= 0;
}

test("the example app runs mogh_ui on versions of its peer ranges", () => {
  // The example (lib/example/ui) is the e2e harness of mogh_ui: it has
  // to run it on the versions mogh_ui requires, which the apps ship,
  // not older ones its own ranges allow.
  const ui = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  const exampleDir = path.join(root, "..", "example", "ui");
  const example = JSON.parse(
    readFileSync(path.join(exampleDir, "package.json"), "utf8"),
  );
  const declared: Record<string, string> = {
    ...example.devDependencies,
    ...example.dependencies,
  };
  for (const [name, peer] of Object.entries<string>(ui.peerDependencies)) {
    const range = declared[name];
    if (range === undefined) {
      assert.ok(
        ui.peerDependenciesMeta?.[name]?.optional,
        `the example doesn't install ${name}, a peer of mogh_ui`,
      );
      continue;
    }
    if (range.startsWith("file:")) {
      // Linked from this repository: its own version counts.
      const linked = JSON.parse(
        readFileSync(
          path.join(exampleDir, range.slice("file:".length), "package.json"),
          "utf8",
        ),
      ).version;
      assert.ok(
        within(linked, peer),
        `${name} ${linked} (linked) isn't in mogh_ui's peer range ${peer}`,
      );
      continue;
    }
    assert.ok(
      within(range, peer),
      `the example's ${name} ${range} allows versions outside mogh_ui's peer range ${peer}`,
    );
  }
});
