import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

test("relative imports in dist have a .js extension", () => {
  // The sources import `.ts` files, rewritten by tsc for the build.
  const dist = path.join(root, "dist");
  const files = readdirSync(dist).filter((file) => file.endsWith(".js"));
  assert.ok(files.includes("index.js"), "build first (npm run build)");
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

test("the package ships no root keys, and the revocation list a release has", async () => {
  const index = await import("../src/index.ts");
  // Each app hardcodes its own root keys.
  assert.ok(!("ROOT_KEYS" in index));
  for (const id of index.REVOKED) {
    assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  }
  assert.ok(Object.isFrozen(index.REVOKED));
});

test("an app's root keys are checked", async () => {
  const { checkRootKeys, rootKeyId, FIXTURE_ROOT_KEY_ID } = await import("../src/index.ts");
  const fixture = await import("./fixture.ts");
  assert.equal(FIXTURE_ROOT_KEY_ID, fixture.ROOT_KID);
  // No root keys yet: no key verifies, which is fine.
  assert.deepEqual(await checkRootKeys([]), []);
  // Another key than the fixture's test root.
  const der = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from("19d3d919475deed4696b5d13018151d1af88b2bd3bcff048b45031c1f36d1858", "hex"),
  ]);
  const spki = der.toString("base64");
  const kid = await rootKeyId(spki);
  // Their ids, in order: to compare with what the platform published.
  const rfc = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
  assert.deepEqual(await checkRootKeys([spki, rfc]), [kid, await rootKeyId(rfc)]);
  // The test root of the fixture is public.
  await assert.rejects(checkRootKeys([spki, ...fixture.ROOT_KEYS]), /test root of the fixture/);
  // Not a key at all: named by its position.
  await assert.rejects(
    checkRootKeys([spki, "MCowBQYDK2VwAyEA"]),
    /The root key at position 2 is not valid \| .*not the SPKI DER of an Ed25519 key/,
  );
  await assert.rejects(checkRootKeys(["not base64!"]), /The root key at position 1 is not valid/);
  // Listed twice, also when written another way.
  await assert.rejects(checkRootKeys([spki, ` ${spki}\n`]), new RegExp(`The root key ${kid} is listed twice`));
});


test("the generated types pin the api's enums", async () => {
  const { Types } = await import("../src/index.ts");
  assert.equal(Types.Tier.Organization, "organization");
  assert.equal(Types.Tier.Individual, "individual");
  assert.equal(Types.Tier.Sponsor, "sponsor");
  assert.equal(Types.SupporterKeySource.Stored, "Stored");
  assert.equal(Types.SupporterKeySource.Config, "Config");
  assert.equal(Types.SupporterKeySource.None, "None");
});

test("generate_types fails when typeshare fails", () => {
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
