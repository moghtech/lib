import { test } from "node:test";
import assert from "node:assert/strict";
import { loadSyntax, tokenAt, tokenizer } from "./monarch.ts";
import { ENV_KEY_VALUE_REGEX } from "../src/components/monaco/syntax/env_key.ts";

// The real `key_value` / `fancy_toml` definitions, through Monaco's own
// Monarch compiler and tokenizer (see ./monarch.ts).
await loadSyntax("key_value", "fancy_toml");

/**
 * A tokenizer for environment variables: `key_value`, or `fancy_toml`
 * inside a triple quoted string (eg. a resource sync's `environment`).
 */
function envTokenizer(context: string) {
  switch (context) {
    case "key_value":
      return tokenizer("key_value");
    case 'fancy_toml """':
    case "fancy_toml '''": {
      const tokenize = tokenizer("fancy_toml");
      tokenize(`environment = ${context.slice(-3)}`);
      return tokenize;
    }
    default:
      throw new Error(context);
  }
}

const CONTEXTS = ["key_value", 'fancy_toml """', "fancy_toml '''"];

test("environment variable entries tokenize their key and '=' / ':'", () => {
  const lines: [string, string][] = [
    ["KEY=1", "KEY"],
    ["KEY: 1", "KEY"],
    ["KEY = value", "KEY"],
    ["  KEY=1", "KEY"],
    ["- KEY=1", "KEY"],
    ["  - KEY: 1", "KEY"],
    ["--KEY=1", "KEY"],
    ["\tKEY_2=x", "KEY_2"],
    // Unicode whitespace is whitespace too
    [" KEY=1", "KEY"],
    ["　- KEY=1", "KEY"],
  ];
  for (const context of CONTEXTS) {
    const tokenize = envTokenizer(context);
    for (const [line, key] of lines) {
      const tokens = tokenize(line);
      const start = line.indexOf(key);
      const operator = line.search(/[=:]/);
      const label = `${context}: ${JSON.stringify(line)}`;
      assert.match(tokenAt(tokens, start) ?? "", /^key\./, label);
      assert.match(
        tokenAt(tokens, operator) ?? "",
        /^(operator\.assignment|delimiter)\./,
        label,
      );
    }
  }
});

test("environment variable key rule reads the part before the key one way", () => {
  const anchored = new RegExp("^(?:" + ENV_KEY_VALUE_REGEX.source + ")");
  const cases: [string, string, string][] = [
    ["KEY=1", "", "KEY"],
    ["  - KEY: 1", "  - ", "KEY"],
    ["- KEY = v", "- ", "KEY"],
    ["--KEY=1", "--", "KEY"],
    [" 　KEY=1", " 　", "KEY"],
  ];
  for (const [line, prefix, key] of cases) {
    const match = anchored.exec(line);
    assert.ok(match, line);
    // Monarch throws unless the groups cover the whole match
    assert.equal(match.slice(1).join(""), match[0], line);
    assert.equal(match[1], prefix, line);
    assert.equal(match[2], key, line);
  }
  assert.equal(anchored.exec("  - "), null);
  assert.equal(anchored.exec("- = 1"), null);
});

test("long runs of whitespace tokenize fast", () => {
  // Whitespace only `\s` matches, not ASCII space / tab. The old rule
  // took seconds for a few thousand characters (cubic), minutes near
  // the longest line Monaco tokenizes (20k characters).
  const RUN = 4_000;
  const lines = [
    " ".repeat(RUN) + "!",
    "　".repeat(RUN) + "!",
    "    ﻿\v\f".repeat(RUN / 7) + "!",
    "- " + " ".repeat(RUN) + "!",
    "KEY" + " ".repeat(RUN) + "!",
    " ".repeat(RUN) + "!",
  ];
  for (const context of CONTEXTS) {
    for (const line of lines) {
      const tokenize = envTokenizer(context);
      const start = performance.now();
      tokenize(line);
      const elapsed = performance.now() - start;
      assert.ok(
        elapsed < 1_000,
        `${context}: ${elapsed.toFixed(0)}ms for a ${line.length} char line`,
      );
    }
  }
});

test("values after a plain run still tokenize", () => {
  // The run of plain characters is consumed at once: what follows it
  // is tokenized as before.
  const cases: [string, string, RegExp][] = [
    ["KEY=some-value 123", "123", /^number/],
    ["KEY=some-value # note", "# note", /^comment/],
    ["KEY=some-value 'quoted'", "'quoted'", /^string/],
    ['KEY=some-value "quoted"', '"quoted"', /^string/],
    ["KEY=some-value true", "true", /^constant\.language\.boolean/],
    ["KEY=some-value nested: 1", "nested", /^key/],
    ["KEY=some-value NEXT=1", "NEXT", /^key/],
  ];
  for (const context of CONTEXTS) {
    const tokenize = envTokenizer(context);
    for (const [line, part, type] of cases) {
      const tokens = tokenize(line);
      const label = `${context}: ${JSON.stringify(line)}`;
      assert.match(tokenAt(tokens, line.lastIndexOf(part)) ?? "", type, label);
    }
  }
});
