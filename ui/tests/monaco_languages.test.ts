import { test } from "node:test";
import assert from "node:assert/strict";
import {
  loadBuiltin,
  loadSyntax,
  loadThemes,
  themes,
  tokenAt,
  tokenizer,
} from "./monarch.ts";

await loadSyntax("toml", "fancy_toml");
await loadBuiltin("yaml");
await loadThemes();
const { vs, vs_dark } = await import(
  // @ts-ignore: monaco-editor ships no types for its internals
  "monaco-editor/editor/standalone/common/themes.js"
);

test("fancy_toml is toml outside its triple quoted strings", () => {
  // One tokenizer, toml.ts's: fancy_toml only reads the triple quoted
  // strings as yaml / environment variables.
  const document = [
    "# A sync",
    "[[stack]]",
    'name = "web"',
    "  [stack.config]",
    "server = 'local'",
    "tags = [\"a\", 'b', 1, 2.5, -3, 0x1F, true]",
    'inline = { a = 1, b = "two" }',
    "date = 1979-05-27T07:32:00Z",
    'escaped = "tab\\tquote\\""',
    "plain-run-without-equals ---- $$$",
  ];
  const toml = tokenizer("toml");
  const fancy = tokenizer("fancy_toml");
  const types = (tokens: { offset: number; type: string }[]) =>
    tokens.map(({ offset, type }) => [offset, type]);
  for (const line of document) {
    assert.deepEqual(types(fancy(line)), types(toml(line)), line);
  }
  // Inside a triple quoted string fancy_toml reads environment
  // variables, toml a string.
  toml('environment = """');
  fancy('environment = """');
  assert.equal(tokenAt(toml("KEY=1"), 0), "string.toml");
  assert.equal(tokenAt(fancy("KEY=1"), 0), "key.toml");
});

test("Monaco's yaml keys are coloured like the keys of the other languages", () => {
  // mogh_ui uses Monaco's yaml as it is, which names its keys `type`.
  const tokens = tokenizer("yaml")("services: web");
  assert.equal(tokenAt(tokens, 0), "type.yaml");
  const key = (theme: { rules: { token: string; foreground?: string }[] }) =>
    theme.rules.find((rule) => rule.token === "key")?.foreground;
  const yamlKey = (name: string) =>
    themes[name].rules.find((rule) => rule.token === "type.yaml")?.foreground;
  assert.equal(yamlKey("light"), key(vs));
  assert.equal(yamlKey("dark"), key(vs_dark));
  // The base themes the two inherit from.
  assert.ok(key(vs) && key(vs_dark));
});
