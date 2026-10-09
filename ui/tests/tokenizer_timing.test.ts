import { test } from "node:test";
import assert from "node:assert/strict";
import { loadBuiltin, loadSyntax, tokenizer } from "./monarch.ts";

// Every Monaco language of mogh_ui, through Monaco's own Monarch
// compiler and tokenizer (see ./monarch.ts), on single lines just under
// the longest Monaco tokenizes (20k characters): a pasted base64 bundle,
// a JSON blob, a separator line. Monarch tries every rule at each
// position, and retries one character further along when none matches,
// so a rule which scans a run to its end before it fails made such a
// line quadratic: up to ~1.3 s of main thread per edit of it.
await loadSyntax("key_value", "fancy_toml", "toml", "string_list");
// Monaco's own, which mogh_ui uses as they are.
await loadBuiltin("yaml", "shell");

const LENGTH = 19_990;
const fill = (unit: string) => unit.repeat(Math.floor(LENGTH / unit.length));
const LINES: Record<string, string> = {
  dashes: fill("-"),
  equals: fill("="),
  colons: fill(":"),
  dollars: fill("$"),
  plus: fill("+"),
  dots: fill("a."),
  word: fill("x"),
  alnum: fill("a1"),
  digits: fill("1"),
  // A base64 run without + and /, as long as they come
  base64: fill("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODkw"),
  spaces: fill(" ") + "x",
  unicode: fill("　") + "x",
  json: fill('{"a":[1,2,{"b":"c"}],"d":"e"},'),
  dashedWords: fill("some-long-name-"),
};

/** Where the line is typed: a language, eg. in a fancy_toml string. */
const CONTEXTS: Record<string, () => (line: string) => unknown> = {
  key_value: () => tokenizer("key_value"),
  fancy_toml: () => tokenizer("fancy_toml"),
  'fancy_toml """': () => {
    const tokenize = tokenizer("fancy_toml");
    tokenize('environment = """');
    return tokenize;
  },
  "fancy_toml '''": () => {
    const tokenize = tokenizer("fancy_toml");
    tokenize("environment = '''");
    return tokenize;
  },
  toml: () => tokenizer("toml"),
  string_list: () => tokenizer("string_list"),
  yaml: () => tokenizer("yaml"),
  shell: () => tokenizer("shell"),
};

/** The fastest of two runs, in ms: a GC pause is no slow tokenizer. */
function time(context: string, line: string) {
  let best = Infinity;
  for (let run = 0; run < 2; run++) {
    const tokenize = CONTEXTS[context]();
    tokenize("warm up = 1");
    const start = performance.now();
    tokenize(line);
    best = Math.min(best, performance.now() - start);
  }
  return best;
}

/**
 * The most a line may take, in ms. Linear is a few ms here, quadratic
 * was 140 to 1300 ms. yaml and shell are Monaco's own definitions: a
 * run of non ASCII whitespace or of `"` still takes ~200 ms in its
 * yaml, which is checked here only not to get much worse.
 */
const LIMIT_MS: Record<string, number> = { yaml: 500, shell: 500 };

for (const context of Object.keys(CONTEXTS)) {
  test(`${context}: long lines tokenize in linear time`, () => {
    for (const [kind, line] of Object.entries(LINES)) {
      const elapsed = time(context, line);
      const limit = LIMIT_MS[context] ?? 100;
      assert.ok(
        elapsed < limit,
        `${context}, ${kind}: ${elapsed.toFixed(0)}ms for a ${line.length} char line`,
      );
    }
  });
}
