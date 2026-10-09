import type * as monaco from "monaco-editor";

/**
 * The key of an environment variable entry (`KEY=value`, `KEY: value`,
 * also as a list item `- KEY=value`) and its `=` / `:`, as the groups
 * (indentation and dashes, key, whitespace, "=" or ":", whitespace).
 * Shared by the `key_value` and `fancy_toml` (inside `"""` / `'''`
 * strings) tokenizers.
 *
 * The part before the key can only be read one way: whitespace, then
 * optionally dashes and more whitespace. The previous `\s*-*\s*` could
 * split a run of whitespace between its two `\s*` every possible way,
 * which it tried wherever no key followed. Monarch retries the rules one
 * character further along when none matches, so on a run of whitespace
 * the other rules don't consume (U+00A0, U+3000, ...) that was cubic:
 * seconds for a few thousand characters, freezing the tab.
 */
export const ENV_KEY_VALUE_REGEX =
  /(\s*(?:-+\s*)?)([A-Za-z0-9_]+)(\s*)(=|:)(\s*)/;

/** The rule of an environment variable entry's key and its `=` / `:`. */
export const ENV_KEY_VALUE_RULE: monaco.languages.IMonarchLanguageRule = [
  ENV_KEY_VALUE_REGEX,
  [
    "", // Indentation, a list item's leading hyphen
    "key", // Key (environment variable)
    "", // Whitespace
    "operator.assignment", // Equals sign (=) or colon (:)
    "", // Whitespace
  ],
];

/**
 * Whitespace between the values, any Unicode whitespace like `\s` (not
 * only ASCII). A run is consumed at once, so the rules before it are
 * tried once for it rather than at each of its characters.
 */
export const WHITESPACE_REGEX = /\s+/;

/**
 * A run of characters none of the value rules starts at: consumed at
 * once, after every other rule failed at its first character. Monarch
 * otherwise retries all the rules one character further along, and the
 * key rules scan to the end of such a run before they fail: quadratic
 * in the run's length, up to about a second for a pasted line near the
 * longest Monaco tokenizes (20k characters). It stops at what the rules
 * do start at: whitespace, quotes, a comment's `#`, brackets, and the
 * `:` / `=` after a key.
 */
export const PLAIN_RUN_REGEX = /[^\s\[\]{},"'#:=]+/;
