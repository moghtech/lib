/**
 * The key of a TOML `key = value` entry (bare, quoted or dotted keys)
 * and its `=`, as the groups (key, "="). Shared by the `toml` and
 * `fancy_toml` tokenizers.
 *
 * Monarch requires the groups of a rule to cover the whole match, so
 * the whitespace around the key (indentation, `key = `) is part of the
 * key group. Otherwise the rule throws and the line loses its tokens.
 *
 * Key segments must be joined by a dot, so a run of word characters can
 * only be read one way. The previous `(?:segment\s*\.?\s*)+` could split
 * it into segments every possible way, which it tried on any line
 * without `=`: the time doubled with each character (seconds for a 30
 * character bare word), freezing the tab.
 */
export const TOML_KEY_VALUE_REGEX =
  /(\s*(?:[A-Za-z0-9_+\-]+|"[^"]*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_+\-]+|"[^"]*"|'[^']*'))*\s*)(=)/;

/**
 * In a TOML line, a run of whitespace, or of characters none of the
 * rules starts at, consumed at once after every other rule failed at its
 * first character (see `PLAIN_RUN_REGEX` of env_key.ts): the key rule
 * scans such a run (a bare word, dashes, indentation) to its end before
 * it fails, which retried at each character was quadratic in its length.
 */
export const TOML_PLAIN_RUN_REGEX = /\s+|[^\s\[\]{},"'#=]+/;
