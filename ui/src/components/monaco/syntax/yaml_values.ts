import type * as monaco from "monaco-editor";
import { WHITESPACE_REGEX } from "./env_key";

type Rule = monaco.languages.IMonarchLanguageRule;

// A yaml value, as `key_value` reads the value of an environment
// variable and `fancy_toml` the yaml / environment variables inside a
// triple quoted string: the rules in their order, and the states they
// use. Each language includes them, and its strings read its own
// `@escapes`.

/** The rules of a yaml value, to spread into a state. */
export const YAML_VALUE_RULES: Rule[] = [
  { include: "@yaml_whitespace" },
  { include: "@yaml_comments" },
  { include: "@yaml_keys" },
  { include: "@yaml_numbers" },
  { include: "@yaml_booleans" },
  { include: "@yaml_strings" },
  { include: "@yaml_constants" },
];

/** The states `YAML_VALUE_RULES` use, to spread into the tokenizer. */
export const YAML_VALUE_STATES: Record<string, Rule[]> = {
  yaml_whitespace: [[WHITESPACE_REGEX, ""]],

  yaml_comments: [[/#.*$/, "comment"]],

  // The key can't hold the ':' / '=' it ends at: on a run without one
  // it fails at the run's end, not after backing off through it.
  yaml_keys: [[/([^\s\[\]{},"':=]+)(\s*)(:)/, ["key", "", "delimiter"]]],

  yaml_numbers: [
    [/\b\d+\.\d*\b/, "number.float"],
    [/\b0x[0-9a-fA-F]+\b/, "number.hex"],
    [/\b\d+\b/, "number"],
  ],

  yaml_booleans: [
    [/\b(true|false|yes|no|on|off)\b/, "constant.language.boolean"],
  ],

  yaml_strings: [
    [/"([^"\\]|\\.)*$/, "string.invalid"], // non-terminated string
    [/'([^'\\]|\\.)*$/, "string.invalid"], // non-terminated string
    [/"/, "string", "@yaml_string_double"],
    [/'/, "string", "@yaml_string_single"],
  ],

  yaml_string_double: [
    [/[^\\"]+/, "string"],
    [/@escapes/, "string.escape"],
    [/\\./, "string.escape.invalid"],
    [/"/, "string", "@pop"],
  ],

  yaml_string_single: [
    [/[^\\']+/, "string"],
    [/@escapes/, "string.escape"],
    [/\\./, "string.escape.invalid"],
    [/'/, "string", "@pop"],
  ],

  yaml_constants: [[/\b(null|~)\b/, "constant.language.null"]],
};
