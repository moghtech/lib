import * as monaco from "monaco-editor";
import { TOML_KEY_VALUE_REGEX, TOML_PLAIN_RUN_REGEX } from "./toml_key";

// TOML. `fancy_toml` (fancy_toml.ts) is this, with yaml / environment
// variables inside its triple quoted strings.

export const toml_conf: monaco.languages.LanguageConfiguration = {
  comments: { lineComment: "#" },
  brackets: [
    ["{", "}"],
    ["[", "]"],
    ["(", ")"],
  ],
  autoClosingPairs: [
    { open: "{", close: "}" },
    { open: "[", close: "]" },
    { open: "(", close: ")" },
    { open: '"', close: '"' },
    { open: "'", close: "'" },
    { open: '"""', close: '"""' },
  ],
  surroundingPairs: [
    { open: "{", close: "}" },
    { open: "[", close: "]" },
    { open: "(", close: ")" },
    { open: '"', close: '"' },
    { open: "'", close: "'" },
    { open: '"""', close: '"""' },
  ],
};

export const toml_language: monaco.languages.IMonarchLanguage = {
  defaultToken: "",
  tokenPostfix: ".toml",

  escapes: /\\(?:[btnfr"'\\\/]|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,

  tokenizer: {
    root: [
      { include: "@comments" },

      /* Tables & array-tables */
      [
        /^(\s*\[\[)([^[\]]+)(\]\])/,
        [
          "punctuation.definition.array.table",
          "entity.other.attribute-name.table.array",
          "punctuation.definition.array.table",
        ],
      ],
      [
        /^(\s*\[)([^[\]]+)(\])/,
        [
          "punctuation.definition.table",
          "entity.other.attribute-name.table",
          "punctuation.definition.table",
        ],
      ],

      /* Inline tables */
      [
        /\{/,
        { token: "punctuation.definition.table.inline", next: "@inlineTable" },
      ],

      /* Key-value pair */
      [TOML_KEY_VALUE_REGEX, ["", "delimiter"]],

      /* Values */
      { include: "@values" },

      /* Anything else, a run at once (not quadratic in its length) */
      [TOML_PLAIN_RUN_REGEX, ""],
    ],

    inlineTable: [
      [/\}/, { token: "punctuation.definition.table.inline", next: "@pop" }],
      { include: "@comments" },
      [/,/, "punctuation.separator.table.inline"],
      { include: "@values" },
    ],

    values: [
      /* Strings: their own state, which fancy_toml replaces */
      { include: "@strings" },

      /* Dates, times, booleans */
      [
        /\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})/,
        "constant.other.time.datetime.offset",
      ],
      [
        /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?/,
        "constant.other.time.datetime.local",
      ],
      [/\d{4}-\d{2}-\d{2}/, "constant.other.time.date"],
      [/\d{2}:\d{2}:\d{2}(?:\.\d+)?/, "constant.other.time.time"],
      [/\b(true|false)\b/, "constant.language.boolean"],

      /* Numbers, not the digits inside a word */
      [/[+-]?(0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+)/, "number.hex"],
      [
        /(?<!\w)([+-]?(0|([1-9](([0-9]|_[0-9])+)?))(?:(?:\.(0|([1-9](([0-9]|_[0-9])+)?)))?[eE][+-]?[1-9]_?[0-9]*|(?:\.[0-9_]*)))(?!\w)/,
        "number.float",
      ],
      [/(?<!\w)((?:[+-]?(0|([1-9](([0-9]|_[0-9])+)?))))(?!\w)/, "number"],

      /* Arrays */
      [/\[/, { token: "punctuation.definition.array", next: "@array" }],
    ],

    strings: [
      [/"""/, { token: "string", next: "@tripleBasicString" }],
      [/"/, { token: "string", next: "@basicString" }],
      [/'''/, { token: "string", next: "@tripleLiteralString" }],
      [/'/, { token: "string", next: "@literalStringSingle" }],
    ],

    array: [
      [/\]/, { token: "punctuation.definition.array", next: "@pop" }],
      [/,/, "punctuation.separator.array"],
      { include: "@values" },
    ],

    basicString: [
      [/[^\\"]+/, "string"],
      [/@escapes/, "string.escape"],
      [/\\./, "invalid"],
      [/"/, { token: "string", next: "@pop" }],
    ],

    tripleBasicString: [
      [/"""/, { token: "string", next: "@pop" }],
      [/[^\\"]+/, "string"],
      [/@escapes/, "string.escape"],
      [/\\./, "string.invalid"],
    ],

    literalStringSingle: [
      [/[^']+/, "string"],
      [/'/, { token: "string", next: "@pop" }],
    ],

    tripleLiteralString: [
      [/'''/, { token: "string", next: "@pop" }],
      [/[^']+/, "string"],
    ],

    comments: [[/\s*((#).*)$/, "comment"]],
  },
};

monaco.languages.register({ id: "toml" });
monaco.languages.setLanguageConfiguration("toml", toml_conf);
monaco.languages.setMonarchTokensProvider("toml", toml_language);
