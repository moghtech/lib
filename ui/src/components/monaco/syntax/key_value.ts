import * as monaco from "monaco-editor";
import { ENV_KEY_VALUE_RULE, PLAIN_RUN_REGEX } from "./env_key";
import { YAML_VALUE_RULES, YAML_VALUE_STATES } from "./yaml_values";

// Environment variables (`KEY=value`, `KEY: value`, as list items too),
// their values read as yaml.

const key_value_conf: monaco.languages.LanguageConfiguration = {
  comments: {
    lineComment: "#",
  },
  brackets: [],
  autoClosingPairs: [
    { open: '"', close: '"' },
    { open: "'", close: "'" },
  ],
  surroundingPairs: [
    { open: '"', close: '"' },
    { open: "'", close: "'" },
  ],
};

const key_value_language: monaco.languages.IMonarchLanguage = {
  defaultToken: "",
  tokenPostfix: ".env",

  escapes:
    /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,

  tokenizer: {
    root: [
      ENV_KEY_VALUE_RULE,
      ...YAML_VALUE_RULES,
      // Anything else, a run at once (not quadratic in its length)
      [PLAIN_RUN_REGEX, ""],
    ],
    ...YAML_VALUE_STATES,
  },
};

monaco.languages.register({ id: "key_value" });
monaco.languages.setLanguageConfiguration("key_value", key_value_conf);
monaco.languages.setMonarchTokensProvider("key_value", key_value_language);
