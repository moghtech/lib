import * as monaco from "monaco-editor";
import { ENV_KEY_VALUE_RULE, PLAIN_RUN_REGEX } from "./env_key";
import { toml_conf, toml_language } from "./toml";
import { YAML_VALUE_RULES, YAML_VALUE_STATES } from "./yaml_values";

// TOML (toml.ts) whose triple quoted strings hold yaml or environment
// variables, eg. a resource's `environment = """ ... """`.

/** Inside a triple quoted string, up to its closing quotes. */
const yamlEnvString = (
  close: RegExp,
): monaco.languages.IMonarchLanguageRule[] => [
  [close, { token: "string", next: "@pop" }],
  ...YAML_VALUE_RULES,
  ENV_KEY_VALUE_RULE,
  // Anything else, a run at once (not quadratic in its length)
  [PLAIN_RUN_REGEX, ""],
];

const fancy_toml_language: monaco.languages.IMonarchLanguage = {
  ...toml_language,
  tokenizer: {
    ...toml_language.tokenizer,
    strings: [
      [/"""/, { token: "string", next: "@tripleStringWithYamlEnv" }],
      [/"/, { token: "string", next: "@basicString" }],
      [/'''/, { token: "string", next: "@literalTripleStringWithYamlEnv" }],
      [/'/, { token: "string", next: "@literalStringSingle" }],
    ],
    tripleStringWithYamlEnv: yamlEnvString(/"""/),
    literalTripleStringWithYamlEnv: yamlEnvString(/'''/),
    ...YAML_VALUE_STATES,
  },
};

monaco.languages.register({ id: "fancy_toml" });
monaco.languages.setLanguageConfiguration("fancy_toml", toml_conf);
monaco.languages.setMonarchTokensProvider("fancy_toml", fancy_toml_language);
