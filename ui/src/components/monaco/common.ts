import { BoxProps } from "@mantine/core";

export type MonacoLanguage =
  | "yaml"
  | "toml"
  | "fancy_toml"
  | "json"
  | "key_value"
  | "ini"
  | "string_list"
  | "shell"
  | "dockerfile"
  | "caddyfile"
  | "corefile"
  | "rust"
  | "javascript"
  | "typescript";

const LANGUAGE_EXTENSIONS: Record<MonacoLanguage, string[]> = {
  yaml: [".yaml", ".yml"],
  toml: [".toml"],
  fancy_toml: [],
  json: [".json"],
  key_value: [".env", ".conf"],
  ini: [".ini"],
  string_list: [],
  shell: [".sh", ".bash", ".zsh"],
  dockerfile: ["Dockerfile"],
  caddyfile: ["Caddyfile", ".caddyfile", ".caddy"],
  corefile: ["Corefile", ".corefile"],
  rust: [".rs"],
  javascript: [".js", ".jsx", ".mjs", ".cjs"],
  typescript: [".ts", ".tsx"],
};

/**
 * File names which are a language's name and a variant after a dot:
 * `Dockerfile.prod`, `Caddyfile.dev`, `Corefile.local`. Checked after
 * `LANGUAGE_EXTENSIONS`, so `Caddyfile.json` is json.
 */
const LANGUAGE_NAME_PREFIXES: Partial<Record<MonacoLanguage, string[]>> = {
  dockerfile: ["Dockerfile."],
  caddyfile: ["Caddyfile."],
  corefile: ["Corefile."],
};

/**
 * The language of a file, by the end of its name (an extension, or a
 * name like `Caddyfile` / `name.Caddyfile`) or the start of its base
 * name (`Caddyfile.dev`). Case sensitive.
 */
export function languageFromPath(path: string) {
  for (const [lang, extensions] of Object.entries(LANGUAGE_EXTENSIONS)) {
    for (const extension of extensions) {
      if (path.endsWith(extension)) {
        return lang as MonacoLanguage;
      }
    }
  }
  const name = path.split("/").pop() ?? path;
  for (const [lang, prefixes] of Object.entries(LANGUAGE_NAME_PREFIXES)) {
    for (const prefix of prefixes) {
      if (name.startsWith(prefix)) {
        return lang as MonacoLanguage;
      }
    }
  }
  return undefined;
}

export interface MonacoEditorProps extends BoxProps {
  value: string | undefined;
  onValueChange?: (value: string) => void;
  language: MonacoLanguage | undefined;
  enableFancyToml?: boolean;
  filename?: string;
  readOnly?: boolean;
  minHeight?: number;
  /** Define max height as proportion of dimension height. Should be between 0 and 1. */
  maxHeightProportion?: number;
  maxHeight?: number;
  id?: string;
}

export interface MonacoDiffEditorProps extends BoxProps {
  original: string | undefined;
  modified: string | undefined;
  onModifiedValueChange?: (value: string) => void;
  language: MonacoLanguage | undefined;
  enableFancyToml?: boolean;
  readOnly?: boolean;
  id?: string;
  hideUnchangedRegions?: boolean;
}
