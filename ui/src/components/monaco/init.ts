import * as monaco from "monaco-editor";

// The `?worker` import pattern is Vite's officially supported way to load
// workers from dependencies. The previous `new URL("monaco-editor/...", import.meta.url)`
// pattern breaks under rolldown-based Vite, which resolves the bare specifier
// relative to this file instead of through node module resolution.
//
// Paths must NOT include the `esm/vs` prefix: monaco-editor's exports map is
// `"./*.js": "./esm/vs/*.js"`, so legacy `monaco-editor/esm/vs/...` specifiers
// no longer resolve.
import EditorWorker from "monaco-editor/editor/editor.worker.js?worker";
import JsonWorker from "monaco-editor/language/json/json.worker.js?worker";
import CssWorker from "monaco-editor/language/css/css.worker.js?worker";
import HtmlWorker from "monaco-editor/language/html/html.worker.js?worker";
import TsWorker from "monaco-editor/language/typescript/ts.worker.js?worker";
import YamlWorker from "monaco-yaml/yaml.worker.js?worker";

self.MonacoEnvironment = {
  getWorker(_, label) {
    if (label === "json") {
      return new JsonWorker();
    }
    if (label === "css" || label === "scss" || label === "less") {
      return new CssWorker();
    }
    if (label === "html" || label === "handlebars" || label === "razor") {
      return new HtmlWorker();
    }
    if (label === "typescript" || label === "javascript") {
      return new TsWorker();
    }
    if (label === "yaml") {
      return new YamlWorker();
    }
    return new EditorWorker();
  },
};

import { loader } from "@monaco-editor/react";
loader.config({ monaco });

// Load the themes
import "./theme";
// Load the parsers
import "./syntax/yaml";
import "./syntax/toml";
import "./syntax/fancy_toml";
import "./syntax/shell";
import "./syntax/key_value";
import "./syntax/string_list";
