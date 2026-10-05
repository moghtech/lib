import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/**/*.{ts,tsx}", "!src/**/*.d.ts"],
  // ESM only, for bundlers (see README): the sources import .scss modules
  // and Vite `?worker`s, and keep extensionless relative imports, so
  // neither format could load in plain Node. The old CJS build even
  // resolved its `require("./x")` to the ESM files.
  format: ["esm"],
  bundle: false,
  shims: true,
  // d.ts emit is handled by `tsc --emitDeclarationOnly` in the build script;
  // tsup's dts (rollup-plugin-dts) is incompatible with typescript 7
  dts: false,
  sourcemap: true,
  clean: true,
  external: [
    "react",
    "react-dom",
    "react-router-dom",
    "@mantine/core",
    "@mantine/form",
    "@mantine/hooks",
    "@mantine/notifications",
    "@tanstack/react-query",
    "@tanstack/react-table",
    "lucide-react",
    "@monaco-editor/react",
    "monaco-editor",
    "monaco-yaml",
    "mogh_auth_client",
    "mogh_supporter",
    "prettier",
    /\.scss$/,
  ],
});
