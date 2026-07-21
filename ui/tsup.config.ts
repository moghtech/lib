import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/**/*.{ts,tsx}", "!src/**/*.d.ts"],
  format: ["esm", "cjs"],
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
    "@mantine/hooks",
    "@mantine/notifications",
    "@tanstack/react-table",
    "lucide-react",
    "@monaco-editor/react",
    "monaco-editor",
    "monaco-yaml",
    /\.scss$/,
  ],
});
