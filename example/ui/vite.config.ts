import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
// The `YYYY-MM-DD` of this build, for the supporter badge: a key covers
// the releases published up to a date, compared against the build,
// never the clock. A release process sets EXAMPLE_RELEASE_DATE.
const RELEASE_DATE =
  process.env.EXAMPLE_RELEASE_DATE ?? new Date().toISOString().slice(0, 10);

export default defineConfig({
  plugins: [react()],
  define: {
    __RELEASE_DATE__: JSON.stringify(RELEASE_DATE),
  },
  server: {
    port: 9222,
  },
  resolve: {
    alias: [
      { find: "@", replacement: path.resolve(import.meta.dirname, "./src") },
      // monaco-editor >= 0.53 has an exports map, legacy deep imports
      // (used by monaco-yaml's worker) have to be rewritten to it.
      {
        find: /^monaco-editor\/esm\/vs\/(.*)$/,
        replacement: "monaco-editor/$1",
      },
    ],
    // mogh_ui and the clients are linked from this repository, and have
    // their own node_modules. These have to be the same instance everywhere.
    dedupe: [
      "@mantine/core",
      "@mantine/form",
      "@mantine/hooks",
      "@mantine/notifications",
      "@monaco-editor/react",
      "@tanstack/react-table",
      "@tanstack/react-query",
      "lucide-react",
      "mogh_auth_client",
      "mogh_supporter",
      "monaco-editor",
      "monaco-yaml",
      "react",
      "react-dom",
      "react-router-dom",
    ],
  },
  optimizeDeps: {
    exclude: ["mogh_ui", "example_client", "mogh_auth_client", "mogh_supporter"],
    include: [
      "path-browserify",
      "@mantine/form",
      "@tanstack/react-table",
      "jwt-decode",
    ],
  },
  build: {
    chunkSizeWarningLimit: 4000,
  },
  css: {
    preprocessorOptions: {
      scss: {
        additionalData: '@use "mogh_ui/theme.scss" as theme;',
      },
    },
  },
});
