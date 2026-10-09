import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { releaseDate } from "mogh_supporter/vite";
import packageJson from "./package.json";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  define: {
    // The release date the supporter badge compares keys with, never
    // the clock: a key covers the releases published up to a date. It
    // is the `releaseDate` of package.json, bumped with the version, so
    // a rebuild keeps it. A production build fails without one, the dev
    // server falls back to today.
    __RELEASE_DATE__: JSON.stringify(releaseDate({ mode, packageJson })),
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
}));
