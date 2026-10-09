import { defineConfig } from "vitest/config";

// The hook and component tests (`tests/**/*.test.tsx`), rendered with
// React in jsdom. The other tests (`tests/**/*.test.ts`) run in node's
// own runner, which can't load `.tsx`: `npm test` runs both.
export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["tests/**/*.test.tsx"],
    setupFiles: ["tests/setup-dom.ts"],
    // Node >= 22 has a `localStorage` of its own (file backed, and
    // without `--localstorage-file` not working), which would shadow
    // jsdom's in the workers. The login tokens are kept there.
    execArgv: ["--no-experimental-webstorage"],
  },
});
