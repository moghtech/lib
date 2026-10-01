import path from "path";
import { defineConfig } from "@playwright/test";

/**
 * UI tests against the real thing: the example server serves the built
 * ui (`npm run build` first) on one origin, with the mock identity
 * provider next to it. Both are started (and built) by playwright.
 */

const REPO = path.resolve(import.meta.dirname, "../..");
const DATA = path.resolve(import.meta.dirname, ".e2e");

export const APP_PORT = 9230;
export const IDP_PORT = 9231;
// `localhost` is a secure context, which passkeys need.
export const APP_URL = `http://localhost:${APP_PORT}`;
export const IDP_URL = `http://127.0.0.1:${IDP_PORT}`;

export default defineConfig({
  testDir: "./e2e",
  globalSetup: "./e2e/global-setup.ts",
  // The tests share one server (and its rate limiter, sessions, ...).
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    baseURL: APP_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: [
    {
      command: `cargo run -q -p example_mock_idp -- ${IDP_PORT}`,
      cwd: REPO,
      url: `${IDP_URL}/.well-known/openid-configuration`,
      timeout: 600_000,
      reuseExistingServer: false,
    },
    {
      // A fresh database for every run.
      command: `rm -rf ${JSON.stringify(DATA)} && cargo run -q -p example_server`,
      cwd: REPO,
      url: `${APP_URL}/version`,
      timeout: 600_000,
      reuseExistingServer: false,
      env: {
        EXAMPLE_TITLE: "Example E2E",
        EXAMPLE_HOST: APP_URL,
        EXAMPLE_PORT: String(APP_PORT),
        EXAMPLE_BIND_IP: "127.0.0.1",
        EXAMPLE_DATABASE_PATH: path.join(DATA, "example.db"),
        EXAMPLE_JWT_SECRET: "e2e-jwt-secret",
        EXAMPLE_UI_PATH: path.resolve(import.meta.dirname, "dist"),
        EXAMPLE_BCRYPT_COST: "4",
        // The tests fail logins on purpose, all from one ip.
        EXAMPLE_AUTH_RATE_LIMIT_MAX_ATTEMPTS: "1000",
        // Short, so a test can wait for a login to stop being recent.
        // Every test logs in at its start and is done long before.
        EXAMPLE_REAUTHENTICATION_WINDOW_SECONDS: "15",
        EXAMPLE_OIDC_ENABLED: "true",
        EXAMPLE_OIDC_PROVIDER: IDP_URL,
        EXAMPLE_OIDC_CLIENT_ID: "example-client-id",
        EXAMPLE_OIDC_CLIENT_SECRET: "example-client-secret",
        EXAMPLE_LOGGING_LEVEL: "debug",
      },
    },
  ],
});
