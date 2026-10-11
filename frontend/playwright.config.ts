import { defineConfig, devices } from "@playwright/test";

// End-to-end tests drive a real browser against the running stack
// (docker compose up -d backend frontend, with ./workspace/shop seeded; see e2e/README.md).
// They are separate from `npm test` (Vitest) because they need Docker.
export default defineConfig({
  testDir: "./e2e",
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3000",
    // Locally, E2E_CHANNEL=chrome reuses the installed Chrome (no browser download).
    channel: process.env.E2E_CHANNEL || undefined,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
