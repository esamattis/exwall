import { defineConfig, devices } from "@playwright/test";

/** Run browser tests against Vite with all REST endpoints mocked in each test. */
export default defineConfig({
    testDir: "./ui/tests",
    fullyParallel: true,
    forbidOnly: Boolean(process.env.CI),
    retries: process.env.CI ? 2 : 0,
    use: {
        baseURL: "http://127.0.0.1:5174",
        serviceWorkers: "block",
        trace: "retain-on-failure",
    },
    projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
    webServer: {
        command: "pnpm dev --port 5174",
        url: "http://127.0.0.1:5174",
        reuseExistingServer: false,
    },
});
