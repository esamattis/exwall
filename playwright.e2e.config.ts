import { readlinkSync } from "node:fs";
import { defineConfig, devices } from "@playwright/test";

if (
    !process.env.EXWALL_E2E_URL ||
    !process.env.EXWALL_E2E_CHROMIUM ||
    !process.env.EXWALL_E2E_CLIENT_SOCKET
) {
    throw new Error("Run ./e2e_tests.sh to create disposable firewall namespaces first.");
}

if (readlinkSync("/proc/self/ns/net") !== process.env.EXWALL_E2E_HOST_NET_NS) {
    throw new Error("Playwright must run in the launcher's host network namespace.");
}

/** Run real UI/firewall tests only through the disposable namespace launcher. */
export default defineConfig({
    testDir: "./ui/e2e",
    workers: 1,
    retries: 0,
    forbidOnly: Boolean(process.env.CI),
    timeout: 60_000,
    outputDir: process.env.EXWALL_E2E_OUTPUT,
    reporter: "list",
    use: {
        ...devices["Desktop Chrome"],
        baseURL: process.env.EXWALL_E2E_URL,
        serviceWorkers: "block",
        trace: "retain-on-failure",
        screenshot: "only-on-failure",
        launchOptions: {
            executablePath: process.env.EXWALL_E2E_CHROMIUM,
            args: ["--disable-quic", "--no-proxy-server"],
        },
    },
});
