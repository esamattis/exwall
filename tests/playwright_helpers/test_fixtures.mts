/** Reusable Playwright resources, policy isolation, authentication, and failure artifacts. @module */
import { test as base, expect } from "@playwright/test";
import type { Page, TestInfo } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fixtureOperation, fixtureRules, writeFixtureRules } from "#playwright_helpers/client.mts";
import { startProtocolFixture } from "#playwright_helpers/proxy_fixture.mts";

/** Rules captured through the API before a test changes the shared policy. */
export interface RulesDocument {
    revision: string;
    rules: { index: number | null; fields: Record<string, unknown> }[];
}

/** Resources requested explicitly by tests or enabled by the policy-specific test exports. */
interface Fixtures {
    protocolProxy: Awaited<ReturnType<typeof startProtocolFixture>>;
    authenticatedPage: Page;
    sharedPolicy: void;
    networkPolicy: void;
}

/** Authenticate a browser and persist the token only in the UI's exact origin. */
export async function loginBrowser(
    page: Page,
    ui = "",
    password = "browser-password",
): Promise<void> {
    const login = await page.request.post(`${ui}/api/login`, {
        data: { username: "admin", password },
    });
    expect(login.status()).toBe(200);
    const { token }: { token: string } = await login.json();
    await page.goto(`${ui}/login`);
    await page.evaluate((value) => localStorage.setItem("exwall.session", value), token);
}

/** Supply the browser's origin-scoped token for explicit API assertions in tests. */
export async function sessionHeaders(page: Page): Promise<Record<string, string>> {
    const token = await page.evaluate(() => localStorage.getItem("exwall.session"));
    expect(token).toBeTruthy();
    return { Authorization: `Bearer ${token}` };
}

/** Attach the current shared policy when a test fails, before restoring its original state. */
async function attachPolicy(testInfo: TestInfo): Promise<void> {
    if (testInfo.status !== testInfo.expectedStatus) {
        await testInfo.attach("firewall-policy", {
            body: await fixtureRules(),
            contentType: "text/plain",
        });
    }
}

/** Wait for the production watcher to apply an expected HTTP policy decision. */
async function waitForPolicy(url: string, status: number): Promise<void> {
    await expect
        .poll(async () => {
            const response = await fixtureOperation({ operation: "http", url });
            if (response.error || typeof response.result !== "object") {
                return response;
            }
            return response.result.status;
        })
        .toBe(status);
}

/** Base test extended with resources that start only when requested. */
export const test = base.extend<Fixtures>({
    /** Own one local proxy and attach its log before closing all child resources. */
    // Playwright requires an object pattern to declare fixture dependencies.
    // eslint-disable-next-line no-empty-pattern
    protocolProxy: async ({}, use, testInfo) => {
        const proxy = await startProtocolFixture();
        await use(proxy);
        try {
            if (testInfo.status !== testInfo.expectedStatus) {
                await testInfo.attach("proxy-log", {
                    body: await readFile(join(proxy.root, "proxy.log")),
                    contentType: "text/plain",
                });
            }
        } finally {
            await proxy.close();
        }
    },
    /** Authenticate the browser without hiding login behavior in tests that exercise it. */
    authenticatedPage: async ({ page }, use) => {
        await loginBrowser(page);
        await use(page);
    },
    /** Restore shared UI policy using a fresh revision and an independent API session. */
    sharedPolicy: async ({ request }, use, testInfo) => {
        const login = await request.post("/api/login", {
            data: { username: "admin", password: "browser-password" },
        });
        expect(login.status()).toBe(200);
        const { token }: { token: string } = await login.json();
        const headers = { Authorization: `Bearer ${token}` };
        const originalResponse = await request.get("/api/rules", { headers });
        expect(originalResponse.status()).toBe(200);
        const original: RulesDocument = await originalResponse.json();
        await use();
        try {
            await attachPolicy(testInfo);
        } finally {
            const currentResponse = await request.get("/api/rules", { headers });
            expect(currentResponse.status()).toBe(200);
            const current: RulesDocument = await currentResponse.json();
            const restored = await request.put("/api/rules", {
                headers,
                data: {
                    revision: current.revision,
                    rules: original.rules.map((rule) => ({ ...rule, index: null })),
                },
            });
            expect(restored.status()).toBe(200);
            await waitForPolicy("https://example.com/browser", 403);
            await waitForPolicy("https://openai.com/domain-control", 403);
        }
    },
    /** Install retained network cases and always reset policy, including failed readiness checks. */
    // Playwright requires an object pattern to declare fixture dependencies.
    // eslint-disable-next-line no-empty-pattern
    networkPolicy: async ({}, use, testInfo) => {
        const rules = await readFile(
            new URL("../fixtures/mitmwall-integration-rules.toml", import.meta.url),
            "utf8",
        );
        try {
            await writeFixtureRules(rules);
            await waitForPolicy("https://pie.dev/get", 200);
            await use();
        } finally {
            try {
                if (testInfo.status !== testInfo.expectedStatus) {
                    await testInfo.attach("network-policy", {
                        body: rules,
                        contentType: "text/plain",
                    });
                }
                await attachPolicy(testInfo);
            } finally {
                await writeFixtureRules(null);
                await waitForPolicy("https://pie.dev/get", 403);
            }
        }
    },
});

/** Apply policy restoration automatically to every shared-firewall UI test. */
export const firewallTest = test.extend<{ restorePolicy: void }>({
    /** Activate shared policy restoration for every test using this export. */
    restorePolicy: [
        async ({ sharedPolicy }, use) => {
            await use(sharedPolicy);
        },
        { auto: true },
    ],
});

/** Apply retained network policy automatically to every network scenario. */
export const networkTest = test.extend<{ installNetworkPolicy: void }>({
    /** Activate network policy setup and reset for every test using this export. */
    installNetworkPolicy: [
        async ({ networkPolicy }, use) => {
            await use(networkPolicy);
        },
        { auto: true },
    ],
});
