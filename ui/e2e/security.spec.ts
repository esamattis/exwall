import { createServer } from "node:http";
import { createConnection } from "node:net";
import { once } from "node:events";
import { writeFile } from "node:fs/promises";
import { expect } from "@playwright/test";
import { test, loginBrowser, sessionHeaders } from "#playwright_helpers/test_fixtures.mts";
import { exchange } from "#playwright_helpers/proxy_fixture.mts";

test("browser sessions persist only at the UI origin and logout revokes them", async ({
    page,
    protocolProxy: fixture,
}) => {
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    await loginBrowser(page, ui, "integration-password");
    await page.goto(ui);
    await expect(page.getByRole("heading", { name: "Traffic", exact: true })).toBeVisible();
    const headers = await sessionHeaders(page);
    await page.reload();
    await expect(page.getByRole("heading", { name: "Traffic", exact: true })).toBeVisible();

    const received: { cookie: string | undefined; authorization: string | undefined }[] = [];
    const other = createServer((request, response) => {
        received.push({
            cookie: request.headers.cookie,
            authorization: request.headers.authorization,
        });
        response.setHeader("Content-Type", "text/html");
        response.end("<!doctype html><title>Other local service</title>");
    });
    try {
        other.listen(0, "127.0.0.1");
        await once(other, "listening");
        const address = other.address();
        if (!address || typeof address === "string") {
            throw new Error("Expected a local TCP listener");
        }
        await page.goto(`http://127.0.0.1:${address.port}/api/check`);
        expect(await page.evaluate(() => localStorage.getItem("exwall.session"))).toBeNull();
        await page.evaluate(() =>
            fetch("/api/check", { credentials: "include" }).then((response) => response.text()),
        );
        expect(received.length).toBeGreaterThanOrEqual(2);
        expect(received.every((request) => !request.cookie && !request.authorization)).toBe(true);
        await page.goto(ui);
        await expect(page.getByRole("heading", { name: "Traffic", exact: true })).toBeVisible();
        await page.getByRole("button", { name: "Sign out", exact: true }).click();
        await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
        expect(await page.evaluate(() => localStorage.getItem("exwall.session"))).toBeNull();
        expect((await page.request.get(`${ui}/api/rules`, { headers })).status()).toBe(401);
    } finally {
        other.closeAllConnections();
        await new Promise<void>((resolve, reject) =>
            other.close((error) => (error ? reject(error) : resolve())),
        );
    }
});

test("a stalled login does not block the API and expires after its body deadline", async ({
    request,
    protocolProxy: fixture,
}) => {
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    const login = await request.post(`${ui}/api/login`, {
        data: { username: "admin", password: "integration-password" },
    });
    expect(login.status()).toBe(200);
    const { token }: { token: string } = await login.json();
    const headers = { Authorization: `Bearer ${token}` };
    const stalled = createConnection({ host: "127.0.0.1", port: fixture.uiPort });
    stalled.setTimeout(15_000, () => stalled.destroy(new Error("Body deadline was not enforced")));
    try {
        await once(stalled, "connect");
        const timedOut = once(stalled, "data");
        stalled.write(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n{",
        );
        for (let attempt = 0; attempt < 3; attempt += 1) {
            expect(
                (await request.get(`${ui}/api/rules`, { headers, timeout: 2000 })).status(),
            ).toBe(200);
        }
        const [response] = await timedOut;
        expect(Buffer.isBuffer(response)).toBe(true);
        expect(response.toString()).toContain("408 Request Timeout");
        expect((await request.get(`${ui}/api/rules`, { headers })).status()).toBe(200);
    } finally {
        stalled.destroy();
    }
});

test("wildcard path allowances reject traversal without changing normal routes", async ({
    protocolProxy: fixture,
}) => {
    await writeFile(
        fixture.rule,
        `${fixture.ruleText}\n[[allow]]\ndomain = '127.0.0.1'\npathname_pattern = '/allowed/*'\n`,
    );
    /** Send raw paths so client URL normalization cannot hide the regression. */
    const get = (path: string) =>
        exchange({
            hostname: "127.0.0.1",
            port: fixture.proxyPort,
            path: `http://127.0.0.1:${fixture.upstreamPort}${path}`,
            headers: { Host: `127.0.0.1:${fixture.upstreamPort}` },
        });
    await expect.poll(async () => (await get("/allowed/file.txt")).status).toBe(200);
    for (const path of [
        "/allowed/../private",
        "/allowed/%2e%2e/private",
        "/allowed/%252e%252e/private",
    ]) {
        expect((await get(path)).status).toBe(403);
    }
    expect((await get("/allowed/file.txt?next=/../private")).status).toBe(200);
});
