import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { queryDns } from "#playwright_helpers/dns.mts";
import { exchange, startProtocolFixture, tlsExchange } from "#playwright_helpers/proxy_fixture.mts";

/** Domain snapshots contain only current protocol totals and the latest update. */
interface DomainStats {
    domain: string;
    dns: { allow: number; block: number };
    http: { allow: number; block: number };
    last_updated: string;
}

test("domains refresh manually without polling, aggregate decisions, and allow every route and method", async ({
    page,
}) => {
    const fixture = await startProtocolFixture();
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    let domainRequests = 0;
    page.on("request", (request) => {
        if (request.url() === `${ui}/api/domains`) {
            domainRequests += 1;
        }
    });
    /** Exercise a real HTTP policy decision against the disposable upstream. */
    const http = (path: string, method = "GET") =>
        exchange({
            hostname: "127.0.0.1",
            port: fixture.proxyPort,
            path: `http://127.0.0.1:${fixture.upstreamPort}${path}`,
            method,
            headers: { Host: `127.0.0.1:${fixture.upstreamPort}` },
        });
    /** Fetch counters using the same authenticated browser context as the UI. */
    const snapshot = async (): Promise<DomainStats[]> => {
        const response = await page.request.get(`${ui}/api/domains`);
        expect(response.status()).toBe(200);
        return response.json();
    };
    try {
        expect((await page.request.get(`${ui}/api/domains`)).status()).toBe(401);
        await page.clock.install();
        await page.goto(`${ui}/login`);
        await page.getByRole("textbox", { name: "Username" }).fill("admin");
        await page.getByLabel("Password", { exact: true }).fill("integration-password");
        await page.getByRole("button", { name: "Sign in", exact: true }).click();
        await page.getByRole("link", { name: "Domains", exact: true }).click();
        await expect(page.getByText("No domains seen yet.")).toBeVisible();

        expect(await queryDns("127.0.0.1", fixture.dnsPort, "LOCALHOST")).toBe(0);
        expect(await queryDns("127.0.0.1", fixture.dnsPort, "denied.test")).toBe(5);
        expect((await http("/allowed")).status).toBe(200);
        expect((await http("/allowed", "POST")).status).toBe(403);
        expect(
            (await tlsExchange(fixture.proxyPort, fixture.securePort, fixture.cert)).status,
        ).toBe(200);
        expect(
            (await tlsExchange(fixture.proxyPort, fixture.securePort, fixture.cert, "/denied"))
                .status,
        ).toBe(403);
        expect(await queryDns("127.0.0.1", fixture.dnsPort, "denied.test", true)).toBe(5);

        await expect
            .poll(async () => (await snapshot()).map((entry) => entry.domain))
            .toEqual(["denied.test", "localhost", "127.0.0.1"]);
        const before = await snapshot();
        expect(before).toEqual([
            {
                domain: "denied.test",
                dns: { allow: 0, block: 2 },
                http: { allow: 0, block: 0 },
                last_updated: expect.any(String),
            },
            {
                domain: "localhost",
                dns: { allow: 1, block: 0 },
                http: { allow: 1, block: 1 },
                last_updated: expect.any(String),
            },
            {
                domain: "127.0.0.1",
                dns: { allow: 0, block: 0 },
                http: { allow: 1, block: 1 },
                last_updated: expect.any(String),
            },
        ]);
        for (const entry of before) {
            expect(Number.isNaN(Date.parse(entry.last_updated))).toBe(false);
        }
        // Traffic and elapsed time must not update the page without a refresh.
        await page.clock.runFor(3000);
        await expect(page.getByText("No domains seen yet.")).toBeVisible();
        expect(domainRequests).toBe(1);
        await page.getByRole("button", { name: "Refresh domains", exact: true }).click();
        const rows = page.getByRole("table").locator("tbody tr");
        await expect(rows).toHaveCount(3);
        await expect(rows.nth(0).getByRole("rowheader")).toHaveText("denied.test");
        const denied = rows.filter({
            has: page.getByRole("rowheader", { name: "denied.test", exact: true }),
        });
        await expect(denied.getByRole("cell").nth(1)).toHaveText("2");
        await expect(denied.locator("time")).toHaveAttribute("datetime", before[0]!.last_updated);

        await page.getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true }).click();
        await expect(page.getByRole("status")).toHaveText(
            "Domain allowed on all routes and methods.",
        );
        const persisted = await readFile(join(fixture.rules, "05-web.toml"), "utf8");
        expect(persisted).toContain('domain = "127.0.0.1"');
        expect(persisted).toContain('methods = "ANY"');
        expect(persisted).not.toContain("pathname_");
        // Wait for the watcher without generating extra traffic or counter increments.
        await expect
            .poll(() => readFile(join(fixture.root, "proxy.log"), "utf8"))
            .toContain("automatically reloaded rules");
        for (const [path, method] of [
            ["/other", "POST"],
            ["/another", "DELETE"],
            ["/allowed", "PATCH"],
        ]) {
            expect((await http(path!, method!)).status).toBe(200);
        }
        await expect(rows.nth(0).getByRole("rowheader")).toHaveText("denied.test");
        expect(domainRequests).toBe(2);
        await page.getByRole("button", { name: "Refresh domains", exact: true }).click();
        await expect(rows.nth(0).getByRole("rowheader")).toHaveText("127.0.0.1");
        await expect(rows.nth(0).getByRole("cell").nth(2)).toHaveText("4");
        const after = await snapshot();
        expect(after[0]!.http).toEqual({ allow: 4, block: 1 });
        expect(Date.parse(after[0]!.last_updated)).toBeGreaterThan(
            Date.parse(before[2]!.last_updated),
        );
        expect(after.find((entry) => entry.domain === "denied.test")).toEqual(before[0]);
        await page.getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true }).click();
        await expect(
            page.getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true }),
        ).toBeEnabled();
        expect(await readFile(join(fixture.rules, "05-web.toml"), "utf8")).toBe(persisted);
        await page.reload();
        await expect(rows).toHaveCount(3);
        await expect(rows.nth(0).getByRole("cell").nth(2)).toHaveText("4");
    } finally {
        await fixture.close();
    }
});
