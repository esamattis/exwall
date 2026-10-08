import { expect } from "@playwright/test";
import type { RulesDocument } from "#playwright_helpers/test_fixtures.mts";
import {
    test,
    firewallTest,
    loginBrowser,
    sessionHeaders,
} from "#playwright_helpers/test_fixtures.mts";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fixtureOperation, fixtureRules, networkRequest } from "#playwright_helpers/client.mts";
import { queryDns } from "#playwright_helpers/dns.mts";
import { exchange, tlsExchange } from "#playwright_helpers/proxy_fixture.mts";

/** Domain snapshots contain only current protocol totals and the latest update. */
interface DomainStats {
    domain: string;
    dns: { allow: number; block: number };
    http: { allow: number; block: number };
    last_updated: string;
    last_allowed: string | null;
    last_denied: string | null;
}

test("domains refresh manually without polling, aggregate decisions, and allow every route and method", async ({
    page,
    protocolProxy: fixture,
}) => {
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
        const response = await page.request.get(`${ui}/api/domains`, {
            headers: await sessionHeaders(page),
        });
        expect(response.status()).toBe(200);
        return response.json();
    };
    expect((await page.request.get(`${ui}/api/domains`)).status()).toBe(401);
    await page.clock.install();
    await page.goto(`${ui}/login`);
    await page.getByRole("textbox", { name: "Username" }).fill("admin");
    await page.getByLabel("Password", { exact: true }).fill("integration-password");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("link", { name: "Domains", exact: true }).click();
    await expect(page.getByText("No domain allows yet.")).toBeVisible();
    await expect(page.getByText("No domain denials yet.")).toBeVisible();

    expect(await queryDns("127.0.0.1", fixture.dnsPort, "LOCALHOST")).toBe(0);
    expect(await queryDns("127.0.0.1", fixture.dnsPort, "denied.test")).toBe(5);
    expect((await http("/allowed")).status).toBe(200);
    expect((await http("/allowed", "POST")).status).toBe(403);
    expect((await tlsExchange(fixture.proxyPort, fixture.securePort, fixture.cert)).status).toBe(
        200,
    );
    expect(
        (await tlsExchange(fixture.proxyPort, fixture.securePort, fixture.cert, "/denied")).status,
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
            last_allowed: null,
            last_denied: expect.any(String),
        },
        {
            domain: "localhost",
            dns: { allow: 1, block: 0 },
            http: { allow: 1, block: 1 },
            last_updated: expect.any(String),
            last_allowed: expect.any(String),
            last_denied: expect.any(String),
        },
        {
            domain: "127.0.0.1",
            dns: { allow: 0, block: 0 },
            http: { allow: 1, block: 1 },
            last_updated: expect.any(String),
            last_allowed: expect.any(String),
            last_denied: expect.any(String),
        },
    ]);
    for (const entry of before) {
        expect(Number.isNaN(Date.parse(entry.last_updated))).toBe(false);
    }
    // Traffic and elapsed time must not update the page without a refresh.
    await page.clock.runFor(3000);
    await expect(page.getByText("No domain allows yet.")).toBeVisible();
    await expect(page.getByText("No domain denials yet.")).toBeVisible();
    expect(domainRequests).toBe(1);
    await page.getByRole("button", { name: "Refresh domains", exact: true }).click();
    const rows = page
        .getByRole("table", { name: "Domain denials, latest outcome first" })
        .locator("tbody tr");
    await expect(rows).toHaveCount(3);
    await expect(rows.nth(0).getByRole("rowheader")).toHaveText("denied.test");
    const denied = rows.filter({
        has: page.getByRole("rowheader", { name: "denied.test", exact: true }),
    });
    await expect(denied.getByRole("cell").nth(0)).toHaveText("2");
    await expect(denied.getByRole("cell").nth(1)).toHaveText("0");
    await expect(denied.getByRole("cell").nth(2)).toHaveText("2");
    const allowedRows = page
        .getByRole("table", { name: "Domain allows, latest outcome first" })
        .locator("tbody tr");
    await expect(allowedRows).toHaveCount(2);
    await expect(allowedRows.getByRole("rowheader")).toHaveText(["localhost", "127.0.0.1"]);
    await expect(allowedRows.nth(0).getByRole("cell").nth(0)).toHaveText("1");
    await expect(allowedRows.nth(0).getByRole("cell").nth(1)).toHaveText("1");
    await expect(allowedRows.nth(0).getByRole("cell").nth(2)).toHaveText("2");
    await expect(denied.locator("time")).toHaveAttribute("datetime", before[0]!.last_updated);

    await page
        .getByRole("region", { name: "Domain denials", exact: true })
        .getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true })
        .click();
    await expect(page.getByRole("status")).toHaveText("Domain allowed on all routes and methods.");
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
    await expect(allowedRows.nth(0).getByRole("rowheader")).toHaveText("127.0.0.1");
    await expect(allowedRows.nth(0).getByRole("cell").nth(1)).toHaveText("4");
    await expect(rows.getByRole("rowheader")).toHaveText(["denied.test", "localhost", "127.0.0.1"]);
    await expect(rows.nth(2).locator("time")).toHaveAttribute("datetime", before[2]!.last_denied!);
    const after = await snapshot();
    expect(after[0]!.http).toEqual({ allow: 4, block: 1 });
    expect(after[0]!.last_denied).toBe(before[2]!.last_denied);
    expect(after[0]!.last_allowed).toBe(after[0]!.last_updated);
    expect(Date.parse(after[0]!.last_updated)).toBeGreaterThan(Date.parse(before[2]!.last_updated));
    expect(after.find((entry) => entry.domain === "denied.test")).toEqual(before[0]);
    await page
        .getByRole("region", { name: "Domain denials", exact: true })
        .getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true })
        .click();
    await expect(
        page
            .getByRole("region", { name: "Domain denials", exact: true })
            .getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true }),
    ).toBeEnabled();
    expect(await readFile(join(fixture.rules, "05-web.toml"), "utf8")).toBe(persisted);
    await page.reload();
    await expect(rows).toHaveCount(3);
    await expect(allowedRows.nth(0).getByRole("cell").nth(1)).toHaveText("4");
});

firewallTest(
    "DNS-only allowance stays out of HTTP and can expand to all methods and subdomains",
    async ({ authenticatedPage: page }) => {
        /** Exercise DNS through the isolated fixture's real UDP or TCP redirect. */
        const dns = (name: string, tcp = false) =>
            fixtureOperation({
                operation: "dns",
                host: "192.0.2.2",
                name,
                tcp,
            });
        /** Observe an HTTP policy result under the fixture's restricted client identity. */
        const http = async (host: string, scheme = "http", method = "POST") => {
            const response = await networkRequest({
                operation: "http",
                url: `${scheme}://${host}/domain-control`,
                method,
            });
            if (response.error || typeof response.result !== "object") {
                throw new Error(JSON.stringify(response));
            }
            return response.result.status;
        };
        /** Wait for a button's save to finish before checking persisted and active policy. */
        const allow = async (name: string, message: string) => {
            await page
                .getByRole("region", { name: "Domain denials", exact: true })
                .getByRole("button", { name, exact: true })
                .click();
            await expect(page.getByRole("status")).toHaveText(message);
        };
        await expect.poll(() => dns("openai.com")).toEqual({ result: 5 });
        expect(await dns("api.openai.com")).toEqual({ result: 5 });
        expect(await http("openai.com")).toBe(403);
        await page.goto("/domains");
        await allow("Allow openai.com DNS only", "Domain allowed for DNS only.");
        const dnsOnly = await fixtureRules();
        expect(dnsOnly).toContain('domain = "openai.com"');
        expect(dnsOnly).toContain("dns_only = true");
        await expect.poll(() => dns("openai.com")).toEqual({ result: 0 });
        expect(await dns("openai.com", true)).toEqual({ result: 0 });
        expect(await dns("api.openai.com")).toEqual({ result: 5 });
        for (const scheme of ["http", "https"]) {
            for (const method of ["GET", "POST", "DELETE"]) {
                expect(await http("openai.com", scheme, method)).toBe(403);
            }
        }
        await allow("Allow openai.com DNS only", "Domain allowed for DNS only.");
        expect(await fixtureRules()).toBe(dnsOnly);
        await page.getByRole("link", { name: "Rules", exact: true }).click();
        await expect(
            page.getByRole("combobox", { name: "Rule 1 dns_only", exact: true }),
        ).toHaveValue("true");
        await page.getByRole("link", { name: "Domains", exact: true }).click();

        await allow("Allow openai.com completely", "Domain allowed on all routes and methods.");
        expect(await fixtureRules()).not.toContain("dns_only");
        await expect.poll(() => http("openai.com")).toBe(200);
        expect(await http("api.openai.com")).toBe(403);
        await allow(
            "Allow openai.com with subdomains",
            "Domain and its subdomains allowed on all routes and methods.",
        );
        const withSubdomains = await fixtureRules();
        expect(withSubdomains).toContain("include_subdomains = true");
        expect(withSubdomains).toContain('methods = "ANY"');
        await expect.poll(() => http("api.openai.com", "https")).toBe(200);
        for (const scheme of ["http", "https"]) {
            for (const host of ["openai.com", "api.openai.com"]) {
                for (const method of ["GET", "POST", "DELETE"]) {
                    expect(await http(host, scheme, method)).toBe(200);
                }
            }
        }
        for (const tcp of [false, true]) {
            expect(await dns("api.openai.com", tcp)).toEqual({ result: 0 });
            expect(await dns("otheropenai.com", tcp)).toEqual({ result: 5 });
        }
        expect(await http("example.com")).toBe(403);
        await allow(
            "Allow openai.com with subdomains",
            "Domain and its subdomains allowed on all routes and methods.",
        );
        expect(await fixtureRules()).toBe(withSubdomains);
        await page.reload();
        await expect(
            page
                .getByRole("region", { name: "Domain denials", exact: true })
                .getByRole("button", { name: "Allow openai.com with subdomains", exact: true }),
        ).toBeVisible();
        expect(await http("api.openai.com", "https", "DELETE")).toBe(200);
    },
);

/** Current metadata for one retained HTTP policy denial. */
interface HttpDenial {
    domain: string;
    method: string;
    pathname: string;
    timestamp: string;
}

test("last 100 HTTP denials refresh manually and allow only an exact method and pathname", async ({
    page,
    protocolProxy: fixture,
}) => {
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    const pathname = "/denied/:item*+(x)";
    /** Exercise real proxy decisions with a query string that must never enter the allow rule. */
    const http = (path: string, method = "POST") =>
        exchange({
            hostname: "127.0.0.1",
            port: fixture.proxyPort,
            path: `http://127.0.0.1:${fixture.upstreamPort}${path}`,
            method,
            headers: { Host: `127.0.0.1:${fixture.upstreamPort}` },
        });
    /** Read the authenticated denial API without changing the manually refreshed table. */
    const snapshot = async (): Promise<HttpDenial[]> => {
        const response = await page.request.get(`${ui}/api/http-denials`, {
            headers: await sessionHeaders(page),
        });
        expect(response.status()).toBe(200);
        return response.json();
    };
    expect((await page.request.get(`${ui}/api/http-denials`)).status()).toBe(401);
    await loginBrowser(page, ui, "integration-password");
    await page.goto(`${ui}/domains`);
    const section = page.getByRole("region", { name: "HTTP denials", exact: true });
    await expect(section.getByText("No HTTP denials yet.")).toBeVisible();
    expect(await queryDns("127.0.0.1", fixture.dnsPort, "denied.test")).toBe(5);
    expect((await http("/allowed?upstream_status=502", "GET")).status).toBe(502);
    for (let index = 0; index < 104; index += 1) {
        expect((await http(`/denied/${index}`)).status).toBe(403);
    }
    expect((await http(`${pathname}?secret=hidden`)).status).toBe(403);
    expect(
        (await tlsExchange(fixture.proxyPort, fixture.securePort, fixture.cert, "/denied")).status,
    ).toBe(403);
    await expect.poll(async () => (await snapshot()).length).toBe(100);
    const before = await snapshot();
    expect(before[0]).toMatchObject({
        domain: "localhost",
        method: "GET",
        pathname: "/denied",
    });
    expect(before[1]).toMatchObject({ domain: "127.0.0.1", method: "POST", pathname });
    expect(before[99]!.pathname).toBe("/denied/6");
    expect(JSON.stringify(before)).not.toContain("secret");
    await expect(section.getByText("No HTTP denials yet.")).toBeVisible();
    await section.getByRole("button", { name: "Refresh HTTP denials", exact: true }).click();
    const rows = section.getByRole("table", { name: "Latest HTTP denials" }).locator("tbody tr");
    await expect(rows).toHaveCount(100);
    await expect(rows.nth(0).getByRole("rowheader")).toHaveText("localhost");
    await expect(rows.nth(1).getByRole("cell").nth(1)).toHaveText(pathname);
    const button = section.getByRole("button", {
        name: `Allow 127.0.0.1 POST ${pathname}`,
        exact: true,
    });
    await button.click();
    await expect(section.getByRole("status")).toHaveText("Method and pathname allowed.");
    const document: RulesDocument = await (
        await page.request.get(`${ui}/api/rules`, { headers: await sessionHeaders(page) })
    ).json();
    expect(document.rules).toHaveLength(1);
    expect(document.rules[0]!.fields).toEqual({
        domain: "127.0.0.1",
        methods: ["POST"],
        pathname_regex: "\\A/denied/:item\\*\\+\\(x\\)\\z",
    });
    await expect.poll(async () => (await http(`${pathname}?another=query`)).status).toBe(200);
    for (const [path, method] of [
        [pathname, "GET"],
        [pathname, "DELETE"],
        [`${pathname}/extra`, "POST"],
        ["/denied/:itemmmmmx", "POST"],
        ["/denied/103", "POST"],
    ]) {
        expect((await http(path!, method!)).status).toBe(403);
    }
    await button.click();
    await expect(button).toBeEnabled();
    expect(
        (
            await (
                await page.request.get(`${ui}/api/rules`, { headers: await sessionHeaders(page) })
            ).json()
        ).rules,
    ).toHaveLength(1);
    const after = await snapshot();
    expect(after).toHaveLength(100);
    expect(after[0]).toMatchObject({ method: "POST", pathname: "/denied/103" });
    await expect(rows.nth(0).getByRole("rowheader")).toHaveText("localhost");
    await section.getByRole("button", { name: "Refresh HTTP denials", exact: true }).click();
    await expect(rows.nth(0).getByRole("cell").nth(1)).toHaveText("/denied/103");
    await page.reload();
    await expect(rows).toHaveCount(100);
    expect((await http(pathname)).status).toBe(200);
});

test("HTTP allow actions remove only fully covered DNS-only rules, including duplicate allowances", async ({
    page,
    protocolProxy: fixture,
}) => {
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    await loginBrowser(page, ui, "integration-password");
    await page.route("**/api/domains", (route) =>
        route.fulfill({
            json: [
                {
                    domain: "example.com",
                    dns: { allow: 0, block: 1 },
                    http: { allow: 0, block: 1 },
                    last_updated: new Date().toISOString(),
                    last_allowed: null,
                    last_denied: new Date().toISOString(),
                },
            ],
        }),
    );
    await page.route("**/api/http-denials", (route) =>
        route.fulfill({
            json: [
                {
                    domain: "example.com",
                    method: "POST",
                    pathname: "/blocked",
                    timestamp: new Date().toISOString(),
                },
            ],
        }),
    );
    const exact = "Allow example.com completely";
    const subdomains = "Allow example.com with subdomains";
    const denial = "Allow example.com POST /blocked";
    const cases: {
        fields: RulesDocument["rules"][number]["fields"];
        button: string;
        retained: boolean;
        existingHttp?: boolean;
    }[] = [
        { fields: { domain: " EXAMPLE.COM. " }, button: exact, retained: false },
        {
            fields: { domain: "example.com", include_subdomains: true },
            button: exact,
            retained: true,
        },
        { fields: { domain: ["example.com", "other.test"] }, button: exact, retained: true },
        {
            fields: { domain: ["example.com", "api.example.com"], include_subdomains: true },
            button: subdomains,
            retained: false,
        },
        { fields: { domain: "otherexample.com" }, button: subdomains, retained: true },
        { fields: { domain_regex: "example" }, button: subdomains, retained: true },
        { fields: { domain: "example.com" }, button: denial, retained: false },
        {
            fields: { domain: "example.com", include_subdomains: true },
            button: denial,
            retained: true,
        },
        { fields: { domain: "example.com" }, button: exact, retained: false, existingHttp: true },
    ];
    for (const entry of cases) {
        const current: RulesDocument = await (
            await page.request.get(`${ui}/api/rules`, { headers: await sessionHeaders(page) })
        ).json();
        current.rules = [{ index: null, fields: { ...entry.fields, dns_only: true } }];
        if (entry.existingHttp) {
            current.rules.push({ index: null, fields: { domain: "example.com", methods: "ANY" } });
        }
        expect(
            (
                await page.request.put(`${ui}/api/rules`, {
                    headers: await sessionHeaders(page),
                    data: current,
                })
            ).status(),
        ).toBe(200);
        await page.goto(`${ui}/domains`);
        await page.getByRole("button", { name: entry.button, exact: true }).click();
        let message = "Domain allowed on all routes and methods.";
        if (entry.button === denial) {
            message = "Method and pathname allowed.";
        } else if (entry.button === subdomains) {
            message = "Domain and its subdomains allowed on all routes and methods.";
        }
        await expect(page.getByRole("status")).toHaveText(message);
        const saved: RulesDocument = await (
            await page.request.get(`${ui}/api/rules`, { headers: await sessionHeaders(page) })
        ).json();
        expect(saved.rules.filter((rule) => rule.fields.dns_only === true)).toEqual(
            entry.retained
                ? [{ index: expect.any(Number), fields: { ...entry.fields, dns_only: true } }]
                : [],
        );
        expect(saved.rules.filter((rule) => rule.fields.dns_only !== true)).toHaveLength(1);
        const persisted = await readFile(join(fixture.rules, "05-web.toml"), "utf8");
        await page.getByRole("button", { name: entry.button, exact: true }).click();
        await expect(page.getByRole("button", { name: entry.button, exact: true })).toBeEnabled();
        expect(await readFile(join(fixture.rules, "05-web.toml"), "utf8")).toBe(persisted);
    }
});
