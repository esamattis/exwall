import { expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import type { RulesDocument } from "#playwright_helpers/test_fixtures.mts";
import {
    test,
    firewallTest,
    loginBrowser,
    sessionHeaders,
} from "#playwright_helpers/test_fixtures.mts";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fixtureOperation, fixtureRules, networkRequest } from "#playwright_helpers/client.mts";
import { queryDns } from "#playwright_helpers/dns.mts";
import { exchange, tlsExchange } from "#playwright_helpers/proxy_fixture.mts";
import { websocketExchange } from "#playwright_helpers/websocket.mts";

/** Select one view of the Traffic page by its tab label. */
async function showTab(page: Page, label: string) {
    await page.getByRole("tab", { name: new RegExp(`^${label}`) }).click();
}

/** Domain snapshots contain only current protocol totals and the latest update. */
interface DomainStats {
    domain: string;
    dns: { allow: number; block: number };
    http: { allow: number; block: number };
    bytes: { up: number; down: number };
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
    await expect(page.getByRole("heading", { name: "Traffic", exact: true })).toBeVisible();
    await expect(page.getByText("No blocked domains yet")).toBeVisible();
    await showTab(page, "Allowed domains");
    await expect(page.getByText("No allowed domains yet")).toBeVisible();

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
            bytes: { up: 0, down: 0 },
            last_updated: expect.any(String),
            last_allowed: null,
            last_denied: expect.any(String),
        },
        {
            domain: "localhost",
            dns: { allow: 1, block: 0 },
            http: { allow: 1, block: 1 },
            bytes: { up: 0, down: expect.any(Number) },
            last_updated: expect.any(String),
            last_allowed: expect.any(String),
            last_denied: expect.any(String),
        },
        {
            domain: "127.0.0.1",
            dns: { allow: 0, block: 0 },
            http: { allow: 1, block: 1 },
            bytes: { up: 0, down: expect.any(Number) },
            last_updated: expect.any(String),
            last_allowed: expect.any(String),
            last_denied: expect.any(String),
        },
    ]);
    for (const entry of before) {
        expect(Number.isNaN(Date.parse(entry.last_updated))).toBe(false);
    }
    // Only forwarded responses carry body bytes; local denials transfer nothing upstream.
    expect(before[1]!.bytes.down).toBeGreaterThan(0);
    expect(before[2]!.bytes.down).toBeGreaterThan(0);
    // Traffic and elapsed time must not update the page without a refresh.
    await page.clock.runFor(3000);
    await expect(page.getByText("No allowed domains yet")).toBeVisible();
    await showTab(page, "Blocked domains");
    await expect(page.getByText("No blocked domains yet")).toBeVisible();
    expect(domainRequests).toBe(1);
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    const rows = page
        .getByRole("table", { name: "Blocked domains, latest first" })
        .locator("tbody tr");
    await expect(rows).toHaveCount(3);
    await expect(rows.nth(0).getByRole("rowheader")).toHaveText("denied.test");
    const denied = rows.filter({
        has: page.getByRole("rowheader", { name: "denied.test", exact: true }),
    });
    await expect(denied.getByRole("cell").nth(0)).toHaveText("2");
    await expect(denied.getByRole("cell").nth(1)).toHaveText("0");
    await expect(denied.getByRole("cell").nth(2)).toHaveText("2");
    await expect(denied.locator("time")).toHaveAttribute("datetime", before[0]!.last_updated);
    const allowedRows = page
        .getByRole("table", { name: "Allowed domains, latest first" })
        .locator("tbody tr");
    await showTab(page, "Allowed domains");
    await expect(allowedRows).toHaveCount(2);
    await expect(allowedRows.getByRole("rowheader")).toHaveText(["localhost", "127.0.0.1"]);
    await expect(allowedRows.nth(0).getByRole("cell").nth(0)).toHaveText("1");
    await expect(allowedRows.nth(0).getByRole("cell").nth(1)).toHaveText("1");
    await expect(allowedRows.nth(0).getByRole("cell").nth(2)).toHaveText("2");
    await expect(allowedRows.nth(0).getByRole("cell").nth(3)).toHaveText("0 B");
    await expect(allowedRows.nth(0).getByRole("cell").nth(4)).toHaveText(/^\d+(\.\d)? k?B$/i);

    // Stat tiles open the tab that lists the entries they count.
    await page.getByRole("link", { name: "Blocked", exact: true }).click();
    await expect(page.getByRole("tab", { name: /^Blocked requests/ })).toHaveAttribute(
        "aria-selected",
        "true",
    );
    await page.getByRole("link", { name: "Blocked domains", exact: true }).click();
    await expect(page.getByRole("tab", { name: /^Blocked domains/ })).toHaveAttribute(
        "aria-selected",
        "true",
    );
    await page
        .getByRole("tabpanel")
        .getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true })
        .click();
    await expect(page.getByRole("status")).toHaveText("Domain allowed on all routes and methods.");
    await expect(
        page.getByRole("tabpanel").getByRole("link", { name: "Allowed · rule #1", exact: true }),
    ).toHaveAttribute("href", "/rules/05-web.toml#rule-1");
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
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await showTab(page, "Allowed domains");
    await expect(allowedRows.nth(0).getByRole("rowheader")).toHaveText("127.0.0.1");
    await expect(allowedRows.nth(0).getByRole("cell").nth(1)).toHaveText("4");
    await showTab(page, "Blocked domains");
    await expect(rows.getByRole("rowheader")).toHaveText(["denied.test", "localhost", "127.0.0.1"]);
    await expect(rows.nth(2).locator("time")).toHaveAttribute("datetime", before[2]!.last_denied!);
    const after = await snapshot();
    expect(after[0]!.http).toEqual({ allow: 4, block: 1 });
    expect(after[0]!.last_denied).toBe(before[2]!.last_denied);
    expect(after[0]!.last_allowed).toBe(after[0]!.last_updated);
    expect(Date.parse(after[0]!.last_updated)).toBeGreaterThan(Date.parse(before[2]!.last_updated));
    expect(after.find((entry) => entry.domain === "denied.test")).toEqual(before[0]);
    await page
        .getByRole("tabpanel")
        .getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true })
        .click();
    await expect(
        page
            .getByRole("tabpanel")
            .getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true }),
    ).toBeEnabled();
    expect(await readFile(join(fixture.rules, "05-web.toml"), "utf8")).toBe(persisted);
    await page.reload();
    await expect(rows).toHaveCount(3);
    await showTab(page, "Allowed domains");
    await expect(allowedRows.nth(0).getByRole("cell").nth(1)).toHaveText("4");

    // Allowed domains offer the same actions; each badge follows its rule as others are added.
    const allowedPanel = page.getByRole("tabpanel");
    await allowedPanel
        .getByRole("button", { name: "Allow 127.0.0.1 completely", exact: true })
        .click();
    await expect(allowedPanel.getByRole("link", { name: "Allowed · rule #1" })).toBeVisible();
    await allowedPanel
        .getByRole("button", { name: "Allow localhost DNS only", exact: true })
        .click();
    await expect(page.getByRole("status")).toHaveText("Domain allowed for DNS only.");
    await expect(
        allowedPanel.getByRole("link", { name: "DNS allowed · rule #1", exact: true }),
    ).toBeVisible();
    await expect(
        allowedPanel.getByRole("link", { name: "Allowed · rule #2", exact: true }),
    ).toHaveAttribute("href", "/rules/05-web.toml#rule-2");
    await allowedPanel.getByRole("link", { name: "Allowed · rule #2", exact: true }).click();
    await expect(page).toHaveURL(`${ui}/rules/05-web.toml#rule-2`);
    await expect(page.getByRole("button", { name: "Rule 2", exact: true })).toHaveAttribute(
        "aria-expanded",
        "true",
    );
    await expect(page.getByRole("button", { name: "Rule 1", exact: true })).toHaveAttribute(
        "aria-expanded",
        "false",
    );
    await expect(page.getByRole("textbox", { name: "Rule 2 domains", exact: true })).toHaveValue(
        "127.0.0.1",
    );
    await page.goBack();
    await expect(allowedRows).toHaveCount(2);

    page.once("dialog", (dialog) => void dialog.accept());
    await page.getByRole("button", { name: "Reset", exact: true }).click();
    await expect(page.getByRole("status")).toHaveText("Traffic statistics reset.");
    await expect(page.getByText("No allowed domains yet")).toBeVisible();
    expect(await snapshot()).toEqual([]);
    const denials = await page.request.get(`${ui}/api/http-denials`, {
        headers: await sessionHeaders(page),
    });
    expect(await denials.json()).toEqual([]);
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
            await page.getByRole("tabpanel").getByRole("button", { name, exact: true }).click();
            await expect(page.getByRole("status")).toHaveText(message);
        };
        await expect.poll(() => dns("openai.com")).toEqual({ result: 5 });
        expect(await dns("api.openai.com")).toEqual({ result: 5 });
        expect(await http("openai.com")).toBe(403);
        await page.goto("/");
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
        await page.getByRole("link", { name: /^05-web\.toml/ }).click();
        await page.getByRole("button", { name: "Rule 1", exact: true }).click();
        await expect(
            page.getByRole("switch", { name: "Rule 1 DNS only", exact: true }),
        ).toBeChecked();
        await page.getByRole("link", { name: "Traffic", exact: true }).click();

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
                .getByRole("tabpanel")
                .getByRole("button", { name: "Allow openai.com with subdomains", exact: true }),
        ).toBeVisible();
        expect(await http("api.openai.com", "https", "DELETE")).toBe(200);
    },
);

/** Current metadata for one retained HTTP request and its repeats. */
interface HttpRequest {
    domain: string;
    method: string;
    pathname: string;
    query?: string;
    rule?: string;
    count: number;
    timestamp: string;
    duration_ms: number;
    finished: boolean;
    pending: number;
}

test("last 200 unique HTTP denials refresh manually and allow only an exact method and pathname", async ({
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
    /** Read an authenticated request API without changing the manually refreshed table. */
    const snapshot = async (endpoint = "http-denials"): Promise<HttpRequest[]> => {
        const response = await page.request.get(`${ui}/api/${endpoint}`, {
            headers: await sessionHeaders(page),
        });
        expect(response.status()).toBe(200);
        return response.json();
    };
    expect((await page.request.get(`${ui}/api/http-denials`)).status()).toBe(401);
    await loginBrowser(page, ui, "integration-password");
    await page.goto(`${ui}/?view=requests`);
    const section = page.getByRole("tabpanel");
    await expect(section.getByText("No blocked requests yet")).toBeVisible();
    expect(await queryDns("127.0.0.1", fixture.dnsPort, "denied.test")).toBe(5);
    expect((await http("/allowed?upstream_status=502", "GET")).status).toBe(502);
    for (let index = 0; index < 204; index += 1) {
        expect((await http(`/denied/${index}`)).status).toBe(403);
    }
    // Repeats are grouped, so they neither take extra slots nor evict older requests.
    expect((await http("/denied/10")).status).toBe(403);
    expect((await http("/denied/10")).status).toBe(403);
    expect((await http(`${pathname}?secret=hidden`)).status).toBe(403);
    expect(
        (await tlsExchange(fixture.proxyPort, fixture.securePort, fixture.cert, "/denied")).status,
    ).toBe(403);
    await expect.poll(async () => (await snapshot()).length).toBe(200);
    const before = await snapshot();
    expect(before[0]).toMatchObject({
        domain: "localhost",
        method: "GET",
        pathname: "/denied",
        count: 1,
    });
    expect(before[1]).toMatchObject({ domain: "127.0.0.1", method: "POST", pathname });
    expect(before[2]).toMatchObject({ pathname: "/denied/10", count: 3 });
    expect(before[199]!.pathname).toBe("/denied/6");
    expect(before[0]).not.toHaveProperty("rule");
    expect(before[0]).not.toHaveProperty("query");
    expect(before[1]!.query).toBe("secret=hidden");
    await expect(section.getByText("No blocked requests yet")).toBeVisible();
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    const rows = section
        .getByRole("table", { name: "Blocked requests, latest first" })
        .locator("tbody tr");
    await expect(rows).toHaveCount(200);
    await expect(rows.nth(0).getByRole("rowheader")).toHaveText("localhost");
    await expect(rows.nth(1).getByRole("cell").nth(1)).toHaveText(`${pathname}?secret=hidden`);
    await expect(rows.nth(2).getByRole("cell").nth(2)).toHaveText("3");
    const button = section.getByRole("button", {
        name: `Allow 127.0.0.1 POST ${pathname}`,
        exact: true,
    });
    await button.click();
    await expect(page.getByRole("status")).toHaveText("Method and pathname allowed.");
    const document: RulesDocument = await (
        await page.request.get(`${ui}/api/rules/05-web.toml`, {
            headers: await sessionHeaders(page),
        })
    ).json();
    expect(document.rules).toHaveLength(1);
    expect(document.rules[0]!.fields).toEqual({
        domain: "127.0.0.1",
        methods: ["POST"],
        pathname,
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
                await page.request.get(`${ui}/api/rules/05-web.toml`, {
                    headers: await sessionHeaders(page),
                })
            ).json()
        ).rules,
    ).toHaveLength(1);
    // Rules saved by older versions as an escaped regex still count as allowing the request.
    const legacy: RulesDocument = await (
        await page.request.get(`${ui}/api/rules/05-web.toml`, {
            headers: await sessionHeaders(page),
        })
    ).json();
    legacy.rules[0]!.fields = {
        domain: "127.0.0.1",
        methods: ["POST"],
        pathname_regex: "\\A/denied/:item\\*\\+\\(x\\)\\z",
    };
    expect(
        (
            await page.request.put(`${ui}/api/rules/05-web.toml`, {
                headers: await sessionHeaders(page),
                data: legacy,
            })
        ).status(),
    ).toBe(200);
    await button.click();
    await expect(button).toBeEnabled();
    expect(
        (
            await (
                await page.request.get(`${ui}/api/rules/05-web.toml`, {
                    headers: await sessionHeaders(page),
                })
            ).json()
        ).rules,
    ).toHaveLength(1);
    const after = await snapshot();
    expect(after).toHaveLength(200);
    expect(after[0]).toMatchObject({ method: "POST", pathname: "/denied/103", count: 2 });
    await expect(rows.nth(0).getByRole("rowheader")).toHaveText("localhost");
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(rows.nth(0).getByRole("cell").nth(1)).toHaveText("/denied/103");
    await page.reload();
    await expect(rows).toHaveCount(200);
    expect((await http(pathname)).status).toBe(200);

    // Allowed requests are grouped the same way, query string included, and name their rule.
    const allowances = await snapshot("http-allowances");
    const rule = expect.stringMatching(/\/05-web\.toml:allow#\d+$/);
    expect(allowances[0]).toMatchObject({
        domain: "127.0.0.1",
        method: "POST",
        pathname,
        count: 1,
        rule,
    });
    expect(allowances[0]).not.toHaveProperty("query");
    expect(allowances[1]).toMatchObject({ pathname, query: "another=query", rule });
    expect(allowances[0]).toMatchObject({ finished: true, pending: 0 });
    expect(allowances[0]!.duration_ms).toBeGreaterThanOrEqual(0);
    expect(allowances.find((request) => request.pathname === "/allowed")).toMatchObject({
        method: "GET",
        query: "upstream_status=502",
        count: 1,
    });
    await page.getByRole("tab", { name: /^Allowed requests/ }).click();
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    const allowedRows = page
        .getByRole("tabpanel")
        .getByRole("table", { name: "Allowed requests, latest first" })
        .locator("tbody tr");
    await expect(allowedRows).toHaveCount(allowances.length);
    await expect(allowedRows.nth(0).getByRole("cell").nth(1)).toHaveText(pathname);
    await expect(allowedRows.nth(1).getByRole("cell").nth(1)).toHaveText(
        `${pathname}?another=query`,
    );
    await expect(allowedRows.nth(0).getByRole("cell").nth(4)).toHaveText(/^\d+(\.\d)? m?s$/);
    await expect(allowedRows.nth(0).getByRole("cell").nth(5)).toHaveText(
        /^05-web\.toml:allow#\d+$/,
    );
    await expect(
        allowedRows.nth(0).getByRole("link", { name: /^05-web\.toml:allow#\d+$/ }),
    ).toHaveAttribute("href", /^\/rules\/05-web\.toml#rule-\d+$/);

    // Allowing an already allowed request, such as one let through by a pause, adds its own rule.
    const allowedPanel = page.getByRole("tabpanel");
    await allowedPanel
        .getByRole("button", { name: "Allow 127.0.0.1 GET /allowed", exact: true })
        .click();
    await expect(page.getByRole("status")).toHaveText("Method and pathname allowed.");
    await allowedPanel.getByRole("link", { name: "Allowed · rule #1", exact: true }).click();
    await expect(page).toHaveURL(`${ui}/rules/05-web.toml#rule-1`);
    await expect(page.getByRole("button", { name: "Rule 1", exact: true })).toHaveAttribute(
        "aria-expanded",
        "true",
    );
    await expect(
        page.getByRole("textbox", { name: "Rule 1 exact paths", exact: true }),
    ).toHaveValue("/allowed");

    // A rule fragment opens and scrolls to a rule far down a long file.
    const current: RulesDocument = await (
        await page.request.get(`${ui}/api/rules/05-web.toml`, {
            headers: await sessionHeaders(page),
        })
    ).json();
    for (let index = 0; index < 40; index += 1) {
        current.rules.push({ index: null, fields: { domain: `filler${index}.test` } });
    }
    expect(
        (
            await page.request.put(`${ui}/api/rules/05-web.toml`, {
                headers: await sessionHeaders(page),
                data: current,
            })
        ).status(),
    ).toBe(200);
    const last = current.rules.length;
    // Load the page afresh rather than changing only the fragment of the open editor.
    await page.goto(`${ui}/rules`);
    await page.goto(`${ui}/rules/05-web.toml#rule-${last}`);
    const target = page.getByRole("region", { name: `Rule ${last}`, exact: true });
    await expect(target.getByRole("textbox", { name: `Rule ${last} domains` })).toHaveValue(
        "filler39.test",
    );
    await expect(target).toBeInViewport();
    await expect(page.getByRole("region", { name: "Rule 1", exact: true })).not.toBeInViewport();
});

test("request rows open details with decoded query strings and opt-in captured headers and bodies", async ({
    page,
    context,
    protocolProxy: fixture,
}) => {
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: ui });
    /** Send a request with an optional body through the proxy to the disposable upstream. */
    const http = (path: string, method: string, body?: string) =>
        exchange(
            {
                hostname: "127.0.0.1",
                port: fixture.proxyPort,
                path: `http://127.0.0.1:${fixture.upstreamPort}${path}`,
                method,
                headers: {
                    Host: `127.0.0.1:${fixture.upstreamPort}`,
                    "X-Client-Key": "client-value",
                    ...(body === undefined ? {} : { "Content-Type": "application/json" }),
                },
            },
            undefined,
            body,
        );
    await loginBrowser(page, ui, "integration-password");
    await page.goto(`${ui}/?view=requests`);
    const capture = page.getByRole("button", { name: "Capture", exact: true });
    await expect(capture).toBeVisible();

    // Requests made while capture is off still open with their decoded query string.
    expect((await http("/uncaptured?q=caf%C3%A9+au+lait&next=%2Fhome", "POST", "{}")).status).toBe(
        403,
    );
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    const rows = page.getByRole("tabpanel").locator("tbody tr");
    await rows.filter({ hasText: "/uncaptured" }).getByRole("cell").nth(3).click();
    let dialog = page.getByRole("dialog", { name: "POST 127.0.0.1/uncaptured" });
    await expect(dialog).toBeVisible();
    const query = dialog.getByRole("table", { name: "Decoded query parameters" });
    await expect(query.getByRole("row")).toHaveText([/^q.*café au lait/, /^next.*\/home/]);
    await expect(dialog.getByText(/Headers and bodies were not captured/)).toBeVisible();
    await dialog.getByRole("button", { name: "Copy query parameter value of q" }).click();
    await expect
        .poll(() => page.evaluate(() => navigator.clipboard.readText()))
        .toBe("café au lait");
    await dialog.getByRole("button", { name: "Copy URL", exact: true }).click();
    await expect
        .poll(() => page.evaluate(() => navigator.clipboard.readText()))
        .toBe(
            `http://127.0.0.1:${fixture.upstreamPort}/uncaptured?q=caf%C3%A9+au+lait&next=%2Fhome`,
        );
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();

    // Turn capture on with a 1 KB limit, so longer bodies are truncated.
    await capture.click();
    const limit = page.getByRole("spinbutton", { name: "Max body size (KB)" });
    await expect(limit).toHaveValue("32");
    await limit.fill("1");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByRole("status")).toHaveText("Header and body capture turned off.");
    await page.getByRole("switch", { name: "Capture headers and bodies" }).click();
    await expect(page.getByRole("status")).toHaveText(
        "Capturing headers and up to 1 KB of each body.",
    );
    await expect(page.getByRole("button", { name: "Capturing · 1 KB" })).toBeVisible();
    const long = JSON.stringify({ data: "x".repeat(2000) });
    expect((await http("/denied/body?tag=a%26b", "POST", long)).status).toBe(403);
    expect((await http("/allowed?mode=echo", "GET")).status).toBe(200);

    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await rows.filter({ hasText: "/denied/body" }).getByRole("cell").nth(3).click();
    dialog = page.getByRole("dialog", { name: "POST 127.0.0.1/denied/body" });
    await expect(dialog.getByRole("row", { name: /^tag/ })).toContainText("a&b");
    const request = dialog.getByRole("region", { name: "Captured request" });
    const headers = request.getByRole("table", { name: "Request headers" });
    await expect(headers.getByRole("row", { name: /^x-client-key/i })).toContainText(
        "client-value",
    );
    await headers.getByRole("button", { name: /^Copy request header name x-client-key$/i }).click();
    await expect
        .poll(() => page.evaluate(() => navigator.clipboard.readText()))
        .toMatch(/^x-client-key$/i);
    await headers
        .getByRole("button", { name: /^Copy request header value of x-client-key$/i })
        .click();
    await expect
        .poll(() => page.evaluate(() => navigator.clipboard.readText()))
        .toBe("client-value");
    await expect(
        request.getByText(
            `Truncated at the 1 KB capture limit: showing the first 1,024 bytes of ${long.length.toLocaleString("en-US")} bytes.`,
        ),
    ).toBeVisible();
    await expect(request.getByLabel("Request body", { exact: true })).toHaveText(
        long.slice(0, 1024),
    );
    const response = dialog.getByRole("region", { name: "Captured response" });
    await expect(response.getByText("403", { exact: true })).toBeVisible();
    await expect(response.getByLabel("Response body", { exact: true })).toHaveText(
        /no allow rule matched/,
    );
    await dialog.getByRole("button", { name: "Close", exact: true }).click();
    await expect(dialog).toBeHidden();

    await page.getByRole("tab", { name: /^Allowed requests/ }).click();
    await rows.filter({ hasText: "/allowed" }).getByRole("cell").nth(3).click();
    dialog = page.getByRole("dialog", { name: "GET 127.0.0.1/allowed" });
    const upstream = dialog.getByRole("region", { name: "Captured response" });
    await expect(upstream.getByText("200", { exact: true })).toBeVisible();
    await expect(upstream.getByLabel("Response body", { exact: true })).toContainText(
        '"path": "/allowed?mode=echo"',
    );
    await expect(dialog.getByRole("region", { name: "Captured request" })).toContainText(
        "No body.",
    );
});

test("WebSocket rows are marked WS and their details list the captured messages", async ({
    page,
    protocolProxy: fixture,
}) => {
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    await loginBrowser(page, ui, "integration-password");
    const enabled = await page.request.put(`${ui}/api/capture`, {
        headers: await sessionHeaders(page),
        data: { enabled: true, body_limit_kb: 32 },
    });
    expect(enabled.status()).toBe(200);
    const socket = (path: string) =>
        websocketExchange({ proxyPort: fixture.proxyPort, port: fixture.upstreamPort, path });
    expect((await socket("/allowed")).status).toBe(101);
    expect((await socket("/denied")).status).toBe(403);

    await page.goto(`${ui}/?view=allowed-requests`);
    const rows = page.getByRole("tabpanel").locator("tbody tr");
    const allowed = rows.filter({ hasText: "/allowed" });
    await expect(allowed.getByRole("cell").nth(0)).toHaveText("GETWS");
    await allowed.getByRole("cell").nth(3).click();
    const dialog = page.getByRole("dialog", { name: "GET WS 127.0.0.1/allowed" });
    await expect(dialog).toBeVisible();
    await expect(
        dialog.getByRole("region", { name: "Captured response" }).getByText("101", { exact: true }),
    ).toBeVisible();
    await expect(dialog.getByText("Body", { exact: true })).toHaveCount(0);
    const messages = dialog.getByRole("region", { name: "WebSocket messages" });
    await expect(messages.getByText(/^Closed by the client after/)).toBeVisible();
    await expect(messages.getByText("Client sent 1 message (5 bytes)")).toBeVisible();
    await expect(
        messages.getByRole("table", { name: "WebSocket messages" }).locator("tbody tr"),
    ).toHaveText([
        /Server → client.*text.*"path":"\/allowed"/,
        /Client → server.*text.*5 bytes.*hello/,
        /Server → client.*text.*echo:hello/,
        // The upstream's close reply ends the handshake and is not relayed.
        /Client → server.*close.*Code 1000/,
    ]);
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();

    await showTab(page, "Blocked requests");
    const denied = rows.filter({ hasText: "/denied" });
    await expect(denied.getByRole("cell").nth(0)).toHaveText("GETWS");
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
                    bytes: { up: 0, down: 0 },
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
                    count: 1,
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
            await page.request.get(`${ui}/api/rules/05-web.toml`, {
                headers: await sessionHeaders(page),
            })
        ).json();
        current.rules = [{ index: null, fields: { ...entry.fields, dns_only: true } }];
        if (entry.existingHttp) {
            current.rules.push({ index: null, fields: { domain: "example.com", methods: "ANY" } });
        }
        expect(
            (
                await page.request.put(`${ui}/api/rules/05-web.toml`, {
                    headers: await sessionHeaders(page),
                    data: current,
                })
            ).status(),
        ).toBe(200);
        await page.goto(entry.button === denial ? `${ui}/?view=requests` : `${ui}/`);
        await page.getByRole("button", { name: entry.button, exact: true }).click();
        let message = "Domain allowed on all routes and methods.";
        if (entry.button === denial) {
            message = "Method and pathname allowed.";
        } else if (entry.button === subdomains) {
            message = "Domain and its subdomains allowed on all routes and methods.";
        }
        await expect(page.getByRole("status")).toHaveText(message);
        const saved: RulesDocument = await (
            await page.request.get(`${ui}/api/rules/05-web.toml`, {
                headers: await sessionHeaders(page),
            })
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

test("rule files show absolute paths that copy to the clipboard", async ({
    page,
    context,
    protocolProxy: fixture,
}) => {
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: ui });
    await loginBrowser(page, ui, "integration-password");
    await page.goto(`${ui}/rules`);
    const files = page.getByRole("list", { name: "Rule files", exact: true });
    const path = join(fixture.rules, "1-test.toml");
    await expect(files.getByText(path, { exact: true })).toBeVisible();
    await expect(
        files.getByText(join(fixture.rules, "05-web.toml"), { exact: true }),
    ).toBeVisible();
    await files.getByRole("button", { name: `Copy path ${path}`, exact: true }).click();
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(path);
    await files.getByRole("link", { name: "Edit 1-test.toml", exact: true }).click();
    await expect(page.getByRole("heading", { name: "1-test.toml", exact: true })).toBeVisible();
    await expect(page.getByText(path, { exact: true })).toBeVisible();
    await expect(
        page.getByRole("button", { name: `Copy path ${path}`, exact: true }),
    ).toBeVisible();
});

test("broken rule files open as TOML with their error and are repaired from the editor", async ({
    page,
    protocolProxy: fixture,
}) => {
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    const path = join(fixture.rules, "30-broken.toml");
    const broken = "[[allow]]\ndomain = 'repaired.test'\nunknown = 1\n";
    await writeFile(path, broken);
    await loginBrowser(page, ui, "integration-password");
    await page.goto(`${ui}/rules`);
    const files = page.getByRole("list", { name: "Rule files", exact: true });
    const brokenFile = files.getByRole("listitem").filter({ hasText: "30-broken.toml" });
    await expect(brokenFile.getByText("Invalid", { exact: true })).toBeVisible();

    await page.goto(`${ui}/rules/30-broken.toml`);
    const alert = page.getByRole("alert");
    await expect(alert).toContainText("30-broken.toml is invalid");
    await expect(alert).toContainText("unknown field `unknown`");
    await expect(page.getByRole("button", { name: "Edit as form", exact: true })).toHaveCount(0);
    const editor = page.locator(".cm-content");
    await expect(editor).toContainText("domain = 'repaired.test'");

    /** Replace the editor's whole text as if typed. */
    async function replaceText(text: string) {
        await editor.click();
        await page.keyboard.press("ControlOrMeta+A");
        await page.keyboard.insertText(text);
    }
    await replaceText("[[allow]\n");
    await page.getByRole("button", { name: "Save changes", exact: true }).click();
    await expect(alert).toContainText("Not saved");
    await expect(alert).toContainText("TOML parse error at line 1");
    expect(await readFile(path, "utf8")).toBe(broken);

    const repaired = "# Repaired in the browser\n[[allow]]\ndomain = 'repaired.test'\n";
    await replaceText(repaired);
    await page.keyboard.press("ControlOrMeta+S");
    await expect(page.getByText("Changes saved.", { exact: true })).toBeVisible();
    await expect(alert).toHaveCount(0);
    expect(await readFile(path, "utf8")).toBe(repaired);

    await page.getByRole("button", { name: "Edit as form", exact: true }).click();
    await expect(page.getByRole("button", { name: "Rule 1", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Edit as TOML", exact: true }).click();
    await expect(editor).toContainText("# Repaired in the browser");
});

test("blocking pauses for the chosen minutes, allows denied requests, and resumes", async ({
    page,
    protocolProxy: fixture,
}) => {
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    /** Send a request that the fixture rules deny while blocking is enforced. */
    const denied = () =>
        exchange({
            hostname: "127.0.0.1",
            port: fixture.proxyPort,
            path: `http://127.0.0.1:${fixture.upstreamPort}/allowed`,
            method: "POST",
            headers: { Host: `127.0.0.1:${fixture.upstreamPort}` },
        });
    expect(
        (await page.request.post(`${ui}/api/blocking/pause`, { data: { minutes: 5 } })).status(),
    ).toBe(401);
    expect((await denied()).status).toBe(403);
    expect(await queryDns("127.0.0.1", fixture.dnsPort, "denied.test")).toBe(5);

    await loginBrowser(page, ui, "integration-password");
    await page.goto(`${ui}/`);
    await page.getByRole("button", { name: "Pause blocking", exact: true }).click();
    const minutes = page.getByRole("spinbutton", { name: "Pause for minutes" });
    await expect(minutes).toHaveValue("5");
    await minutes.fill("2");
    await page.locator("#pause-blocking").getByRole("button", { name: "Pause blocking" }).click();
    await expect(page.getByText("Blocking paused for 2 minutes.")).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "Blocking is paused" })).toContainText(
        /for (2:00|1:5\d)\./,
    );
    const status = await page.request.get(`${ui}/api/blocking`, {
        headers: await sessionHeaders(page),
    });
    const { paused_seconds_remaining: remaining } = await status.json();
    expect(remaining).toBeGreaterThan(100);
    expect(remaining).toBeLessThanOrEqual(120);

    expect((await denied()).status).toBe(200);
    expect(await queryDns("127.0.0.1", fixture.dnsPort, "denied.test")).toBe(0);

    await page.getByRole("button", { name: "Resume blocking", exact: true }).click();
    await expect(page.getByText("Blocking resumed.")).toBeVisible();
    await expect(page.getByText("Blocking is paused")).toHaveCount(0);
    expect((await denied()).status).toBe(403);
    expect(await queryDns("127.0.0.1", fixture.dnsPort, "denied.test")).toBe(5);
});
