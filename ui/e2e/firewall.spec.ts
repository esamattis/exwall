import { fixtureRules, networkRequest, upstreamRequests } from "#playwright_helpers/client.mts";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

/** Save through the production API and wait for the editor's success feedback. */
async function save(page: Page) {
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByRole("status")).toHaveText("Changes saved.");
}

/** Run the existing client as nobody and wait for real firewall policy changes. */
async function expectTraffic(url: string, status: number, header?: string, method = "GET") {
    await expect
        .poll(async () => {
            const response = await networkRequest({
                operation: "http",
                url,
                method,
            });
            if (response.error || typeof response.result === "boolean") return response;
            const result: Record<string, unknown> = { status: response.result?.status };
            if (status === 200 && response.result?.status === 200) {
                const payload = JSON.parse(response.result.body);
                result.fixture = payload.fixture;
                result.method = payload.method;
                if (url.startsWith("https:")) result.httpVersion = payload.httpVersion;
                if (header) {
                    result.header = Object.entries(payload.headers).find(
                        ([name]) => name.toLowerCase() === "x-browser-e2e",
                    )?.[1];
                }
            }
            return result;
        })
        .toEqual({
            status,
            ...(status === 200 ? { fixture: "exwall-local-upstream", method } : {}),
            ...(header ? { header } : {}),
            ...(status === 200 && url.startsWith("https:") ? { httpVersion: "2.0" } : {}),
        });
}

test("real login, edits, validation, persistence, and HTTP/TLS interception", async ({
    page,
    context,
}) => {
    // The restricted helper must reach allowed upstreams and receive exwall denials for others.
    await expectTraffic("http://github.com/control", 200);
    await expectTraffic("http://example.com/browser", 403);
    await expectTraffic("https://example.com/browser", 403);
    expect(
        (await upstreamRequests()).some(
            (request) =>
                request.headers.host === "example.com" ||
                request.headers[":authority"] === "example.com",
        ),
    ).toBe(false);

    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Sign in to edit rules" })).toBeVisible();
    await page.getByRole("link", { name: "Sign in", exact: true }).click();
    await page.getByRole("textbox", { name: "Username" }).fill("admin");
    await page.getByLabel("Password", { exact: true }).fill("wrong-password");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("alert")).toBeVisible();
    await page.getByLabel("Password", { exact: true }).fill("browser-password");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Rules", exact: true })).toBeVisible();

    await page.getByRole("button", { name: "Add rule", exact: true }).click();
    await page.getByRole("textbox", { name: "Rule 1 domain", exact: true }).fill("example.com");
    await page
        .getByRole("textbox", { name: "Rule 1 pathname_pattern", exact: true })
        .fill("/browser");
    await save(page);
    expect(await fixtureRules()).toContain('domain = "example.com"');
    for (const scheme of ["http", "https"]) {
        await expectTraffic(`${scheme}://example.com/browser`, 200);
        await expectTraffic(`${scheme}://example.com/other`, 403);
    }

    await page.getByRole("button", { name: "Add header", exact: true }).click();
    await page.getByRole("textbox", { name: "Rule 1 inject_headers 1 name" }).fill("X-Browser-E2E");
    await page
        .getByRole("textbox", { name: "Rule 1 inject_headers 1 value" })
        .fill("saved-in-browser");
    await save(page);
    await expectTraffic("https://example.com/browser", 200, "saved-in-browser");
    // Production rules intentionally refuse to inject headers into plaintext traffic.
    await expectTraffic("http://example.com/browser", 403);

    // A real validation failure must preserve both the file and active policy.
    const persisted = await fixtureRules();
    await page.getByRole("textbox", { name: "Rule 1 pathname_regex", exact: true }).fill("[");
    const rejected = page.waitForResponse(
        (response) =>
            response.url().endsWith("/api/rules") && response.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save changes" }).click();
    expect((await rejected).status()).toBe(400);
    await expect(page.getByRole("alert")).toBeVisible();
    expect(await fixtureRules()).toBe(persisted);
    await expectTraffic("https://example.com/browser", 200, "saved-in-browser");
    await page.reload();
    await expect(
        page.getByRole("textbox", { name: "Rule 1 pathname_regex", exact: true }),
    ).toHaveValue("");
    await expect(page.getByRole("textbox", { name: "Rule 1 domain", exact: true })).toHaveValue(
        "example.com",
    );

    // Exercise IPv6 redirects with the same restricted client UID.
    await expectTraffic("http://[fd00:7261::2]/browser", 403);
    await page
        .getByRole("textbox", { name: "Rule 1 domain", exact: true })
        .fill("example.com\nfd00:7261::2");
    await page.getByRole("button", { name: "Remove Rule 1 inject_headers 1" }).click();
    await save(page);
    await expectTraffic("http://[fd00:7261::2]/browser", 200);
    await expectTraffic("https://[fd00:7261::2]/browser", 200);

    // Two authenticated tabs must not silently overwrite each other's saved revisions.
    const stale = await context.newPage();
    await stale.goto("/");
    await expect(stale.getByRole("textbox", { name: "Rule 1 domain", exact: true })).toHaveValue(
        "example.com\nfd00:7261::2",
    );
    await page.getByRole("combobox", { name: "Rule 1 methods", exact: true }).selectOption("any");
    await save(page);
    const current = await fixtureRules();
    await stale.getByRole("textbox", { name: "Rule 1 domain", exact: true }).fill("github.com");
    await stale.getByRole("button", { name: "Save changes" }).click();
    await expect(stale.getByRole("alert")).toHaveText("05-web.toml changed. Reload before saving.");
    expect(await fixtureRules()).toBe(current);
    await expectTraffic("https://example.com/browser", 200);
    await expectTraffic("https://example.com/browser", 200, undefined, "POST");
    await stale.close();

    await page.getByRole("button", { name: "Remove rule", exact: true }).click();
    await save(page);
    for (const url of [
        "http://example.com/browser",
        "https://example.com/browser",
        "http://[fd00:7261::2]/browser",
    ]) {
        await expectTraffic(url, 403);
    }
    await expectTraffic("https://github.com/control", 200);
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Sign in to edit rules" })).toBeVisible();
});

test("pathname patterns, regexes, query strings, and POST bodies reach an HTTP/2 upstream", async ({
    page,
}) => {
    await page.goto("/login");
    await page.getByRole("textbox", { name: "Username" }).fill("admin");
    await page.getByLabel("Password", { exact: true }).fill("browser-password");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Rules", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Add rule", exact: true }).click();
    await page.getByRole("textbox", { name: "Rule 1 domain", exact: true }).fill("pathname.test");
    await page
        .getByRole("textbox", { name: "Rule 1 pathname_pattern", exact: true })
        .fill("/api/:account/items/:item");
    await page
        .getByRole("combobox", { name: "Rule 1 methods", exact: true })
        .selectOption("custom");
    await page.getByRole("textbox", { name: "Rule 1 methods list", exact: true }).fill("POST");
    await save(page);
    await expectTraffic(
        "https://pathname.test/api/acme/items/42?format=json",
        200,
        undefined,
        "POST",
    );
    const exchange = await networkRequest({
        operation: "http",
        url: "https://pathname.test/api/acme/items/42?format=json",
        method: "POST",
        body: "test-payload",
        headers: { "Content-Type": "text/plain" },
    });
    if (exchange.error || typeof exchange.result === "boolean" || !exchange.result)
        throw new Error(JSON.stringify(exchange));
    expect(exchange.result.status).toBe(200);
    const payload = JSON.parse(exchange.result.body);
    expect(payload).toMatchObject({
        path: "/api/acme/items/42?format=json",
        pathname: "/api/acme/items/42",
        query: { format: "json" },
        method: "POST",
        body: "test-payload",
        httpVersion: "2.0",
    });
    const deniedPaths = ["/api/acme/items", "/api/acme/items/42/extra", "/other"];
    for (const path of deniedPaths)
        await expectTraffic(`https://pathname.test${path}`, 403, undefined, "POST");
    await expectTraffic("https://pathname.test/api/acme/items/42", 403);
    const reached = await upstreamRequests();
    expect(reached.some((request) => deniedPaths.includes(request.pathname))).toBe(false);

    await page.getByRole("textbox", { name: "Rule 1 pathname_pattern", exact: true }).fill("");
    await page
        .getByRole("textbox", { name: "Rule 1 pathname_regex", exact: true })
        .fill("^/reports/[0-9]+$");
    await page
        .getByRole("combobox", { name: "Rule 1 methods", exact: true })
        .selectOption("default");
    await save(page);
    await expectTraffic("https://pathname.test/reports/123?download=true", 200);
    await expectTraffic("https://pathname.test/reports/letters", 403);
    await expectTraffic("https://pathname.test/reports/123/extra", 403);
    await expectTraffic("https://pathname.test/reports/123", 403, undefined, "POST");
    await page.getByRole("button", { name: "Remove rule", exact: true }).click();
    await save(page);
});
