import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { fixtureCheck, fixtureOperation, writeFixtureRules } from "#playwright_helpers/client.mts";
import type { HttpResult, NetworkOperation } from "#playwright_helpers/protocol.mts";

/** Retained mitmwall HTTP case names and expected outcomes, checked through both protocols. */
interface NetworkCase {
    name: string;
    url: string;
    method: string;
    status: number;
}
const cases: NetworkCase[] = JSON.parse(
    await readFile(new URL("../../tests/fixtures/network-cases.json", import.meta.url), "utf8"),
);
const rules = await readFile(
    new URL("../../tests/fixtures/mitmwall-integration-rules.toml", import.meta.url),
    "utf8",
);

/** Require an HTTP response rather than treating a transport error as a policy denial. */
async function http(
    url: string,
    method = "GET",
    headers?: Record<string, string>,
): Promise<HttpResult> {
    const response = await fixtureOperation({ operation: "http", url, method, headers });
    if (response.error || !response.result || typeof response.result !== "object") {
        throw new Error(JSON.stringify(response));
    }
    return response.result;
}

test.beforeEach(async () => {
    await writeFixtureRules(rules);
    await expect.poll(async () => (await http("https://pie.dev/get")).status).toBe(200);
});
test.afterEach(async () => {
    await writeFixtureRules(null);
    await expect.poll(async () => (await http("https://pie.dev/get")).status).toBe(403);
});

for (const { name, url, method, status } of cases) {
    test(name, async () => {
        for (const target of [url, url.replace("https://", "http://")]) {
            const response = await http(target, method);
            expect(response.status).toBe(status);
            if (status === 200 && method !== "HEAD") {
                const parsed = new URL(target);
                expect(JSON.parse(response.body)).toMatchObject({
                    fixture: "exwall-local-upstream",
                    method,
                    path: `${parsed.pathname}${parsed.search}`,
                });
            }
        }
    });
}

test("header injection replaces authorization", async () => {
    const response = await http("https://pie.dev/headers", "GET", { Authorization: "old" });
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body).headers).toMatchObject({
        authorization: "Secret",
        "x-mitmwall-test": "enabled",
    });
});

for (const [host, port] of [
    ["github.com", 22],
    ["ftp.ubuntu-tw.org", 21],
] satisfies [string, number][]) {
    test(`direct TCP to ${host}:${port} is dropped with a reachable control`, async () => {
        const operation: NetworkOperation = { operation: "tcp", host, port };
        expect(await fixtureOperation(operation, "bypass")).toEqual({ result: true });
        expect(await fixtureOperation(operation)).toMatchObject({ error_type: "TimeoutError" });
    });
}

for (const host of ["8.8.8.8", "172.64.155.209"]) {
    test(`network bypass ${host} preserves the upstream certificate`, async () => {
        const operation: NetworkOperation = {
            operation: "certificate",
            host,
            port: 443,
            hostname: "dns.google",
        };
        const direct = await fixtureOperation(operation, "bypass");
        expect(direct.error).toBeUndefined();
        expect(await fixtureOperation(operation)).toEqual(direct);
    });
}

test("configured user bypasses interception", async () => {
    const operation: NetworkOperation = {
        operation: "certificate",
        host: "1.1.1.1",
        port: 443,
        hostname: "cloudflare-dns.com",
    };
    const direct = await fixtureOperation(operation, "bypass");
    const proxied = await fixtureOperation(operation);
    expect(direct.error).toBeUndefined();
    expect(proxied.error).toBeUndefined();
    expect(proxied).not.toEqual(direct);
});

test("UDP and TCP DNS redirects enforce literal and regex rules in both families", async () => {
    for (const host of ["192.0.2.2", "fd00:7261::2"]) {
        for (const tcp of [false, true]) {
            for (const [name, expected] of [
                ["github.com", 0],
                ["ipinfo.io", 0],
                ["not-allowed.mitmwall.invalid", 5],
            ] satisfies [string, number][]) {
                const operation: NetworkOperation = { operation: "dns", host, name, tcp };
                expect(await fixtureOperation(operation, "bypass")).toEqual({ result: 0 });
                expect(await fixtureOperation(operation)).toEqual({ result: expected });
            }
        }
    }
});

test("ordinary UID can reach localhost and send ICMPv6 over loopback and veth", async () => {
    expect(await fixtureOperation({ operation: "tcp", host: "127.0.0.1", port: 58000 })).toEqual({
        result: true,
    });
    for (const host of ["::1", "fd00:7261::2"]) {
        expect(await fixtureOperation({ operation: "ping", host })).toEqual({ result: true });
    }
});

test("control domains and subdomains allow arbitrary paths, methods, and DNS", async () => {
    for (const host of ["chatgpt.com", "openai.com", "api.openai.com", "cdn.chatgpt.com"]) {
        for (const method of ["GET", "POST", "PATCH"]) {
            for (const scheme of ["https", "http"]) {
                expect((await http(`${scheme}://${host}/arbitrary/path`, method)).status).toBe(200);
            }
        }
        expect(await fixtureOperation({ operation: "dns", host: "192.0.2.2", name: host })).toEqual(
            { result: 0 },
        );
    }
});

for (const [name, scenario] of [
    ["conntrack direction, jump ordering, user bypasses, and ICMP allowances", "ordering"],
    ["hook permissions, idempotence, malformed-file cleanup, and exact restoration", "state"],
    ["configured command logging and normalized CIDR bypass ordering", "logging"],
    ["empty custom policy removes installed bypasses", "empty-bypasses"],
    ["invalid policy and listener startup failures retain enforcement", "invalid-policy"],
    ["initial invalid configuration installs a bootstrap guard", "bootstrap"],
    ["corrupt forwarding state retains diagnostics and sysctls", "corrupt-state"],
    ["full installed hooks intercept IPv6 domain traffic", "ipv6-hosts"],
    ["production systemd failures and automatic restarts remain closed", "systemd"],
    [
        "transparent original destinations and authorized-host routing avoid attackers",
        "transparent",
    ],
]) {
    test(name!, async () => {
        await fixtureCheck(scenario!);
    });
}
