import { expect } from "@playwright/test";
import { test } from "#playwright_helpers/test_fixtures.mts";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { exchange, tlsExchange } from "#playwright_helpers/proxy_fixture.mts";
import { queryDns } from "#playwright_helpers/dns.mts";
import { runCommand, stopProcess } from "#playwright_helpers/processes.mts";
import { websocketExchange } from "#playwright_helpers/websocket.mts";

test("local proxy protocols, TLS trust, streaming, DNS, reloads, UI API, and access logs", async ({
    request,
    protocolProxy: fixture,
}) => {
    const { proxyPort, upstreamPort, securePort, cert, dnsPort } = fixture;
    /** Send an absolute-form request through the real proxy listener. */
    const http = (
        path: string,
        method = "GET",
        headers: Record<string, string> = {},
        host = "127.0.0.1",
        ipv6 = false,
    ) =>
        exchange({
            hostname: ipv6 ? "::1" : "127.0.0.1",
            port: proxyPort,
            path: `http://${host}:${upstreamPort}${path}`,
            method,
            headers: { Host: `${host}:${upstreamPort}`, ...headers },
        });
    for (const host of ["127.0.0.1", "[::1]"]) {
        const response = await request.get(`http://${host}:${fixture.uiPort}/`);
        expect(response.status()).toBe(200);
        const html = await response.text();
        expect(html).toContain("<title>exwall</title>");
        const asset = html.match(/src="([^"]+\.js)"/)?.[1];
        expect(asset).toBeTruthy();
        const script = await request.get(`http://${host}:${fixture.uiPort}${asset}`);
        expect(script.status()).toBe(200);
        expect(script.headers()["content-type"]).toMatch(/^text\/javascript/);
        expect(await script.text()).toContain("Save changes");
        expect(
            (await request.get(`http://${host}:${fixture.uiPort}/assets/missing.js`)).status(),
        ).toBe(404);
    }
    const ui = `http://127.0.0.1:${fixture.uiPort}`;
    expect((await request.get(`${ui}/api/rules`)).status()).toBe(401);
    const login = await request.post(`${ui}/api/login`, {
        data: { username: "admin", password: "integration-password" },
    });
    expect(login.status()).toBe(200);
    const { token }: { token: string } = await login.json();
    const headers = { Authorization: `Bearer ${token}` };
    expect(
        (await readdir(join(fixture.root, "sessions"))).filter((name) => name.endsWith(".json")),
    ).toHaveLength(1);
    expect(await (await request.get(`${ui}/api/rules`, { headers })).json()).toEqual([
        { name: "05-web.toml", path: join(fixture.rules, "05-web.toml"), rules: 0 },
        { name: "1-test.toml", path: join(fixture.rules, "1-test.toml"), rules: 2 },
    ]);
    const webRules = `${ui}/api/rules/05-web.toml`;
    expect((await request.get(`${ui}/api/rules/missing.toml`, { headers })).status()).toBe(404);
    let document = await (await request.get(webRules, { headers })).json();
    expect(document.rules).toEqual([]);
    document.rules = [{ index: null, fields: { domain: "ui.test" } }];
    const saved = await request.put(webRules, { headers, data: document });
    expect(saved.status()).toBe(200);
    document = await saved.json();
    expect(await readFile(join(fixture.rules, "05-web.toml"), "utf8")).toContain(
        'domain = "ui.test"',
    );
    await expect.poll(() => queryDns("127.0.0.1", dnsPort, "ui.test")).toBe(0);
    const basic = await request.get(webRules, {
        headers: {
            Authorization: `Basic ${Buffer.from("admin:integration-password").toString("base64")}`,
            Cookie: "",
        },
    });
    expect(basic.status()).toBe(200);
    expect((await basic.json()).revision).toBe(document.revision);
    document.rules = [];
    expect((await request.put(webRules, { headers, data: document })).status()).toBe(200);
    expect((await request.post(`${ui}/api/logout`, { headers, data: {} })).status()).toBe(200);
    expect(
        (await readdir(join(fixture.root, "sessions"))).filter((name) => name.endsWith(".json")),
    ).toHaveLength(0);

    expect(JSON.parse((await http("/allowed?query=retained")).body)).toEqual({
        path: "/allowed?query=retained",
        authorization: null,
        trace: null,
        upgrade: null,
    });
    expect((await http("/allowed", "GET", {}, "127.0.0.1", true)).status).toBe(200);
    expect((await http("/allowed?upstream_status=502")).status).toBe(502);
    expect(
        JSON.parse(
            (
                await http("/allowed", "GET", {
                    Authorization: "old",
                    Connection: "Authorization",
                })
            ).body,
        ).authorization,
    ).toBeNull();
    for (const [path, method, headers, expected] of [
        ["/secure", "GET", {}, 403],
        ["/allowed", "GET", { Host: "denied.test" }, 421],
        ["/denied", "GET", {}, 403],
        ["/allowed", "POST", {}, 403],
    ] satisfies [string, string, Record<string, string>, number][]) {
        expect((await http(path, method, headers)).status).toBe(expected);
    }
    expect((await http("/allowed", "GET", {}, "denied.test")).status).toBe(403);
    // Upgrade offers other than WebSocket are stripped, so the client stays on HTTP/1.1.
    const offers: Record<string, string>[] = [
        {
            Upgrade: "h2c",
            Connection: "Upgrade, HTTP2-Settings",
            "HTTP2-Settings": "AAMAAABkAAQAAP__",
        },
        { Upgrade: "websocket" },
        { Upgrade: "TLS/1.0", Connection: "Upgrade" },
    ];
    for (const offer of offers) {
        const response = await http("/allowed", "GET", offer);
        expect(response.status).toBe(200);
        expect(JSON.parse(response.body).upgrade).toBeNull();
    }
    const h2c = await runCommand([
        "curl",
        "--silent",
        "--show-error",
        "--noproxy",
        "",
        "--http2",
        "--proxy",
        `http://127.0.0.1:${proxyPort}`,
        `http://127.0.0.1:${upstreamPort}/allowed`,
        "--write-out",
        "\n%{http_version}",
    ]);
    expect(h2c.endsWith("\n1.1")).toBe(true);
    expect(JSON.parse(h2c.slice(0, h2c.lastIndexOf("\n"))).upgrade).toBeNull();
    // WebSockets are relayed wherever the rules allow their handshake GET.
    const plainSocket = await websocketExchange({
        proxyPort,
        port: upstreamPort,
        path: "/allowed",
    });
    expect(plainSocket).toEqual({
        status: 101,
        accepted: true,
        greeting: { path: "/allowed", authorization: null },
        echo: "echo:hello",
        closeCode: 1000,
    });
    for (const tunnel of [false, true]) {
        const secureSocket = await websocketExchange({
            proxyPort,
            port: securePort,
            path: "/secure",
            secure: { ca: cert, tunnel },
        });
        expect(secureSocket).toEqual({
            status: 101,
            accepted: true,
            greeting: { path: "/secure", authorization: "replacement" },
            echo: "echo:hello",
            closeCode: 1000,
        });
    }
    expect(await websocketExchange({ proxyPort, port: upstreamPort, path: "/denied" })).toEqual({
        status: 403,
    });
    for (const tunnel of [false, true]) {
        const response = await tlsExchange(proxyPort, securePort, cert, "/secure", tunnel);
        expect(response.status).toBe(200);
        expect(response.headers["x-upstream-protocol"]).toBe("HTTP/1.1");
        expect(response.headers["x-upstream-alpn"]).toBe("http/1.1");
        expect(JSON.parse(response.body)).toMatchObject({
            authorization: "replacement",
            trace: "injected",
        });
        expect((await tlsExchange(proxyPort, securePort, cert, "/denied", tunnel)).status).toBe(
            403,
        );
    }
    expect(
        (await tlsExchange(proxyPort, securePort, cert, "/secure", false, "127.0.0.1")).status,
    ).toBe(421);
    expect((await tlsExchange(proxyPort, fixture.roguePort, cert)).status).toBe(502);
    await runCommand([
        process.execPath,
        "tests/http2_upstream.mjs",
        String(proxyPort),
        join(fixture.root, "upstream.pem"),
        join(fixture.root, "upstream.key"),
        join(fixture.ca, "exwall-ca-cert.pem"),
    ]);
    const h2 = await runCommand([
        "curl",
        "--silent",
        "--show-error",
        "--noproxy",
        "",
        "--http2",
        "--cacert",
        join(fixture.ca, "exwall-ca-cert.pem"),
        "--proxy",
        `http://127.0.0.1:${proxyPort}`,
        `https://localhost:${securePort}/secure`,
        "--write-out",
        "\n%{http_version}",
    ]);
    expect(h2.endsWith("\n2")).toBe(true);
    const stream = await http("/stream");
    expect(stream.body).toBe("firstsecond");
    expect(stream.firstMilliseconds).toBeLessThan(400);
    for (const tcp of [false, true]) {
        for (const host of ["127.0.0.1", "::1"]) {
            expect(await queryDns(host, dnsPort, "localhost", tcp)).toBe(0);
            expect(await queryDns(host, dnsPort, "denied.test", tcp)).toBe(5);
        }
    }
    await writeFile(fixture.rule, "");
    await expect.poll(async () => (await http("/allowed")).status).toBe(403);
    await writeFile(fixture.rule, fixture.ruleText);
    await expect.poll(async () => (await http("/allowed")).status).toBe(200);
    await writeFile(fixture.rule, "[[allow]]\nunknown = true\n");
    await expect
        .poll(() => readFile(join(fixture.root, "proxy.log"), "utf8"))
        .toContain("rule reload rejected; keeping previous policy");
    expect((await http("/allowed")).status).toBe(200);
    await writeFile(fixture.rule, fixture.ruleText);
    await writeFile(
        fixture.config,
        `watch_rules = false\nblock_dns = false\nmanage_resolv_conf = false\n${fixture.accessConfig}`,
    );
    await runCommand(["kill", "-HUP", String(fixture.proxy.pid)]);
    await expect.poll(() => queryDns("127.0.0.1", dnsPort, "denied.test")).toBe(0);
    await writeFile(fixture.rule, "");
    await delay(350);
    expect((await http("/allowed")).status).toBe(200);
    await writeFile(
        fixture.config,
        `watch_rules = true\nblock_dns = false\nmanage_resolv_conf = false\n${fixture.accessConfig}`,
    );
    await runCommand(["kill", "-HUP", String(fixture.proxy.pid)]);
    await expect.poll(async () => (await http("/allowed")).status).toBe(403);
    await writeFile(fixture.rule, fixture.ruleText);
    await expect.poll(async () => (await http("/allowed")).status).toBe(200);
    await stopProcess(fixture.proxy);
    expect(fixture.proxy.output?.exitCode).toBe(0);
    const log = await readFile(join(fixture.root, "proxy.log"), "utf8");
    expect(log).toContain("automatically reloaded rules");
    for (const message of [
        "allowed HTTP request",
        "blocked HTTP request",
        "blocked DNS request",
        "rule regex evaluation failed",
        `${fixture.rule}:allow#2`,
    ]) {
        expect(log).not.toContain(message);
    }
    const access = await readFile(fixture.accessLog, "utf8");
    const rows = access
        .trim()
        .split("\n")
        .map((line) => line.split(/\s+/));
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
        expect([9, 10]).toContain(row.length);
        if (row.length === 10) {
            expect(row[9]).toMatch(/^x[1-9]\d*$/);
            expect(Number(row[9]?.slice(1))).toBeGreaterThan(1);
        }
    }
    const entries = rows.map((row) =>
        Object.fromEntries(
            [
                "timestamp",
                "protocol",
                "decision",
                "rule",
                "method",
                "url",
                "http_status",
                "dns_rcode",
                "error",
            ].map((name, index) => [name, row[index]]),
        ),
    );
    for (const expected of [
        {
            protocol: "http",
            decision: "ALLOW",
            rule: `${fixture.rule}:allow#2`,
            method: "GET",
            http_status: "200",
            error: "-",
            url: expect.stringContaining("/allowed?query=retained"),
        },
        {
            protocol: "http",
            decision: "DENY",
            method: "POST",
            rule: "-",
            http_status: "403",
            error: "-",
        },
        ...["GET", "CONNECT"].map((method) => ({
            protocol: "https",
            decision: "ALLOW",
            rule: `${fixture.rule}:allow#1`,
            method,
            http_status: "200",
            error: "-",
        })),
        { protocol: "https", decision: "DENY", http_status: "403", error: "-" },
        {
            protocol: "ws",
            decision: "ALLOW",
            rule: `${fixture.rule}:allow#2`,
            method: "GET",
            url: `ws://127.0.0.1:${upstreamPort}/allowed`,
            http_status: "101",
            error: "-",
        },
        {
            protocol: "wss",
            decision: "ALLOW",
            rule: `${fixture.rule}:allow#1`,
            method: "GET",
            url: `wss://localhost:${securePort}/secure`,
            http_status: "101",
            error: "-",
        },
        { protocol: "ws", decision: "DENY", rule: "-", http_status: "403", error: "-" },
        { protocol: "https", decision: "ALLOW", http_status: "502", error: "UPSTREAM_FAILURE" },
        {
            protocol: "http",
            decision: "ALLOW",
            http_status: "502",
            error: "-",
            url: expect.stringContaining("/allowed?upstream_status=502"),
        },
        {
            protocol: "dns",
            decision: "ALLOW",
            rule: `${fixture.rule}:allow#1`,
            url: "dns://localhost/A",
            dns_rcode: "NOERROR",
            error: "-",
        },
        {
            protocol: "dns",
            decision: "DENY",
            rule: "-",
            url: "dns://denied.test/A",
            dns_rcode: "REFUSED",
            error: "-",
        },
        {
            protocol: "dns",
            decision: "ALLOW",
            rule: "@dns-bypass",
            dns_rcode: "NOERROR",
            error: "-",
        },
    ]) {
        expect(entries).toEqual(expect.arrayContaining([expect.objectContaining(expected)]));
    }
    expect(
        entries.every((entry) =>
            entry.protocol === "dns"
                ? entry.http_status === "-" && entry.method === "-"
                : entry.dns_rcode === "-",
        ),
    ).toBe(true);
    expect(access).not.toContain("replacement");
    expect(access).not.toContain("proxy-secret");
});
