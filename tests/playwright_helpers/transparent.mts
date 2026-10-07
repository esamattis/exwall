/** Source-scoped redirects verify original destinations and authorized-host routing in both families. */
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createConnection } from "node:net";
import { connect } from "node:tls";
import { once } from "node:events";
import { startMockServer } from "#playwright_helpers/mock_server.mts";
import type { MockServer } from "#playwright_helpers/mock_server.mts";
import { certificate, exchange, freePort } from "#playwright_helpers/proxy_fixture.mts";
import {
    runCommand,
    startProcess,
    stopProcess,
    waitForPort,
    bounded,
} from "#playwright_helpers/processes.mts";
import type { LifecycleFixture } from "#playwright_helpers/lifecycle.mts";

/** Check transparent HTTP/TLS, filtering, injection, and attacker avoidance on IPv4 and IPv6. */
export async function checkTransparent(fixture: LifecycleFixture): Promise<void> {
    const root = join(fixture.root, "transparent");
    const rules = join(root, "rules");
    await mkdir(rules, { recursive: true });
    const config = join(root, "config.toml");
    await writeFile(config, "manage_resolv_conf = false\n[ui]\nhosts = []\n");
    await writeFile(
        join(rules, "1-test.toml"),
        "[[allow]]\ndomain = ['allowed.test', 'allowed-v6.test']\npathname_pattern = '/secure'\ninject_headers = [{name='Authorization', value='injected'}]\n[[allow]]\ndomain = ['allowed.test', 'allowed-v6.test']\npathname_pattern = '/allowed'\n",
    );
    const hosts = join(root, "hosts");
    await writeFile(hosts, "127.0.0.2 allowed.test\n::1 allowed-v6.test\n", { mode: 0o644 });
    await runCommand(["mount", "--bind", hosts, "/etc/hosts"]);
    const cleanup: (() => Promise<unknown>)[] = [() => runCommand(["umount", "/etc/hosts"])];
    try {
        const material = await certificate(root, fixture.ca, ["allowed.test", "allowed-v6.test"]);
        const proxyPort = await freePort();
        const dnsPort = await freePort();
        const proxy = startProcess(
            [
                fixture.binary,
                "--config",
                config,
                "--rules-dir",
                rules,
                "serve",
                "--listen",
                `[::]:${proxyPort}`,
                "--dns-listen",
                `[::]:${dnsPort}`,
                "--ca-dir",
                fixture.ca,
            ],
            {
                env: {
                    ...process.env,
                    SSL_CERT_FILE: fixture.cert,
                    SSL_CERT_DIR: join(root, "empty-trust"),
                },
            },
        );
        cleanup.push(() => stopProcess(proxy));
        await waitForPort(proxyPort, proxy);
        /** Redirect a single source port, leaving all proxy upstream connections untouched. */
        async function intercepted(
            server: MockServer,
            ipv6: boolean,
            tls: boolean,
            path: string,
            destination?: string,
        ) {
            const address = ipv6 ? "::1" : "127.0.0.2";
            const hostname = ipv6 ? "allowed-v6.test" : "allowed.test";
            const sourcePort = await freePort();
            const tool = ipv6 ? "ip6tables" : "iptables";
            const redirect = [
                "-p",
                "tcp",
                "--sport",
                String(sourcePort),
                "--dport",
                String(server.port),
                "-j",
                "REDIRECT",
                "--to-ports",
                String(proxyPort),
            ];
            await runCommand([tool, "-t", "nat", "-I", "OUTPUT", ...redirect]);
            const socket = createConnection({
                host: destination ?? address,
                port: server.port,
                localAddress: address,
                localPort: sourcePort,
            });
            try {
                await bounded(once(socket, "connect"), 3000, "Transparent connection");
                if (tls) {
                    const secure = connect({
                        socket,
                        servername: hostname,
                        ca: await readFile(fixture.cert),
                    });
                    await bounded(once(secure, "secureConnect"), 3000, "Transparent TLS");
                    return await exchange(
                        {
                            host: hostname,
                            port: server.port,
                            path,
                            headers: { Host: hostname, Connection: "close" },
                        },
                        secure,
                    );
                }
                return await exchange(
                    {
                        host: hostname,
                        port: server.port,
                        path,
                        headers: { Host: hostname, Connection: "close" },
                    },
                    socket,
                );
            } finally {
                socket.destroy();
                await runCommand([tool, "-t", "nat", "-D", "OUTPUT", ...redirect]);
            }
        }
        for (const ipv6 of [false, true]) {
            for (const tls of [false, true]) {
                const server = await startMockServer({
                    host: ipv6 ? "::1" : "127.0.0.2",
                    tls: tls ? { ...material, allowHTTP1: true } : undefined,
                });
                cleanup.push(() => server.close());
                const response = await intercepted(server, ipv6, tls, tls ? "/secure" : "/allowed");
                assert.equal(response.status, 200);
                assert.equal(
                    JSON.parse(response.body).headers.authorization ?? null,
                    tls ? "injected" : null,
                );
                if (!tls) {
                    assert.equal((await intercepted(server, ipv6, tls, "/secure")).status, 403);
                }
                assert.equal((await intercepted(server, ipv6, tls, "/denied")).status, 403);
                if (!ipv6) {
                    const attacker = await startMockServer({
                        host: "127.0.0.1",
                        port: server.port,
                    });
                    cleanup.push(() => attacker.close());
                    const routed = await intercepted(
                        server,
                        false,
                        tls,
                        tls ? "/secure" : "/allowed",
                        "127.0.0.1",
                    );
                    assert.equal(routed.status, 200);
                    assert.equal(
                        JSON.parse(routed.body).headers.authorization ?? null,
                        tls ? "injected" : null,
                    );
                    if (!tls) {
                        assert.equal(
                            (await intercepted(server, false, false, "/secure", "127.0.0.1"))
                                .status,
                            403,
                        );
                    }
                    assert.deepEqual(attacker.requests, []);
                }
            }
        }
        await stopProcess(proxy);
        assert.equal(proxy.output?.exitCode, 0);
    } finally {
        for (const close of cleanup.reverse()) {
            await close();
        }
    }
}
