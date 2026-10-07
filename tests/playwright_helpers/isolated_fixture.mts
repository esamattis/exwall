/**
 * Sets up and owns the disposable Playwright environment: private configuration,
 * networking, certificates, upstreams, real exwall hooks, and socket services. Restores
 * namespace state and removes temporary resources when the host ends the run.
 * @module
 */

import {
    chmod,
    chown,
    copyFile,
    mkdir,
    mkdtemp,
    readlink,
    rm,
    writeFile,
    open,
    readFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Server as HttpServer } from "node:http";
import type { ProcessPromise } from "zx/core";
import {
    assertIsolated,
    firewallSnapshot,
    forwardingSnapshot,
} from "#playwright_helpers/namespace_safety.mts";
import {
    runCommand,
    startProcess,
    stopProcess,
    processMessages,
    waitForControlEnd,
    waitForPort,
    isMain,
} from "#playwright_helpers/processes.mts";
import type { UiBridge } from "#playwright_helpers/ui_bridge.mts";
import { startUiBridge } from "#playwright_helpers/ui_bridge.mts";
import { fixtureHosts } from "#playwright_helpers/fixture_constants.mts";
import { runFixtureCheck } from "#playwright_helpers/lifecycle.mts";
import { startClientBroker, closeClientBroker } from "#playwright_helpers/client_broker.mts";

/** Start a private dual-stack service, real hooks, and an h2-only upstream for one suite. */
async function main(): Promise<void> {
    await assertIsolated();
    const [binary, sockets, output, ownerUid, ownerGid] = process.argv.slice(2);
    if (!binary || !sockets || !output || !ownerUid || !ownerGid) {
        throw new Error("Missing fixture arguments");
    }
    const uid = Number(ownerUid);
    const gid = Number(ownerGid);
    const root = await mkdtemp(join(tmpdir(), "exwall-playwright-"));
    await chmod(root, 0o755);
    const ca = join(root, "ca");
    const cert = join(ca, "exwall-ca-cert.pem");
    const config = join(root, "config.toml");
    const rules = join(root, "rules");
    const configText = await readFile(
        new URL("../fixtures/mitmwall-integration-config.toml", import.meta.url),
        "utf8",
    );
    const requestSocket = join(root, "requests.sock");
    const proxyPort = 58080;
    const dnsPort = 58053;
    const uiPort = 58000;
    const hook = [
        binary,
        "--config",
        config,
        "--rules-dir",
        rules,
        "hook",
        "--proxy-user",
        "root",
        "--state-dir",
        join(root, "state"),
        "--proxy-port",
        String(proxyPort),
        "--dns-port",
        String(dnsPort),
    ];
    const cleanup: (() => Promise<unknown>)[] = [];
    let baseline: string[] | undefined;
    let sysctls: string | undefined;
    let hooksStarted = false;
    const failures: unknown[] = [];
    try {
        await mkdir(rules);
        await writeFile(join(rules, "10-admin.toml"), '[[allow]]\ndomain = "github.com"\n');
        await writeFile(
            config,
            `${configText}\n[ui]\nhosts = ["127.0.0.1", "::1"]\nport = ${uiPort}\nusername = "admin"\npassword = "browser-password"\nsessions_dir = ${JSON.stringify(join(root, "sessions"))}\n[access_log]\npath = ${JSON.stringify(join(root, "access.log"))}\n`,
        );
        const hosts = join(root, "hosts");
        await writeFile(
            hosts,
            `127.0.0.1 localhost\n::1 localhost\n192.0.2.2 ${fixtureHosts.join(" ")}\n`,
            { mode: 0o644 },
        );
        await runCommand(["mount", "--bind", hosts, "/etc/hosts"]);
        const passwd = join(root, "passwd");
        await writeFile(
            passwd,
            "root:x:0:0::/root:/bin/sh\ndaemon:x:1:1::/nonexistent:/usr/sbin/nologin\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\nsystemd-resolve:x:990:990::/nonexistent:/usr/sbin/nologin\n",
            { mode: 0o644 },
        );
        await runCommand(["mount", "--bind", passwd, "/etc/passwd"]);
        await runCommand(["ip", "link", "set", "lo", "up"]);
        await runCommand(["sysctl", "-w", "net.ipv4.ping_group_range=65534 65534"]);
        await runCommand([binary, "init-ca", "--ca-dir", ca]);
        await chmod(ca, 0o755);
        await chmod(cert, 0o644);
        const key = join(root, "upstream.key");
        const upstreamCert = join(root, "upstream.pem");
        const csr = join(root, "upstream.csr");
        const extensions = join(root, "extensions.cnf");
        await writeFile(
            extensions,
            `subjectAltName=${fixtureHosts.map((host) => `DNS:${host}`).join(",")},IP:192.0.2.2,IP:fd00:7261::2\nextendedKeyUsage=serverAuth\n`,
        );
        await runCommand([
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key,
            "-out",
            csr,
            "-subj",
            "/CN=example.com",
        ]);
        await runCommand([
            "openssl",
            "x509",
            "-req",
            "-in",
            csr,
            "-CA",
            cert,
            "-CAkey",
            join(ca, "exwall-ca-key.pem"),
            "-CAcreateserial",
            "-out",
            upstreamCert,
            "-days",
            "1",
            "-extfile",
            extensions,
        ]);
        const upstreamLog = await open(join(root, "upstream.log"), "w");
        cleanup.push(() => upstreamLog.close());
        const mockScript = fileURLToPath(
            import.meta.resolve("#playwright_helpers/mock_server.mts"),
        );
        const upstream = startProcess(
            ["unshare", "--net", process.execPath, mockScript, upstreamCert, key, requestSocket],
            { stdio: ["pipe", "pipe", upstreamLog.fd] },
        );
        cleanup.push(() => stopProcess(upstream, true));
        const messages = processMessages(upstream);
        cleanup.push(async () => messages.close());
        const isolated = await messages.next<{ phase: string; pid: number }>();
        if (isolated.phase !== "isolated") {
            throw new Error("Upstream did not verify isolation");
        }
        await runCommand([
            "ip",
            "link",
            "add",
            "pw-client",
            "type",
            "veth",
            "peer",
            "name",
            "pw-server",
        ]);
        await runCommand(["ip", "link", "set", "pw-server", "netns", String(isolated.pid)]);
        await runCommand(["ip", "addr", "add", "192.0.2.1/24", "dev", "pw-client"]);
        await runCommand([
            "ip",
            "-6",
            "addr",
            "add",
            "fd00:7261::1/64",
            "dev",
            "pw-client",
            "nodad",
        ]);
        await runCommand(["ip", "link", "set", "pw-client", "up"]);
        const peer = ["nsenter", "-t", String(isolated.pid), "--net"];
        await runCommand([...peer, "ip", "link", "set", "lo", "up"]);
        await runCommand([...peer, "ip", "addr", "add", "192.0.2.2/24", "dev", "pw-server"]);
        await runCommand([
            ...peer,
            "ip",
            "-6",
            "addr",
            "add",
            "fd00:7261::2/64",
            "dev",
            "pw-server",
            "nodad",
        ]);
        await runCommand([...peer, "ip", "link", "set", "pw-server", "up"]);
        for (const address of ["8.8.8.8", "172.64.155.209", "1.1.1.1"]) {
            await runCommand([...peer, "ip", "addr", "add", `${address}/32`, "dev", "pw-server"]);
            await runCommand(["ip", "route", "add", `${address}/32`, "via", "192.0.2.2"]);
        }
        upstream.stdin.write("start\n");
        if ((await messages.next<{ phase: string }>()).phase !== "ready") {
            throw new Error("Upstream failed to start");
        }
        const proxyLog = await open(join(root, "proxy.log"), "w");
        cleanup.push(() => proxyLog.close());
        const proxy: ProcessPromise = startProcess(
            [
                binary,
                "--config",
                config,
                "--rules-dir",
                rules,
                "serve",
                "--listen",
                `[::]:${proxyPort}`,
                "--dns-listen",
                `[::]:${dnsPort}`,
                "--dns-upstream",
                "192.0.2.2:53",
                "--ca-dir",
                ca,
            ],
            {
                stdio: ["pipe", proxyLog.fd, proxyLog.fd],
                env: {
                    ...process.env,
                    SSL_CERT_FILE: cert,
                    SSL_CERT_DIR: join(root, "empty-trust"),
                },
            },
        );
        cleanup.push(() => stopProcess(proxy));
        await waitForPort(uiPort, proxy);
        await waitForPort(proxyPort, proxy);
        for (const tool of ["iptables", "ip6tables"]) {
            for (const table of ["filter", "nat"]) {
                await runCommand([
                    tool,
                    "-t",
                    table,
                    "-A",
                    "OUTPUT",
                    "-o",
                    "lo",
                    "-m",
                    "comment",
                    "--comment",
                    "exwall-integration-admin",
                    "-j",
                    "ACCEPT",
                ]);
            }
        }
        baseline = await firewallSnapshot();
        sysctls = await forwardingSnapshot();
        hooksStarted = true;
        await runCommand([...hook, "start"]);
        const uiSocket = join(sockets, "ui.sock");
        const bridge: UiBridge = await startUiBridge(
            { path: uiSocket },
            { host: "127.0.0.1", port: uiPort },
        );
        cleanup.push(() => bridge.close());
        await chmod(uiSocket, 0o600);
        await chown(uiSocket, uid, gid);
        const clientSocket = join(sockets, "client.sock");
        const broker: HttpServer = await startClientBroker({
            socket: clientSocket,
            rules: join(rules, "05-web.toml"),
            certificate: cert,
            requestSocket,
            cwd: root,
            policyRules: join(rules, "20-network.toml"),
            check: (name) =>
                runFixtureCheck(name, {
                    root,
                    binary,
                    config,
                    rules,
                    ca,
                    cert,
                    hook,
                    proxyPort,
                    dnsPort,
                    proxy,
                    baseline: baseline ?? [],
                    sysctls: sysctls ?? "",
                }),
            uid,
            gid,
        });
        cleanup.push(() => closeClientBroker(broker));
        process.stdout.write(
            `${JSON.stringify({ uiSocket, clientSocket, netNamespace: await readlink("/proc/self/ns/net") })}\n`,
        );
        await waitForControlEnd();
    } catch (error) {
        failures.push(error);
    } finally {
        if (hooksStarted) {
            try {
                await runCommand([...hook, "stop"]);
                if (JSON.stringify(await firewallSnapshot()) !== JSON.stringify(baseline)) {
                    failures.push(new Error("Hooks did not restore namespace firewall"));
                }
                if ((await forwardingSnapshot()) !== sysctls) {
                    failures.push(new Error("Hooks did not restore namespace sysctls"));
                }
            } catch (error) {
                failures.push(error);
            }
        }
        for (const close of cleanup.reverse()) {
            try {
                await close();
            } catch (error) {
                failures.push(error);
            }
        }
        for (const name of ["proxy.log", "upstream.log", "access.log"]) {
            try {
                const target = join(output, name);
                await copyFile(join(root, name), target);
                await chown(target, uid, gid);
            } catch (error) {
                if (hooksStarted) {
                    failures.push(error);
                }
            }
        }
        await rm(root, { recursive: true, force: true });
    }
    if (failures.length) {
        throw new AggregateError(failures, "Isolated fixture failed");
    }
}

if (isMain(import.meta.url)) {
    await main();
}
