/** Named privileged assertions run only inside the launcher's verified disposable namespaces. */
import assert from "node:assert/strict";
import { access, readFile, readlink, stat, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ProcessPromise } from "zx/core";
import { startProcess, runCommand } from "#playwright_helpers/processes.mts";
import { firewallSnapshot, forwardingSnapshot } from "#playwright_helpers/namespace_safety.mts";
import type {
    NetworkOperation,
    NetworkResult,
    ClientResponse,
} from "#playwright_helpers/protocol.mts";
import { fixtureHosts } from "#playwright_helpers/fixture_constants.mts";
import { checkSystemd } from "#playwright_helpers/systemd_lifecycle.mts";
import { checkTransparent } from "#playwright_helpers/transparent.mts";

/** Fixture-owned paths and baseline state; callers cannot supply arbitrary command arguments. */
export interface LifecycleFixture {
    root: string;
    binary: string;
    config: string;
    rules: string;
    ca: string;
    cert: string;
    hook: string[];
    proxyPort: number;
    dnsPort: number;
    proxy: ProcessPromise;
    baseline: string[];
    sysctls: string;
}

/** Run a fixed network operation with a fixture-selected ordinary, bypass, or administrative UID. */
export async function fixtureClient(
    fixture: LifecycleFixture,
    operation: NetworkOperation,
    role = "restricted",
): Promise<ClientResponse<NetworkResult>> {
    return JSON.parse(
        await runCommand(
            [
                process.execPath,
                fileURLToPath(import.meta.resolve("#playwright_helpers/network_client.mts")),
                JSON.stringify(operation),
                fixture.cert,
                process.env.EXWALL_HOST_NET_NS ?? "",
                await readlink("/proc/self/ns/net"),
                role,
            ],
            { cwd: fixture.root, timeout: "8s" },
        ),
    );
}

/** Require a live FTP positive control and a timeout under the ordinary UID. */
export async function restricted(fixture: LifecycleFixture): Promise<void> {
    const operation: NetworkOperation = { operation: "tcp", host: "ftp.ubuntu-tw.org", port: 21 };
    assert.deepEqual(await fixtureClient(fixture, operation, "admin"), { result: true });
    const denied = await fixtureClient(fixture, operation);
    assert.equal(denied.error_type, "TimeoutError", JSON.stringify(denied));
}

/** Check whether a fixture file exists without swallowing unrelated I/O failures. */
async function exists(path: string): Promise<boolean> {
    try {
        await access(path);
        return true;
    } catch (error) {
        if (error instanceof Error && "code" in error && error.code === "ENOENT") {
            return false;
        }
        throw error;
    }
}

/** Execute one named lifecycle scenario, restoring its policy and hooks even on failure. */
export async function runFixtureCheck(name: string, fixture: LifecycleFixture): Promise<void> {
    for (const kind of ["net", "mnt"]) {
        const hostNamespace = process.env[`EXWALL_HOST_${kind.toUpperCase()}_NS`];
        if (!hostNamespace || (await readlink(`/proc/self/ns/${kind}`)) === hostNamespace) {
            throw new Error("Refusing host lifecycle checks");
        }
    }
    const { config, rules, hook, root } = fixture;
    const originalConfig = await readFile(config, "utf8");
    const rule = join(rules, "20-network.toml");
    const originalRule = await readFile(rule, "utf8").catch(() => "");
    const state = join(root, "state");
    const stateFile = join(state, "forwarding.json");
    const snapshot = await firewallSnapshot();
    const saved = await readFile(stateFile);
    /** Run a hook expected to fail while retaining stderr and its exit status. */
    const failedHook = () => startProcess([...hook, "start"], { timeout: "20s" });
    try {
        switch (name) {
            case "ordering": {
                for (const tool of ["iptables", "ip6tables"]) {
                    const output = (await runCommand([tool, "-S", "EXWALL_OUTPUT"])).split("\n");
                    const first = output.find((line) => line.startsWith("-A "))?.split(" ") ?? [];
                    assert.deepEqual(first.slice(-2), ["-j", "ACCEPT"]);
                    assert.deepEqual(
                        new Set(first[first.indexOf("--ctstate") + 1]?.split(",")),
                        new Set(["ESTABLISHED", "RELATED"]),
                    );
                    assert.equal(first[first.indexOf("--ctdir") + 1], "REPLY");
                    for (const [table, chain] of [
                        ["filter", "EXWALL_OUTPUT"],
                        ["nat", "EXWALL_NAT"],
                    ]) {
                        assert.equal(
                            (await runCommand([tool, "-t", table!, "-S", "OUTPUT"]))
                                .split("\n")
                                .find((line) => line.startsWith("-A ")),
                            `-A OUTPUT -j ${chain}`,
                        );
                    }
                    const nat = await runCommand([tool, "-t", "nat", "-S", "EXWALL_NAT"]);
                    assert.ok(nat.indexOf("--uid-owner 0") < nat.indexOf("REDIRECT"));
                    for (const table of ["filter", "nat"]) {
                        assert.match(
                            await runCommand([
                                tool,
                                "-t",
                                table,
                                "-S",
                                table === "filter" ? "EXWALL_OUTPUT" : "EXWALL_NAT",
                            ]),
                            /--uid-owner 1 -j ACCEPT/,
                        );
                    }
                }
                const v6 = (await runCommand(["ip6tables", "-S", "EXWALL_OUTPUT"])).split("\n");
                const allow = "-A EXWALL_OUTPUT -p ipv6-icmp -j ACCEPT";
                assert.equal(v6.filter((line) => line === allow).length, 1);
                assert.ok(v6.indexOf(allow) < v6.indexOf("-A EXWALL_OUTPUT -j DROP"));
                const v4 = await runCommand(["iptables", "-S", "EXWALL_OUTPUT"]);
                for (const protocol of ["icmp", "tcp", "udp"]) {
                    assert.ok(!v4.includes(`-A EXWALL_OUTPUT -p ${protocol} -j ACCEPT`));
                }
                break;
            }
            case "state": {
                for (const [path, mode] of [
                    [state, 0o700],
                    [stateFile, 0o600],
                ] satisfies [string, number][]) {
                    const metadata = await stat(path);
                    assert.equal(metadata.mode & 0o777, mode);
                    assert.equal(metadata.uid, 0);
                    assert.equal(metadata.gid, 0);
                }
                await runCommand([...hook, "start"]);
                assert.deepEqual(await readFile(stateFile), saved);
                assert.deepEqual(await firewallSnapshot(), snapshot);
                assert.equal(await forwardingSnapshot(), "1\n1\n0\n");
                for (const [index, tool] of ["iptables", "ip6tables"].entries()) {
                    assert.equal(
                        (await runCommand([tool, "-S", "FORWARD"])).includes(
                            "exwall-forwarding-guard",
                        ),
                        fixture.sysctls.trim().split("\n")[index] === "0",
                    );
                }
                await writeFile(config, "not valid TOML");
                await writeFile(rule, "not valid TOML");
                await runCommand([...hook, "stop"]);
                await runCommand([...hook, "stop"]);
                assert.deepEqual(await firewallSnapshot(), fixture.baseline);
                assert.equal(await forwardingSnapshot(), fixture.sysctls);
                assert.equal(await exists(stateFile), false);
                break;
            }
            case "logging": {
                await writeFile(
                    config,
                    `log_level = 'debug'\n${originalConfig}\n[[iptables.bypass]]\nnetwork = '192.0.2.19/24'\nport = 443\n`,
                );
                const logs = await runCommand([...hook, "start"], {
                    env: { ...process.env, RUST_LOG: "error" },
                });
                for (const program of ["iptables", "ip6tables", "id", "sysctl"]) {
                    assert.ok(
                        logs
                            .split("\n")
                            .some(
                                (line) =>
                                    line.includes("DEBUG") &&
                                    line.includes("executing command") &&
                                    line.includes(`${program} `),
                            ),
                        logs,
                    );
                }
                assert.match(logs, /iptables -w 10 -t filter/);
                assert.ok(!logs.includes('"-w"'));
                const nat = await runCommand(["iptables", "-t", "nat", "-S", "EXWALL_NAT"]);
                assert.ok(
                    nat.indexOf("192.0.2.0/24") >= 0 &&
                        nat.indexOf("192.0.2.0/24") < nat.indexOf("REDIRECT"),
                );
                await writeFile(config, `log_level = 'info'\n${originalConfig}`);
                assert.ok(
                    !(
                        await runCommand([...hook, "start"], {
                            env: { ...process.env, RUST_LOG: "debug" },
                        })
                    ).includes("executing command"),
                );
                break;
            }
            case "empty-bypasses": {
                const operation: NetworkOperation = {
                    operation: "certificate",
                    host: "8.8.8.8",
                    port: 443,
                    hostname: "dns.google",
                };
                const direct = await fixtureClient(fixture, operation);
                assert.ok(!direct.error);
                await writeFile(
                    config,
                    "manage_resolv_conf = false\nbypass_users = ['daemon']\n[iptables]\nbypass = []\n",
                );
                await runCommand([...hook, "start"]);
                const first = await firewallSnapshot();
                await runCommand([...hook, "start"]);
                assert.deepEqual(await firewallSnapshot(), first);
                for (const tool of ["iptables", "ip6tables"]) {
                    for (const [table, chain] of [
                        ["filter", "EXWALL_OUTPUT"],
                        ["nat", "EXWALL_NAT"],
                    ]) {
                        const managed = await runCommand([tool, "-t", table!, "-S", chain!]);
                        for (const network of [
                            "8.8.8.8",
                            "172.64.155.209",
                            "2001:db8::/32",
                            "192.168.5.0/24",
                        ]) {
                            assert.ok(!managed.includes(network));
                        }
                        assert.match(
                            await runCommand([tool, "-t", table!, "-S"]),
                            /exwall-integration-admin/,
                        );
                    }
                }
                const proxied = await fixtureClient(fixture, operation);
                assert.ok(!proxied.error);
                assert.notDeepEqual(proxied, direct);
                break;
            }
            case "invalid-policy": {
                for (const path of [rule, config]) {
                    const text = await readFile(path, "utf8");
                    await writeFile(path, "not valid TOML");
                    for (let attempt = 0; attempt < 3; attempt++) {
                        assert.notEqual((await failedHook()).exitCode, 0);
                        assert.deepEqual(await firewallSnapshot(), snapshot);
                        assert.deepEqual(await readFile(stateFile), saved);
                        assert.equal(await forwardingSnapshot(), "1\n1\n0\n");
                        await restricted(fixture);
                    }
                    await writeFile(path, text);
                }
                await runCommand([...hook, "start"]);
                const failed = await startProcess(
                    [
                        fixture.binary,
                        "--config",
                        config,
                        "--rules-dir",
                        rules,
                        "serve",
                        "--listen",
                        `[::]:${fixture.proxyPort}`,
                        "--dns-listen",
                        `[::]:${fixture.dnsPort}`,
                        "--ca-dir",
                        fixture.ca,
                    ],
                    { timeout: "20s" },
                );
                assert.notEqual(failed.exitCode, 0);
                assert.match(failed.stderr, /bind HTTP proxy/);
                assert.deepEqual(await firewallSnapshot(), snapshot);
                await restricted(fixture);
                break;
            }
            case "bootstrap": {
                for (const path of [config, rule]) {
                    await runCommand([...hook, "stop"]);
                    const text = await readFile(path, "utf8");
                    await writeFile(path, "not valid TOML");
                    for (let attempt = 0; attempt < 2; attempt++) {
                        assert.notEqual((await failedHook()).exitCode, 0);
                        for (const tool of ["iptables", "ip6tables"]) {
                            assert.match(await runCommand([tool, "-S", "OUTPUT"]), /EXWALL_GUARD/);
                        }
                        await restricted(fixture);
                    }
                    await runCommand([...hook, "stop"]);
                    assert.deepEqual(await firewallSnapshot(), fixture.baseline);
                    assert.equal(await forwardingSnapshot(), fixture.sysctls);
                    await writeFile(path, text);
                }
                break;
            }
            case "corrupt-state": {
                await runCommand([...hook, "stop"]);
                await writeFile(stateFile, "not json\n", { mode: 0o600 });
                try {
                    const failed = await failedHook();
                    assert.notEqual(failed.exitCode, 0);
                    assert.match(failed.stderr, /corrupt state/);
                    assert.equal(await forwardingSnapshot(), fixture.sysctls);
                    assert.equal(await readFile(stateFile, "utf8"), "not json\n");
                } finally {
                    await unlink(stateFile);
                    await runCommand([...hook, "stop"]);
                }
                assert.deepEqual(await firewallSnapshot(), fixture.baseline);
                break;
            }
            case "ipv6-hosts": {
                const hosts = join(root, "ipv6-hosts");
                await writeFile(
                    hosts,
                    `127.0.0.1 localhost\n::1 localhost\nfd00:7261::2 ${fixtureHosts.join(" ")}\n`,
                    { mode: 0o644 },
                );
                await runCommand(["mount", "--bind", hosts, "/etc/hosts"]);
                try {
                    for (const [url, expected] of [
                        ["https://github.com/", 200],
                        ["https://example.com/", 403],
                    ] satisfies [string, number][]) {
                        const result = await fixtureClient(fixture, { operation: "http", url });
                        assert.ok(result.result && typeof result.result === "object");
                        assert.equal(result.result.status, expected);
                    }
                } finally {
                    await runCommand(["umount", "/etc/hosts"]);
                }
                break;
            }
            case "systemd":
                await checkSystemd(fixture);
                break;
            case "transparent":
                await checkTransparent(fixture);
                break;
            default:
                throw new Error(`Unknown lifecycle check: ${name}`);
        }
    } finally {
        await writeFile(config, originalConfig);
        await writeFile(rule, originalRule);
        await runCommand([...hook, "start"]);
    }
}
