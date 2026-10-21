/** Exercise the production unit with a private systemd manager inside disposable namespaces. */
import assert from "node:assert/strict";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { isDeepStrictEqual } from "node:util";
import { freePort } from "#playwright_helpers/proxy_fixture.mts";
import { runCommand, startProcess, bounded, waitForPort } from "#playwright_helpers/processes.mts";
import { firewallSnapshot, forwardingSnapshot } from "#playwright_helpers/namespace_safety.mts";
import { fixtureClient, restricted } from "#playwright_helpers/lifecycle.mts";
import type { LifecycleFixture } from "#playwright_helpers/lifecycle.mts";
import type { NetworkOperation } from "#playwright_helpers/protocol.mts";

/** Poll private manager properties with a deadline rather than waiting indefinitely. */
async function waitUntil(predicate: () => Promise<boolean>, message: string): Promise<void> {
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
        if (await predicate()) {
            return;
        }
        await delay(50);
    }
    throw new Error(message);
}

/** Report whether the firewall and forwarding sysctls match the fixture's original state. */
async function restored(fixture: LifecycleFixture): Promise<boolean> {
    return (
        isDeepStrictEqual(await firewallSnapshot(), fixture.baseline) &&
        (await forwardingSnapshot()) === fixture.sysctls
    );
}

/** Require exact host restoration and a working connection under the ordinary UID. */
async function unrestricted(fixture: LifecycleFixture): Promise<void> {
    assert.deepEqual(await firewallSnapshot(), fixture.baseline);
    assert.equal(await forwardingSnapshot(), fixture.sysctls);
    const operation: NetworkOperation = { operation: "tcp", host: "ftp.ubuntu-tw.org", port: 21 };
    assert.deepEqual(await fixtureClient(fixture, operation), { result: true });
}

/** Verify that stops, failed starts, and crashes restore the host and restarts re-enforce. */
export async function checkSystemd(fixture: LifecycleFixture): Promise<void> {
    const directory = join(fixture.root, "systemd");
    const runtime = join(directory, "runtime");
    const units = join(directory, "units");
    await mkdir(runtime, { recursive: true, mode: 0o700 });
    await mkdir(units);
    for (const target of ["default", "basic", "shutdown", "network-online"]) {
        await writeFile(
            join(units, `${target}.target`),
            "[Unit]\nDescription=Private test target\nDefaultDependencies=no\n",
        );
    }
    await writeFile(
        join(units, "systemd-resolved.service"),
        "[Service]\nExecStart=/bin/sleep infinity\n",
    );
    const proxyPort = await freePort();
    const dnsPort = await freePort();
    const config = join(directory, "config.toml");
    const sourceConfig = await readFile(fixture.config, "utf8");
    // The service needs a separate UI-free configuration while the browser fixture stays alive.
    const configText = `${await readFile(new URL("../fixtures/mitmwall-integration-config.toml", import.meta.url), "utf8")}\n[ui]\nhosts = []\n`;
    await writeFile(config, configText);
    const args = [fixture.binary, "--config", config, "--rules-dir", fixture.rules];
    const hook = [
        ...args,
        "hook",
        "--proxy-user",
        "root",
        "--state-dir",
        join(fixture.root, "state"),
        "--proxy-port",
        String(proxyPort),
        "--dns-port",
        String(dnsPort),
    ];
    const serve = [
        ...args,
        "serve",
        "--listen",
        `[::]:${proxyPort}`,
        "--dns-listen",
        `[::]:${dnsPort}`,
        "--ca-dir",
        fixture.ca,
    ];
    const production = await readFile(
        new URL("../../systemd/exwall.service", import.meta.url),
        "utf8",
    );
    const lines: string[] = [];
    for (let line of production.split("\n")) {
        if (line.startsWith("LogsDirectory=") || line.startsWith("LogsDirectoryMode=")) {
            continue;
        }
        if (line === "User=exwall") {
            line = "User=root";
        } else if (line === "Group=exwall") {
            line = "Group=root";
        } else if (line.startsWith("ExecStartPre=+") || line.startsWith("ExecStopPost=+")) {
            const key = line.slice(0, line.indexOf("="));
            line = `${key}=+${[...hook, line.split(" ").at(-1)!].map((argument) => JSON.stringify(argument)).join(" ")}`;
        } else if (line.startsWith("ExecStart=")) {
            line = `ExecStart=${serve.map((argument) => JSON.stringify(argument)).join(" ")}`;
        }
        lines.push(line);
        if (line === "[Service]") {
            lines.push(
                `StandardOutput=append:${join(directory, "service.log")}`,
                "StandardError=inherit",
            );
        }
    }
    await writeFile(join(units, "exwall.service"), lines.join("\n"));
    const environment: NodeJS.ProcessEnv = {
        ...process.env,
        XDG_RUNTIME_DIR: runtime,
        SYSTEMD_UNIT_PATH: units,
    };
    delete environment.DBUS_SESSION_BUS_ADDRESS;
    delete environment.DBUS_SESSION_BUS_PID;
    /** Address only the private manager, retaining failed-start status for assertions. */
    const control = (args: string[]) =>
        startProcess(["systemctl", "--user", ...args], { env: environment, timeout: "20s" });
    /** Require successful control operations with their diagnostic stderr. */
    async function checked(...args: string[]) {
        const output = await control(args);
        assert.equal(output.exitCode, 0, output.stderr);
    }
    /** Read a single property from the production service instance. */
    async function property(name: string) {
        return (
            await control(["show", "exwall.service", `--property=${name}`, "--value"])
        ).stdout.trim();
    }
    const rule = join(fixture.rules, "20-network.toml");
    const ruleText = await readFile(rule, "utf8");
    /** Fetch a host the fixture rules allow as the restricted user, returning the HTTP status. */
    async function allowedHostStatus(): Promise<number | undefined> {
        const response = await fixtureClient(fixture, {
            operation: "http",
            url: "https://github.com/",
        });
        return typeof response.result === "object" ? response.result.status : undefined;
    }
    const manager = startProcess(["/usr/lib/systemd/systemd", "--user"], { env: environment });
    try {
        await waitUntil(
            () =>
                access(join(runtime, "systemd/private")).then(
                    () => true,
                    () => false,
                ),
            "Private manager failed",
        );
        await checked("start", "systemd-resolved.service");
        await checked("start", "exwall.service");
        await waitUntil(
            async () => (await property("ActiveState")) === "active",
            "Proxy did not start",
        );
        await waitForPort(proxyPort, manager);
        await restricted(fixture);
        assert.notEqual(await allowedHostStatus(), 403);
        await writeFile(config, "not valid TOML");
        await control(["restart", "exwall.service"]);
        await waitUntil(
            async () => Number(await property("NRestarts")) >= 1,
            "Invalid configuration was not retried",
        );
        // Each failed attempt runs ExecStopPost cleanup before the next retry.
        await waitUntil(() => restored(fixture), "Failed start did not restore the host");
        await writeFile(config, configText);
        await checked("reset-failed", "exwall.service");
        await checked("restart", "exwall.service");
        await waitUntil(
            async () => (await property("ActiveState")) === "active",
            "Configuration repair failed",
        );
        await waitForPort(proxyPort, manager);
        // Invalid rules still start the service, with no rules, so they can be repaired in the UI.
        await writeFile(rule, "not valid TOML");
        await checked("restart", "exwall.service");
        await waitUntil(
            async () => (await property("ActiveState")) === "active",
            "Invalid rules stopped the service",
        );
        await waitForPort(proxyPort, manager);
        await restricted(fixture);
        assert.equal(await allowedHostStatus(), 403);
        await writeFile(rule, ruleText);
        await checked("restart", "exwall.service");
        await waitUntil(
            async () => (await property("ActiveState")) === "active",
            "Rule repair failed",
        );
        await waitForPort(proxyPort, manager);
        assert.notEqual(await allowedHostStatus(), 403);
        await restricted(fixture);
        const restarts = Number(await property("NRestarts"));
        await checked("kill", "--signal=KILL", "--kill-whom=main", "exwall.service");
        await waitUntil(
            async () =>
                Number(await property("NRestarts")) > restarts &&
                (await property("ActiveState")) === "active",
            "Crash was not restarted",
        );
        await waitForPort(proxyPort, manager);
        await restricted(fixture);
        await checked("stop", "exwall.service");
        await unrestricted(fixture);
        const occupied = createServer();
        await new Promise<void>((resolve, reject) => {
            occupied.once("error", reject);
            occupied.listen(proxyPort, "127.0.0.1", resolve);
        });
        try {
            await control(["start", "exwall.service"]);
            await waitUntil(
                async () => (await property("ExecMainStatus")) === "1",
                "Startup failure missing",
            );
            await waitUntil(() => restored(fixture), "Failed start did not restore the host");
        } finally {
            await new Promise<void>((resolve) => occupied.close(() => resolve()));
        }
        await checked("stop", "exwall.service");
        await unrestricted(fixture);
        // Manual cleanup after a stop is an idempotent no-op.
        await runCommand([...hook, "stop"]);
        await unrestricted(fixture);
    } catch (error) {
        console.error(manager.output?.stderr ?? "Private manager still running");
        console.error(
            await readFile(join(directory, "service.log"), "utf8").catch(() => "No service log"),
        );
        throw error;
    } finally {
        await writeFile(fixture.config, sourceConfig);
        await writeFile(rule, ruleText);
        await control(["stop", "exwall.service", "systemd-resolved.service"]);
        if (!manager.output && manager.pid) {
            await runCommand(["kill", "-KILL", String(manager.pid)]);
        }
        await bounded(
            manager.then(() => undefined),
            5000,
            "Private manager shutdown",
        );
        await runCommand([...fixture.hook, "start"]);
    }
}
