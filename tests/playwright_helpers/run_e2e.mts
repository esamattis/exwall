/**
 * Coordinates the Playwright E2E run from the host: builds exwall, starts the
 * isolated fixture, launches host Chromium, and verifies cleanup and unchanged host state.
 * @module
 */

import { access, mkdir, mkdtemp, readlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import {
    bounded,
    isMain,
    runCommand,
    startProcess,
    stopProcess,
    processMessages,
} from "#playwright_helpers/processes.mts";
import { hostSnapshot } from "#playwright_helpers/namespace_safety.mts";
import type { UiBridge } from "#playwright_helpers/ui_bridge.mts";
import { startUiBridge } from "#playwright_helpers/ui_bridge.mts";
import type { FixtureReady } from "#playwright_helpers/protocol.mts";

/** Build the production app and run host Playwright against private namespace transports. */
async function main(): Promise<void> {
    const repository = dirname(fileURLToPath(new URL("../../package.json", import.meta.url)));
    const environment = { ...process.env };
    for (const name of Object.keys(environment)) {
        if (
            name.toLowerCase().endsWith("_proxy") ||
            ["SSL_CERT_FILE", "SSL_CERT_DIR"].includes(name)
        ) {
            delete environment[name];
        }
    }
    if (!process.argv.includes("--no-build")) {
        await runCommand(["pnpm", "build:ui"], {
            cwd: repository,
            env: environment,
            timeout: "120s",
            stdio: "inherit",
        });
        await runCommand(["cargo", "build", "--locked"], {
            cwd: repository,
            env: environment,
            timeout: "120s",
            stdio: "inherit",
        });
    }
    const privilege = process.getuid?.() === 0 ? [] : ["sudo", "-n"];
    if (privilege.length) {
        await runCommand([...privilege, "true"]);
    }
    const browser = chromium.executablePath();
    await access(browser).catch((error: unknown) => {
        throw new Error(
            "Install Chromium first: mise exec -- pnpm exec playwright install chromium",
            { cause: error },
        );
    });
    await mkdir(join(repository, "test-results"), { recursive: true });
    const output = await mkdtemp(join(repository, "test-results/e2e-"));
    const sockets = await mkdtemp(join(tmpdir(), "exwall-browser-"));
    const hostNet = await readlink("/proc/self/ns/net");
    const identities = [
        `EXWALL_HOST_NET_NS=${hostNet}`,
        `EXWALL_HOST_MNT_NS=${await readlink("/proc/self/ns/mnt")}`,
    ];
    const before = await hostSnapshot(privilege);
    const failures: unknown[] = [];
    try {
        const script = fileURLToPath(
            import.meta.resolve("#playwright_helpers/isolated_fixture.mts"),
        );
        const fixture = startProcess(
            [
                ...privilege,
                "env",
                ...identities,
                "unshare",
                "--net",
                "--mount",
                "--pid",
                "--fork",
                "--mount-proc",
                "--kill-child",
                "--propagation",
                "private",
                process.execPath,
                script,
                join(repository, "target/debug/exwall"),
                sockets,
                output,
                String(process.getuid?.()),
                String(process.getgid?.()),
            ],
            { env: environment, stdio: ["pipe", "pipe", "inherit"] },
        );
        const messages = processMessages(fixture);
        let bridge: UiBridge | undefined;
        try {
            const ready = await messages.next<FixtureReady>();
            bridge = await startUiBridge({ host: "127.0.0.1", port: 0 }, { path: ready.uiSocket });
            const address = bridge.server.address();
            if (!address || typeof address === "string") {
                throw new Error("UI forwarder has no TCP address");
            }
            await runCommand(
                [
                    process.execPath,
                    join(repository, "node_modules/@playwright/test/cli.js"),
                    "test",
                    "--config",
                    "playwright.e2e.config.ts",
                ],
                {
                    cwd: repository,
                    timeout: "180s",
                    stdio: "inherit",
                    env: {
                        ...environment,
                        EXWALL_E2E_URL: `http://127.0.0.1:${address.port}`,
                        EXWALL_E2E_HOST_NET_NS: hostNet,
                        EXWALL_E2E_CLIENT_SOCKET: ready.clientSocket,
                        EXWALL_E2E_CHROMIUM: browser,
                        EXWALL_E2E_OUTPUT: output,
                    },
                },
            );
        } catch (error) {
            failures.push(error);
        } finally {
            if (bridge) {
                await bridge.close().catch((error: unknown) => {
                    failures.push(error);
                });
            }
            fixture.stdin.end();
            await bounded(
                fixture.then((result) => result),
                30_000,
                "Namespace fixture shutdown",
            )
                .then((finished) => {
                    if (finished.exitCode !== 0) {
                        failures.push(
                            new Error(`Namespace fixture exited with ${finished.exitCode}`),
                        );
                    }
                })
                .catch((error: unknown) => {
                    failures.push(error);
                });
            await stopProcess(fixture, true).catch((error: unknown) => {
                failures.push(error);
            });
            messages.close();
        }
    } catch (error) {
        failures.push(error);
    } finally {
        await rm(sockets, { recursive: true, force: true }).catch((error: unknown) => {
            failures.push(error);
        });
        console.log(`Playwright artifacts: ${output}`);
        await hostSnapshot(privilege)
            .then((after) => {
                if (after !== before) {
                    failures.push(new Error("Browser E2E changed host system state"));
                }
            })
            .catch((error: unknown) => {
                failures.push(error);
            });
    }
    if (failures.length) {
        throw new AggregateError(failures, "Playwright E2E failed");
    }
    console.log("PASS: host Playwright, isolated client/hooks, and unchanged host state");
}

if (isMain(import.meta.url)) {
    await main();
}
