/**
 * Provides zx-based child process execution and lifecycle helpers for the Playwright
 * harness, including readiness messages, bounded waits, and graceful shutdown.
 * @module
 */

import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { createConnection } from "node:net";
import { $ } from "zx/core";
import type { Options, ProcessPromise } from "zx/core";

/** Start an argument-vector command through zx, retaining its actual process PID. */
export function startProcess(args: string[], options: Partial<Options> = {}): ProcessPromise {
    if (!args.length) {
        throw new Error("Cannot start an empty command");
    }
    return $({ quiet: true, nothrow: true, ...options, prefix: "exec ", postfix: "" })`${args}`;
}

/** Execute a bounded command and retain its stderr when reporting failure. */
export async function runCommand(args: string[], options: Partial<Options> = {}): Promise<string> {
    const output = await startProcess(args, { timeout: "20s", ...options });
    if (output.exitCode !== 0) {
        throw new Error(
            `Command failed (${output.exitCode}): ${args.join(" ")}\n${output.stderr}`,
            { cause: output },
        );
    }
    return output.stdout;
}

/** Bound a readiness or shutdown wait without leaving its timer active afterward. */
export async function bounded<T>(
    work: Promise<T>,
    milliseconds: number,
    label: string,
): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    try {
        return await Promise.race([
            work,
            new Promise<never>((_, reject) => {
                timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds);
            }),
        ]);
    } finally {
        clearTimeout(timer);
    }
}

/** Read ordered JSON readiness messages while preserving the child's control stdin. */
export function processMessages(child: ProcessPromise) {
    const reader = createInterface({ input: child.stdout });
    const messages = reader[Symbol.asyncIterator]();
    return {
        /** Read one message or fail promptly when the child exits before readiness. */
        async next<T>(): Promise<T> {
            const message = await bounded(messages.next(), 30_000, "Child readiness");
            if (message.done) {
                throw new Error(`Child exited before readiness: ${child.output?.stderr}`);
            }
            return JSON.parse(message.value);
        },
        /** Release the reader after the child has been reaped. */
        close() {
            reader.close();
        },
    };
}

/** Signal a zx-owned process using a quoted command rather than an unescaped shell invocation. */
async function signalProcess(child: ProcessPromise, signal: NodeJS.Signals): Promise<void> {
    if (child.output || !child.pid) {
        return;
    }
    try {
        await runCommand(["kill", "-s", signal, String(child.pid)]);
    } catch (error) {
        if (!child.output) {
            throw error;
        }
    }
}

/** Stop a service by signal or a fixture by control EOF, escalating only after bounded waits. */
export async function stopProcess(child: ProcessPromise, controlPipe = false): Promise<void> {
    if (child.output) {
        return;
    }
    if (controlPipe) {
        child.stdin.end();
    } else {
        await signalProcess(child, "SIGTERM");
    }
    try {
        await bounded(
            child.then(() => undefined),
            15_000,
            "Child shutdown",
        );
    } catch {
        await signalProcess(child, "SIGTERM");
        try {
            await bounded(
                child.then(() => undefined),
                5_000,
                "Child termination",
            );
        } catch {
            await signalProcess(child, "SIGKILL");
            await child;
        }
    }
}

/** Wait for the real service to accept TCP connections, checking for early process failure. */
export async function waitForPort(port: number, child: ProcessPromise): Promise<void> {
    await bounded(
        (async () => {
            while (!child.output) {
                const listening = await new Promise<boolean>((resolveListening) => {
                    const socket = createConnection({ host: "127.0.0.1", port });
                    socket.once("connect", () => {
                        socket.destroy();
                        resolveListening(true);
                    });
                    socket.once("error", () => {
                        socket.destroy();
                        resolveListening(false);
                    });
                    socket.setTimeout(500, () => {
                        socket.destroy();
                        resolveListening(false);
                    });
                });
                if (listening) {
                    return;
                }
                await delay(50);
            }
            throw new Error(`Service exited before readiness: ${child.output?.stderr}`);
        })(),
        10_000,
        "Service readiness",
    );
}

/** Keep a namespace fixture alive until its parent closes the control pipe. */
export async function waitForControlEnd(): Promise<void> {
    for await (const _chunk of process.stdin) {
        // Control data is intentionally ignored; only EOF requests shutdown.
    }
}

/** Detect executable entry points while keeping helpers safe to import. */
export function isMain(url: string): boolean {
    return process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(url);
}
