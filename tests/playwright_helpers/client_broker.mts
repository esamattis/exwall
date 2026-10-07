/**
 * Runs inside the disposable namespace and serves private Unix-socket requests
 * for rules-file edits, upstream observations, fixed-identity clients, and named lifecycle checks.
 * @module
 */

import { chmod, chown, readFile, readlink, writeFile, unlink } from "node:fs/promises";
import { createServer } from "node:http";
import type { ServerResponse, IncomingMessage, Server } from "node:http";
import { fileURLToPath } from "node:url";
import { parseOperation } from "#playwright_helpers/protocol.mts";
import { runCommand } from "#playwright_helpers/processes.mts";
import { requestUnixJson } from "#playwright_helpers/client.mts";

/** Paths and identity supplied by the privileged fixture rather than by test requests. */
export interface BrokerOptions {
    socket: string;
    rules: string;
    certificate: string;
    requestSocket: string;
    uid: number;
    gid: number;
    cwd: string;
    policyRules: string;
    /** Run only named namespace lifecycle checks selected by the fixture. */
    check(name: string): Promise<void>;
}

/** Return JSON fixture results while keeping broker failures separate from firewall responses. */
function sendJson(response: ServerResponse, status: number, value: unknown): void {
    const content = JSON.stringify(value);
    response.writeHead(status, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(content),
    });
    response.end(content);
}

/** Decode a bounded request body before launching any restricted child process. */
async function readJson(request: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of request) {
        const buffer: Buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        length += buffer.length;
        if (length > 65536) {
            throw new Error("Client request is too large");
        }
        chunks.push(buffer);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

/** Expose fixture-owned files, fixed client identities, and named checks over a private socket. */
export async function startClientBroker(options: BrokerOptions): Promise<Server> {
    const hostNet = process.env.EXWALL_HOST_NET_NS;
    const fixtureNet = await readlink("/proc/self/ns/net");
    if (!hostNet || fixtureNet === hostNet) {
        throw new Error("Broker requires an isolated network namespace");
    }
    const script = fileURLToPath(import.meta.resolve("#playwright_helpers/network_client.mts"));
    /** Route fixture requests without accepting arbitrary commands, users, or CA paths. */
    async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
        if (request.method === "GET" && request.url === "/rules") {
            sendJson(response, 200, { rules: await readFile(options.rules, "utf8") });
        } else if (request.method === "POST" && request.url === "/rules") {
            const value = await readJson(request);
            if (typeof value !== "string" && value !== null) {
                throw new Error("Expected TOML text or null to remove the test policy");
            }
            if (value === null) {
                await unlink(options.policyRules).catch((error: NodeJS.ErrnoException) => {
                    if (error.code !== "ENOENT") {
                        throw error;
                    }
                });
            } else {
                await writeFile(options.policyRules, value);
            }
            sendJson(response, 200, { ok: true });
        } else if (request.method === "POST" && request.url === "/check") {
            const name = await readJson(request);
            if (typeof name !== "string") {
                throw new Error("Expected a named fixture check");
            }
            await options.check(name);
            sendJson(response, 200, { ok: true });
        } else if (request.method === "GET" && request.url === "/requests") {
            sendJson(response, 200, await requestUnixJson(options.requestSocket, "/requests"));
        } else if (
            request.method === "POST" &&
            ["/client", "/client/bypass", "/client/admin"].includes(request.url ?? "")
        ) {
            let operation;
            try {
                operation = parseOperation(await readJson(request));
            } catch (error) {
                sendJson(response, 400, { error: String(error) });
                return;
            }
            const output = await runCommand(
                [
                    process.execPath,
                    script,
                    JSON.stringify(operation),
                    options.certificate,
                    hostNet ?? "",
                    fixtureNet,
                    request.url?.split("/")[2] ?? "restricted",
                ],
                { cwd: options.cwd, timeout: "8s" },
            );
            sendJson(response, 200, JSON.parse(output));
        } else {
            sendJson(response, 404, { error: "Unknown fixture endpoint" });
        }
    }
    const server = createServer((request, response) => {
        void handle(request, response).catch((error: unknown) => {
            if (!response.headersSent) {
                sendJson(response, 500, { error: String(error) });
            } else {
                response.destroy(error instanceof Error ? error : new Error(String(error)));
            }
        });
    });
    server.requestTimeout = 10_000;
    await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(options.socket, () => {
            server.off("error", reject);
            resolve();
        });
    });
    await chmod(options.socket, 0o600);
    await chown(options.socket, options.uid, options.gid);
    return server;
}

/** Stop the broker and close HTTP connections before destroying namespace fixtures. */
export async function closeClientBroker(server: Server): Promise<void> {
    const closed = new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
    );
    server.closeAllConnections();
    await closed;
}
