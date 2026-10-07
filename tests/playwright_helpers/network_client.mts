/**
 * Executes one real HTTP, HTTPS, or TCP check inside the fixture network namespace.
 * Drops to nobody before opening sockets and reports responses or transport errors as JSON.
 * @module
 */

import { readFileSync, readlinkSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { createConnection } from "node:net";
import { isMain } from "#playwright_helpers/processes.mts";
import { parseOperation } from "#playwright_helpers/protocol.mts";
import type { ClientResponse, HttpOperation, HttpResult } from "#playwright_helpers/protocol.mts";

/** Make a real HTTP/HTTPS exchange with explicit fixture CA verification and bounded I/O. */
async function requestHttp(operation: HttpOperation, certificate: string): Promise<HttpResult> {
    const url = new URL(operation.url);
    return new Promise((resolve, reject) => {
        const request = url.protocol === "https:" ? httpsRequest : httpRequest;
        const call = request(
            url,
            {
                method: operation.method ?? "GET",
                headers: operation.headers,
                ca: readFileSync(certificate),
                agent: false,
            },
            (response) => {
                const chunks: Buffer[] = [];
                response.on("data", (chunk: Buffer) => chunks.push(chunk));
                response.on("error", reject);
                response.on("end", () =>
                    resolve({
                        status: response.statusCode ?? 0,
                        body: Buffer.concat(chunks).toString("utf8"),
                    }),
                );
            },
        );
        call.on("error", reject);
        call.setTimeout(3_000, () => call.destroy(new Error("Network request timed out")));
        call.end(operation.body);
    });
}

/** Drop all bypass privileges before opening sockets and return one JSON network result. */
async function main(): Promise<void> {
    const [input, certificate, hostNet, fixtureNet] = process.argv.slice(2);
    if (!input || !certificate || !hostNet || !fixtureNet) {
        throw new Error("Missing restricted client arguments");
    }
    const actualNet = readlinkSync("/proc/self/ns/net");
    if (actualNet === hostNet || actualNet !== fixtureNet) {
        throw new Error("Refusing network operations outside the fixture namespace");
    }
    const operation = parseOperation(JSON.parse(input));
    if (!process.setgroups || !process.setgid || !process.setuid) {
        throw new Error("Linux client identities are required");
    }
    process.setgroups([]);
    process.setgid(65534);
    process.setuid(65534);
    let result: ClientResponse<HttpResult | boolean>;
    try {
        if (operation.operation === "http") {
            result = { result: await requestHttp(operation, certificate) };
        } else {
            await new Promise<void>((resolve, reject) => {
                const socket = createConnection({ host: operation.host, port: operation.port });
                socket.once("connect", () => {
                    socket.destroy();
                    resolve();
                });
                socket.once("error", reject);
                socket.setTimeout(500, () => socket.destroy(new Error("TCP connection timed out")));
            });
            result = { result: true };
        }
    } catch (error) {
        result = {
            error: error instanceof Error ? error.message : String(error),
            error_type: error instanceof Error ? error.name : "Error",
        };
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (isMain(import.meta.url)) {
    await main();
}
