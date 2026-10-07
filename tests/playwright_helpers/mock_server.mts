/**
 * Provides reusable HTTP and TLS HTTP/2 upstream servers with configurable routes
 * and recorded requests. As an executable, serves the Playwright fixture upstreams
 * in their separate disposable network namespace.
 * @module
 */

import { readFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { createSecureServer } from "node:http2";
import type { IncomingMessage, ServerResponse, IncomingHttpHeaders } from "node:http";
import type { Http2ServerRequest, Http2ServerResponse } from "node:http2";
import type { Socket } from "node:net";
import { createServer as createTcpServer } from "node:net";
import { startDns } from "#playwright_helpers/dns.mts";
import { createInterface } from "node:readline";
import { isMain } from "#playwright_helpers/processes.mts";
import { assertIsolated } from "#playwright_helpers/namespace_safety.mts";

/** A request that actually reached the mock upstream, before any route response was chosen. */
export interface MockRequest {
    fixture: string;
    path: string;
    pathname: string;
    query: Record<string, string>;
    method: string;
    headers: IncomingHttpHeaders;
    body: string;
    httpVersion: string;
}

/** Match an exact pathname or regex and optionally customize the upstream response. */
export interface MockRoute {
    pathname?: string;
    pathnameRegex?: string;
    method?: string;
    status?: number;
    headers?: Record<string, string>;
    body?: unknown;
}

/** Bind a plain HTTP server or a TLS HTTP/2 server, optionally permitting HTTP/1 fallback. */
export interface MockServerOptions {
    host: string;
    port?: number;
    tls?: { key: string | Buffer; cert: string | Buffer; allowHTTP1?: boolean };
    routes?: MockRoute[];
}

/** A reusable upstream with its bound port, observed requests, and deterministic shutdown. */
export interface MockServer {
    port: number;
    requests: MockRequest[];
    /** Stop the listener and all persistent upstream connections. */
    close(): Promise<void>;
}

/** Echo request metadata by default while supporting pathname/method-specific fixture responses. */
export async function startMockServer(options: MockServerOptions): Promise<MockServer> {
    const requests: MockRequest[] = [];
    const sockets = new Set<Socket>();
    const routes = (options.routes ?? []).map((route) => ({
        ...route,
        matcher: route.pathnameRegex ? new RegExp(route.pathnameRegex) : undefined,
    }));
    /** Record the complete request and send the matching fixture response. */
    async function respond(
        request: IncomingMessage | Http2ServerRequest,
        response: ServerResponse | Http2ServerResponse,
    ) {
        const chunks: Buffer[] = [];
        let length = 0;
        for await (const chunk of request) {
            const buffer: Buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            length += buffer.length;
            if (length > 1_048_576) {
                response.statusCode = 413;
                response.end();
                return;
            }
            chunks.push(buffer);
        }
        const path = request.url ?? "/";
        const url = new URL(path, "http://fixture.invalid");
        const record: MockRequest = {
            fixture: "exwall-local-upstream",
            path,
            pathname: url.pathname,
            query: Object.fromEntries(url.searchParams),
            method: request.method ?? "GET",
            headers: request.headers,
            body: Buffer.concat(chunks).toString("utf8"),
            httpVersion: request.httpVersion,
        };
        requests.push(record);
        const route = routes.find(
            (candidate) =>
                (!candidate.method || candidate.method === record.method) &&
                (!candidate.pathname || candidate.pathname === record.pathname) &&
                (!candidate.matcher || candidate.matcher.test(record.pathname)),
        );
        const payload = JSON.stringify(route?.body ?? record);
        response.statusCode = route?.status ?? 200;
        for (const [name, value] of Object.entries({
            "content-type": "application/json",
            "content-length": Buffer.byteLength(payload),
            ...route?.headers,
        })) {
            response.setHeader(name, value);
        }
        if (record.method === "HEAD") {
            response.end();
        } else {
            response.end(payload);
        }
    }
    /** Contain malformed upstream requests without crashing other fixture connections. */
    function handle(
        request: IncomingMessage | Http2ServerRequest,
        response: ServerResponse | Http2ServerResponse,
    ) {
        void respond(request, response).catch((error: unknown) =>
            response.destroy(error instanceof Error ? error : new Error(String(error))),
        );
    }
    const server = options.tls
        ? createSecureServer(
              { ...options.tls, allowHTTP1: options.tls.allowHTTP1 ?? false },
              handle,
          )
        : createHttpServer(handle);
    server.on("connection", (socket) => {
        sockets.add(socket);
        socket.once("close", () => sockets.delete(socket));
    });
    await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(
            { host: options.host, port: options.port ?? 0, ipv6Only: options.host.includes(":") },
            () => {
                server.off("error", reject);
                resolve();
            },
        );
    });
    const address = server.address();
    if (!address || typeof address === "string") {
        throw new Error("Mock upstream has no TCP address");
    }
    return {
        port: address.port,
        requests,
        /** Stop accepting connections and reap persistent HTTP/2 sessions. */
        async close() {
            const closed = new Promise<void>((resolve, reject) =>
                server.close((error) => (error ? reject(error) : resolve())),
            );
            for (const socket of sockets) {
                socket.destroy();
            }
            await closed;
        },
    };
}

/** Start dual-stack HTTP and h2-only HTTPS fixtures after the parent configures the veth pair. */
async function main(): Promise<void> {
    await assertIsolated();
    const [certificate, privateKey, requestSocket] = process.argv.slice(2);
    if (!certificate || !privateKey || !requestSocket) {
        throw new Error("Missing upstream fixture arguments");
    }
    const controls = createInterface({ input: process.stdin });
    const messages = controls[Symbol.asyncIterator]();
    process.stdout.write(`${JSON.stringify({ phase: "isolated", pid: process.pid })}\n`);
    const configure = await messages.next();
    if (configure.done || configure.value !== "start") {
        throw new Error("Upstream setup was not completed");
    }
    const servers: MockServer[] = [];
    const extraCleanup: (() => Promise<void>)[] = [];
    const recorder = createHttpServer((request, response) => {
        if (request.url !== "/requests") {
            response.writeHead(404);
            response.end();
            return;
        }
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify(servers.flatMap((server) => server.requests)));
    });
    try {
        const cert = await readFile(certificate);
        const key = await readFile(privateKey);
        for (const host of ["192.0.2.2", "fd00:7261::2"]) {
            servers.push(await startMockServer({ host, port: 80 }));
            servers.push(await startMockServer({ host, port: 443, tls: { cert, key } }));
        }
        for (const host of ["192.0.2.2", "fd00:7261::2"]) {
            const dns = await startDns(host, 53);
            extraCleanup.push(() => dns.close());
            for (const port of [21, 22]) {
                const tcp = createTcpServer((socket) => socket.end());
                await new Promise<void>((resolve, reject) => {
                    tcp.once("error", reject);
                    tcp.listen({ host, port, ipv6Only: host.includes(":") }, resolve);
                });
                extraCleanup.push(
                    () =>
                        new Promise<void>((resolve, reject) =>
                            tcp.close((error) => (error ? reject(error) : resolve())),
                        ),
                );
            }
        }
        for (const host of ["8.8.8.8", "172.64.155.209", "1.1.1.1"]) {
            servers.push(
                await startMockServer({ host, port: 443, tls: { cert, key, allowHTTP1: true } }),
            );
        }
        await new Promise<void>((resolve, reject) => {
            recorder.once("error", reject);
            recorder.listen(requestSocket, resolve);
        });
        process.stdout.write(`${JSON.stringify({ phase: "ready" })}\n`);
        while (!(await messages.next()).done) {
            // EOF on the parent control pipe requests graceful fixture shutdown.
        }
    } finally {
        controls.close();
        if (recorder.listening) {
            await new Promise<void>((resolve) => recorder.close(() => resolve()));
        }
        for (const close of extraCleanup.reverse()) {
            await close();
        }
        for (const server of servers.reverse()) {
            await server.close();
        }
    }
}

if (isMain(import.meta.url)) {
    await main();
}
