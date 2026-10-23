/** Local protocol fixtures use temporary files and sockets without installing firewall hooks. */
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer, Agent, request } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { createConnection, createServer as createTcpServer } from "node:net";
import { connect } from "node:tls";
import { once } from "node:events";
import type { Socket } from "node:net";
import type { RequestOptions, Server, RequestListener } from "node:http";
import { startDns } from "#playwright_helpers/dns.mts";
import { debugBinaryPath } from "#playwright_helpers/fixture_constants.mts";
import {
    bounded,
    startProcess,
    stopProcess,
    waitForPort,
    runCommand,
} from "#playwright_helpers/processes.mts";

/** Generate a short-lived upstream certificate signed by the private fixture CA. */
export async function certificate(root: string, ca: string, names: string[]) {
    await mkdir(root, { recursive: true });
    const key = join(root, "upstream.key");
    const cert = join(root, "upstream.pem");
    const csr = join(root, "upstream.csr");
    const extensions = join(root, "extensions.cnf");
    await writeFile(
        extensions,
        `subjectAltName=${names.map((name) => `DNS:${name}`).join(",")}\nextendedKeyUsage=serverAuth\n`,
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
        `/CN=${names[0]}`,
    ]);
    await runCommand([
        "openssl",
        "x509",
        "-req",
        "-in",
        csr,
        "-CA",
        join(ca, "exwall-ca-cert.pem"),
        "-CAkey",
        join(ca, "exwall-ca-key.pem"),
        "-CAcreateserial",
        "-out",
        cert,
        "-days",
        "1",
        "-extfile",
        extensions,
    ]);
    return { key: await readFile(key), cert: await readFile(cert) };
}

/** Select an ephemeral TCP port for a child service listener. */
export async function freePort(): Promise<number> {
    const server = createTcpServer();
    await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") {
        throw new Error("Missing listener address");
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));
    return address.port;
}

/**
 * Execute an HTTP exchange, optionally over an already connected interception socket and
 * with a request body.
 */
export async function exchange(options: RequestOptions, socket?: Socket, body?: string) {
    const agent = new Agent();
    if (socket) {
        agent.createConnection = () => socket;
    }
    try {
        return await bounded(
            new Promise<{
                status: number;
                body: string;
                headers: Record<string, string | string[] | undefined>;
                firstMilliseconds: number;
            }>((resolve, reject) => {
                const started = performance.now();
                const call = request({ ...options, agent }, (response) => {
                    const chunks: Buffer[] = [];
                    let firstMilliseconds = 0;
                    response.on("data", (chunk: Buffer) => {
                        if (!chunks.length) {
                            firstMilliseconds = performance.now() - started;
                        }
                        chunks.push(chunk);
                    });
                    response.on("error", reject);
                    response.on("end", () =>
                        resolve({
                            status: response.statusCode ?? 0,
                            body: Buffer.concat(chunks).toString(),
                            headers: response.headers,
                            firstMilliseconds,
                        }),
                    );
                });
                call.on("error", reject);
                call.setTimeout(3000, () => call.destroy(new Error("HTTP exchange timed out")));
                call.end(body);
            }),
            5000,
            "HTTP exchange",
        );
    } finally {
        agent.destroy();
        socket?.destroy();
    }
}

/** Wrap direct TLS or a CONNECT tunnel while preserving the proxy's authority validation. */
export async function tlsExchange(
    proxyPort: number,
    upstreamPort: number,
    ca: Buffer,
    path = "/secure",
    tunnel = false,
    host = "localhost",
) {
    const socket = createConnection({ host: "127.0.0.1", port: proxyPort });
    try {
        await once(socket, "connect");
        if (tunnel) {
            const received = bounded(
                new Promise<void>((resolve, reject) => {
                    let header = "";
                    /** Consume exactly the CONNECT response before beginning TLS. */
                    function data(chunk: Buffer) {
                        header += chunk.toString();
                        if (header.endsWith("\r\n\r\n")) {
                            socket.off("data", data);
                            if (!header.startsWith("HTTP/1.1 200")) {
                                reject(new Error(header));
                            } else {
                                resolve();
                            }
                        }
                    }
                    socket.on("data", data);
                    socket.once("error", reject);
                }),
                3000,
                "CONNECT response",
            );
            socket.write(
                `CONNECT localhost:${upstreamPort} HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\n\r\n`,
            );
            await received;
        }
        const secure = connect({ socket, servername: "localhost", ca });
        await bounded(once(secure, "secureConnect"), 3000, "TLS handshake");
        return await exchange(
            {
                host: "localhost",
                port: upstreamPort,
                path,
                headers: { Host: `${host}:${upstreamPort}`, Connection: "close" },
            },
            secure,
        );
    } finally {
        socket.destroy();
    }
}

/** Start echo upstreams, DNS, and a real exwall server with its production file watcher. */
export async function startProtocolFixture() {
    const root = await mkdtemp(join(tmpdir(), "exwall-protocol-"));
    const binary = resolve(debugBinaryPath);
    const ca = join(root, "ca");
    const config = join(root, "config.toml");
    const rules = join(root, "rules");
    const rule = join(rules, "1-test.toml");
    const accessLog = join(root, "access.log");
    const uiPort = await freePort();
    const proxyPort = await freePort();
    const dnsPort = await freePort();
    const accessConfig = `[access_log]\npath = ${JSON.stringify(accessLog)}\n[ui]\nhosts = ['127.0.0.1', '::1']\nport = ${uiPort}\nusername = 'admin'\npassword = 'integration-password'\nsessions_dir = ${JSON.stringify(join(root, "sessions"))}\n`;
    const ruleText = `[[allow]]\ndomain = ['127.0.0.1', 'localhost']\npathname_pattern = '/secure'\nmethods = ['GET']\ninject_headers = [{name='Authorization', value='replacement'}, {name='X-Trace', value='injected'}]\nstream = true\n[[allow]]\ndomain = ['127.0.0.1', 'localhost']\npathname_pattern = ['/allowed', '/stream']\nmethods = ['GET']\n`;
    const cleanup: (() => Promise<unknown>)[] = [() => rm(root, { recursive: true, force: true })];
    try {
        await mkdir(rules);
        await writeFile(rule, ruleText);
        // The start hook always creates the UI rules file; this fixture runs without hooks.
        await writeFile(join(rules, "05-web.toml"), "");
        await writeFile(
            config,
            `log_level = 'debug'\nblock_dns = true\nmanage_resolv_conf = false\n${accessConfig}`,
        );
        await runCommand([binary, "init-ca", "--ca-dir", ca]);
        const cert = await readFile(join(ca, "exwall-ca-cert.pem"));
        const material = await certificate(root, ca, ["localhost"]);
        const rogueCa = join(root, "rogue-ca");
        await runCommand([binary, "init-ca", "--ca-dir", rogueCa]);
        const rogueMaterial = await certificate(join(root, "rogue"), rogueCa, ["localhost"]);
        /** Return request headers or a deliberately delayed response stream. */
        const handler: RequestListener = (req, res) => {
            if (req.url === "/stream") {
                res.writeHead(200, { "content-length": 11 });
                res.write("first");
                setTimeout(() => res.end("second"), 500);
            } else {
                const body = JSON.stringify({
                    path: req.url,
                    authorization: req.headers.authorization ?? null,
                    trace: req.headers["x-trace"] ?? null,
                });
                res.writeHead(req.url === "/allowed?upstream_status=502" ? 502 : 200, {
                    "content-length": Buffer.byteLength(body),
                    "x-upstream-protocol": `HTTP/${req.httpVersion}`,
                    "x-upstream-alpn": "http/1.1",
                });
                res.end(body);
            }
        };
        /** Bind one upstream and register deterministic connection cleanup. */
        async function listen(server: Server): Promise<number> {
            await new Promise<void>((resolve, reject) => {
                server.once("error", reject);
                server.listen(0, "127.0.0.1", resolve);
            });
            cleanup.push(
                () =>
                    new Promise<void>((resolve) => {
                        server.close(() => resolve());
                        server.closeAllConnections();
                    }),
            );
            const address = server.address();
            if (!address || typeof address === "string") {
                throw new Error("Missing upstream port");
            }
            return address.port;
        }
        const upstreamPort = await listen(createServer(handler));
        const securePort = await listen(
            createTlsServer({ ...material, ALPNProtocols: ["http/1.1"] }, handler),
        );
        const roguePort = await listen(createTlsServer(rogueMaterial, handler));
        const dns = await startDns("127.0.0.1");
        cleanup.push(() => dns.close());
        const log = await open(join(root, "proxy.log"), "w");
        cleanup.push(() => log.close());
        const proxy = startProcess(
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
                `127.0.0.1:${dns.port}`,
                "--ca-dir",
                ca,
            ],
            {
                stdio: ["pipe", log.fd, log.fd],
                env: {
                    ...process.env,
                    SSL_CERT_FILE: join(ca, "exwall-ca-cert.pem"),
                    SSL_CERT_DIR: join(root, "empty-trust"),
                },
            },
        );
        cleanup.push(() => stopProcess(proxy));
        await waitForPort(proxyPort, proxy);
        await waitForPort(uiPort, proxy);
        return {
            root,
            config,
            rules,
            rule,
            ruleText,
            accessConfig,
            accessLog,
            ca,
            cert,
            proxy,
            proxyPort,
            dnsPort,
            uiPort,
            upstreamPort,
            securePort,
            roguePort,
            /** Reap all child services before deleting temporary test files. */
            async close() {
                for (const close of cleanup.reverse()) {
                    await close();
                }
            },
        };
    } catch (error) {
        for (const close of cleanup.reverse()) {
            await close();
        }
        throw error;
    }
}
