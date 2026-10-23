/** Minimal RFC 6455 WebSocket peers for end-to-end proxy tests, using only Node built-ins. */
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { createConnection } from "node:net";
import { connect } from "node:tls";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { bounded } from "#playwright_helpers/processes.mts";
import { openTunnel } from "#playwright_helpers/proxy_fixture.mts";

/** The GUID that RFC 6455 appends to a handshake key. */
const handshakeGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/** The text message opcode. */
const textOpcode = 0x1;
/** The close message opcode. */
const closeOpcode = 0x8;

/** One received WebSocket frame. */
interface Frame {
    opcode: number;
    payload: Buffer;
}

/** Compute the `Sec-WebSocket-Accept` value answering a handshake key. */
function acceptKey(key: string): string {
    return createHash("sha1")
        .update(key + handshakeGuid)
        .digest("base64");
}

/** Encode one final frame of under 64 KiB, masked when a client sends it. */
function encodeFrame(opcode: number, payload: Buffer, masked: boolean): Buffer {
    const extended = payload.length >= 126;
    const header = Buffer.alloc(extended ? 4 : 2);
    header[0] = 0x80 | opcode;
    header[1] = (masked ? 0x80 : 0) | (extended ? 126 : payload.length);
    if (extended) {
        header.writeUInt16BE(payload.length, 2);
    }
    if (!masked) {
        return Buffer.concat([header, payload]);
    }
    const mask = randomBytes(4);
    const body = Buffer.from(payload.map((byte, index) => byte ^ (mask[index % 4] ?? 0)));
    return Buffer.concat([header, mask, body]);
}

/** Read frames from a socket, starting with bytes that arrived after the handshake. */
function frameReader(socket: Duplex, initial: Buffer) {
    let buffer = initial;
    const frames: Frame[] = [];
    const waiters: ((frame: Frame | Error) => void)[] = [];
    /** Hand a frame or failure to the oldest waiter, or queue a frame for the next one. */
    const deliver = (frame: Frame | Error) => {
        const waiter = waiters.shift();
        if (waiter) {
            waiter(frame);
        } else if (!(frame instanceof Error)) {
            frames.push(frame);
        }
    };
    /** Decode every complete frame in the buffer. */
    const parse = () => {
        while (buffer.length >= 2) {
            const opcode = (buffer[0] ?? 0) & 0x0f;
            const masked = ((buffer[1] ?? 0) & 0x80) !== 0;
            let length = (buffer[1] ?? 0) & 0x7f;
            let offset = 2;
            if (length === 126) {
                if (buffer.length < 4) {
                    return;
                }
                length = buffer.readUInt16BE(2);
                offset = 4;
            } else if (length === 127) {
                if (buffer.length < 10) {
                    return;
                }
                length = Number(buffer.readBigUInt64BE(2));
                offset = 10;
            }
            const mask = masked ? buffer.subarray(offset, offset + 4) : null;
            offset += masked ? 4 : 0;
            if (buffer.length < offset + length) {
                return;
            }
            const data = buffer.subarray(offset, offset + length);
            const payload = Buffer.from(
                mask ? data.map((byte, index) => byte ^ (mask[index % 4] ?? 0)) : data,
            );
            buffer = buffer.subarray(offset + length);
            deliver({ opcode, payload });
        }
    };
    socket.on("data", (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk]);
        parse();
    });
    socket.on("close", () => deliver(new Error("WebSocket connection closed")));
    socket.on("error", (error: Error) => deliver(error));
    parse();
    return {
        /** Wait for the next frame. */
        next(): Promise<Frame> {
            const queued = frames.shift();
            if (queued) {
                return Promise.resolve(queued);
            }
            return bounded(
                new Promise<Frame>((resolve, reject) =>
                    waiters.push((frame) =>
                        frame instanceof Error ? reject(frame) : resolve(frame),
                    ),
                ),
                3000,
                "WebSocket frame",
            );
        },
    };
}

/**
 * Accept a WebSocket upgrade on an upstream server: greet the client with the handshake's
 * path and Authorization header as JSON, echo text messages with an `echo:` prefix, and
 * answer a close message.
 */
export function serveWebSocket(request: IncomingMessage, socket: Duplex, head: Buffer) {
    const key = request.headers["sec-websocket-key"];
    if (request.headers.upgrade?.toLowerCase() !== "websocket" || typeof key !== "string") {
        socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    socket.on("error", () => socket.destroy());
    socket.write(
        `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`,
    );
    const greeting = JSON.stringify({
        path: request.url,
        authorization: request.headers.authorization ?? null,
    });
    socket.write(encodeFrame(textOpcode, Buffer.from(greeting), false));
    const reader = frameReader(socket, head);
    void (async () => {
        for (;;) {
            const frame = await reader.next();
            if (frame.opcode === textOpcode) {
                socket.write(
                    encodeFrame(textOpcode, Buffer.from(`echo:${frame.payload.toString()}`), false),
                );
            } else if (frame.opcode === closeOpcode) {
                socket.end(encodeFrame(closeOpcode, frame.payload, false));
                return;
            }
        }
    })().catch(() => socket.destroy());
}

/** Read an HTTP response head, returning it and any bytes that followed it. */
function readHead(socket: Duplex): Promise<{ head: string; rest: Buffer }> {
    return bounded(
        new Promise((resolve, reject) => {
            let buffer = Buffer.alloc(0);
            /** Collect bytes until the blank line ending the head. */
            function data(chunk: Buffer) {
                buffer = Buffer.concat([buffer, chunk]);
                const end = buffer.indexOf("\r\n\r\n");
                if (end !== -1) {
                    socket.off("data", data);
                    socket.pause();
                    resolve({
                        head: buffer.subarray(0, end).toString(),
                        rest: buffer.subarray(end + 4),
                    });
                }
            }
            socket.on("data", data);
            socket.once("error", reject);
            socket.once("close", () => reject(new Error("closed before the response head")));
        }),
        3000,
        "WebSocket handshake response",
    );
}

/** What a WebSocket exchange through the proxy saw. */
export interface WebSocketExchange {
    /** The handshake response status. */
    status: number;
    /** Whether `Sec-WebSocket-Accept` answered the key that was sent. */
    accepted?: boolean;
    /** The upstream's greeting: the handshake path and Authorization header it received. */
    greeting?: { path: string; authorization: string | null };
    /** The upstream's reply to the text message `hello`. */
    echo?: string;
    /** The status code of the close message answering the client's close. */
    closeCode?: number;
}

/**
 * Open a WebSocket through the proxy to `127.0.0.1:port` in plaintext, or to `localhost:port`
 * over TLS, either intercepted transparently or inside a CONNECT tunnel. Send `hello`, read the
 * echo, and close with code 1000.
 */
export async function websocketExchange(options: {
    proxyPort: number;
    port: number;
    path: string;
    secure?: { ca: Buffer; tunnel: boolean };
}): Promise<WebSocketExchange> {
    const { proxyPort, port, path, secure } = options;
    const raw = createConnection({ host: "127.0.0.1", port: proxyPort });
    try {
        await once(raw, "connect");
        let socket: Duplex = raw;
        if (secure) {
            if (secure.tunnel) {
                await openTunnel(raw, port);
            }
            const tls = connect({
                socket: raw,
                servername: "localhost",
                ca: secure.ca,
                ALPNProtocols: ["http/1.1"],
            });
            await bounded(once(tls, "secureConnect"), 3000, "TLS handshake");
            socket = tls;
        }
        const host = secure ? "localhost" : "127.0.0.1";
        const key = randomBytes(16).toString("base64");
        const response = readHead(socket);
        socket.write(
            `GET ${path} HTTP/1.1\r\nHost: ${host}:${port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
        );
        const { head, rest } = await response;
        const status = Number(head.split(" ")[1]);
        if (status !== 101) {
            return { status };
        }
        const accepted = head
            .split("\r\n")
            .some(
                (line) =>
                    line.toLowerCase() === `sec-websocket-accept: ${acceptKey(key)}`.toLowerCase(),
            );
        const reader = frameReader(socket, rest);
        socket.resume();
        const greeting = JSON.parse((await reader.next()).payload.toString());
        socket.write(encodeFrame(textOpcode, Buffer.from("hello"), true));
        const echo = (await reader.next()).payload.toString();
        socket.write(encodeFrame(closeOpcode, Buffer.from([0x03, 0xe8]), true));
        const close = await reader.next();
        return { status, accepted, greeting, echo, closeCode: close.payload.readUInt16BE(0) };
    } finally {
        raw.destroy();
    }
}
