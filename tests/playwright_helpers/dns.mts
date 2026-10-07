/** UDP/TCP DNS fixtures and clients shared by protocol and firewall tests. */
import assert from "node:assert/strict";
import { createSocket } from "node:dgram";
import { createServer, createConnection } from "node:net";
import { bounded } from "#playwright_helpers/processes.mts";

/** Send a DNS A query, checking the transaction ID and response framing. */
export async function queryDns(
    host: string,
    port: number,
    name: string,
    tcp = false,
): Promise<number> {
    const header = Buffer.alloc(12);
    header.writeUInt16BE(42, 0);
    header.writeUInt16BE(0x100, 2);
    header.writeUInt16BE(1, 4);
    const wire = Buffer.concat([
        header,
        ...name
            .split(".")
            .map((part) => Buffer.concat([Buffer.from([part.length]), Buffer.from(part)])),
        Buffer.from([0, 0, 1, 0, 1]),
    ]);
    const response = await bounded(
        new Promise<Buffer>((resolve, reject) => {
            if (tcp) {
                const socket = createConnection({ host, port });
                let received = Buffer.alloc(0);
                socket.on("error", reject);
                socket.on("close", () =>
                    reject(new Error("DNS TCP connection closed before response")),
                );
                socket.setTimeout(3000, () => socket.destroy(new Error("DNS timeout")));
                socket.on("connect", () => {
                    const size = Buffer.alloc(2);
                    size.writeUInt16BE(wire.length);
                    socket.end(Buffer.concat([size, wire]));
                });
                socket.on("data", (chunk: Buffer) => {
                    received = Buffer.concat([received, chunk]);
                    if (received.length >= 2 && received.length >= received.readUInt16BE(0) + 2) {
                        resolve(received.subarray(2));
                        socket.destroy();
                    }
                });
            } else {
                const socket = createSocket(host.includes(":") ? "udp6" : "udp4");
                const timer = setTimeout(() => {
                    socket.close();
                    reject(new Error("DNS timeout"));
                }, 3000);
                socket.once("error", (error) => {
                    clearTimeout(timer);
                    socket.close();
                    reject(error);
                });
                socket.once("message", (message) => {
                    clearTimeout(timer);
                    socket.close();
                    resolve(message);
                });
                socket.send(wire, port, host);
            }
        }),
        4000,
        "DNS query",
    );
    assert.ok(response.length >= 12 && response[2]! & 0x80);
    assert.equal(response.readUInt16BE(0), 42);
    return response[3]! & 15;
}

/** Serve an empty successful answer on both DNS transports using the same port. */
export async function startDns(host: string, port = 0) {
    const udp = createSocket(host.includes(":") ? "udp6" : "udp4");
    /** Echo a query with response and recursion flags set. */
    function answer(wire: Buffer): Buffer {
        const response = Buffer.from(wire);
        response.writeUInt16BE(0x8180, 2);
        return response;
    }
    udp.on("message", (wire, peer) => udp.send(answer(wire), peer.port, peer.address));
    await new Promise<void>((resolve, reject) => {
        udp.once("error", reject);
        udp.bind(port, host, resolve);
    });
    const actualPort = udp.address().port;
    const tcp = createServer((socket) => {
        let received = Buffer.alloc(0);
        socket.on("error", () => socket.destroy());
        socket.on("data", (chunk: Buffer) => {
            received = Buffer.concat([received, chunk]);
            if (received.length >= 2 && received.length >= received.readUInt16BE(0) + 2) {
                const response = answer(received.subarray(2, received.readUInt16BE(0) + 2));
                socket.end(Buffer.concat([received.subarray(0, 2), response]));
            }
        });
    });
    await new Promise<void>((resolve, reject) => {
        tcp.once("error", reject);
        tcp.listen({ host, port: actualPort, ipv6Only: host.includes(":") }, resolve);
    });
    return {
        port: actualPort,
        /** Close both DNS listeners after their bounded exchanges finish. */
        async close() {
            udp.close();
            await new Promise<void>((resolve, reject) =>
                tcp.close((error) => (error ? reject(error) : resolve())),
            );
        },
    };
}
