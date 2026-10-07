/**
 * Forwards real UI traffic between host Chromium and namespace-local exwall through
 * a Unix socket, without connecting the host and fixture networks through IP routes.
 * @module
 */

import { createConnection, createServer } from "node:net";
import type { Server, Socket, NetConnectOpts, ListenOptions } from "node:net";

/** A UI forwarder with explicit ownership of its accepted connections. */
export interface UiBridge {
    server: Server;
    /** Stop listening and close browser keep-alive connections before returning. */
    close(): Promise<void>;
}

/** Relay UI traffic through a Unix socket without adding IP routes between namespaces. */
export async function startUiBridge(
    listen: ListenOptions,
    destination: NetConnectOpts,
): Promise<UiBridge> {
    const sockets = new Set<Socket>();
    const server = createServer((incoming) => {
        const upstream = createConnection(destination);
        sockets.add(incoming);
        sockets.add(upstream);
        incoming.on("error", () => upstream.destroy());
        upstream.on("error", () => incoming.destroy());
        incoming.on("close", () => {
            sockets.delete(incoming);
            upstream.destroy();
        });
        upstream.on("close", () => {
            sockets.delete(upstream);
            incoming.destroy();
        });
        incoming.pipe(upstream);
        upstream.pipe(incoming);
    });
    await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(listen, () => {
            server.off("error", reject);
            resolve();
        });
    });
    return {
        server,
        /** Reap accepted connections so shutdown never waits on browser keep-alives. */
        async close() {
            const closed = new Promise<void>((resolve, reject) =>
                server.close((error) => (error ? reject(error) : resolve())),
            );
            for (const socket of sockets) socket.destroy();
            await closed;
        },
    };
}
