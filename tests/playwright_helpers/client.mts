/**
 * Provides the host-side API imported by Playwright tests to request restricted
 * network checks and read fixture rules or upstream observations over a private Unix socket.
 * @module
 */

import { request } from "node:http";
import type {
    ClientResponse,
    HttpResult,
    NetworkOperation,
} from "#playwright_helpers/protocol.mts";
import type { MockRequest } from "#playwright_helpers/mock_server.mts";

/** Send JSON over a filesystem Unix socket without requiring sudo in the calling test. */
export async function requestUnixJson<T>(
    socketPath: string,
    path: string,
    body?: unknown,
): Promise<T> {
    const content = body === undefined ? undefined : JSON.stringify(body);
    return new Promise((resolve, reject) => {
        const call = request(
            {
                socketPath,
                path,
                method: content === undefined ? "GET" : "POST",
                headers:
                    content === undefined
                        ? {}
                        : {
                              "content-type": "application/json",
                              "content-length": Buffer.byteLength(content),
                          },
            },
            (response) => {
                const chunks: Buffer[] = [];
                response.on("data", (chunk: Buffer) => chunks.push(chunk));
                response.on("error", reject);
                response.on("end", () => {
                    const text = Buffer.concat(chunks).toString("utf8");
                    if (response.statusCode !== 200) {
                        reject(
                            new Error(`Namespace broker returned ${response.statusCode}: ${text}`),
                        );
                        return;
                    }
                    try {
                        resolve(JSON.parse(text));
                    } catch (error) {
                        reject(error);
                    }
                });
            },
        );
        call.on("error", reject);
        call.setTimeout(10_000, () =>
            call.destroy(new Error("Namespace broker request timed out")),
        );
        call.end(content);
    });
}

/** Resolve the private broker configured by the host E2E launcher. */
function clientSocket(): string {
    const path = process.env.EXWALL_E2E_CLIENT_SOCKET;
    if (!path) throw new Error("Run ./e2e_tests.sh to create the namespace fixture first");
    return path;
}

/** Ask the broker to make an HTTP exchange or TCP check under the restricted UID. */
export async function networkRequest(
    operation: NetworkOperation,
): Promise<ClientResponse<HttpResult | boolean>> {
    return requestUnixJson(clientSocket(), "/client", operation);
}

/** Read the actual private rules file for persistence and failed-save assertions. */
export async function fixtureRules(): Promise<string> {
    return (await requestUnixJson<{ rules: string }>(clientSocket(), "/rules")).rules;
}

/** List requests observed by the upstream to distinguish denial from accidental forwarding. */
export async function upstreamRequests(): Promise<MockRequest[]> {
    return requestUnixJson(clientSocket(), "/requests");
}
