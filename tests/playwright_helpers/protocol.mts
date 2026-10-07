/**
 * Defines and validates the request and response messages shared by Playwright
 * tests, the namespace broker, and the restricted network client.
 * @module
 */

/** An HTTP response observed by a client subject to the real namespace firewall. */
export interface HttpResult {
    status: number;
    body: string;
}

/** An HTTP request executed under the fixture's non-bypass client identity. */
export interface HttpOperation {
    operation: "http";
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
}

/** A direct TCP reachability check executed under the restricted identity. */
export interface TcpOperation {
    operation: "tcp";
    host: string;
    port: number;
}

/** Either a successful network exchange or an explicit transport failure. */
export type ClientResponse<T> =
    | { result: T; error?: never; error_type?: never }
    | { error: string; error_type: string; result?: never };

/** Network operations accepted by the private test broker. */
export type NetworkOperation =
    | HttpOperation
    | TcpOperation
    | DnsOperation
    | CertificateOperation
    | PingOperation;

/** DNS query executed through the real UDP or TCP redirect. */
export interface DnsOperation {
    operation: "dns";
    host: string;
    name: string;
    port?: number;
    tcp?: boolean;
}

/** Verified peer certificate used to distinguish bypasses from interception. */
export interface CertificateOperation {
    operation: "certificate";
    host: string;
    port: number;
    hostname: string;
}

/** ICMPv6 echo check under the ordinary UID. */
export interface PingOperation {
    operation: "ping";
    host: string;
}

/** Results returned by all supported restricted network operations. */
export type NetworkResult = HttpResult | boolean | number | string;

/** Paths announced after both private fixture transports are ready. */
export interface FixtureReady {
    uiSocket: string;
    clientSocket: string;
}

/** Check untrusted socket JSON before passing arguments to the restricted client. */
export function parseOperation(value: unknown): NetworkOperation {
    if (!value || typeof value !== "object") {
        throw new Error("Expected a network operation object");
    }
    if ("user" in value || "cert" in value) {
        throw new Error("The fixture controls identity and CA");
    }
    if (!("operation" in value)) {
        throw new Error("Missing network operation");
    }
    if (value.operation === "http") {
        if (!("url" in value) || typeof value.url !== "string") {
            throw new Error("Missing request URL");
        }
        const url = new URL(value.url);
        if (!["http:", "https:"].includes(url.protocol)) {
            throw new Error("Expected HTTP or HTTPS");
        }
        const operation: HttpOperation = { operation: "http", url: value.url };
        if ("method" in value) {
            if (typeof value.method !== "string") {
                throw new Error("Invalid HTTP method");
            }
            operation.method = value.method;
        }
        if ("body" in value) {
            if (typeof value.body !== "string") {
                throw new Error("Invalid request body");
            }
            operation.body = value.body;
        }
        if ("headers" in value) {
            if (!value.headers || typeof value.headers !== "object") {
                throw new Error("Invalid headers");
            }
            const headers: Record<string, string> = {};
            for (const [name, content] of Object.entries(value.headers)) {
                if (typeof content !== "string") {
                    throw new Error("Header values must be strings");
                }
                headers[name] = content;
            }
            operation.headers = headers;
        }
        return operation;
    }
    if (
        value.operation === "dns" &&
        "host" in value &&
        typeof value.host === "string" &&
        "name" in value &&
        typeof value.name === "string"
    ) {
        if (
            ("tcp" in value && typeof value.tcp !== "boolean") ||
            ("port" in value &&
                (typeof value.port !== "number" ||
                    !Number.isInteger(value.port) ||
                    value.port < 1 ||
                    value.port > 65535))
        ) {
            throw new Error("Invalid DNS options");
        }
        return {
            operation: "dns",
            host: value.host,
            name: value.name,
            tcp: "tcp" in value ? value.tcp === true : false,
            port: "port" in value && typeof value.port === "number" ? value.port : 53,
        };
    }
    if (value.operation === "ping" && "host" in value && typeof value.host === "string") {
        return { operation: "ping", host: value.host };
    }
    if (
        value.operation === "certificate" &&
        "host" in value &&
        typeof value.host === "string" &&
        "port" in value &&
        typeof value.port === "number" &&
        Number.isInteger(value.port) &&
        value.port > 0 &&
        value.port <= 65535 &&
        "hostname" in value &&
        typeof value.hostname === "string"
    ) {
        return {
            operation: "certificate",
            host: value.host,
            port: value.port,
            hostname: value.hostname,
        };
    }
    if (value.operation === "tcp" && "host" in value && "port" in value) {
        if (
            typeof value.host !== "string" ||
            typeof value.port !== "number" ||
            !Number.isInteger(value.port) ||
            value.port < 1 ||
            value.port > 65535
        ) {
            throw new Error("Invalid TCP destination");
        }
        return { operation: "tcp", host: value.host, port: value.port };
    }
    throw new Error("Unsupported network operation");
}
