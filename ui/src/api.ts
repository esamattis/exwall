/** A header added to matching upstream requests. */
export interface InjectedHeader {
    name: string;
    value: string;
}

/** Ordinary JSON values used by the rule editing API. */
export type FieldValue = string | string[] | boolean | InjectedHeader[];

/** An editable allow table with its original position for comment preservation. */
export interface RuleDraft {
    index: number | null;
    fields: Record<string, FieldValue>;
}

/** Rules and a revision used to reject overwriting concurrent file edits. */
export interface RulesDocument {
    revision: string;
    rules: RuleDraft[];
}

/**
 * A rule file as loaded for editing: its exact text as the revision, plus either
 * the rules for the form editor or why the file is invalid.
 */
export interface RuleFileContents {
    revision: string;
    /** The allow tables, absent when the file is invalid. */
    rules?: RuleDraft[];
    /** Why the file cannot be loaded or edited as a form, absent when it is valid. */
    error?: string;
}

/** One rule file in the rules directory. */
export interface RuleFileSummary {
    name: string;
    /** The absolute path on the host. */
    path: string;
    /** The number of allow tables, or null when the file is invalid. */
    rules: number | null;
}

/** The rule file that Traffic page allowances extend; the service always creates it. */
export const webRulesFile = "05-web.toml";

/** Where an allowing rule lives, for linking to it in the rule editor. */
export interface RuleLocation {
    /** The rule file name in the rules directory. */
    file: string;
    /** The 1-based rule number, as in `allow#N` access-log labels. */
    rule: number;
}

/** Locate the rule named by an access-log label such as `/etc/exwall/rules/web.toml:allow#2`. */
export function parseRuleLabel(label: string): RuleLocation | null {
    const match = /([^/]+):allow#(\d+)$/.exec(label);
    if (!match?.[1] || !match[2]) {
        return null;
    }
    return { file: match[1], rule: Number(match[2]) };
}

/** The API path of one rule file. */
export function rulesPath(file: string): string {
    return `rules/${encodeURIComponent(file)}`;
}

/** Replace a rule file with TOML text, which the server validates before saving. */
export function saveRulesToml(
    file: string,
    revision: string,
    toml: string,
): Promise<RuleFileContents> {
    return api<RuleFileContents>(rulesPath(file), "PUT", { revision, toml });
}

/** Load the rules that Traffic page allowances extend, refusing to edit an invalid file. */
async function readWebRules(): Promise<RulesDocument> {
    const { revision, rules, error } = await api<RuleFileContents>(rulesPath(webRulesFile));
    if (rules === undefined) {
        throw new Error(
            `${webRulesFile} is invalid. Fix it on the Rules page first: ${error ?? "unknown error"}`,
        );
    }
    return { revision, rules };
}

/** Current counters for a domain, without individual request history. */
export interface DomainStats {
    domain: string;
    dns: { allow: number; block: number };
    http: { allow: number; block: number };
    /** HTTP(S) body bytes forwarded upstream (up) and back to clients (down). */
    bytes: { up: number; down: number };
    last_updated: string;
    last_allowed: string | null;
    last_denied: string | null;
}

/** One retained HTTP request and its repeats, grouped by method, pathname, and query string. */
export interface HttpRequest {
    /** The URL scheme; `ws` and `wss` mark WebSocket handshakes. */
    scheme: "http" | "https" | "ws" | "wss";
    domain: string;
    /** The destination port; absent when it is the scheme's default. */
    port?: number;
    method: string;
    pathname: string;
    /** The raw query string without `?`; absent when the request had none. */
    query?: string;
    /** The rule or exception that allowed the latest repeat; absent for denials. */
    rule?: string;
    /** How many times the request was seen since it was first retained. */
    count: number;
    /** When the latest repeat was seen. */
    timestamp: string;
    /** The latest captured repeat's headers and bodies; absent when none was captured. */
    capture_id?: number;
}

/** Report whether a retained request is a WebSocket handshake rather than plain HTTP(S). */
export function isWebSocket(request: HttpRequest): boolean {
    return request.scheme === "ws" || request.scheme === "wss";
}

/** One query string parameter, percent- and form-decoded. */
export interface QueryParameter {
    name: string;
    value: string;
}

/** Split a raw query string into decoded parameters in their original order. */
export function parseQuery(query: string): QueryParameter[] {
    return [...new URLSearchParams(query)].map(([name, value]) => ({ name, value }));
}

/** Whether HTTP headers and bodies are captured, and how much of each body is kept. */
export interface CaptureSettings {
    enabled: boolean;
    /** The most bytes kept from each request and response body, in KB (1024 bytes). */
    body_limit_kb: number;
}

/** The largest body size limit the server accepts, in KB. */
export const maxBodyLimitKb = 1024;

/** Turn capturing of HTTP headers and bodies on or off for new requests. */
export function updateCapture(settings: CaptureSettings): Promise<CaptureSettings> {
    return api<CaptureSettings>("capture", "PUT", settings);
}

/** One header as received; repeated headers appear as separate entries. */
export interface CapturedHeader {
    /** The header name, with the case the client or upstream sent where it is known. */
    name: string;
    value: string;
}

/** The captured leading part of a request or response body. */
export interface CapturedBody {
    /** Every byte seen, including bytes beyond the capture limit. */
    size: number;
    /** The bytes kept. */
    captured: number;
    /** Whether bytes beyond the capture limit were not kept. */
    truncated: boolean;
    /** Whether the body was read to its end. */
    complete: boolean;
    /** The body's Content-Encoding, if any. */
    encoding?: string;
    /** Whether `text` was decompressed from `encoding`. */
    decoded: boolean;
    /** The body as text; absent when it is binary. */
    text?: string;
}

/** A captured request or response. */
export interface CapturedMessage {
    /** The response status; absent for requests. */
    status?: number;
    headers: CapturedHeader[];
    /** The body, or null while it is still streaming. */
    body: CapturedBody | null;
}

/** A request's captured headers and bodies. */
export interface CaptureDetails {
    id: number;
    /** When the captured request arrived. */
    timestamp: string;
    /** The most bytes kept from each body. */
    body_limit: number;
    /** The request as the client sent it, before any header injection. */
    request: CapturedMessage;
    /** The response returned to the client, or null before its headers arrive. */
    response: CapturedMessage | null;
    /** The messages of a WebSocket whose handshake succeeded; absent for other requests. */
    websocket?: CapturedWebSocket;
}

/** Message and byte totals for one direction of a WebSocket. */
export interface WebSocketTally {
    /** Text and binary messages, including those not kept. */
    messages: number;
    /** Decoded text and binary payload bytes. */
    bytes: number;
}

/** One captured WebSocket message. */
export interface WebSocketMessage {
    /** `up` from the client to the server, or `down` back to the client. */
    direction: "up" | "down";
    kind: "text" | "binary" | "close";
    /** The decoded payload size. */
    size: number;
    /** The payload bytes kept. */
    captured: number;
    /** Milliseconds after the WebSocket opened. */
    at_ms: number;
    /** The close status code of a close message. */
    code?: number;
    /** The kept payload as text, or a close reason. */
    text?: string;
    /** The kept payload in hexadecimal, when it is not text. */
    hex?: string;
}

/** The captured messages of a WebSocket. */
export interface CapturedWebSocket {
    /** The most messages kept in each direction. */
    message_limit: number;
    /** The kept messages in arrival order. */
    messages: WebSocketMessage[];
    up: WebSocketTally;
    down: WebSocketTally;
    /** How the WebSocket ended, or null while it is open. */
    ended: {
        duration_ms: number;
        /** Which side sent the first close message, or null when neither did. */
        closed_by: "client" | "server" | null;
        /** The access-log error token for an abnormal end, or null. */
        failure: string | null;
    } | null;
}

/** The firewall host, identified in the page header. */
export interface HostInfo {
    /** The kernel hostname, or null when it cannot be read. */
    hostname: string | null;
    /** Reachable interface addresses, default-route interfaces first, then IPv4 before IPv6. */
    addresses: InterfaceAddress[];
}

/** One address assigned to a network interface on the firewall host. */
export interface InterfaceAddress {
    /** Whether the interface carries a default route. */
    default_route: boolean;
    /** The assigned IPv4 or IPv6 address. */
    address: string;
    /** The interface name, such as eth0 or docker0. */
    interface: string;
}

/** The signed-in account. */
export interface Session {
    username: string;
}

/** Parameters shared by domain allowance actions. */
export interface DomainAllowance {
    domain: string;
    dnsOnly: boolean;
    includeSubdomains?: boolean;
}

/** An API failure retaining its HTTP status for authentication handling. */
export class ApiError extends Error {
    status: number;

    /** Record the HTTP status alongside the server's message. */
    constructor(status: number, message: string) {
        super(message);
        this.status = status;
    }
}

/** Persist sessions within this exact scheme, hostname, and port rather than shared cookies. */
export const sessionKey = "exwall.session";

/** Report whether this origin holds a session token. */
export function hasSession(): boolean {
    return localStorage.getItem(sessionKey) !== null;
}

/** Fetch same-origin JSON with a token that other localhost ports cannot read or receive. */
export async function api<T>(
    path: string,
    method: "GET" | "POST" | "PUT" = "GET",
    body?: unknown,
): Promise<T> {
    const headers = new Headers();
    const token = localStorage.getItem(sessionKey);
    if (token && path !== "login") {
        headers.set("Authorization", `Bearer ${token}`);
    }
    if (body !== undefined) {
        headers.set("Content-Type", "application/json");
    }
    const options: RequestInit = {
        method,
        credentials: "omit",
        redirect: "error",
        headers,
    };
    if (method !== "GET" && body !== undefined) {
        options.body = JSON.stringify(body);
    }
    const response = await fetch(`/api/${path}`, options);
    const result: T & { error?: string } = await response.json();
    if (!response.ok) {
        if (response.status === 401 && path !== "login") {
            localStorage.removeItem(sessionKey);
        }
        throw new ApiError(response.status, result.error ?? "Request failed");
    }
    return result;
}

/** Forget all domain counters, transfer totals, and retained requests. */
export async function resetTraffic(): Promise<void> {
    await api("traffic/reset", "POST", {});
}

/**
 * Escape pathname characters into the regex that older versions of the UI saved to allow
 * exactly one literal path.
 */
function exactPathRegex(pathname: string): string {
    return `\\A${pathname.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\z`;
}

/** Normalize domain fields the same way as the proxy's hostname matcher. */
function normalizeDomain(domain: string): string {
    return domain.trim().replace(/\.+$/, "").toLowerCase();
}

/** Remove DNS-only tables whose entire hostname scope is covered by an HTTP allowance. */
function removeCoveredDnsRules(
    document: RulesDocument,
    domain: string,
    includeSubdomains = false,
): boolean {
    const allowedDomain = normalizeDomain(domain);
    const previousCount = document.rules.length;
    document.rules = document.rules.filter((rule) => {
        if (
            rule.fields.dns_only !== true ||
            rule.fields.domain_regex !== undefined ||
            (!includeSubdomains && rule.fields.include_subdomains === true)
        ) {
            return true;
        }
        const domains = rule.fields.domain;
        const names = typeof domains === "string" ? [domains] : domains;
        if (!Array.isArray(names) || names.length === 0) {
            return true;
        }
        return !names.every((name) => {
            if (typeof name !== "string") {
                return false;
            }
            const normalized = normalizeDomain(name);
            return (
                normalized === allowedDomain ||
                (includeSubdomains && normalized.endsWith(`.${allowedDomain}`))
            );
        });
    });
    return document.rules.length !== previousCount;
}

/** Match rules that already allow everything a domain allowance would add. */
export function coversDomain({
    domain,
    dnsOnly,
    includeSubdomains = false,
}: DomainAllowance): (rule: RuleDraft) => boolean {
    return (rule) =>
        rule.fields.domain === domain &&
        (!includeSubdomains || rule.fields.include_subdomains === true) &&
        (dnsOnly ||
            (rule.fields.dns_only !== true &&
                rule.fields.methods === "ANY" &&
                rule.fields.pathname === undefined &&
                rule.fields.pathname_pattern === undefined &&
                rule.fields.pathname_regex === undefined &&
                rule.fields.inject_headers === undefined));
}

/** Match rules that already allow exactly what allowing one request would add. */
export function coversRequest(request: HttpRequest): (rule: RuleDraft) => boolean {
    const pathnameRegex = exactPathRegex(request.pathname);
    return (rule) =>
        rule.fields.domain === request.domain &&
        rule.fields.dns_only !== true &&
        Array.isArray(rule.fields.methods) &&
        rule.fields.methods.some((method) => method === request.method) &&
        rule.fields.pathname_pattern === undefined &&
        // Rules saved before exact pathnames existed used an escaped regex instead.
        ((rule.fields.pathname === request.pathname && rule.fields.pathname_regex === undefined) ||
            (rule.fields.pathname_regex === pathnameRegex && rule.fields.pathname === undefined)) &&
        rule.fields.inject_headers === undefined;
}

/**
 * Add `fields` as the first web rule unless a rule matching `covers` exists, then save the
 * web rules if anything changed.
 */
async function ensureWebRule(
    document: RulesDocument,
    changed: boolean,
    covers: (rule: RuleDraft) => boolean,
    fields: Record<string, FieldValue>,
): Promise<RulesDocument> {
    const exists = document.rules.some(covers);
    if (!exists) {
        document.rules.unshift({ index: null, fields });
    }
    if (changed || !exists) {
        return api<RulesDocument>(rulesPath(webRulesFile), "PUT", document);
    }
    return document;
}

/** Add a rule allowing a domain, unless an equivalent rule already exists. */
export async function allowDomain(allowance: DomainAllowance): Promise<RulesDocument> {
    const { domain, dnsOnly, includeSubdomains = false } = allowance;
    const document = await readWebRules();
    const changed = !dnsOnly && removeCoveredDnsRules(document, domain, includeSubdomains);
    return ensureWebRule(document, changed, coversDomain(allowance), {
        domain,
        ...(dnsOnly ? { dns_only: true } : { methods: "ANY" }),
        ...(includeSubdomains ? { include_subdomains: true } : {}),
    });
}

/** Add a rule allowing one request's exact method and pathname, with any query string. */
export async function allowRequest(request: HttpRequest): Promise<RulesDocument> {
    const document = await readWebRules();
    const changed = removeCoveredDnsRules(document, request.domain);
    return ensureWebRule(document, changed, coversRequest(request), {
        domain: request.domain,
        methods: [request.method],
        pathname: request.pathname,
    });
}

/** Whether blocking is enforced or temporarily paused. */
export interface BlockingStatus {
    /** Whole seconds until blocking resumes, or null while blocking is enforced. */
    paused_seconds_remaining: number | null;
}

/** Let all HTTP(S) requests and DNS lookups through for `minutes`, then resume blocking. */
export function pauseBlocking(minutes: number): Promise<BlockingStatus> {
    return api<BlockingStatus>("blocking/pause", "POST", { minutes });
}

/** End a blocking pause immediately. */
export function resumeBlocking(): Promise<BlockingStatus> {
    return api<BlockingStatus>("blocking/resume", "POST", {});
}
