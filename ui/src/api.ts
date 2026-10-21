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

/** One retained policy denial, with the exact pathname and no query string. */
export interface HttpDenial {
    domain: string;
    method: string;
    pathname: string;
    timestamp: string;
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

/** Forget all domain counters, transfer totals, and retained denials. */
export async function resetTraffic(): Promise<void> {
    await api("traffic/reset", "POST", {});
}

/** Escape pathname characters so an allow rule matches exactly one literal path. */
export function exactPathRegex(pathname: string): string {
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

/** Add a rule allowing a domain, unless an equivalent rule already exists. */
export async function allowDomain({
    domain,
    dnsOnly,
    includeSubdomains = false,
}: DomainAllowance): Promise<RulesDocument> {
    const document = await readWebRules();
    let changed = !dnsOnly && removeCoveredDnsRules(document, domain, includeSubdomains);
    if (
        !document.rules.some(
            (rule) =>
                rule.fields.domain === domain &&
                (!includeSubdomains || rule.fields.include_subdomains === true) &&
                (dnsOnly ||
                    (rule.fields.dns_only !== true &&
                        rule.fields.methods === "ANY" &&
                        rule.fields.pathname_pattern === undefined &&
                        rule.fields.pathname_regex === undefined &&
                        rule.fields.inject_headers === undefined)),
        )
    ) {
        document.rules.unshift({
            index: null,
            fields: {
                domain,
                ...(dnsOnly ? { dns_only: true } : { methods: "ANY" }),
                ...(includeSubdomains ? { include_subdomains: true } : {}),
            },
        });
        changed = true;
    }
    return changed ? api<RulesDocument>(rulesPath(webRulesFile), "PUT", document) : document;
}

/** Add a rule allowing one denied request's exact method and pathname. */
export async function allowRequest(denial: HttpDenial): Promise<RulesDocument> {
    const document = await readWebRules();
    const pathnameRegex = exactPathRegex(denial.pathname);
    let changed = removeCoveredDnsRules(document, denial.domain);
    if (
        !document.rules.some(
            (rule) =>
                rule.fields.domain === denial.domain &&
                rule.fields.dns_only !== true &&
                Array.isArray(rule.fields.methods) &&
                rule.fields.methods.some((method) => method === denial.method) &&
                rule.fields.pathname_regex === pathnameRegex &&
                rule.fields.pathname_pattern === undefined &&
                rule.fields.inject_headers === undefined,
        )
    ) {
        document.rules.unshift({
            index: null,
            fields: {
                domain: denial.domain,
                methods: [denial.method],
                pathname_regex: pathnameRegex,
            },
        });
        changed = true;
    }
    return changed ? api<RulesDocument>(rulesPath(webRulesFile), "PUT", document) : document;
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
