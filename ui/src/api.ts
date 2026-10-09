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

/** Current counters for a domain, without individual request history. */
export interface DomainStats {
    domain: string;
    dns: { allow: number; block: number };
    http: { allow: number; block: number };
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
    const document = await api<RulesDocument>("rules");
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
    return changed ? api<RulesDocument>("rules", "PUT", document) : document;
}

/** Add a rule allowing one denied request's exact method and pathname. */
export async function allowRequest(denial: HttpDenial): Promise<RulesDocument> {
    const document = await api<RulesDocument>("rules");
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
    return changed ? api<RulesDocument>("rules", "PUT", document) : document;
}
