import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import {
    allowDomain,
    allowRequest,
    api,
    resetTraffic,
    type DomainAllowance,
    type DomainStats,
    type HttpDenial,
} from "./api.ts";
import {
    CheckIcon,
    EmptyState,
    ErrorBanner,
    FilterInput,
    PageHeader,
    RefreshIcon,
    RelativeTime,
    Spinner,
    TrashIcon,
    useNow,
    useToast,
} from "./components.tsx";

/** The three traffic views selectable from the tab bar. */
export type TrafficView = "blocked" | "allowed" | "requests";

/** Validate the `view` search parameter, defaulting to blocked domains. */
export function parseTrafficView(value: unknown): TrafficView {
    if (value === "allowed" || value === "requests") {
        return value;
    }
    return "blocked";
}

/** Query options shared by the manually refreshed traffic queries. */
const manualQuery = {
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: false,
};

/** A domain row paired with the timestamp of the outcome its table shows. */
interface DomainEntry {
    entry: DomainStats;
    timestamp: string;
}

/** Select domains with the given outcome, ordered by their latest occurrence of it. */
function domainEntries(domains: DomainStats[], outcome: "allow" | "block"): DomainEntry[] {
    const entries = domains.flatMap((entry) => {
        const timestamp = outcome === "allow" ? entry.last_allowed : entry.last_denied;
        return timestamp === null ? [] : [{ entry, timestamp }];
    });
    // The API emits UTC timestamps; omit Z so fractional seconds sort after whole seconds.
    entries.sort(
        (left, right) =>
            right.timestamp.slice(0, -1).localeCompare(left.timestamp.slice(0, -1)) ||
            left.entry.domain.localeCompare(right.entry.domain),
    );
    return entries;
}

/** Units used when formatting transferred byte counts. */
const byteUnits = ["B", "kB", "MB", "GB", "TB", "PB"];

/** Format a byte count with a decimal unit, such as `1.5 MB`. */
function formatBytes(bytes: number): string {
    let value = bytes;
    let unit = 0;
    while (value >= 1000 && unit < byteUnits.length - 1) {
        value /= 1000;
        unit += 1;
    }
    const digits = unit === 0 || value >= 100 ? 0 : 1;
    return `${value.toFixed(digits)} ${byteUnits[unit]}`;
}

/** Describe a completed domain allowance for the confirmation toast. */
function allowanceMessage(allowance: DomainAllowance): string {
    if (allowance.dnsOnly) {
        return "Domain allowed for DNS only.";
    }
    if (allowance.includeSubdomains) {
        return "Domain and its subdomains allowed on all routes and methods.";
    }
    return "Domain allowed on all routes and methods.";
}

/** Describe a domain allowance for its row's confirmation badge. */
function allowanceLabel(allowance: DomainAllowance): string {
    if (allowance.dnsOnly) {
        return "DNS allowed";
    }
    if (allowance.includeSubdomains) {
        return "Allowed + subdomains";
    }
    return "Allowed";
}

/** Show seen domains and recent denials, with one-click allow actions. */
export function TrafficPage({ view }: { view: TrafficView }) {
    const client = useQueryClient();
    const navigate = useNavigate();
    const toast = useToast();
    const now = useNow();
    const [filter, setFilter] = useState("");
    const [allowedDomains, setAllowedDomains] = useState<Record<string, DomainAllowance>>({});
    const [allowedRequests, setAllowedRequests] = useState<Record<string, boolean>>({});
    const domains = useQuery({
        queryKey: ["domains"],
        queryFn: () => api<DomainStats[]>("domains"),
        ...manualQuery,
    });
    const denials = useQuery({
        queryKey: ["http-denials"],
        queryFn: () => api<HttpDenial[]>("http-denials"),
        ...manualQuery,
    });
    const domainAllow = useMutation({
        mutationFn: allowDomain,
        onSuccess: async (_, allowance) => {
            setAllowedDomains((previous) => ({ ...previous, [allowance.domain]: allowance }));
            toast(allowanceMessage(allowance));
            await client.invalidateQueries({ queryKey: ["rules"] });
        },
    });
    const requestAllow = useMutation({
        mutationFn: allowRequest,
        onSuccess: async (_, denial) => {
            setAllowedRequests((previous) => ({ ...previous, [requestKey(denial)]: true }));
            toast("Method and pathname allowed.");
            await client.invalidateQueries({ queryKey: ["rules"] });
        },
    });
    const reset = useMutation({
        mutationFn: resetTraffic,
        onSuccess: async () => {
            setAllowedDomains({});
            setAllowedRequests({});
            toast("Traffic statistics reset.");
            await Promise.all([domains.refetch(), denials.refetch()]);
        },
    });
    const refreshing = domains.isFetching || denials.isFetching;
    const blocked = domainEntries(domains.data ?? [], "block");
    const allowed = domainEntries(domains.data ?? [], "allow");
    const needle = filter.trim().toLowerCase();
    const tabs: { id: TrafficView; label: string; count: number | undefined }[] = [
        { id: "blocked", label: "Blocked domains", count: domains.data && blocked.length },
        { id: "allowed", label: "Allowed domains", count: domains.data && allowed.length },
        { id: "requests", label: "Blocked requests", count: denials.data?.length },
    ];
    const updatedAt = Math.max(domains.dataUpdatedAt, denials.dataUpdatedAt);
    const actionError = domainAllow.error ?? requestAllow.error ?? reset.error;
    const loadError = domains.error ?? denials.error;
    let panel: ReactNode = (
        <p role="status" className="flex items-center gap-2 px-4 py-10 text-sm text-zinc-400">
            <Spinner /> Loading traffic…
        </p>
    );
    if (view === "requests" && denials.data) {
        panel = (
            <RequestsTable
                denials={denials.data.filter(
                    (denial) =>
                        denial.domain.toLowerCase().includes(needle) ||
                        denial.pathname.toLowerCase().includes(needle),
                )}
                filtered={needle !== "" && denials.data.length > 0}
                now={now}
                isPending={requestAllow.isPending}
                allowed={allowedRequests}
                onAllow={requestAllow.mutate}
            />
        );
    } else if (view !== "requests" && domains.data) {
        const entries = view === "blocked" ? blocked : allowed;
        panel = (
            <DomainsTable
                outcome={view === "blocked" ? "block" : "allow"}
                entries={entries.filter(({ entry }) => entry.domain.toLowerCase().includes(needle))}
                filtered={needle !== "" && entries.length > 0}
                now={now}
                isPending={domainAllow.isPending}
                allowed={allowedDomains}
                onAllow={domainAllow.mutate}
            />
        );
    }
    return (
        <>
            <PageHeader
                title="Traffic"
                description="DNS lookups and HTTP(S) requests checked since exwall started or the last reset. Counters live in memory and reset on restart."
                actions={
                    <>
                        {updatedAt > 0 && (
                            <span className="text-xs text-zinc-500">
                                Updated {new Date(updatedAt).toLocaleTimeString()}
                            </span>
                        )}
                        <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={refreshing}
                            onClick={() => {
                                void domains.refetch();
                                void denials.refetch();
                            }}
                        >
                            {refreshing ? <Spinner /> : <RefreshIcon />}
                            Refresh
                        </button>
                        <button
                            type="button"
                            className="btn btn-secondary"
                            title="Clear all domain counters, transferred bytes, and blocked requests"
                            disabled={reset.isPending}
                            onClick={() => {
                                if (
                                    window.confirm(
                                        "Reset all traffic counters, transferred bytes, and blocked requests?",
                                    )
                                ) {
                                    reset.mutate();
                                }
                            }}
                        >
                            {reset.isPending ? <Spinner /> : <TrashIcon />}
                            Reset
                        </button>
                    </>
                }
            />
            <StatTiles domains={domains.data} />
            {loadError && (
                <div className="mb-4">
                    <ErrorBanner>{loadError.message}</ErrorBanner>
                </div>
            )}
            {actionError && (
                <div className="mb-4">
                    <ErrorBanner>{actionError.message}</ErrorBanner>
                </div>
            )}
            <div className="panel overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-2 pt-2 sm:pr-3">
                    <div
                        role="tablist"
                        aria-label="Traffic views"
                        className="-mb-px flex max-w-full gap-1 overflow-x-auto"
                    >
                        {tabs.map((tab) => {
                            const selected = tab.id === view;
                            return (
                                <button
                                    key={tab.id}
                                    id={`tab-${tab.id}`}
                                    type="button"
                                    role="tab"
                                    aria-selected={selected}
                                    aria-controls={`panel-${tab.id}`}
                                    onClick={() =>
                                        void navigate({ to: "/", search: { view: tab.id } })
                                    }
                                    className={`flex items-center gap-2 border-b-2 whitespace-nowrap px-3 py-2.5 text-sm font-medium transition ${
                                        selected
                                            ? "border-emerald-400 text-white"
                                            : "border-transparent text-zinc-400 hover:text-zinc-200"
                                    }`}
                                >
                                    {tab.label}
                                    {tab.count !== undefined && (
                                        <span
                                            className={`rounded-full px-1.5 py-px text-xs tabular-nums ${
                                                selected
                                                    ? "bg-white/10 text-zinc-200"
                                                    : "bg-white/5 text-zinc-500"
                                            }`}
                                        >
                                            {tab.count}
                                        </span>
                                    )}
                                </button>
                            );
                        })}
                    </div>
                    <div className="w-full pb-2 sm:w-auto">
                        <FilterInput
                            label="Filter"
                            placeholder={
                                view === "requests" ? "Filter domains or paths" : "Filter domains"
                            }
                            value={filter}
                            onChange={setFilter}
                        />
                    </div>
                </div>
                <div role="tabpanel" id={`panel-${view}`} aria-labelledby={`tab-${view}`}>
                    {panel}
                </div>
            </div>
        </>
    );
}

/** Summarize domain counters as a row of headline numbers. */
function StatTiles({ domains }: { domains: DomainStats[] | undefined }) {
    const sum = (pick: (entry: DomainStats) => number) =>
        domains?.reduce((total, entry) => total + pick(entry), 0);
    const tiles: { label: string; value: number | undefined; dot: string; hint: string }[] = [
        {
            label: "Domains seen",
            value: domains?.length,
            dot: "bg-zinc-400",
            hint: "Up to 1000 most recent",
        },
        {
            label: "Blocked domains",
            value: domains?.filter((entry) => entry.last_denied !== null).length,
            dot: "bg-rose-400",
            hint: "At least one denial",
        },
        {
            label: "Blocked",
            value: sum((entry) => entry.dns.block + entry.http.block),
            dot: "bg-rose-400",
            hint: "DNS lookups and HTTP requests",
        },
        {
            label: "Allowed",
            value: sum((entry) => entry.dns.allow + entry.http.allow),
            dot: "bg-emerald-400",
            hint: "DNS lookups and HTTP requests",
        },
    ];
    return (
        <dl className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
            {tiles.map((tile) => (
                <div key={tile.label} className="panel px-4 py-3">
                    <dt className="flex items-center gap-2 text-xs font-medium text-zinc-400">
                        <span className={`size-1.5 rounded-full ${tile.dot}`} aria-hidden="true" />
                        {tile.label}
                    </dt>
                    <dd className="mt-1 text-2xl font-semibold text-white tabular-nums">
                        {tile.value === undefined ? "–" : tile.value.toLocaleString()}
                    </dd>
                    <dd className="text-xs text-zinc-500">{tile.hint}</dd>
                </div>
            ))}
        </dl>
    );
}

/** Shared header cell styling for traffic tables. */
const headerCell = "px-4 py-2.5 text-xs font-medium tracking-wide text-zinc-500 uppercase";

/** Show domains with one outcome, with allow actions for blocked domains. */
function DomainsTable({
    outcome,
    entries,
    filtered,
    now,
    isPending,
    allowed,
    onAllow,
}: {
    outcome: "allow" | "block";
    entries: DomainEntry[];
    filtered: boolean;
    now: number;
    isPending: boolean;
    allowed: Record<string, DomainAllowance>;
    onAllow: (allowance: DomainAllowance) => void;
}) {
    const title = outcome === "allow" ? "Allowed domains" : "Blocked domains";
    if (entries.length === 0) {
        if (filtered) {
            return <EmptyState title="No matching domains" />;
        }
        return outcome === "allow" ? (
            <EmptyState title="No allowed domains yet">
                Domains appear here once a DNS lookup or HTTP request is allowed.
            </EmptyState>
        ) : (
            <EmptyState title="No blocked domains yet">
                Domains appear here when a DNS lookup or HTTP request is denied. Press Refresh to
                load new activity.
            </EmptyState>
        );
    }
    return (
        <div className="relative overflow-x-auto">
            <table className="w-full text-left text-sm">
                <caption className="sr-only">{title}, latest first</caption>
                <thead className="border-b border-white/10 bg-white/[0.02]">
                    <tr>
                        <th className={headerCell}>Domain</th>
                        <th className={`${headerCell} text-right`}>DNS</th>
                        <th className={`${headerCell} text-right`}>HTTP</th>
                        <th className={`${headerCell} text-right`}>Total</th>
                        <th
                            className={`${headerCell} text-right`}
                            title="HTTP(S) request body bytes sent upstream"
                        >
                            Up
                        </th>
                        <th
                            className={`${headerCell} text-right`}
                            title="HTTP(S) response body bytes received from upstream"
                        >
                            Down
                        </th>
                        <th className={headerCell}>
                            {outcome === "allow" ? "Last allowed" : "Last blocked"}
                        </th>
                        {outcome === "block" && (
                            <th className={`${headerCell} text-right`}>
                                <span className="sr-only">Actions</span>
                            </th>
                        )}
                    </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                    {entries.map(({ entry, timestamp }) => {
                        const done = allowed[entry.domain];
                        return (
                            <tr key={entry.domain} className="transition hover:bg-white/[0.03]">
                                <th
                                    scope="row"
                                    className="max-w-xs truncate px-4 py-2.5 font-mono text-[13px] font-medium text-zinc-100"
                                    title={entry.domain}
                                >
                                    {entry.domain}
                                </th>
                                <td className="px-4 py-2.5 text-right text-zinc-300 tabular-nums">
                                    {entry.dns[outcome]}
                                </td>
                                <td className="px-4 py-2.5 text-right text-zinc-300 tabular-nums">
                                    {entry.http[outcome]}
                                </td>
                                <td className="px-4 py-2.5 text-right font-medium text-white tabular-nums">
                                    {entry.dns[outcome] + entry.http[outcome]}
                                </td>
                                <td
                                    className="px-4 py-2.5 text-right whitespace-nowrap text-zinc-300 tabular-nums"
                                    title={`${entry.bytes.up.toLocaleString()} bytes`}
                                >
                                    {formatBytes(entry.bytes.up)}
                                </td>
                                <td
                                    className="px-4 py-2.5 text-right whitespace-nowrap text-zinc-300 tabular-nums"
                                    title={`${entry.bytes.down.toLocaleString()} bytes`}
                                >
                                    {formatBytes(entry.bytes.down)}
                                </td>
                                <td className="px-4 py-2.5 text-zinc-400">
                                    <RelativeTime timestamp={timestamp} now={now} />
                                </td>
                                {outcome === "block" && (
                                    <td className="px-4 py-2">
                                        <div className="flex items-center justify-end gap-1.5">
                                            {done && (
                                                <span className="badge badge-allow mr-1">
                                                    <CheckIcon className="size-3" />
                                                    {allowanceLabel(done)}
                                                </span>
                                            )}
                                            <button
                                                type="button"
                                                className="btn btn-sm btn-primary"
                                                aria-label={`Allow ${entry.domain} completely`}
                                                title="Allow DNS and every HTTP(S) method and path"
                                                disabled={isPending}
                                                onClick={() =>
                                                    onAllow({
                                                        domain: entry.domain,
                                                        dnsOnly: false,
                                                    })
                                                }
                                            >
                                                Allow
                                            </button>
                                            <button
                                                type="button"
                                                className="btn btn-sm btn-secondary"
                                                aria-label={`Allow ${entry.domain} with subdomains`}
                                                title="Allow this domain and all of its subdomains completely"
                                                disabled={isPending}
                                                onClick={() =>
                                                    onAllow({
                                                        domain: entry.domain,
                                                        dnsOnly: false,
                                                        includeSubdomains: true,
                                                    })
                                                }
                                            >
                                                + Subdomains
                                            </button>
                                            <button
                                                type="button"
                                                className="btn btn-sm btn-secondary"
                                                aria-label={`Allow ${entry.domain} DNS only`}
                                                title="Resolve this name but keep blocking HTTP(S)"
                                                disabled={isPending}
                                                onClick={() =>
                                                    onAllow({ domain: entry.domain, dnsOnly: true })
                                                }
                                            >
                                                DNS only
                                            </button>
                                        </div>
                                    </td>
                                )}
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}

/** Identify a denial by the rule it would create. */
function requestKey(denial: HttpDenial): string {
    return `${denial.domain} ${denial.method} ${denial.pathname}`;
}

/** Color HTTP methods by how much they can change on the server. */
function methodBadge(method: string): string {
    if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
        return "badge-info";
    }
    if (method === "DELETE") {
        return "badge-block";
    }
    return "badge-warn";
}

/** Show the latest denied HTTP requests, each allowable by exact method and path. */
function RequestsTable({
    denials,
    filtered,
    now,
    isPending,
    allowed,
    onAllow,
}: {
    denials: HttpDenial[];
    filtered: boolean;
    now: number;
    isPending: boolean;
    allowed: Record<string, boolean>;
    onAllow: (denial: HttpDenial) => void;
}) {
    if (denials.length === 0) {
        if (filtered) {
            return <EmptyState title="No matching requests" />;
        }
        return (
            <EmptyState title="No blocked requests yet">
                The latest 100 denied HTTP and HTTPS requests appear here, newest first.
            </EmptyState>
        );
    }
    return (
        <div className="relative overflow-x-auto">
            <p className="border-b border-white/5 px-4 py-2 text-xs text-zinc-500">
                The latest 100 denied HTTP(S) requests, newest first. Query strings are not
                recorded; allowing a request matches its exact method and path only.
            </p>
            <table className="w-full text-left text-sm">
                <caption className="sr-only">Blocked requests, latest first</caption>
                <thead className="border-b border-white/10 bg-white/[0.02]">
                    <tr>
                        <th className={headerCell}>Domain</th>
                        <th className={headerCell}>Method</th>
                        <th className={headerCell}>Path</th>
                        <th className={headerCell}>When</th>
                        <th className={`${headerCell} text-right`}>
                            <span className="sr-only">Actions</span>
                        </th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                    {denials.map((denial, index) => {
                        const label = `${denial.domain} ${denial.method} ${denial.pathname}`;
                        return (
                            <tr
                                key={`${denial.timestamp}:${index}`}
                                className="transition hover:bg-white/[0.03]"
                            >
                                <th
                                    scope="row"
                                    className="max-w-[14rem] truncate px-4 py-2.5 font-mono text-[13px] font-medium text-zinc-100"
                                    title={denial.domain}
                                >
                                    {denial.domain}
                                </th>
                                <td className="px-4 py-2.5">
                                    <span
                                        className={`badge font-mono ${methodBadge(denial.method)}`}
                                    >
                                        {denial.method}
                                    </span>
                                </td>
                                <td
                                    className="max-w-md truncate px-4 py-2.5 font-mono text-[13px] text-zinc-300"
                                    title={denial.pathname}
                                >
                                    {denial.pathname}
                                </td>
                                <td className="px-4 py-2.5 text-zinc-400">
                                    <RelativeTime timestamp={denial.timestamp} now={now} />
                                </td>
                                <td className="px-4 py-2">
                                    <div className="flex items-center justify-end gap-1.5">
                                        {allowed[requestKey(denial)] && (
                                            <span className="badge badge-allow">
                                                <CheckIcon className="size-3" />
                                                Allowed
                                            </span>
                                        )}
                                        <button
                                            type="button"
                                            className="btn btn-sm btn-secondary"
                                            aria-label={`Allow ${label}`}
                                            title="Allow exactly this method and path"
                                            disabled={isPending}
                                            onClick={() => onAllow(denial)}
                                        >
                                            Allow request
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}
