import { createContext, useContext, useState, type MouseEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Outlet, useLocation } from "@tanstack/react-router";
import {
    allowDomain,
    allowRequest,
    api,
    coversDomain,
    coversRequest,
    isWebSocket,
    parseRuleLabel,
    resetTraffic,
    rulesPath,
    webRulesFile,
    type AccessLogSettings,
    type DomainAllowance,
    type DomainStats,
    type HttpRequest,
    type RuleDraft,
    type RuleFileContents,
    type RuleLocation,
} from "./api.ts";
import {
    CheckIcon,
    CopyButton,
    EmptyState,
    ErrorBanner,
    FilterInput,
    PageHeader,
    RefreshButton,
    RecordIcon,
    RelativeTime,
    Spinner,
    TrashIcon,
    formatBytes,
    methodBadge,
    useNow,
    useToast,
} from "./components.tsx";
import { CaptureButton, RequestDialog, RequestTiming, WebSocketBadge } from "./capture.tsx";
import { ruleAnchor } from "./rules.tsx";

/**
 * The traffic views selectable from the tab bar, each routed at `/traffic/<view>`;
 * `blocked` and `allowed` list domains.
 */
export type TrafficView = "blocked" | "allowed" | "blocked-requests" | "allowed-requests";

/** Map a `?view=` value from the former single-page Traffic URLs to its routed view. */
export function legacyTrafficView(value: unknown): TrafficView {
    if (value === "allowed" || value === "allowed-requests") {
        return value;
    }
    if (value === "requests") {
        return "blocked-requests";
    }
    return "blocked";
}

/** The number of unique requests the server retains for each outcome. */
const requestCapacity = 200;

/** Query options shared by the manually refreshed traffic queries. */
const manualQuery = {
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    retry: false,
};

/** Find the current position of the first web rule matching `covers`, if any. */
type LocateRule = (covers: (rule: RuleDraft) => boolean) => RuleLocation | undefined;

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

/** An allow action shared by the layout and its views: whether it runs, and how to start it. */
interface AllowAction<T> {
    isPending: boolean;
    mutate: (target: T) => void;
}

/** Traffic data and actions the layout shares with the view in its tab panel. */
interface TrafficState {
    /** Domain counters, absent until loaded. */
    domains: DomainStats[] | undefined;
    /** Recently denied HTTP(S) requests, absent until loaded. */
    denials: HttpRequest[] | undefined;
    /** Recently allowed HTTP(S) requests, absent until loaded. */
    allowances: HttpRequest[] | undefined;
    /** The lowercased filter text; empty when nothing is filtered. */
    needle: string;
    /** The current time for relative timestamps, in milliseconds since the epoch. */
    now: number;
    locateRule: LocateRule;
    /** Domains allowed from this page since it loaded, by domain. */
    allowedDomains: Record<string, DomainAllowance>;
    /** Requests allowed from this page since it loaded, by `requestKey`. */
    allowedRequests: Record<string, boolean>;
    domainAllow: AllowAction<DomainAllowance>;
    requestAllow: AllowAction<HttpRequest>;
}

/** Carries the layout's traffic state to the routed view. */
const TrafficContext = createContext<TrafficState | null>(null);

/** Read the traffic state of the enclosing `TrafficLayout`. */
function useTraffic(): TrafficState {
    const state = useContext(TrafficContext);
    if (!state) {
        throw new Error("Traffic views must render inside TrafficLayout");
    }
    return state;
}

/**
 * Show traffic counters, the view tabs, and the access log note around the routed
 * view, which shares this layout's data, filter, and one-click allow actions.
 */
export function TrafficLayout() {
    const client = useQueryClient();
    const toast = useToast();
    const now = useNow();
    const pathname = useLocation({ select: (location) => location.pathname });
    const [filter, setFilter] = useState("");
    const [allowedDomains, setAllowedDomains] = useState<Record<string, DomainAllowance>>({});
    const [allowedRequests, setAllowedRequests] = useState<Record<string, boolean>>({});
    // Rules shift as others are added, so links look up their rule in the current file.
    const webRules = useQuery({
        queryKey: ["rules", webRulesFile],
        queryFn: () => api<RuleFileContents>(rulesPath(webRulesFile)),
        enabled: Object.keys(allowedDomains).length + Object.keys(allowedRequests).length > 0,
        ...manualQuery,
    });
    const locateRule: LocateRule = (covers) => {
        const position = webRules.data?.rules?.findIndex(covers) ?? -1;
        return position === -1 ? undefined : { file: webRulesFile, rule: position + 1 };
    };
    const domains = useQuery({
        queryKey: ["domains"],
        queryFn: () => api<DomainStats[]>("domains"),
        ...manualQuery,
    });
    const denials = useQuery({
        queryKey: ["http-denials"],
        queryFn: () => api<HttpRequest[]>("http-denials"),
        ...manualQuery,
    });
    const allowances = useQuery({
        queryKey: ["http-allowances"],
        queryFn: () => api<HttpRequest[]>("http-allowances"),
        ...manualQuery,
    });
    const domainAllow = useMutation({
        mutationFn: allowDomain,
        onSuccess: async (document, allowance) => {
            client.setQueryData(["rules", webRulesFile], document);
            setAllowedDomains((previous) => ({ ...previous, [allowance.domain]: allowance }));
            toast(allowanceMessage(allowance));
            await client.invalidateQueries({ queryKey: ["rules"] });
        },
    });
    const requestAllow = useMutation({
        mutationFn: allowRequest,
        onSuccess: async (document, request) => {
            client.setQueryData(["rules", webRulesFile], document);
            setAllowedRequests((previous) => ({ ...previous, [requestKey(request)]: true }));
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
            await Promise.all([domains.refetch(), denials.refetch(), allowances.refetch()]);
        },
    });
    const refreshing = domains.isFetching || denials.isFetching || allowances.isFetching;
    const tabs: { id: TrafficView; label: string; count: number | undefined }[] = [
        {
            id: "blocked",
            label: "Blocked domains",
            count: domains.data && domainEntries(domains.data, "block").length,
        },
        {
            id: "allowed",
            label: "Allowed domains",
            count: domains.data && domainEntries(domains.data, "allow").length,
        },
        { id: "blocked-requests", label: "Blocked requests", count: denials.data?.length },
        { id: "allowed-requests", label: "Allowed requests", count: allowances.data?.length },
    ];
    const view = tabs.find((tab) => pathname === `/traffic/${tab.id}`)?.id;
    const updatedAt = Math.max(
        domains.dataUpdatedAt,
        denials.dataUpdatedAt,
        allowances.dataUpdatedAt,
    );
    const actionError = domainAllow.error ?? requestAllow.error ?? reset.error;
    const loadError = domains.error ?? denials.error ?? allowances.error;
    const state: TrafficState = {
        domains: domains.data,
        denials: denials.data,
        allowances: allowances.data,
        needle: filter.trim().toLowerCase(),
        now,
        locateRule,
        allowedDomains,
        allowedRequests,
        domainAllow,
        requestAllow,
    };
    return (
        <>
            <PageHeader
                title="Traffic"
                description="DNS lookups and HTTP(S) requests checked since exwall started or the last reset. Counters live in memory and reset on restart."
                refresh={
                    <RefreshButton
                        busy={refreshing}
                        updatedAt={updatedAt}
                        onClick={() => {
                            void domains.refetch();
                            void denials.refetch();
                            void allowances.refetch();
                        }}
                    />
                }
                actions={
                    <>
                        <CaptureButton />
                        <button
                            type="button"
                            className="btn btn-secondary"
                            title="Clear all domain counters, transferred bytes, and recorded requests"
                            disabled={reset.isPending}
                            onClick={() => {
                                if (
                                    window.confirm(
                                        "Reset all traffic counters, transferred bytes, and recorded requests?",
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
            <StatTiles domains={domains.data} view={view} />
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
                                <Link
                                    key={tab.id}
                                    id={`tab-${tab.id}`}
                                    to={`/traffic/${tab.id}`}
                                    role="tab"
                                    aria-selected={selected}
                                    aria-controls="traffic-panel"
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
                                </Link>
                            );
                        })}
                    </div>
                    <div className="w-full pb-2 sm:w-auto">
                        <FilterInput
                            label="Filter"
                            placeholder={
                                view === "blocked-requests" || view === "allowed-requests"
                                    ? "Filter domains or paths"
                                    : "Filter domains"
                            }
                            value={filter}
                            onChange={setFilter}
                        />
                    </div>
                </div>
                <div
                    role="tabpanel"
                    id="traffic-panel"
                    aria-labelledby={view === undefined ? undefined : `tab-${view}`}
                >
                    <TrafficContext value={state}>
                        <Outlet />
                    </TrafficContext>
                </div>
            </div>
            <AccessLogNote />
        </>
    );
}

/** The access log's column header line, as documented for operators. */
const accessLogColumns =
    "TIMESTAMP PROTOCOL RESULT RULE HTTP_METHOD URL HTTP_STATUS DNS_RCODE ERROR";

/** Sample access-log lines illustrating an allowed request, a denial, and merged repeats. */
const accessLogExample = [
    "2026-10-07T12:34:56Z https ALLOW /etc/exwall/rules.d/10-examples.toml:allow#1 GET https://github.com:443/api 200 - -",
    "2026-10-07T12:34:57Z http DENY - POST http://denied.test/upload?id=7 403 - -",
    "2026-10-07T12:34:58Z dns DENY - - dns://denied.test/A - REFUSED - x3",
].join("\n");

/**
 * Point to the full access log on the host, with a button copying its path, and
 * explain how the file is trimmed and how its lines are formatted.
 */
function AccessLogNote() {
    // The settings are fixed until the service restarts.
    const settings = useQuery({
        queryKey: ["access-log"],
        queryFn: () => api<AccessLogSettings>("access-log"),
        staleTime: Infinity,
        ...manualQuery,
    });
    if (!settings.data) {
        return null;
    }
    const { path, check_interval, max_size_bytes, keep_size_bytes } = settings.data;
    return (
        <section
            aria-labelledby="access-log-heading"
            className="panel mt-6 space-y-3 p-4 text-sm text-zinc-400"
        >
            <h2 id="access-log-heading" className="font-medium text-zinc-200">
                Full access log
            </h2>
            <p>
                This page keeps counters and only the {requestCapacity} most recently seen requests
                of each outcome, in memory. Every DNS query and HTTP(S) request is also written, one
                line each, to the access log on this host, which is kept across restarts and
                readable with sudo:
            </p>
            <div className="flex min-w-0 items-center gap-1">
                <code className="truncate font-mono text-[13px] text-zinc-100" title={path}>
                    {path}
                </code>
                <CopyButton text={path} label={`Copy path ${path}`} />
            </div>
            <p>
                After every {check_interval.toLocaleString()} lines, exwall checks the file size.
                Once it is over {formatBytes(max_size_bytes)}, the oldest lines are removed so that
                about {formatBytes(keep_size_bytes)} of the newest lines remain.
            </p>
            <p>
                Each line has these space-separated columns, with <code>-</code> for an empty one:
            </p>
            <pre className="overflow-x-auto rounded-md bg-black/30 px-3 py-2 font-mono text-xs text-zinc-300">
                {`${accessLogColumns}\n${accessLogExample}`}
            </pre>
            <p>
                <code>RULE</code> is the rule file and number that allowed the request, or{" "}
                <code>@paused</code> while blocking was paused. Identical lines within one second
                are merged into the first, with a trailing count such as <code>x3</code>; lines that
                differ in any column, including the URL's query string, stay separate. A WebSocket
                is logged once, when it closes, with the time it opened.
            </p>
        </section>
    );
}

/** The placeholder shown in the tab panel until its traffic data loads. */
function TrafficLoading() {
    return (
        <p role="status" className="flex items-center gap-2 px-4 py-10 text-sm text-zinc-400">
            <Spinner /> Loading traffic…
        </p>
    );
}

/** The routed tab listing domains with one outcome, filtered by the layout's filter text. */
export function DomainsView({ outcome }: { outcome: "allow" | "block" }) {
    const traffic = useTraffic();
    if (!traffic.domains) {
        return <TrafficLoading />;
    }
    const entries = domainEntries(traffic.domains, outcome);
    return (
        <DomainsTable
            outcome={outcome}
            entries={entries.filter(({ entry }) =>
                entry.domain.toLowerCase().includes(traffic.needle),
            )}
            filtered={traffic.needle !== "" && entries.length > 0}
            now={traffic.now}
            isPending={traffic.domainAllow.isPending}
            allowed={traffic.allowedDomains}
            locateRule={traffic.locateRule}
            onAllow={traffic.domainAllow.mutate}
        />
    );
}

/** The routed tab listing recent requests with one outcome, filtered by domain or path. */
export function RequestsView({ outcome }: { outcome: "allow" | "block" }) {
    const traffic = useTraffic();
    const requests = outcome === "block" ? traffic.denials : traffic.allowances;
    if (!requests) {
        return <TrafficLoading />;
    }
    return (
        <RequestsTable
            outcome={outcome}
            requests={requests.filter(
                (request) =>
                    request.domain.toLowerCase().includes(traffic.needle) ||
                    requestPath(request).toLowerCase().includes(traffic.needle),
            )}
            filtered={traffic.needle !== "" && requests.length > 0}
            now={traffic.now}
            isPending={traffic.requestAllow.isPending}
            allowed={traffic.allowedRequests}
            locateRule={traffic.locateRule}
            onAllow={traffic.requestAllow.mutate}
        />
    );
}

/** A headline number, optionally linked to the traffic view that lists its entries. */
interface StatTile {
    label: string;
    value: number | undefined;
    dot: string;
    hint: string;
    view?: TrafficView;
}

/** Summarize domain counters as a row of headline numbers that open their related tabs. */
function StatTiles({
    domains,
    view,
}: {
    domains: DomainStats[] | undefined;
    /** The routed view, highlighting the tile that opens it. */
    view: TrafficView | undefined;
}) {
    const sum = (pick: (entry: DomainStats) => number) =>
        domains?.reduce((total, entry) => total + pick(entry), 0);
    const tiles: StatTile[] = [
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
            view: "blocked",
        },
        {
            label: "Blocked",
            value: sum((entry) => entry.dns.block + entry.http.block),
            dot: "bg-rose-400",
            hint: "DNS lookups and HTTP requests",
            view: "blocked-requests",
        },
        {
            label: "Allowed",
            value: sum((entry) => entry.dns.allow + entry.http.allow),
            dot: "bg-emerald-400",
            hint: "DNS lookups and HTTP requests",
            view: "allowed-requests",
        },
    ];
    return (
        <dl className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
            {tiles.map((tile) => {
                const selected = tile.view !== undefined && tile.view === view;
                return (
                    <div
                        key={tile.label}
                        className={`panel relative px-4 py-3 transition ${
                            tile.view === undefined
                                ? ""
                                : "has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-emerald-400/60 hover:border-white/20 hover:bg-white/[0.03]"
                        } ${selected ? "border-white/20" : ""}`}
                    >
                        <dt className="flex items-center gap-2 text-xs font-medium text-zinc-400">
                            <span
                                className={`size-1.5 rounded-full ${tile.dot}`}
                                aria-hidden="true"
                            />
                            {tile.view === undefined ? (
                                tile.label
                            ) : (
                                <Link
                                    to={`/traffic/${tile.view}`}
                                    aria-current={selected ? "page" : undefined}
                                    className="after:absolute after:inset-0 after:rounded-[inherit] focus-visible:outline-none"
                                >
                                    {tile.label}
                                </Link>
                            )}
                        </dt>
                        <dd className="mt-1 text-2xl font-semibold text-white tabular-nums">
                            {tile.value === undefined ? "–" : tile.value.toLocaleString()}
                        </dd>
                        <dd className="text-xs text-zinc-500">{tile.hint}</dd>
                    </div>
                );
            })}
        </dl>
    );
}

/** Shared header cell styling for traffic tables. */
const headerCell = "px-4 py-2.5 text-xs font-medium tracking-wide text-zinc-500 uppercase";

/** Show domains with one outcome, with allow actions that link to the rule they add. */
function DomainsTable({
    outcome,
    entries,
    filtered,
    now,
    isPending,
    allowed,
    locateRule,
    onAllow,
}: {
    outcome: "allow" | "block";
    entries: DomainEntry[];
    filtered: boolean;
    now: number;
    isPending: boolean;
    allowed: Record<string, DomainAllowance>;
    locateRule: LocateRule;
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
                Domains appear here when a DNS lookup or HTTP request is denied. Use the refresh
                button to load new activity.
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
                        <th className={`${headerCell} text-right`}>
                            <span className="sr-only">Actions</span>
                        </th>
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
                                <td className="px-4 py-2">
                                    <DomainActions
                                        domain={entry.domain}
                                        done={done}
                                        location={done && locateRule(coversDomain(done))}
                                        isPending={isPending}
                                        onAllow={onAllow}
                                    />
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}

/** Link to a rule in its file's editor, which opens the rule and scrolls to it. */
function RuleLink({
    location,
    className,
    title,
    children,
}: {
    location: RuleLocation;
    className: string;
    title: string;
    children: ReactNode;
}) {
    return (
        <Link
            to="/rules/$file"
            params={{ file: location.file }}
            hash={ruleAnchor(location.rule)}
            className={className}
            title={title}
        >
            {children}
        </Link>
    );
}

/**
 * Confirm a completed allow action, linking to the rule that now allows the traffic while
 * that rule is still in the web rules file.
 */
function AllowedBadge({ location, label }: { location: RuleLocation | undefined; label: string }) {
    const className = "badge badge-allow mr-1 whitespace-nowrap";
    if (location === undefined) {
        return (
            <span className={className}>
                <CheckIcon className="size-3" />
                {label}
            </span>
        );
    }
    return (
        <RuleLink
            location={location}
            className={`${className} transition hover:brightness-125`}
            title={`Open rule #${location.rule} in ${location.file}`}
        >
            <CheckIcon className="size-3" />
            {label} · rule #{location.rule}
        </RuleLink>
    );
}

/** Offer every way to allow a domain, linking to the rule once one is added. */
function DomainActions({
    domain,
    done,
    location,
    isPending,
    onAllow,
}: {
    domain: string;
    /** The latest allow action completed for this domain. */
    done: DomainAllowance | undefined;
    /** The rule that action added or found. */
    location: RuleLocation | undefined;
    isPending: boolean;
    onAllow: (allowance: DomainAllowance) => void;
}) {
    return (
        <div className="flex items-center justify-end gap-1.5">
            {done && <AllowedBadge location={location} label={allowanceLabel(done)} />}
            <button
                type="button"
                className="btn btn-sm btn-primary"
                aria-label={`Allow ${domain} completely`}
                title="Allow DNS and every HTTP(S) method and path"
                disabled={isPending}
                onClick={() => onAllow({ domain, dnsOnly: false })}
            >
                Allow
            </button>
            <button
                type="button"
                className="btn btn-sm btn-secondary"
                aria-label={`Allow ${domain} with subdomains`}
                title="Allow this domain and all of its subdomains completely"
                disabled={isPending}
                onClick={() => onAllow({ domain, dnsOnly: false, includeSubdomains: true })}
            >
                + Subdomains
            </button>
            <button
                type="button"
                className="btn btn-sm btn-secondary"
                aria-label={`Allow ${domain} DNS only`}
                title="Resolve this name but keep blocking HTTP(S)"
                disabled={isPending}
                onClick={() => onAllow({ domain, dnsOnly: true })}
            >
                DNS only
            </button>
        </div>
    );
}

/** Show a request's pathname with its query string, if any. */
function requestPath(request: HttpRequest): string {
    return request.query === undefined ? request.pathname : `${request.pathname}?${request.query}`;
}

/** Identify a request by the rule allowing it would create, which ignores the query string. */
function requestKey(request: HttpRequest): string {
    return `${request.domain} ${request.method} ${request.pathname}`;
}

/**
 * Show what allowed a request: a link to the matching rule, shortened to its file name and
 * number, or an exception label such as `@paused`.
 */
function RuleSource({ rule }: { rule: string | undefined }) {
    if (rule === undefined) {
        return "–";
    }
    const location = parseRuleLabel(rule);
    if (location === null) {
        return <span title={rule}>{rule}</span>;
    }
    return (
        <RuleLink
            location={location}
            className="text-zinc-300 underline decoration-white/20 underline-offset-2 transition hover:text-white hover:decoration-white/60"
            title={`Open ${rule}`}
        >
            {location.file}:allow#{location.rule}
        </RuleLink>
    );
}

/** Identify a retained request row, whose repeats are grouped by scheme, port, and query string too. */
function rowKey(request: HttpRequest): string {
    const port = request.port ?? "";
    return `${request.scheme} ${request.domain} ${port} ${request.method} ${requestPath(request)}`;
}

/** Report whether a click landed on a link or button rather than on the row itself. */
function isControlClick(event: MouseEvent): boolean {
    return event.target instanceof Element && event.target.closest("a, button") !== null;
}

/**
 * Show the most recently seen unique HTTP requests with one outcome and how often each repeated.
 * Each can be allowed by exact method and path, which also keeps requests made while blocking is
 * paused allowed afterwards; allowed requests also show what allowed them. Clicking a request
 * opens a dialog with its decoded query string and any captured headers and bodies.
 */
function RequestsTable({
    outcome,
    requests,
    filtered,
    now,
    isPending,
    allowed,
    locateRule,
    onAllow,
}: {
    outcome: "allow" | "block";
    requests: HttpRequest[];
    filtered: boolean;
    now: number;
    isPending: boolean;
    allowed: Record<string, boolean>;
    locateRule: LocateRule;
    onAllow: (request: HttpRequest) => void;
}) {
    const [selectedKey, setSelectedKey] = useState<string | null>(null);
    const selected = requests.find((request) => rowKey(request) === selectedKey);
    const title = outcome === "allow" ? "Allowed requests" : "Blocked requests";
    const verb = outcome === "allow" ? "allowed" : "denied";
    if (requests.length === 0) {
        if (filtered) {
            return <EmptyState title="No matching requests" />;
        }
        return (
            <EmptyState title={`No ${title.toLowerCase()} yet`}>
                The {requestCapacity} most recently seen {verb} HTTP and HTTPS requests appear here,
                newest first.
            </EmptyState>
        );
    }
    return (
        <div className="relative overflow-x-auto">
            <p className="border-b border-white/5 px-4 py-2 text-xs text-zinc-500">
                The {requestCapacity} most recently seen {verb} HTTP(S) requests, newest first, with
                repeats of the same method, path, and query string counted together. WebSockets are
                marked WS. Requests still waiting for or streaming a response are marked pending.
                Allowing a request adds a rule for its exact method and path, with any query string.
                Click a request to see its details.
            </p>
            <table className="w-full text-left text-sm">
                <caption className="sr-only">{title}, latest first</caption>
                <thead className="border-b border-white/10 bg-white/[0.02]">
                    <tr>
                        <th className={headerCell}>Domain</th>
                        <th className={headerCell}>Method</th>
                        <th className={headerCell}>Path</th>
                        <th
                            className={`${headerCell} text-right`}
                            title="Times seen since first recorded"
                        >
                            Count
                        </th>
                        <th className={headerCell}>{outcome === "allow" ? "Last seen" : "When"}</th>
                        <th
                            className={headerCell}
                            title="How long the latest request took, and whether any are still open"
                        >
                            Duration
                        </th>
                        {outcome === "allow" && <th className={headerCell}>Allowed by</th>}
                        <th className={`${headerCell} text-right`}>
                            <span className="sr-only">Actions</span>
                        </th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                    {requests.map((request) => {
                        const label = requestKey(request);
                        const path = requestPath(request);
                        const done = allowed[label] === true;
                        const key = rowKey(request);
                        return (
                            <tr
                                key={key}
                                className="cursor-pointer transition hover:bg-white/[0.03]"
                                onClick={(event) => {
                                    if (!isControlClick(event)) {
                                        setSelectedKey(key);
                                    }
                                }}
                            >
                                <th
                                    scope="row"
                                    className="max-w-[14rem] truncate px-4 py-2.5 font-mono text-[13px] font-medium text-zinc-100"
                                    title={request.domain}
                                >
                                    {request.domain}
                                </th>
                                <td className="px-4 py-2.5">
                                    <span className="flex items-center gap-1">
                                        <span
                                            className={`badge font-mono ${methodBadge(request.method)}`}
                                        >
                                            {request.method}
                                        </span>
                                        {isWebSocket(request) && <WebSocketBadge />}
                                    </span>
                                </td>
                                <td className="max-w-md px-4 py-2.5 font-mono text-[13px] text-zinc-300">
                                    <span className="flex min-w-0 items-center gap-1.5">
                                        <button
                                            type="button"
                                            className="truncate text-left hover:text-white focus-visible:underline focus-visible:outline-none"
                                            aria-label={`Show details of ${request.method} ${request.domain}${path}`}
                                            title={path}
                                            onClick={() => setSelectedKey(key)}
                                        >
                                            {request.pathname}
                                            {request.query !== undefined && (
                                                <span className="text-zinc-500">
                                                    ?{request.query}
                                                </span>
                                            )}
                                        </button>
                                        {request.capture_id !== undefined && (
                                            <span
                                                className="shrink-0 text-sky-300"
                                                title="Headers and bodies captured"
                                            >
                                                <RecordIcon className="size-3.5" />
                                                <span className="sr-only">
                                                    Headers and bodies captured
                                                </span>
                                            </span>
                                        )}
                                    </span>
                                </td>
                                <td className="px-4 py-2.5 text-right text-zinc-300 tabular-nums">
                                    {request.count.toLocaleString()}
                                </td>
                                <td className="px-4 py-2.5 whitespace-nowrap text-zinc-400">
                                    <RelativeTime timestamp={request.timestamp} now={now} />
                                </td>
                                <td className="px-4 py-2.5 text-zinc-400">
                                    <RequestTiming request={request} />
                                </td>
                                {outcome === "allow" && (
                                    <td className="max-w-[14rem] truncate px-4 py-2.5 font-mono text-[13px] text-zinc-400">
                                        <RuleSource rule={request.rule} />
                                    </td>
                                )}
                                <td className="px-4 py-2">
                                    <div className="flex items-center justify-end gap-1.5">
                                        {done && (
                                            <AllowedBadge
                                                location={locateRule(coversRequest(request))}
                                                label="Allowed"
                                            />
                                        )}
                                        <button
                                            type="button"
                                            className="btn btn-sm btn-secondary"
                                            aria-label={`Allow ${label}`}
                                            title="Add a rule allowing exactly this method and path"
                                            disabled={isPending}
                                            onClick={() => onAllow(request)}
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
            {selected && (
                <RequestDialog
                    key={selectedKey}
                    request={selected}
                    outcome={outcome}
                    allowedBy={<RuleSource rule={selected.rule} />}
                    now={now}
                    onClose={() => setSelectedKey(null)}
                />
            )}
        </div>
    );
}
