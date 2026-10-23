import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    api,
    isWebSocket,
    maxBodyLimitKb,
    parseQuery,
    updateCapture,
    type CaptureDetails,
    type CaptureSettings,
    type CapturedBody,
    type CapturedMessage,
    type CapturedWebSocket,
    type HttpRequest,
    type WebSocketMessage,
} from "./api.ts";
import {
    CloseIcon,
    CopyButton,
    ErrorBanner,
    formatDuration,
    RecordIcon,
    RefreshIcon,
    RelativeTime,
    Spinner,
    Switch,
    methodBadge,
    useToast,
} from "./components.tsx";

/** The query caching the capture settings. */
const captureKey = ["capture"];

/** A header button whose popover turns header and body capture on or off and sets its limit. */
export function CaptureButton() {
    const client = useQueryClient();
    const toast = useToast();
    const settings = useQuery({
        queryKey: captureKey,
        queryFn: () => api<CaptureSettings>("capture"),
        refetchOnWindowFocus: false,
    });
    const [open, setOpen] = useState(false);
    const [limit, setLimit] = useState("");
    const container = useRef<HTMLDivElement>(null);
    const limitId = useId();
    const update = useMutation({
        mutationFn: updateCapture,
        onSuccess: (data) => {
            client.setQueryData(captureKey, data);
            setLimit(String(data.body_limit_kb));
            toast(
                data.enabled
                    ? `Capturing headers and up to ${data.body_limit_kb} KB of each body.`
                    : "Header and body capture turned off.",
            );
        },
    });
    useEffect(() => {
        if (!open) {
            return undefined;
        }
        const close = (event: MouseEvent | KeyboardEvent) => {
            if (
                (event instanceof KeyboardEvent && event.key === "Escape") ||
                (event instanceof MouseEvent &&
                    event.target instanceof Node &&
                    !container.current?.contains(event.target))
            ) {
                setOpen(false);
            }
        };
        document.addEventListener("mousedown", close);
        document.addEventListener("keydown", close);
        return () => {
            document.removeEventListener("mousedown", close);
            document.removeEventListener("keydown", close);
        };
    }, [open]);
    const current = settings.data;
    const parsedLimit = Number(limit);
    const validLimit =
        Number.isInteger(parsedLimit) && parsedLimit >= 1 && parsedLimit <= maxBodyLimitKb;
    return (
        <div ref={container} className="relative">
            <button
                type="button"
                className={
                    current?.enabled
                        ? "btn btn-secondary border-sky-400/30 text-sky-200"
                        : "btn btn-secondary"
                }
                aria-expanded={open}
                aria-controls="capture-settings"
                disabled={current === undefined}
                onClick={() => {
                    update.reset();
                    if (current) {
                        setLimit(String(current.body_limit_kb));
                    }
                    setOpen((previous) => !previous);
                }}
            >
                <RecordIcon className={current?.enabled ? "size-4 text-sky-300" : "size-4"} />
                {current?.enabled ? `Capturing · ${current.body_limit_kb} KB` : "Capture"}
            </button>
            {settings.error && (
                <div className="absolute left-0 z-40 mt-2 w-72">
                    <ErrorBanner>{settings.error.message}</ErrorBanner>
                </div>
            )}
            {open && current && (
                <form
                    id="capture-settings"
                    className="panel absolute left-0 z-40 mt-2 w-80 bg-zinc-900 p-4 shadow-2xl shadow-black/50"
                    onSubmit={(event) => {
                        event.preventDefault();
                        if (validLimit) {
                            update.mutate({ enabled: current.enabled, body_limit_kb: parsedLimit });
                        }
                    }}
                >
                    <Switch
                        label="Capture headers and bodies"
                        title="Capture headers and bodies"
                        description="Record request and response headers and bodies of new HTTP(S) requests, and WebSocket messages."
                        checked={current.enabled}
                        disabled={update.isPending || !validLimit}
                        onChange={(enabled) =>
                            update.mutate({ enabled, body_limit_kb: parsedLimit })
                        }
                    />
                    <div className="mt-4">
                        <label className="field-label" htmlFor={limitId}>
                            Max body size (KB)
                        </label>
                        <div className="flex gap-2">
                            <input
                                id={limitId}
                                className="input"
                                type="number"
                                inputMode="numeric"
                                min={1}
                                max={maxBodyLimitKb}
                                step={1}
                                required
                                value={limit}
                                onChange={(event) => setLimit(event.target.value)}
                            />
                            <button
                                type="submit"
                                className="btn btn-secondary"
                                disabled={
                                    !validLimit ||
                                    update.isPending ||
                                    parsedLimit === current.body_limit_kb
                                }
                            >
                                {update.isPending && <Spinner />}
                                Save
                            </button>
                        </div>
                    </div>
                    <p className="field-hint">
                        Longer bodies are truncated to this size. Captures stay in memory with the
                        request lists until Reset or restart, and capturing turns off when exwall
                        restarts. Headers and bodies can contain credentials.
                    </p>
                    {update.error && (
                        <div className="mt-3">
                            <ErrorBanner>{update.error.message}</ErrorBanner>
                        </div>
                    )}
                </form>
            )}
        </div>
    );
}

/** A section heading inside the request dialog. */
function SectionTitle({ children, actions }: { children: ReactNode; actions?: ReactNode }) {
    return (
        <div className="mb-2 flex min-h-7 items-center justify-between gap-2">
            <h3 className="text-xs font-medium tracking-wide text-zinc-400 uppercase">
                {children}
            </h3>
            {actions}
        </div>
    );
}

/** Name and value pairs, each with buttons copying the name and the value separately. */
function PairTable({
    caption,
    kind,
    pairs,
}: {
    /** The accessible table caption. */
    caption: string;
    /** What the pairs are, used in copy button labels, such as "request header". */
    kind: string;
    pairs: { name: string; value: string }[];
}) {
    return (
        <div className="overflow-x-auto rounded-lg border border-white/10">
            <table className="w-full text-left font-mono text-[13px]">
                <caption className="sr-only">{caption}</caption>
                <tbody className="divide-y divide-white/5">
                    {pairs.map(({ name, value }, index) => (
                        <tr key={`${index}:${name}`} className="align-top">
                            <th
                                scope="row"
                                className="w-0 py-1 pr-2 pl-3 font-medium whitespace-nowrap text-sky-200"
                            >
                                <span className="flex items-center gap-1">
                                    {name}
                                    <CopyButton text={name} label={`Copy ${kind} name ${name}`} />
                                </span>
                            </th>
                            <td className="py-1 pr-3 pl-2 break-all text-zinc-200">
                                <span className="flex items-start justify-between gap-1">
                                    <span className="py-1">{value}</span>
                                    <CopyButton
                                        text={value}
                                        label={`Copy ${kind} value of ${name}`}
                                    />
                                </span>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

/** Format a byte count with digit grouping. */
function bytes(count: number): string {
    return `${count.toLocaleString()} byte${count === 1 ? "" : "s"}`;
}

/** Explain how much of a body was captured and why any of it is missing. */
function bodyNotes(body: CapturedBody, limitKb: number): string[] {
    const notes: string[] = [];
    if (body.truncated && body.complete) {
        notes.push(
            `Truncated at the ${limitKb} KB capture limit: showing the first ${bytes(body.captured)} of ${bytes(body.size)}.`,
        );
    } else if (body.truncated) {
        notes.push(
            `Truncated at the ${limitKb} KB capture limit: showing the first ${bytes(body.captured)}. The body was not read to its end.`,
        );
    } else if (!body.complete) {
        notes.push(`The body ended early after ${bytes(body.size)}.`);
    }
    if (body.encoding && body.decoded) {
        notes.push(`Decoded from ${body.encoding}.`);
    } else if (body.encoding) {
        notes.push(`Encoded as ${body.encoding}, which is shown undecoded.`);
    }
    return notes;
}

/** Pretty-print JSON text, or return null when it is not complete JSON. */
function prettyJson(text: string): string | null {
    const trimmed = text.trim();
    if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
        return null;
    }
    try {
        return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
        return null;
    }
}

/** Show a captured body with notes on truncation and encoding. */
function BodyView({
    side,
    body,
    limitKb,
}: {
    side: "request" | "response";
    body: CapturedBody | null;
    limitKb: number;
}) {
    if (body === null) {
        return <p className="text-sm text-zinc-500">The body is still being transferred.</p>;
    }
    if (body.size === 0 && body.complete) {
        return <p className="text-sm text-zinc-500">No body.</p>;
    }
    const notes = bodyNotes(body, limitKb);
    const pretty = body.text === undefined ? null : prettyJson(body.text);
    return (
        <div>
            {notes.map((note) => (
                <p key={note} className="mb-2 text-xs text-amber-200/90">
                    {note}
                </p>
            ))}
            {body.text === undefined ? (
                <p className="text-sm text-zinc-500">
                    Binary content ({bytes(body.captured)} captured) is not shown.
                </p>
            ) : (
                <div className="relative">
                    <div className="absolute top-1 right-1 flex items-center gap-1">
                        {pretty !== null && <span className="badge badge-neutral">JSON</span>}
                        <CopyButton text={body.text} label={`Copy ${side} body`} />
                    </div>
                    <pre
                        aria-label={`${side === "request" ? "Request" : "Response"} body`}
                        className="max-h-[32rem] overflow-auto rounded-lg border border-white/10 bg-black/30 p-3 pr-20 font-mono text-[13px] break-all whitespace-pre-wrap text-zinc-200"
                    >
                        {pretty ?? body.text}
                    </pre>
                </div>
            )}
        </div>
    );
}

/** Show one captured request or response: its headers and, unless it opened a WebSocket, its body. */
function MessageView({
    side,
    message,
    limitKb,
    showBody = true,
}: {
    side: "request" | "response";
    message: CapturedMessage;
    limitKb: number;
    /** Whether to show the body; a WebSocket handshake shows its messages instead. */
    showBody?: boolean;
}) {
    return (
        <>
            <SectionTitle>Headers</SectionTitle>
            {message.headers.length === 0 ? (
                <p className="text-sm text-zinc-500">No headers.</p>
            ) : (
                <PairTable
                    caption={`${side === "request" ? "Request" : "Response"} headers`}
                    kind={`${side} header`}
                    pairs={message.headers}
                />
            )}
            {showBody && (
                <div className="mt-5">
                    <SectionTitle>Body</SectionTitle>
                    <BodyView side={side} body={message.body} limitKb={limitKb} />
                </div>
            )}
        </>
    );
}

/** Describe whether a WebSocket is open, or how and when it ended. */
function webSocketState(websocket: CapturedWebSocket): string {
    const ended = websocket.ended;
    if (ended === null) {
        return "Open";
    }
    const after = `after ${formatDuration(ended.duration_ms)}`;
    if (ended.failure !== null) {
        return `Ended ${after}: ${ended.failure}`;
    }
    if (ended.closed_by !== null) {
        return `Closed by the ${ended.closed_by} ${after}`;
    }
    return `Ended ${after}`;
}

/** Group hexadecimal digits into bytes separated by spaces. */
function spacedHex(hex: string): string {
    return hex.replace(/(..)(?!$)/g, "$1 ");
}

/** Show the kept payload of one WebSocket message, or its close code and reason. */
function WebSocketPayload({ message }: { message: WebSocketMessage }) {
    if (message.kind === "close") {
        return (
            <span className="text-zinc-300">
                {message.code === undefined ? "No close code" : `Code ${message.code}`}
                {message.text !== undefined && message.text !== "" && `: ${message.text}`}
            </span>
        );
    }
    const content = message.text ?? spacedHex(message.hex ?? "");
    return (
        <>
            {message.captured < message.size && (
                <span className="mb-1 block font-sans text-xs text-amber-200/90">
                    {message.captured === 0
                        ? "Not kept: the capture limit was reached."
                        : `Showing the first ${bytes(message.captured)}.`}
                </span>
            )}
            {content !== "" && (
                <span className="block max-h-48 overflow-auto break-all whitespace-pre-wrap text-zinc-200">
                    {content}
                </span>
            )}
        </>
    );
}

/** List the captured messages of a WebSocket with its totals and state. */
function WebSocketMessages({
    websocket,
    limitKb,
}: {
    websocket: CapturedWebSocket;
    limitKb: number;
}) {
    const kept = (direction: WebSocketMessage["direction"]) =>
        websocket.messages.filter((message) => message.direction === direction).length;
    const limited =
        kept("up") >= websocket.message_limit || kept("down") >= websocket.message_limit;
    const tally = (count: number, size: number) =>
        `${count.toLocaleString()} message${count === 1 ? "" : "s"} (${bytes(size)})`;
    return (
        <section aria-label="WebSocket messages" className="mt-6">
            <SectionTitle>Messages</SectionTitle>
            <p className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-zinc-400">
                <span
                    className={`badge ${websocket.ended === null ? "badge-allow" : "badge-neutral"}`}
                >
                    {webSocketState(websocket)}
                </span>
                <span>Client sent {tally(websocket.up.messages, websocket.up.bytes)}</span>
                <span>Server sent {tally(websocket.down.messages, websocket.down.bytes)}</span>
            </p>
            {limited && (
                <p className="mb-2 text-xs text-amber-200/90">
                    Only the first {websocket.message_limit} messages in each direction are kept.
                </p>
            )}
            <p className="mb-2 text-xs text-zinc-500">
                Messages are shown decoded, with up to {limitKb} KB of content kept in each
                direction. Pings and pongs are not listed.
            </p>
            {websocket.messages.length === 0 ? (
                <p className="text-sm text-zinc-500">No messages yet.</p>
            ) : (
                <div className="overflow-x-auto rounded-lg border border-white/10">
                    <table className="w-full text-left text-[13px]">
                        <caption className="sr-only">WebSocket messages</caption>
                        <thead className="border-b border-white/10 bg-white/[0.02] text-xs text-zinc-400">
                            <tr>
                                <th className="px-3 py-1.5 font-medium">Time</th>
                                <th className="px-3 py-1.5 font-medium">Direction</th>
                                <th className="px-3 py-1.5 font-medium">Type</th>
                                <th className="px-3 py-1.5 text-right font-medium">Size</th>
                                <th className="px-3 py-1.5 font-medium">Content</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-white/5">
                            {websocket.messages.map((message, index) => (
                                <tr key={index} className="align-top">
                                    <td className="px-3 py-1.5 whitespace-nowrap text-zinc-500 tabular-nums">
                                        +{formatDuration(message.at_ms)}
                                    </td>
                                    <td
                                        className={`px-3 py-1.5 whitespace-nowrap ${message.direction === "up" ? "text-sky-300" : "text-emerald-300"}`}
                                    >
                                        {message.direction === "up"
                                            ? "Client → server"
                                            : "Server → client"}
                                    </td>
                                    <td className="px-3 py-1.5">
                                        <span className="badge badge-neutral">{message.kind}</span>
                                    </td>
                                    <td className="px-3 py-1.5 text-right whitespace-nowrap text-zinc-400 tabular-nums">
                                        {bytes(message.size)}
                                    </td>
                                    <td className="min-w-[16rem] px-3 py-1.5 font-mono">
                                        <WebSocketPayload message={message} />
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    );
}

/** Load and show the captured headers and bodies of a request and its response. */
function CapturedExchange({ id, now }: { id: number; now: number }) {
    const details = useQuery({
        queryKey: ["captures", id],
        queryFn: () => api<CaptureDetails>(`captures/${id}`),
        refetchOnWindowFocus: false,
        retry: false,
    });
    if (details.error) {
        return <ErrorBanner>{details.error.message}</ErrorBanner>;
    }
    if (!details.data) {
        return (
            <p role="status" className="flex items-center gap-2 text-sm text-zinc-400">
                <Spinner /> Loading captured request…
            </p>
        );
    }
    const capture = details.data;
    const limitKb = capture.body_limit / 1024;
    const status = capture.response?.status;
    const websocket = capture.websocket;
    const showBody = websocket === undefined;
    return (
        <>
            <div className="mb-4 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-zinc-500">
                <span>
                    Captured <RelativeTime timestamp={capture.timestamp} now={now} />
                </span>
                <span>Body limit {limitKb} KB</span>
                <span className="ml-auto">
                    <button
                        type="button"
                        className="btn btn-sm btn-ghost"
                        disabled={details.isFetching}
                        onClick={() => void details.refetch()}
                    >
                        {details.isFetching ? (
                            <Spinner className="size-3.5" />
                        ) : (
                            <RefreshIcon className="size-3.5" />
                        )}
                        Reload capture
                    </button>
                </span>
            </div>
            <div className="grid gap-6 xl:grid-cols-2">
                <section aria-label="Captured request" className="min-w-0">
                    <h3 className="mb-3 text-sm font-semibold text-white">Request</h3>
                    <MessageView
                        side="request"
                        message={capture.request}
                        limitKb={limitKb}
                        showBody={showBody}
                    />
                </section>
                <section aria-label="Captured response" className="min-w-0">
                    <h3 className="mb-3 flex items-center gap-2 text-sm font-semibold text-white">
                        Response
                        {status !== undefined && (
                            <span
                                className={`badge font-mono ${status < 400 ? "badge-allow" : "badge-block"}`}
                            >
                                {status}
                            </span>
                        )}
                    </h3>
                    {capture.response === null ? (
                        <p className="text-sm text-zinc-500">No response has been received yet.</p>
                    ) : (
                        <MessageView
                            side="response"
                            message={capture.response}
                            limitKb={limitKb}
                            showBody={showBody}
                        />
                    )}
                </section>
            </div>
            {websocket !== undefined && (
                <WebSocketMessages websocket={websocket} limitKb={limitKb} />
            )}
        </>
    );
}

/** Mark a request as a WebSocket handshake. */
export function WebSocketBadge() {
    return (
        <span className="badge badge-neutral font-mono" title="WebSocket">
            WS
        </span>
    );
}

/**
 * Show how long a request's latest repeat took, or has been open so far, and mark requests
 * with repeats still waiting for or streaming a response as pending.
 */
export function RequestTiming({ request }: { request: HttpRequest }) {
    const duration = formatDuration(request.duration_ms);
    const label = request.pending === 1 ? "Pending" : `${request.pending} pending`;
    return (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span
                className="tabular-nums"
                title={
                    request.finished
                        ? "How long the latest request took"
                        : "How long the latest request had been open when refreshed"
                }
            >
                {request.finished ? duration : `${duration}…`}
            </span>
            {request.pending > 0 && (
                <span
                    className="badge badge-warn"
                    title="Still waiting for or streaming a response when refreshed"
                >
                    <span className="size-1.5 animate-pulse rounded-full bg-amber-300" />
                    {label}
                </span>
            )}
        </span>
    );
}

/**
 * A near full-window modal dialog describing one retained request: its URL parts with a
 * decoded query string, and its captured headers and bodies when capture was on.
 */
export function RequestDialog({
    request,
    outcome,
    allowedBy,
    now,
    onClose,
}: {
    request: HttpRequest;
    outcome: "allow" | "block";
    /** What allowed the request, for allowed requests. */
    allowedBy: ReactNode;
    now: number;
    onClose: () => void;
}) {
    const dialog = useRef<HTMLDialogElement>(null);
    const close = useRef<HTMLButtonElement>(null);
    const titleId = useId();
    useEffect(() => {
        dialog.current?.showModal();
        // Opening moves focus to the first control, which would highlight a header action.
        close.current?.focus();
    }, []);
    const query = request.query === undefined ? [] : parseQuery(request.query);
    const target = `${request.pathname}${request.query === undefined ? "" : `?${request.query}`}`;
    // IPv6 addresses are retained bare but need brackets in a URL.
    const host = request.domain.includes(":") ? `[${request.domain}]` : request.domain;
    const authority = request.port === undefined ? host : `${host}:${request.port}`;
    const url = `${request.scheme}://${authority}${target}`;
    return (
        <dialog
            ref={dialog}
            aria-labelledby={titleId}
            onClose={onClose}
            onClick={(event) => {
                if (event.target === dialog.current) {
                    dialog.current.close();
                }
            }}
            className="m-auto h-[calc(100dvh-2rem)] max-h-none w-[calc(100vw-2rem)] max-w-none overflow-hidden rounded-xl border border-white/10 bg-zinc-950 p-0 text-zinc-100 shadow-2xl shadow-black/60 backdrop:bg-black/70 backdrop:backdrop-blur-sm"
        >
            <div className="flex h-full flex-col">
                <header className="flex items-start gap-3 border-b border-white/10 px-5 py-4">
                    <div className="min-w-0 flex-1">
                        <h2
                            id={titleId}
                            className="flex flex-wrap items-center gap-2 text-base font-semibold text-white"
                        >
                            <span className={`badge font-mono ${methodBadge(request.method)}`}>
                                {request.method}
                            </span>
                            {isWebSocket(request) && <WebSocketBadge />}
                            <span className="font-mono break-all">
                                {request.domain}
                                <span className="text-zinc-400">{request.pathname}</span>
                            </span>
                        </h2>
                        <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-zinc-500">
                            <span
                                className={`badge ${outcome === "allow" ? "badge-allow" : "badge-block"}`}
                            >
                                {outcome === "allow" ? "Allowed" : "Blocked"}
                            </span>
                            <span>
                                Seen {request.count.toLocaleString()}{" "}
                                {request.count === 1 ? "time" : "times"}, last{" "}
                                <RelativeTime timestamp={request.timestamp} now={now} />
                            </span>
                            <RequestTiming request={request} />
                            {outcome === "allow" && (
                                <span className="font-mono">Allowed by {allowedBy}</span>
                            )}
                        </p>
                    </div>
                    <CopyButton text={url} label="Copy URL" />
                    <button
                        type="button"
                        className="btn btn-icon btn-ghost"
                        aria-label="Close"
                        title="Close"
                        ref={close}
                        onClick={() => dialog.current?.close()}
                    >
                        <CloseIcon className="size-5" />
                    </button>
                </header>
                <div className="flex-1 overflow-y-auto px-5 py-5">
                    <section aria-label="Query string" className="mb-6">
                        <SectionTitle
                            actions={
                                request.query !== undefined && (
                                    <CopyButton
                                        text={request.query}
                                        label="Copy raw query string"
                                    />
                                )
                            }
                        >
                            Query string
                        </SectionTitle>
                        {request.query === undefined ? (
                            <p className="text-sm text-zinc-500">No query string.</p>
                        ) : (
                            <>
                                <p className="mb-2 font-mono text-xs break-all text-zinc-500">
                                    ?{request.query}
                                </p>
                                {query.length === 0 ? (
                                    <p className="text-sm text-zinc-500">No parameters.</p>
                                ) : (
                                    <PairTable
                                        caption="Decoded query parameters"
                                        kind="query parameter"
                                        pairs={query}
                                    />
                                )}
                            </>
                        )}
                    </section>
                    {request.capture_id === undefined ? (
                        <p className="rounded-lg border border-white/10 bg-white/[0.02] px-4 py-3 text-sm text-zinc-400">
                            {isWebSocket(request)
                                ? "Headers and messages were not captured for this WebSocket."
                                : "Headers and bodies were not captured for this request."}{" "}
                            Turn on Capture at the top of the page, then repeat the request.
                        </p>
                    ) : (
                        <CapturedExchange id={request.capture_id} now={now} />
                    )}
                </div>
            </div>
        </dialog>
    );
}
