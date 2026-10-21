import {
    createContext,
    useCallback,
    useContext,
    useEffect,
    useMemo,
    useState,
    type ReactNode,
} from "react";

/** Shared attributes for the inline stroke icons. */
interface IconProps {
    className?: string;
}

/** Render a 24-unit stroke icon from one or more SVG path definitions. */
function Icon({ paths, className = "size-4" }: IconProps & { paths: string[] }) {
    return (
        <svg
            className={className}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.8}
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
        >
            {paths.map((path) => (
                <path key={path} d={path} />
            ))}
        </svg>
    );
}

/** A shield, used as the product mark. */
export function ShieldIcon(props: IconProps) {
    return (
        <Icon
            {...props}
            paths={[
                "M12 3 4.5 6v5.5c0 4.6 3.2 8.3 7.5 9.5 4.3-1.2 7.5-4.9 7.5-9.5V6z",
                "m9 12 2 2 4-4",
            ]}
        />
    );
}

/** Two circular arrows for refreshing data. */
export function RefreshIcon(props: IconProps) {
    return (
        <Icon
            {...props}
            paths={[
                "M20 11a8 8 0 0 0-14.9-3.5L4 9",
                "M4 4v5h5",
                "M4 13a8 8 0 0 0 14.9 3.5L20 15",
                "M20 20v-5h-5",
            ]}
        />
    );
}

/** A plus sign for adding items. */
export function PlusIcon(props: IconProps) {
    return <Icon {...props} paths={["M12 5v14", "M5 12h14"]} />;
}

/** A trash can for removing items. */
export function TrashIcon(props: IconProps) {
    return (
        <Icon
            {...props}
            paths={["M4 7h16", "M10 11v6", "M14 11v6", "M6 7l1 13h10l1-13", "M9 7V4h6v3"]}
        />
    );
}

/** A downward chevron for disclosure controls. */
export function ChevronIcon(props: IconProps) {
    return <Icon {...props} paths={["m6 9 6 6 6-6"]} />;
}

/** Angle brackets marking source code. */
export function CodeIcon(props: IconProps) {
    return <Icon {...props} paths={["m8 6-6 6 6 6", "m16 6 6 6-6 6"]} />;
}

/** A magnifying glass for filter fields. */
export function SearchIcon(props: IconProps) {
    return <Icon {...props} paths={["M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14", "m20 20-4-4"]} />;
}

/** A check mark for completed actions. */
export function CheckIcon(props: IconProps) {
    return <Icon {...props} paths={["m5 12 5 5L20 7"]} />;
}

/** Two overlapping sheets for copying text. */
export function CopyIcon(props: IconProps) {
    return <Icon {...props} paths={["M9 9h11v11H9z", "M5 15H4V4h11v1"]} />;
}

/** A warning triangle for errors. */
export function AlertIcon(props: IconProps) {
    return <Icon {...props} paths={["M12 4 2.5 20h19z", "M12 10v4", "M12 17h.01"]} />;
}

/** A door with an arrow for signing out. */
export function SignOutIcon(props: IconProps) {
    return <Icon {...props} paths={["M15 4h4v16h-4", "M10 8l-4 4 4 4", "M6 12h10"]} />;
}

/** A pause symbol for temporarily disabling blocking. */
export function PauseIcon(props: IconProps) {
    return <Icon {...props} paths={["M9 5v14", "M15 5v14"]} />;
}

/** A play symbol for resuming blocking. */
export function PlayIcon(props: IconProps) {
    return <Icon {...props} paths={["M7 4.5v15L19 12z"]} />;
}

/** A spinning ring shown while work is in progress. */
export function Spinner({ className = "size-4" }: IconProps) {
    return (
        <svg className={`${className} animate-spin`} viewBox="0 0 24 24" aria-hidden="true">
            <circle
                cx="12"
                cy="12"
                r="9"
                fill="none"
                stroke="currentColor"
                strokeOpacity={0.25}
                strokeWidth={3}
            />
            <path
                d="M21 12a9 9 0 0 0-9-9"
                fill="none"
                stroke="currentColor"
                strokeWidth={3}
                strokeLinecap="round"
            />
        </svg>
    );
}

/** Copy text, falling back to a selection copy where the Clipboard API is unavailable. */
async function copyText(text: string): Promise<void> {
    // The UI is often served over plain HTTP on a LAN address, which is not a secure context.
    if (window.isSecureContext && navigator.clipboard) {
        await navigator.clipboard.writeText(text);
        return;
    }
    const field = document.createElement("textarea");
    field.value = text;
    field.readOnly = true;
    field.style.position = "fixed";
    field.style.opacity = "0";
    document.body.append(field);
    field.select();
    const copied = document.execCommand("copy");
    field.remove();
    if (!copied) {
        throw new Error("Copy failed");
    }
}

/** An icon button that copies text and briefly confirms the result. */
export function CopyButton({ text, label }: { text: string; label: string }) {
    const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
    useEffect(() => {
        if (state === "idle") {
            return undefined;
        }
        const timer = window.setTimeout(() => setState("idle"), 2000);
        return () => window.clearTimeout(timer);
    }, [state]);
    let title = label;
    if (state === "copied") {
        title = "Copied";
    } else if (state === "failed") {
        title = "Copy failed";
    }
    return (
        <button
            type="button"
            className={`btn btn-icon btn-ghost shrink-0 ${state === "failed" ? "text-rose-300" : ""}`}
            aria-label={label}
            title={title}
            onClick={() => {
                copyText(text).then(
                    () => setState("copied"),
                    () => setState("failed"),
                );
            }}
        >
            {state === "copied" ? (
                <CheckIcon className="size-3.5 text-emerald-400" />
            ) : (
                <CopyIcon className="size-3.5" />
            )}
        </button>
    );
}

/** A host file path in monospace with a button that copies it. */
export function FilePath({ path }: { path: string }) {
    return (
        <span className="flex min-w-0 items-center gap-1">
            <code className="truncate font-mono text-xs text-zinc-500" title={path}>
                {path}
            </code>
            <CopyButton text={path} label={`Copy path ${path}`} />
        </span>
    );
}

/** A page title with an optional description and right-aligned actions. */
export function PageHeader({
    title,
    description,
    actions,
}: {
    title: string;
    description: ReactNode;
    actions?: ReactNode;
}) {
    return (
        <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
            <div className="min-w-0">
                <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
                <p className="mt-1 max-w-2xl text-sm text-zinc-400">{description}</p>
            </div>
            {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
    );
}

/** A centered placeholder for lists without entries. */
export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
    return (
        <div className="flex flex-col items-center px-6 py-14 text-center">
            <div className="mb-3 rounded-full bg-white/5 p-3 text-zinc-500">
                <ShieldIcon className="size-6" />
            </div>
            <p className="font-medium text-zinc-200">{title}</p>
            {children && <p className="mt-1 max-w-sm text-sm text-zinc-500">{children}</p>}
        </div>
    );
}

/** An inline error banner announced to assistive technology. */
export function ErrorBanner({ children }: { children: ReactNode }) {
    return (
        <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
            <AlertIcon className="mt-0.5 size-4 shrink-0 text-rose-400" />
            <p role="alert">{children}</p>
        </div>
    );
}

/** A text input with a leading search icon. */
export function FilterInput({
    label,
    value,
    onChange,
    placeholder,
}: {
    label: string;
    value: string;
    onChange: (value: string) => void;
    placeholder: string;
}) {
    return (
        <div className="relative w-full sm:w-64">
            <SearchIcon className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-zinc-500" />
            <input
                type="search"
                className="input py-1.5 pl-8"
                aria-label={label}
                placeholder={placeholder}
                value={value}
                onChange={(event) => onChange(event.target.value)}
            />
        </div>
    );
}

/** One option of a segmented control. */
export interface SegmentOption<T extends string> {
    value: T;
    label: string;
}

/** A compact single-choice control exposed as a radio group. */
export function Segmented<T extends string>({
    label,
    value,
    options,
    onChange,
    disabled = false,
}: {
    label: string;
    value: T;
    options: SegmentOption<T>[];
    onChange: (value: T) => void;
    disabled?: boolean;
}) {
    return (
        <div
            role="radiogroup"
            aria-label={label}
            className="inline-flex flex-wrap rounded-md border border-white/10 bg-zinc-900 p-0.5"
        >
            {options.map((option) => {
                const selected = option.value === value;
                return (
                    <button
                        key={option.value}
                        type="button"
                        role="radio"
                        aria-checked={selected}
                        disabled={disabled}
                        onClick={() => onChange(option.value)}
                        className={`rounded px-2.5 py-1 text-xs font-medium transition disabled:cursor-not-allowed ${
                            selected
                                ? "bg-white/10 text-white shadow-sm"
                                : "text-zinc-400 hover:text-zinc-200"
                        }`}
                    >
                        {option.label}
                    </button>
                );
            })}
        </div>
    );
}

/** An on/off toggle with a visible title and description. */
export function Switch({
    label,
    title,
    description,
    checked,
    onChange,
    disabled = false,
}: {
    label: string;
    title: string;
    description: string;
    checked: boolean;
    onChange: (checked: boolean) => void;
    disabled?: boolean;
}) {
    return (
        <div className={`flex items-start gap-3 ${disabled ? "opacity-50" : ""}`}>
            <button
                type="button"
                role="switch"
                aria-checked={checked}
                aria-label={label}
                disabled={disabled}
                onClick={() => onChange(!checked)}
                className={`relative mt-0.5 inline-flex h-5 w-9 shrink-0 rounded-full border border-white/10 transition focus-visible:ring-2 focus-visible:ring-emerald-400/60 focus-visible:outline-none disabled:cursor-not-allowed ${
                    checked ? "bg-emerald-500" : "bg-zinc-800"
                }`}
            >
                <span
                    className={`absolute top-0.5 size-3.5 rounded-full bg-white shadow transition-all ${
                        checked ? "left-[1.1rem]" : "left-0.5"
                    }`}
                />
            </button>
            <div className="text-sm">
                <p className="font-medium text-zinc-200">{title}</p>
                <p className="text-xs text-zinc-500">{description}</p>
            </div>
        </div>
    );
}

/** Return the current time, refreshed periodically so relative labels stay accurate. */
export function useNow(intervalMs = 30_000): number {
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        const timer = window.setInterval(() => setNow(Date.now()), intervalMs);
        return () => window.clearInterval(timer);
    }, [intervalMs]);
    return now;
}

/** Describe how long ago a timestamp was, in compact English. */
export function relativeTime(timestamp: string, now: number): string {
    const seconds = Math.round((now - Date.parse(timestamp)) / 1000);
    if (Number.isNaN(seconds)) {
        return timestamp;
    }
    if (seconds < 10) {
        return "just now";
    }
    if (seconds < 60) {
        return `${seconds}s ago`;
    }
    if (seconds < 3600) {
        return `${Math.floor(seconds / 60)}m ago`;
    }
    if (seconds < 86_400) {
        return `${Math.floor(seconds / 3600)}h ago`;
    }
    return `${Math.floor(seconds / 86_400)}d ago`;
}

/** A machine-readable timestamp shown relative to now, with the full time on hover. */
export function RelativeTime({ timestamp, now }: { timestamp: string; now: number }) {
    const date = new Date(timestamp);
    const title = Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString();
    return (
        <time dateTime={timestamp} title={title} className="whitespace-nowrap">
            {relativeTime(timestamp, now)}
        </time>
    );
}

/** One transient confirmation message. */
interface Toast {
    id: number;
    message: string;
}

/** Show a transient confirmation message. */
type ShowToast = (message: string) => void;

/** Distributes the toast function to every page. */
const ToastContext = createContext<ShowToast>(() => {});

/** Return the function that shows a confirmation toast. */
export function useToast(): ShowToast {
    return useContext(ToastContext);
}

/** Provide a single confirmation toast slot shown at the bottom of the screen. */
export function ToastProvider({ children }: { children: ReactNode }) {
    const [toast, setToast] = useState<Toast | null>(null);
    const show = useCallback<ShowToast>((message) => {
        setToast({ id: Date.now(), message });
    }, []);
    useEffect(() => {
        if (toast === null) {
            return undefined;
        }
        const timer = window.setTimeout(() => setToast(null), 5000);
        return () => window.clearTimeout(timer);
    }, [toast]);
    const value = useMemo(() => show, [show]);
    return (
        <ToastContext.Provider value={value}>
            {children}
            {toast && (
                <div className="pointer-events-none fixed inset-x-0 top-16 z-50 flex justify-end px-4 sm:px-6">
                    <div
                        key={toast.id}
                        className="pointer-events-auto flex items-center gap-2 rounded-lg border border-emerald-400/30 bg-zinc-900 px-4 py-2.5 text-sm text-zinc-100 shadow-2xl shadow-black/50"
                    >
                        <CheckIcon className="size-4 text-emerald-400" />
                        <p role="status">{toast.message}</p>
                    </div>
                </div>
            )}
        </ToastContext.Provider>
    );
}
