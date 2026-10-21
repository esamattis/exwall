import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from "@tanstack/react-query";
import { api, pauseBlocking, resumeBlocking, type BlockingStatus } from "./api.ts";
import {
    AlertIcon,
    ErrorBanner,
    PauseIcon,
    PlayIcon,
    Spinner,
    useNow,
    useToast,
} from "./components.tsx";

/** The pause length offered by default, in minutes. */
const defaultPauseMinutes = 5;
/** The longest pause the server accepts, in minutes. */
const maxPauseMinutes = 24 * 60;
/** The query caching the blocking status. */
const blockingKey = ["blocking"];

/** The blocking status query and the live countdown of an active pause. */
export interface BlockingState {
    status: UseQueryResult<BlockingStatus>;
    /** Whole seconds until blocking resumes, or null while blocking is enforced. */
    secondsLeft: number | null;
}

/** Format a number of seconds as `m:ss`, or `h:mm:ss` for an hour or more. */
function formatCountdown(totalSeconds: number): string {
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    const padded = (value: number) => value.toString().padStart(2, "0");
    return hours > 0
        ? `${hours}:${padded(minutes)}:${padded(seconds)}`
        : `${minutes}:${padded(seconds)}`;
}

/**
 * Load the blocking status and count down an active pause every second.
 *
 * The countdown runs from when the status was fetched, so it does not depend on
 * the browser and server clocks agreeing. The status is refetched periodically
 * and when the countdown ends, so a pause changed elsewhere is picked up too.
 */
export function useBlockingStatus(): BlockingState {
    const status = useQuery({
        queryKey: blockingKey,
        queryFn: () => api<BlockingStatus>("blocking"),
        refetchInterval: 15_000,
    });
    const now = useNow(1000);
    const remaining = status.data?.paused_seconds_remaining ?? null;
    // The clock ticks independently of fetches, so never count above the reported time.
    const secondsLeft =
        remaining === null
            ? null
            : Math.max(
                  0,
                  Math.min(
                      remaining,
                      Math.ceil((status.dataUpdatedAt + remaining * 1000 - now) / 1000),
                  ),
              );
    const { refetch } = status;
    useEffect(() => {
        if (secondsLeft === 0) {
            void refetch();
        }
    }, [secondsLeft, refetch]);
    return { status, secondsLeft: secondsLeft === 0 ? null : secondsLeft };
}

/** A header button that pauses blocking for a chosen number of minutes, or resumes it. */
export function BlockingButton({ blocking }: { blocking: BlockingState }) {
    const client = useQueryClient();
    const toast = useToast();
    const { status, secondsLeft } = blocking;
    const [open, setOpen] = useState(false);
    const [minutes, setMinutes] = useState(String(defaultPauseMinutes));
    const container = useRef<HTMLDivElement>(null);
    const pause = useMutation({
        mutationFn: pauseBlocking,
        onSuccess: (data, pausedMinutes) => {
            client.setQueryData(blockingKey, data);
            setOpen(false);
            toast(`Blocking paused for ${pausedMinutes} minute${pausedMinutes === 1 ? "" : "s"}.`);
        },
    });
    const resume = useMutation({
        mutationFn: resumeBlocking,
        onSuccess: (data) => {
            client.setQueryData(blockingKey, data);
            toast("Blocking resumed.");
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
    const parsedMinutes = Number(minutes);
    const validMinutes =
        Number.isInteger(parsedMinutes) && parsedMinutes >= 1 && parsedMinutes <= maxPauseMinutes;
    const paused = secondsLeft !== null;
    return (
        <div ref={container} className="relative">
            {paused ? (
                <button
                    type="button"
                    className="btn btn-secondary border-amber-400/30 text-amber-200"
                    disabled={resume.isPending}
                    onClick={() => resume.mutate()}
                >
                    {resume.isPending ? <Spinner /> : <PlayIcon />}
                    Resume blocking
                </button>
            ) : (
                <button
                    type="button"
                    className="btn btn-ghost"
                    aria-expanded={open}
                    aria-controls="pause-blocking"
                    disabled={status.data === undefined}
                    onClick={() => {
                        pause.reset();
                        resume.reset();
                        setOpen((previous) => !previous);
                    }}
                >
                    <PauseIcon />
                    Pause blocking
                </button>
            )}
            {resume.error && (
                <div className="absolute right-0 z-40 mt-2 w-72">
                    <ErrorBanner>{resume.error.message}</ErrorBanner>
                </div>
            )}
            {open && !paused && (
                <form
                    id="pause-blocking"
                    className="panel absolute right-0 z-40 mt-2 w-72 bg-zinc-900 p-4 shadow-2xl shadow-black/50"
                    onSubmit={(event) => {
                        event.preventDefault();
                        if (validMinutes) {
                            pause.mutate(parsedMinutes);
                        }
                    }}
                >
                    <label className="block">
                        <span className="field-label">Pause for minutes</span>
                        <input
                            className="input"
                            type="number"
                            inputMode="numeric"
                            min={1}
                            max={maxPauseMinutes}
                            step={1}
                            required
                            autoFocus
                            value={minutes}
                            onChange={(event) => setMinutes(event.target.value)}
                        />
                    </label>
                    <p className="field-hint">
                        All HTTP(S) requests and DNS lookups are allowed until the pause ends. Other
                        outbound traffic stays blocked.
                    </p>
                    {pause.error && (
                        <div className="mt-3">
                            <ErrorBanner>{pause.error.message}</ErrorBanner>
                        </div>
                    )}
                    <button
                        type="submit"
                        className="btn btn-primary mt-4 w-full"
                        disabled={!validMinutes || pause.isPending}
                    >
                        {pause.isPending ? <Spinner /> : <PauseIcon />}
                        Pause blocking
                    </button>
                </form>
            )}
        </div>
    );
}

/** A strip under the navigation announcing an active pause and its remaining time. */
export function BlockingBanner({ secondsLeft }: { secondsLeft: number | null }) {
    if (secondsLeft === null) {
        return null;
    }
    return (
        <div role="status" className="border-t border-amber-400/30 bg-amber-500/10">
            <div className="mx-auto flex max-w-6xl items-center gap-2 px-4 py-2 text-sm text-amber-100 sm:px-6">
                <AlertIcon className="size-4 shrink-0 text-amber-300" />
                <p>
                    Blocking is paused. All HTTP(S) requests and DNS lookups are allowed for{" "}
                    <span className="font-mono tabular-nums">{formatCountdown(secondsLeft)}</span>.
                </p>
            </div>
        </div>
    );
}
