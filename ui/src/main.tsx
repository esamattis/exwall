import { StrictMode, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
    MutationCache,
    QueryCache,
    QueryClient,
    QueryClientProvider,
    useMutation,
    useQuery,
    useQueryClient,
} from "@tanstack/react-query";
import {
    createRootRoute,
    createRoute,
    createRouter,
    Link,
    Outlet,
    redirect,
    RouterProvider,
    useNavigate,
} from "@tanstack/react-router";
import { api, ApiError, hasSession, sessionKey, type HostInfo, type Session } from "./api.ts";
import { BlockingBanner, BlockingButton, useBlockingStatus } from "./blocking.tsx";
import {
    ChevronIcon,
    CopyButton,
    ErrorBanner,
    SignOutIcon,
    Spinner,
    ToastProvider,
} from "./components.tsx";
import { RuleFilesPage, RulesPage } from "./rules.tsx";
import { DomainsView, legacyTrafficView, RequestsView, TrafficLayout } from "./traffic.tsx";
import "./style.css";
import iconUrl from "../../assets/icon.svg";

/** Accept only same-origin paths as post-login destinations. */
function safeRedirect(value: unknown): string | undefined {
    if (typeof value === "string" && value.startsWith("/") && !value.startsWith("//")) {
        return value;
    }
    return undefined;
}

/** The product mark and name. */
function Brand() {
    return (
        <span className="flex items-center gap-2 text-base font-semibold tracking-tight text-white">
            <img src={iconUrl} alt="" className="size-7" />
            exwall
        </span>
    );
}

/** The managed host's name with its main address below, opening a list of all addresses. */
function HostLabel() {
    const host = useQuery({
        queryKey: ["host"],
        queryFn: () => api<HostInfo>("host"),
        refetchInterval: 60_000,
        refetchOnWindowFocus: false,
    });
    const [open, setOpen] = useState(false);
    const container = useRef<HTMLDivElement>(null);
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
    if (!host.data?.hostname) {
        return null;
    }
    const [primary, ...others] = host.data.addresses;
    return (
        <div
            ref={container}
            className="relative flex min-w-0 flex-col justify-center border-l border-white/10 pl-4 leading-tight"
        >
            <span
                className="truncate text-base font-semibold text-white"
                title={host.data.hostname}
            >
                {host.data.hostname}
            </span>
            {primary && (
                <button
                    type="button"
                    className="flex items-center gap-1.5 self-start rounded font-mono text-[10px] text-zinc-500 transition hover:text-zinc-300"
                    aria-expanded={open}
                    aria-controls="host-addresses"
                    title="Show all addresses"
                    onClick={() => setOpen((previous) => !previous)}
                >
                    {primary.address}
                    {others.length > 0 && (
                        <span className="rounded bg-white/10 px-1 font-sans font-medium text-zinc-400">
                            +{others.length}
                        </span>
                    )}
                    <ChevronIcon className={`size-3 transition ${open ? "rotate-180" : ""}`} />
                </button>
            )}
            {open && (
                <div
                    id="host-addresses"
                    className="panel absolute top-full left-0 z-40 mt-3 w-80 bg-zinc-900 py-2 shadow-2xl shadow-black/50"
                >
                    <p className="field-label px-4 pb-1">Addresses</p>
                    <ul>
                        {host.data.addresses.map((entry) => (
                            <li
                                key={entry.address}
                                className="flex items-center gap-3 py-0.5 pr-2 pl-4"
                            >
                                <code
                                    className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-200"
                                    title={entry.address}
                                >
                                    {entry.address}
                                </code>
                                <span
                                    className={`shrink-0 text-xs ${entry.default_route ? "text-emerald-400" : "text-zinc-500"}`}
                                    title={
                                        entry.default_route
                                            ? "This interface carries a default route"
                                            : undefined
                                    }
                                >
                                    {entry.interface}
                                </span>
                                <CopyButton
                                    text={entry.address}
                                    label={`Copy address ${entry.address}`}
                                />
                            </li>
                        ))}
                    </ul>
                    {host.data.addresses.some((entry) => entry.default_route) && (
                        <p className="px-4 pt-2 text-xs text-zinc-500">
                            <span className="text-emerald-400">Green</span> interfaces carry a
                            default route.
                        </p>
                    )}
                </div>
            )}
        </div>
    );
}

/** Render the signed-in application frame with navigation and account controls. */
function AppShell() {
    const navigate = useNavigate();
    const client = useQueryClient();
    const session = useQuery({
        queryKey: ["session"],
        queryFn: () => api<Session>("session"),
        retry: false,
        refetchOnWindowFocus: false,
        staleTime: Infinity,
    });
    const logout = useMutation({
        mutationFn: () => api("logout", "POST", {}),
        onSuccess: async () => {
            localStorage.removeItem(sessionKey);
            client.clear();
            await navigate({ to: "/login" });
        },
    });
    const blocking = useBlockingStatus();
    const navLink =
        "rounded-md px-3 py-1.5 text-sm font-medium text-zinc-400 transition hover:text-zinc-100";
    return (
        <div className="min-h-screen">
            <header className="sticky top-0 z-30 border-b border-white/10 bg-zinc-950/80 backdrop-blur">
                <div className="mx-auto flex h-14 max-w-6xl items-center gap-6 px-4 sm:px-6">
                    <div className="flex items-center gap-2">
                        <Link to="/traffic" aria-label="exwall home">
                            <Brand />
                        </Link>
                        {session.data && (
                            <span
                                className="font-mono text-[10px] text-zinc-500"
                                title={`exwall version ${session.data.version}`}
                            >
                                v{session.data.version}
                            </span>
                        )}
                    </div>
                    <HostLabel />
                    <nav aria-label="Main" className="flex gap-1">
                        <Link
                            to="/traffic"
                            className={navLink}
                            activeProps={{ className: "bg-white/10 text-white" }}
                        >
                            Traffic
                        </Link>
                        <Link
                            to="/rules"
                            className={navLink}
                            activeProps={{ className: "bg-white/10 text-white" }}
                        >
                            Rules
                        </Link>
                    </nav>
                    <div className="ml-auto flex items-center gap-3">
                        <BlockingButton blocking={blocking} />
                        {session.data && (
                            <span className="hidden text-sm text-zinc-500 sm:inline">
                                {session.data.username}
                            </span>
                        )}
                        <button
                            type="button"
                            className="btn btn-ghost"
                            disabled={logout.isPending}
                            onClick={() => logout.mutate()}
                        >
                            <SignOutIcon />
                            Sign out
                        </button>
                    </div>
                </div>
                <BlockingBanner secondsLeft={blocking.secondsLeft} />
            </header>
            <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
                {logout.error && (
                    <div className="mb-4">
                        <ErrorBanner>{logout.error.message}</ErrorBanner>
                    </div>
                )}
                <Outlet />
            </main>
        </div>
    );
}

/** Authenticate and continue to the page that required signing in. */
function LoginPage() {
    const { redirect: destination } = loginRoute.useSearch();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const navigate = useNavigate();
    const client = useQueryClient();
    const login = useMutation({
        mutationFn: () =>
            api<{ username: string; token: string }>("login", "POST", { username, password }),
        onSuccess: async ({ token }) => {
            localStorage.setItem(sessionKey, token);
            client.clear();
            await navigate({ href: destination ?? "/" });
        },
    });
    let error = login.error?.message;
    if (login.error instanceof ApiError && login.error.status === 401) {
        error = "Incorrect username or password.";
    }
    return (
        <main className="grid min-h-screen place-items-center bg-[radial-gradient(ellipse_at_top,rgba(52,211,153,0.08),transparent_60%)] px-4">
            <div className="w-full max-w-sm">
                <div className="mb-8 flex justify-center">
                    <Brand />
                </div>
                <section className="panel p-6 shadow-2xl shadow-black/40">
                    <h1 className="text-xl font-semibold text-white">Sign in</h1>
                    <p className="mt-1 text-sm text-zinc-400">
                        Use the account configured for this firewall.
                    </p>
                    <form
                        className="mt-6 space-y-4"
                        onSubmit={(event) => {
                            event.preventDefault();
                            login.mutate();
                        }}
                    >
                        <label className="block">
                            <span className="field-label">Username</span>
                            <input
                                className="input"
                                autoComplete="username"
                                autoFocus
                                required
                                value={username}
                                onChange={(event) => setUsername(event.target.value)}
                            />
                        </label>
                        <label className="block">
                            <span className="field-label">Password</span>
                            <input
                                className="input"
                                type="password"
                                autoComplete="current-password"
                                required
                                value={password}
                                onChange={(event) => setPassword(event.target.value)}
                            />
                        </label>
                        {error && <ErrorBanner>{error}</ErrorBanner>}
                        <button
                            type="submit"
                            className="btn btn-primary w-full py-2"
                            disabled={login.isPending}
                        >
                            {login.isPending && <Spinner />}
                            {login.isPending ? "Signing in…" : "Sign in"}
                        </button>
                    </form>
                </section>
            </div>
        </main>
    );
}

/** Send the browser to the login page, remembering where it was. */
function requireLogin(): never {
    const { pathname, search } = window.location;
    throw redirect({
        to: "/login",
        search: { redirect: pathname === "/login" ? undefined : `${pathname}${search}` },
    });
}

const rootRoute = createRootRoute({
    component: () => (
        <ToastProvider>
            <Outlet />
        </ToastProvider>
    ),
});
const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/login",
    validateSearch: (search: Record<string, unknown>): { redirect?: string } => {
        const destination = safeRedirect(search.redirect);
        return destination ? { redirect: destination } : {};
    },
    component: LoginPage,
});
const appRoute = createRoute({
    getParentRoute: () => rootRoute,
    id: "app",
    beforeLoad: () => {
        if (!hasSession()) {
            requireLogin();
        }
    },
    component: AppShell,
});
/** The start page, which opens Traffic and keeps former `/?view=` links working. */
const homeRoute = createRoute({
    getParentRoute: () => appRoute,
    path: "/",
    validateSearch: (search: Record<string, unknown>): { view?: unknown } =>
        search.view === undefined ? {} : { view: search.view },
    beforeLoad: ({ search }) => {
        throw redirect({ to: `/traffic/${legacyTrafficView(search.view)}`, replace: true });
    },
});
const trafficRoute = createRoute({
    getParentRoute: () => appRoute,
    path: "/traffic",
    component: TrafficLayout,
});
const trafficIndexRoute = createRoute({
    getParentRoute: () => trafficRoute,
    path: "/",
    beforeLoad: () => {
        throw redirect({ to: "/traffic/blocked", replace: true });
    },
});
const blockedDomainsRoute = createRoute({
    getParentRoute: () => trafficRoute,
    path: "blocked",
    component: () => <DomainsView outcome="block" />,
});
const allowedDomainsRoute = createRoute({
    getParentRoute: () => trafficRoute,
    path: "allowed",
    component: () => <DomainsView outcome="allow" />,
});
const blockedRequestsRoute = createRoute({
    getParentRoute: () => trafficRoute,
    path: "blocked-requests",
    component: () => <RequestsView outcome="block" />,
});
const allowedRequestsRoute = createRoute({
    getParentRoute: () => trafficRoute,
    path: "allowed-requests",
    component: () => <RequestsView outcome="allow" />,
});
const rulesRoute = createRoute({
    getParentRoute: () => appRoute,
    path: "/rules",
});
const ruleFilesRoute = createRoute({
    getParentRoute: () => rulesRoute,
    path: "/",
    component: RuleFilesPage,
});
const ruleFileRoute = createRoute({
    getParentRoute: () => rulesRoute,
    path: "$file",
    component: RuleFileEditor,
});

/** Open the editor for the rule file named in the route, resetting its state per file. */
function RuleFileEditor() {
    const { file } = ruleFileRoute.useParams();
    return <RulesPage key={file} file={file} />;
}
const domainsRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/domains",
    beforeLoad: () => {
        throw redirect({ to: "/traffic", replace: true });
    },
});
const router = createRouter({
    routeTree: rootRoute.addChildren([
        loginRoute,
        domainsRoute,
        appRoute.addChildren([
            homeRoute,
            trafficRoute.addChildren([
                trafficIndexRoute,
                blockedDomainsRoute,
                allowedDomainsRoute,
                blockedRequestsRoute,
                allowedRequestsRoute,
            ]),
            rulesRoute.addChildren([ruleFilesRoute, ruleFileRoute]),
        ]),
    ]),
});

/** Return to the login page when the server rejects the stored session. */
function onApiError(error: Error) {
    if (error instanceof ApiError && error.status === 401 && !hasSession()) {
        const { pathname, search } = window.location;
        if (pathname !== "/login") {
            void router.navigate({ to: "/login", search: { redirect: `${pathname}${search}` } });
        }
    }
}

const queryClient = new QueryClient({
    queryCache: new QueryCache({ onError: onApiError }),
    mutationCache: new MutationCache({ onError: onApiError }),
});

declare module "@tanstack/react-router" {
    interface Register {
        router: typeof router;
    }
}

const root = document.getElementById("root");
if (!root) {
    throw new Error("Missing React root element");
}
createRoot(root).render(
    <StrictMode>
        <QueryClientProvider client={queryClient}>
            <RouterProvider router={router} />
        </QueryClientProvider>
    </StrictMode>,
);
