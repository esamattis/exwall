import { StrictMode, useState } from "react";
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
import { api, ApiError, hasSession, sessionKey, type Session } from "./api.ts";
import { BlockingBanner, BlockingButton, useBlockingStatus } from "./blocking.tsx";
import { ErrorBanner, ShieldIcon, SignOutIcon, Spinner, ToastProvider } from "./components.tsx";
import { RuleFilesPage, RulesPage } from "./rules.tsx";
import { parseTrafficView, TrafficPage } from "./traffic.tsx";
import "./style.css";

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
            <span className="grid size-7 place-items-center rounded-lg bg-emerald-400/15 text-emerald-300 ring-1 ring-emerald-400/30">
                <ShieldIcon className="size-4" />
            </span>
            exwall
        </span>
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
                    <Link to="/" search={{}} aria-label="exwall home">
                        <Brand />
                    </Link>
                    <nav aria-label="Main" className="flex gap-1">
                        <Link
                            to="/"
                            search={{}}
                            className={navLink}
                            activeOptions={{ exact: true, includeSearch: false }}
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
const trafficRoute = createRoute({
    getParentRoute: () => appRoute,
    path: "/",
    validateSearch: (search: Record<string, unknown>): { view?: string } =>
        search.view === undefined ? {} : { view: parseTrafficView(search.view) },
    component: () => <TrafficPage view={parseTrafficView(trafficRoute.useSearch().view)} />,
});
const rulesRoute = createRoute({
    getParentRoute: () => appRoute,
    path: "/rules",
    component: RuleFilesPage,
});
const ruleFileRoute = createRoute({
    getParentRoute: () => appRoute,
    path: "/rules/$file",
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
        throw redirect({ to: "/", search: {} });
    },
});
const router = createRouter({
    routeTree: rootRoute.addChildren([
        loginRoute,
        domainsRoute,
        appRoute.addChildren([trafficRoute, rulesRoute, ruleFileRoute]),
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
