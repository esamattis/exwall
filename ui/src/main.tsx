import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import {
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
    RouterProvider,
    useNavigate,
} from "@tanstack/react-router";
import "./style.css";

/** A header added to matching upstream requests. */
interface InjectedHeader {
    name: string;
    value: string;
}

/** Ordinary JSON values used by the rule editing API. */
type FieldValue = string | string[] | boolean | InjectedHeader[];

/** An editable allow table with its original position for comment preservation. */
interface RuleDraft {
    index: number | null;
    fields: Record<string, FieldValue>;
}

/** Rules and a revision used to reject overwriting concurrent file edits. */
interface RulesDocument {
    revision: string;
    rules: RuleDraft[];
}

/** An API failure retaining its HTTP status for authentication handling. */
class ApiError extends Error {
    status: number;
    constructor(status: number, message: string) {
        super(message);
        this.status = status;
    }
}

/** Fetch same-origin JSON using the browser's persistent session cookie. */
async function api<T>(
    path: string,
    method: "GET" | "POST" | "PUT" = "GET",
    body?: unknown,
): Promise<T> {
    const options: RequestInit = {
        method,
        credentials: "same-origin",
        headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    };
    if (method !== "GET" && body !== undefined) {
        options.body = JSON.stringify(body);
    }
    const response = await fetch(`/api/${path}`, options);
    const result: T & { error?: string } = await response.json();
    if (!response.ok) {
        throw new ApiError(response.status, result.error ?? "Request failed");
    }
    return result;
}

/** Render the common application frame and navigation. */
function Layout() {
    return (
        <div className="min-h-screen bg-slate-950 text-slate-100">
            <header className="border-b border-slate-800 px-6 py-5">
                <div className="mx-auto flex max-w-5xl items-center justify-between">
                    <Link to="/" className="text-xl font-semibold tracking-tight text-teal-400">
                        exwall
                    </Link>
                    <span className="text-sm text-slate-400">Egress firewall</span>
                </div>
            </header>
            <main className="mx-auto max-w-5xl px-6 py-10">
                <Outlet />
            </main>
        </div>
    );
}

/** Authenticate through TanStack Query and navigate to the rules editor. */
function LoginPage() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const navigate = useNavigate();
    const client = useQueryClient();
    const login = useMutation({
        mutationFn: () => api<{ username: string }>("login", "POST", { username, password }),
        onSuccess: async () => {
            client.clear();
            await navigate({ to: "/" });
        },
    });
    return (
        <section className="mx-auto mt-10 max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-8">
            <h1 className="text-3xl font-semibold">Sign in</h1>
            <p className="mt-3 text-slate-400">
                Use your configured account to manage firewall rules.
            </p>
            <form
                className="mt-8 space-y-5"
                onSubmit={(event) => {
                    event.preventDefault();
                    login.mutate();
                }}
            >
                <label className="block">
                    Username
                    <input
                        className="input mt-2"
                        autoComplete="username"
                        required
                        value={username}
                        onChange={(event) => setUsername(event.target.value)}
                    />
                </label>
                <label className="block">
                    Password
                    <input
                        className="input mt-2"
                        type="password"
                        autoComplete="current-password"
                        required
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                    />
                </label>
                {login.error && (
                    <p role="alert" className="text-red-400">
                        {login.error.message}
                    </p>
                )}
                <button className="button w-full" disabled={login.isPending}>
                    {login.isPending ? "Signing in…" : "Sign in"}
                </button>
            </form>
        </section>
    );
}

const fields = [
    "domain",
    "domain_regex",
    "include_subdomains",
    "methods",
    "pathname_pattern",
    "pathname_regex",
    "stream",
    "inject_headers",
];
const hints: Record<string, string> = {
    domain: "example.com",
    domain_regex: "^.*\\.example\\.com$",
    pathname_pattern: "/api/*",
    pathname_regex: "^/api/",
};

/** Edit a typed field without requiring configuration-file syntax. */
function RuleField({
    name,
    field,
    value,
    onChange,
}: {
    name: string;
    field: string;
    value: FieldValue | undefined;
    onChange: (value: FieldValue | undefined) => void;
}) {
    const [text, setText] = useState(() => {
        if (typeof value === "string") {
            return value;
        }
        if (Array.isArray(value)) {
            return value.filter((item) => typeof item === "string").join("\n");
        }
        return "";
    });
    if (field === "include_subdomains" || field === "stream") {
        return (
            <select
                className="input mt-2"
                aria-label={name}
                value={typeof value === "boolean" ? String(value) : ""}
                onChange={(event) =>
                    onChange(event.target.value === "" ? undefined : event.target.value === "true")
                }
            >
                <option value="">Default ({field === "stream" ? "enabled" : "disabled"})</option>
                <option value="true">Enabled</option>
                <option value="false">Disabled</option>
            </select>
        );
    }
    if (field === "methods") {
        let mode = "custom";
        if (value === undefined) {
            mode = "default";
        } else if (typeof value === "string") {
            mode = "any";
        }
        return (
            <div className="mt-2 space-y-2">
                <select
                    className="input"
                    aria-label={name}
                    value={mode}
                    onChange={(event) => {
                        const next = event.target.value;
                        if (next === "default") {
                            onChange(undefined);
                        } else if (next === "any") {
                            onChange("ANY");
                        } else {
                            onChange(["GET", "HEAD"]);
                        }
                        setText("GET\nHEAD");
                    }}
                >
                    <option value="default">Default (GET and HEAD)</option>
                    <option value="any">Any method</option>
                    <option value="custom">Choose methods</option>
                </select>
                {mode === "custom" && (
                    <textarea
                        className="input"
                        aria-label={`${name} list`}
                        rows={3}
                        value={text}
                        placeholder={"GET\nHEAD\nPOST"}
                        onChange={(event) => {
                            setText(event.target.value);
                            onChange(
                                event.target.value
                                    .split("\n")
                                    .map((item) => item.trim())
                                    .filter(Boolean),
                            );
                        }}
                    />
                )}
                {mode === "custom" && (
                    <p className="text-xs text-slate-400">One method per line.</p>
                )}
            </div>
        );
    }
    if (field === "inject_headers") {
        const headers: InjectedHeader[] = Array.isArray(value)
            ? value.filter((item): item is InjectedHeader => typeof item !== "string")
            : [];
        return (
            <div className="mt-2 space-y-3">
                {headers.map((header, index) => (
                    <div key={index} className="flex flex-wrap items-center gap-2">
                        <input
                            className="input flex-1"
                            aria-label={`${name} ${index + 1} name`}
                            placeholder="Header name"
                            required
                            value={header.name}
                            onChange={(event) =>
                                onChange(
                                    headers.map((item, position) =>
                                        position === index
                                            ? { ...item, name: event.target.value }
                                            : item,
                                    ),
                                )
                            }
                        />
                        <input
                            className="input flex-1"
                            aria-label={`${name} ${index + 1} value`}
                            placeholder="Header value"
                            value={header.value}
                            onChange={(event) =>
                                onChange(
                                    headers.map((item, position) =>
                                        position === index
                                            ? { ...item, value: event.target.value }
                                            : item,
                                    ),
                                )
                            }
                        />
                        <button
                            type="button"
                            className="text-red-400"
                            aria-label={`Remove ${name} ${index + 1}`}
                            onClick={() => {
                                const remaining = headers.filter(
                                    (_, position) => position !== index,
                                );
                                onChange(remaining.length ? remaining : undefined);
                            }}
                        >
                            Remove
                        </button>
                    </div>
                ))}
                <button
                    type="button"
                    className="text-teal-400"
                    onClick={() => onChange([...headers, { name: "", value: "" }])}
                >
                    Add header
                </button>
            </div>
        );
    }
    return (
        <div>
            <textarea
                className="input mt-2 font-mono"
                aria-label={name}
                rows={2}
                value={text}
                placeholder={hints[field]}
                onChange={(event) => {
                    const next = event.target.value;
                    setText(next);
                    const items = next.split("\n").filter((item) => item.trim());
                    if (items.length === 0) {
                        onChange(undefined);
                    } else if (items.length === 1 && !Array.isArray(value)) {
                        onChange(items[0]);
                    } else {
                        onChange(items);
                    }
                }}
            />
            <p className="mt-1 text-xs text-slate-400">One value per line.</p>
        </div>
    );
}

/** Edit ordinary rule values while retaining optional fields and original rule positions. */
function Editor({
    document,
    onSaved,
    onEdit,
}: {
    document: RulesDocument;
    onSaved: () => void;
    onEdit: () => void;
}) {
    const [rules, setRules] = useState(document.rules);
    const client = useQueryClient();
    const save = useMutation({
        mutationFn: () =>
            api<RulesDocument>("rules", "PUT", { revision: document.revision, rules }),
        onSuccess: (result) => {
            client.setQueryData(["rules"], result);
            onSaved();
        },
    });
    /** Update or omit one field without changing the other rule tables. */
    function update(index: number, key: string, value: FieldValue | undefined) {
        onEdit();
        setRules((previous) =>
            previous.map((rule, position) => {
                if (position !== index) {
                    return rule;
                }
                const next = { ...rule.fields };
                if (value !== undefined) {
                    next[key] = value;
                } else {
                    delete next[key];
                }
                return { ...rule, fields: next };
            }),
        );
    }
    const dirty = JSON.stringify(rules) !== JSON.stringify(document.rules);
    return (
        <form
            className="space-y-6"
            onSubmit={(event) => {
                event.preventDefault();
                save.mutate();
            }}
        >
            <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                    <h1 className="text-3xl font-semibold">Rules</h1>
                    <p className="mt-2 text-slate-400">
                        Edit allow rules in 05-web.toml. Other rule files stay active.
                    </p>
                </div>
                <button className="button" disabled={save.isPending || !dirty}>
                    {save.isPending ? "Saving…" : "Save changes"}
                </button>
            </div>
            <p className="rounded-xl border border-slate-800 bg-slate-900 p-4 text-sm text-slate-400">
                Enter plain text, with one domain or pattern per line. Leave optional fields empty
                to use their defaults. Each rule needs either a domain or a domain regex. Saved
                rules are validated before they take effect.
            </p>
            {save.error && (
                <p role="alert" className="text-red-400">
                    {save.error.message}
                </p>
            )}
            {rules.length === 0 && (
                <p className="py-8 text-slate-400">
                    No rules in 05-web.toml yet. Add an allow rule to get started.
                </p>
            )}
            {rules.map((rule, index) => (
                <fieldset
                    key={rule.index ?? `new-${index}`}
                    disabled={save.isPending}
                    className="rounded-2xl border border-slate-800 bg-slate-900 p-6"
                >
                    <legend className="px-2 font-semibold">Allow rule {index + 1}</legend>
                    <div className="grid gap-5 md:grid-cols-2">
                        {fields.map((key) => (
                            <div
                                key={key}
                                className={`block text-sm text-slate-300 ${key === "inject_headers" ? "md:col-span-2" : ""}`}
                            >
                                {key.replaceAll("_", " ")}
                                <RuleField
                                    name={`Rule ${index + 1} ${key}`}
                                    field={key}
                                    value={rule.fields[key]}
                                    onChange={(value) => update(index, key, value)}
                                />
                            </div>
                        ))}
                    </div>
                    <button
                        type="button"
                        className="mt-5 text-sm text-red-400 hover:text-red-300"
                        onClick={() => {
                            onEdit();
                            setRules(rules.filter((_, position) => position !== index));
                        }}
                    >
                        Remove rule
                    </button>
                </fieldset>
            ))}
            <button
                type="button"
                className="rounded-lg border border-slate-700 px-4 py-2 hover:bg-slate-800"
                disabled={save.isPending}
                onClick={() => {
                    onEdit();
                    setRules([...rules, { index: null, fields: { domain: "example.com" } }]);
                }}
            >
                Add rule
            </button>
        </form>
    );
}

/** Load rules with TanStack Query and offer login when the session has expired. */
function RulesPage() {
    const [generation, setGeneration] = useState(0);
    const [saved, setSaved] = useState(false);
    const client = useQueryClient();
    const navigate = useNavigate();
    const rules = useQuery({
        queryKey: ["rules"],
        queryFn: () => api<RulesDocument>("rules"),
        retry: false,
        refetchOnWindowFocus: false,
    });
    const logout = useMutation({
        mutationFn: () => api("logout", "POST", {}),
        onSuccess: async () => {
            client.clear();
            await navigate({ to: "/login" });
        },
    });
    if (rules.isPending) {
        return (
            <p role="status" className="text-slate-400">
                Loading rules…
            </p>
        );
    }
    if (rules.error instanceof ApiError && rules.error.status === 401) {
        return (
            <section>
                <h1 className="text-3xl font-semibold">Sign in to edit rules</h1>
                <p className="my-4 text-slate-400">
                    A configured account is required to access the firewall rules.
                </p>
                <Link className="button inline-block" to="/login">
                    Sign in
                </Link>
            </section>
        );
    }
    if (rules.error) {
        return (
            <p role="alert" className="text-red-400">
                {rules.error.message}
            </p>
        );
    }
    return (
        <>
            <div className="mb-6 flex justify-end gap-5 text-sm">
                <button
                    onClick={() => {
                        if (window.confirm("Reload 05-web.toml and discard unsaved edits?")) {
                            setSaved(false);
                            void rules.refetch().then(() => setGeneration((value) => value + 1));
                        }
                    }}
                    className="text-slate-400 hover:text-white"
                >
                    Reload from file
                </button>
                <button
                    disabled={logout.isPending}
                    onClick={() => logout.mutate()}
                    className="text-slate-400 hover:text-white"
                >
                    Sign out
                </button>
            </div>
            {logout.error && (
                <p role="alert" className="mb-4 text-red-400">
                    {logout.error.message}
                </p>
            )}
            {saved && (
                <p role="status" className="mb-4 text-teal-400">
                    Changes saved.
                </p>
            )}
            <Editor
                key={`${generation}:${rules.data.revision}`}
                document={rules.data}
                onEdit={() => setSaved(false)}
                onSaved={() => {
                    setGeneration((value) => value + 1);
                    setSaved(true);
                }}
            />
        </>
    );
}

const rootRoute = createRootRoute({ component: Layout });
const indexRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/",
    component: RulesPage,
});
const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/login",
    component: LoginPage,
});
const router = createRouter({ routeTree: rootRoute.addChildren([indexRoute, loginRoute]) });
const queryClient = new QueryClient();

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
