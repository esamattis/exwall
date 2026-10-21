import { useRef, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import CodeMirror, { EditorView, Prec, keymap } from "@uiw/react-codemirror";
import { StreamLanguage } from "@codemirror/language";
import { toml } from "@codemirror/legacy-modes/mode/toml";
import {
    api,
    rulesPath,
    saveRulesToml,
    webRulesFile,
    type FieldValue,
    type InjectedHeader,
    type RuleDraft,
    type RuleFileContents,
    type RuleFileSummary,
    type RulesDocument,
} from "./api.ts";
import {
    ChevronIcon,
    CodeIcon,
    EmptyState,
    ErrorBanner,
    FilePath,
    FilterInput,
    PageHeader,
    PlusIcon,
    RefreshIcon,
    Segmented,
    Spinner,
    Switch,
    TrashIcon,
    useToast,
} from "./components.tsx";

/** Methods offered as toggles when a rule lists its methods explicitly. */
const commonMethods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/** Read a string or string-list field as a list. */
function lines(value: FieldValue | undefined): string[] {
    if (typeof value === "string") {
        return [value];
    }
    if (Array.isArray(value)) {
        return value.filter((item) => typeof item === "string");
    }
    return [];
}

/** Read the injected header rows of a rule. */
function headerRows(value: FieldValue | undefined): InjectedHeader[] {
    if (!Array.isArray(value)) {
        return [];
    }
    return value.filter((item): item is InjectedHeader => typeof item !== "string");
}

/** The three ways a rule can constrain HTTP methods. */
type MethodMode = "default" | "any" | "custom";

/** Classify a rule's `methods` field. */
function methodMode(value: FieldValue | undefined): MethodMode {
    if (value === undefined) {
        return "default";
    }
    if (typeof value === "string") {
        return "any";
    }
    return "custom";
}

/** Find the 1-based rule number named in a server validation message. */
function invalidRuleNumber(message: string | undefined): number | null {
    const match = message?.match(/allow#(\d+)/);
    return match?.[1] ? Number(match[1]) : null;
}

/** Describe a rule file's allow table count, or flag a file that is invalid. */
function RuleCount({ rules }: { rules: number | null }) {
    if (rules === null) {
        return <span className="badge badge-warn">Invalid</span>;
    }
    return (
        <span className="badge badge-neutral">
            {rules} {rules === 1 ? "rule" : "rules"}
        </span>
    );
}

/** The query listing every rule file, shared by the list and the editor's path display. */
const ruleFilesQuery = {
    queryKey: ["rules"],
    queryFn: () => api<RuleFileSummary[]>("rules"),
    retry: false,
    refetchOnWindowFocus: false,
};

/** List every rule file in the rules directory with a link to its editor. */
export function RuleFilesPage() {
    const files = useQuery(ruleFilesQuery);
    let content: ReactNode;
    if (files.isPending) {
        content = (
            <p role="status" className="flex items-center gap-2 text-sm text-zinc-400">
                <Spinner /> Loading rule files…
            </p>
        );
    } else if (files.error) {
        content = <ErrorBanner>{files.error.message}</ErrorBanner>;
    } else if (files.data.length === 0) {
        content = (
            <div className="panel">
                <EmptyState title="No rule files yet">
                    Add <code className="text-zinc-300">*.toml</code> files to the rules directory,
                    or allow blocked domains from the Traffic page.
                </EmptyState>
            </div>
        );
    } else {
        content = (
            <ul aria-label="Rule files" className="panel divide-y divide-white/10">
                {files.data.map((file) => (
                    <li key={file.name} className="flex items-center gap-2 pr-2">
                        <div className="flex min-w-0 flex-1 flex-col gap-0.5 py-2 pl-4">
                            <Link
                                to="/rules/$file"
                                params={{ file: file.name }}
                                className="flex items-center gap-3 rounded-md transition hover:text-white focus-visible:ring-2 focus-visible:ring-emerald-400/60 focus-visible:outline-none"
                            >
                                <span className="min-w-0 truncate font-mono text-[13px] font-medium text-zinc-100">
                                    {file.name}
                                </span>
                                <RuleCount rules={file.rules} />
                            </Link>
                            <FilePath path={file.path} />
                        </div>
                        <Link
                            to="/rules/$file"
                            params={{ file: file.name }}
                            aria-label={`Edit ${file.name}`}
                            className="btn btn-icon btn-ghost"
                        >
                            <ChevronIcon className="size-4 -rotate-90" />
                        </Link>
                    </li>
                ))}
            </ul>
        );
    }
    return (
        <div>
            <PageHeader
                title="Rules"
                description={
                    <>
                        Rule files in the rules directory, loaded in name order. Domains allowed
                        from the Traffic page are added to{" "}
                        <code className="text-zinc-300">{webRulesFile}</code>.
                    </>
                }
                actions={
                    <button
                        type="button"
                        className="btn btn-secondary"
                        disabled={files.isFetching}
                        onClick={() => void files.refetch()}
                    >
                        <RefreshIcon />
                        Refresh
                    </button>
                }
            />
            {content}
        </div>
    );
}

/** Load one rule file and remount the editor whenever a new revision arrives. */
export function RulesPage({ file }: { file: string }) {
    const [generation, setGeneration] = useState(0);
    const [expanded, setExpanded] = useState<Set<number>>(() => new Set());
    const [filter, setFilter] = useState("");
    const [mode, setMode] = useState<"form" | "toml">("form");
    const rules = useQuery({
        queryKey: ["rules", file],
        queryFn: () => api<RuleFileContents>(rulesPath(file)),
        retry: false,
        refetchOnWindowFocus: false,
    });
    const files = useQuery(ruleFilesQuery);
    if (rules.isPending) {
        return (
            <p role="status" className="flex items-center gap-2 text-sm text-zinc-400">
                <Spinner /> Loading rules…
            </p>
        );
    }
    if (rules.error) {
        return (
            <div>
                <BackToFiles />
                <ErrorBanner>{rules.error.message}</ErrorBanner>
            </div>
        );
    }
    const { revision, rules: drafts } = rules.data;
    const path = files.data?.find((summary) => summary.name === file)?.path;
    const key = `${generation}:${revision}`;

    /** Load the file again and remount the editor with its contents. */
    async function reload() {
        await rules.refetch();
        setGeneration((value) => value + 1);
    }

    /** Remount the editor with the loaded contents, discarding local edits. */
    function discard() {
        setGeneration((value) => value + 1);
    }

    // Invalid files can only be repaired as TOML.
    if (drafts === undefined || mode === "toml") {
        return (
            <TomlEditor
                key={key}
                file={file}
                path={path}
                contents={rules.data}
                onReload={reload}
                onDiscard={discard}
                onSaved={() => setMode("toml")}
                onEditForm={drafts === undefined ? null : () => setMode("form")}
            />
        );
    }
    return (
        <Editor
            key={key}
            file={file}
            path={path}
            document={{ revision, rules: drafts }}
            expanded={expanded}
            setExpanded={setExpanded}
            filter={filter}
            setFilter={setFilter}
            onReload={reload}
            onDiscard={discard}
            onEditToml={() => setMode("toml")}
        />
    );
}

/** CodeMirror extensions for TOML highlighting, saving with Mod-S, and a theme matching the panels. */
const tomlExtensions = [
    StreamLanguage.define(toml),
    keymap.of([
        {
            key: "Mod-s",
            // Submitting the surrounding form saves through the editor's usual path.
            run: (view) => {
                view.dom.closest("form")?.requestSubmit();
                return true;
            },
        },
    ]),
    // The dark theme's own background would otherwise take precedence.
    Prec.highest(
        EditorView.theme(
            {
                "&": { backgroundColor: "transparent", fontSize: "13px" },
                "&.cm-focused": { outline: "none" },
                ".cm-scroller": { fontFamily: "var(--font-mono)" },
                ".cm-gutters": {
                    backgroundColor: "transparent",
                    borderRight: "1px solid rgb(255 255 255 / 0.1)",
                },
            },
            { dark: true },
        ),
    ),
];

/** Show a heading and a verbatim, possibly multi-line error message. */
function ErrorDetails({ heading, message }: { heading: string; message: string }) {
    return (
        <>
            <span className="block font-medium">{heading}</span>
            <code className="mt-1 block font-mono text-xs whitespace-pre-wrap">{message}</code>
        </>
    );
}

/** Edit one rule file as TOML text, showing why it is invalid above the editor. */
function TomlEditor({
    file,
    path,
    contents,
    onReload,
    onDiscard,
    onSaved,
    onEditForm,
}: {
    file: string;
    path: string | undefined;
    contents: RuleFileContents;
    onReload: () => Promise<void>;
    onDiscard: () => void;
    onSaved: () => void;
    /** Switch to the form editor, or null when the file is invalid. */
    onEditForm: (() => void) | null;
}) {
    const [text, setText] = useState(contents.revision);
    const client = useQueryClient();
    const toast = useToast();
    const save = useMutation({
        mutationFn: () => saveRulesToml(file, contents.revision, text),
        onSuccess: async (result) => {
            // Stay in the TOML editor even when the saved file could be edited as a form.
            onSaved();
            client.setQueryData(["rules", file], result);
            toast("Changes saved.");
            await client.invalidateQueries({ queryKey: ["rules"], exact: true });
        },
    });
    const dirty = text !== contents.revision;
    const conflict = save.error?.message.includes("Reload") ?? false;

    /** Save the text unless it is unchanged or already being saved. */
    function submit() {
        if (dirty && !save.isPending) {
            save.mutate();
        }
    }

    /** Ask before discarding edits, then load the file again. */
    function reload() {
        if (!dirty || window.confirm(`Reload ${file} and discard unsaved edits?`)) {
            void onReload();
        }
    }

    /** Ask before discarding edits, then switch to the form editor. */
    function editForm() {
        if (
            onEditForm &&
            (!dirty || window.confirm("Discard unsaved TOML edits and edit as a form?"))
        ) {
            onEditForm();
        }
    }

    return (
        <form
            className="pb-24"
            onSubmit={(event) => {
                event.preventDefault();
                submit();
            }}
        >
            <BackToFiles />
            <PageHeader
                title={file}
                description={
                    <>
                        {path && (
                            <span className="mb-1 block">
                                <FilePath path={path} />
                            </span>
                        )}
                        Saved TOML is validated and enforced immediately. Comments and formatting
                        are saved exactly as written.
                    </>
                }
                actions={
                    <>
                        <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={save.isPending}
                            onClick={reload}
                        >
                            <RefreshIcon />
                            Reload from file
                        </button>
                        {onEditForm && (
                            <button
                                type="button"
                                className="btn btn-secondary"
                                disabled={save.isPending}
                                onClick={editForm}
                            >
                                Edit as form
                            </button>
                        )}
                    </>
                }
            />
            {(save.error || contents.error) && (
                <div className="mb-3">
                    <ErrorBanner>
                        {save.error ? (
                            <ErrorDetails heading="Not saved" message={save.error.message} />
                        ) : (
                            <ErrorDetails
                                heading={`${file} is invalid, so rule changes are not applied until it is fixed.`}
                                message={contents.error ?? ""}
                            />
                        )}
                    </ErrorBanner>
                </div>
            )}
            <div className="panel overflow-hidden">
                <CodeMirror
                    value={text}
                    onChange={(value) => {
                        save.reset();
                        setText(value);
                    }}
                    editable={!save.isPending}
                    theme="dark"
                    minHeight="20rem"
                    extensions={tomlExtensions}
                    aria-label={`${file} TOML`}
                />
            </div>
            {(dirty || save.isPending || conflict) && (
                <div className="fixed inset-x-0 bottom-0 z-40 border-t border-white/10 bg-zinc-950/90 backdrop-blur">
                    <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
                        <p className="flex min-w-0 flex-1 items-center gap-2 text-sm text-zinc-300">
                            <span className="size-2 rounded-full bg-amber-400" />
                            Unsaved changes
                        </p>
                        <div className="flex gap-2">
                            {conflict ? (
                                <button
                                    type="button"
                                    className="btn btn-secondary"
                                    onClick={reload}
                                >
                                    Reload from file
                                </button>
                            ) : (
                                <button
                                    type="button"
                                    className="btn btn-ghost"
                                    disabled={save.isPending || !dirty}
                                    onClick={onDiscard}
                                >
                                    Discard
                                </button>
                            )}
                            <button
                                type="submit"
                                className="btn btn-primary"
                                disabled={save.isPending || !dirty}
                            >
                                {save.isPending && <Spinner />}
                                {save.isPending ? "Saving…" : "Save changes"}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </form>
    );
}

/** Link back to the list of rule files. */
function BackToFiles() {
    return (
        <Link
            to="/rules"
            className="mb-3 inline-flex items-center gap-1 text-sm text-zinc-400 transition hover:text-zinc-100"
        >
            <ChevronIcon className="size-4 rotate-90" />
            All rule files
        </Link>
    );
}

/** Edit the allow tables of one rule file and save them as one revision-checked document. */
function Editor({
    file,
    path,
    document,
    expanded,
    setExpanded,
    filter,
    setFilter,
    onReload,
    onDiscard,
    onEditToml,
}: {
    file: string;
    path: string | undefined;
    document: RulesDocument;
    expanded: Set<number>;
    setExpanded: (update: (previous: Set<number>) => Set<number>) => void;
    filter: string;
    setFilter: (value: string) => void;
    onReload: () => Promise<void>;
    onDiscard: () => void;
    onEditToml: () => void;
}) {
    // Stable React keys keep each card's local text when other rules are added or removed.
    const [items, setItems] = useState(() =>
        document.rules.map((rule, position) => ({ key: position, rule })),
    );
    const nextKey = useRef(document.rules.length);
    const rules = items.map((item) => item.rule);
    const client = useQueryClient();
    const toast = useToast();
    const save = useMutation({
        mutationFn: () =>
            api<RulesDocument>(rulesPath(file), "PUT", { revision: document.revision, rules }),
        onSuccess: async (result) => {
            client.setQueryData(["rules", file], result);
            toast("Changes saved.");
            await client.invalidateQueries({ queryKey: ["rules"], exact: true });
        },
        onError: (error) => {
            const number = invalidRuleNumber(error.message);
            if (number !== null) {
                setExpanded((previous) => new Set(previous).add(number - 1));
            }
        },
    });
    const dirty = JSON.stringify(rules) !== JSON.stringify(document.rules);
    const invalid = save.error ? invalidRuleNumber(save.error.message) : null;
    const conflict = save.error?.message.includes("Reload") ?? false;
    const needle = filter.trim().toLowerCase();

    /** Replace one rule's fields, clearing any stale save error. */
    function update(position: number, fields: Record<string, FieldValue>) {
        save.reset();
        setItems((previous) =>
            previous.map((item, index) =>
                index === position ? { ...item, rule: { ...item.rule, fields } } : item,
            ),
        );
    }

    /** Add an empty rule at the top and open it for editing. */
    function addRule() {
        save.reset();
        setFilter("");
        const key = nextKey.current;
        nextKey.current += 1;
        setItems((previous) => [
            { key, rule: { index: null, fields: { domain: "" } } },
            ...previous,
        ]);
        setExpanded((previous) => new Set([0, ...[...previous].map((index) => index + 1)]));
    }

    /** Remove one rule, keeping the remaining rules' disclosure states. */
    function removeRule(position: number) {
        save.reset();
        setItems((previous) => previous.filter((_, index) => index !== position));
        setExpanded(
            (previous) =>
                new Set(
                    [...previous]
                        .filter((index) => index !== position)
                        .map((index) => (index > position ? index - 1 : index)),
                ),
        );
    }

    /** Ask before discarding edits, then load the file again. */
    function reload() {
        if (!dirty || window.confirm(`Reload ${file} and discard unsaved edits?`)) {
            void onReload();
        }
    }

    /** Ask before discarding edits, then switch to the TOML editor. */
    function editToml() {
        if (!dirty || window.confirm("Discard unsaved edits and edit as TOML?")) {
            onEditToml();
        }
    }

    const visible = items
        .map((item, position) => ({ ...item, position }))
        .filter(
            ({ rule }) =>
                [...lines(rule.fields.domain), ...lines(rule.fields.domain_regex)].some((domain) =>
                    domain.toLowerCase().includes(needle),
                ) || needle === "",
        );
    return (
        <form
            className="pb-24"
            onSubmit={(event) => {
                event.preventDefault();
                save.mutate();
            }}
        >
            <BackToFiles />
            <PageHeader
                title={file}
                description={
                    <>
                        {path && (
                            <span className="mb-1 block">
                                <FilePath path={path} />
                            </span>
                        )}
                        Rules in other files stay active and are not shown here. Saved rules are
                        validated and enforced immediately.
                    </>
                }
                actions={
                    <>
                        <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={save.isPending}
                            onClick={reload}
                        >
                            <RefreshIcon />
                            Reload from file
                        </button>
                        <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={save.isPending}
                            onClick={editToml}
                        >
                            <CodeIcon />
                            Edit as TOML
                        </button>
                        <button
                            type="button"
                            className="btn btn-primary"
                            disabled={save.isPending}
                            onClick={addRule}
                        >
                            <PlusIcon />
                            Add rule
                        </button>
                    </>
                }
            />
            <details className="group panel mb-4 px-4 py-3 text-sm text-zinc-400">
                <summary className="flex cursor-pointer list-none items-center gap-2 font-medium text-zinc-300 select-none">
                    <ChevronIcon className="size-4 -rotate-90 transition group-open:rotate-0" />
                    How rules work
                </summary>
                <ul className="mt-2 ml-6 list-disc space-y-1">
                    <li>
                        Every rule allows DNS lookups for its domains. Unless it is DNS only, it
                        also allows HTTP and HTTPS requests that match its methods and paths.
                    </li>
                    <li>
                        Enter one domain, pattern, or regex per line. Leave paths empty to allow
                        every path.
                    </li>
                    <li>
                        Path patterns use URLPattern syntax such as{" "}
                        <code className="text-zinc-300">/api/*</code> or{" "}
                        <code className="text-zinc-300">/items/:id</code>. Path regexes match the
                        pathname without the query string.
                    </li>
                    <li>Injected headers are only added to HTTPS requests.</li>
                </ul>
            </details>
            {rules.length > 0 && (
                <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                    <p className="text-sm text-zinc-500">
                        {rules.length} {rules.length === 1 ? "rule" : "rules"}
                    </p>
                    <FilterInput
                        label="Filter rules"
                        placeholder="Filter by domain"
                        value={filter}
                        onChange={setFilter}
                    />
                </div>
            )}
            {rules.length === 0 && (
                <div className="panel">
                    <EmptyState title={`No rules in ${file} yet`}>
                        {file === webRulesFile
                            ? "Add a rule here, or allow blocked domains from the Traffic page."
                            : "Add a rule here."}
                    </EmptyState>
                </div>
            )}
            {rules.length > 0 && visible.length === 0 && (
                <div className="panel">
                    <EmptyState title="No matching rules" />
                </div>
            )}
            <div className="space-y-2">
                {visible.map(({ key, rule, position }) => (
                    <RuleCard
                        key={key}
                        number={position + 1}
                        rule={rule}
                        open={expanded.has(position)}
                        invalid={invalid === position + 1}
                        disabled={save.isPending}
                        onToggle={() =>
                            setExpanded((previous) => {
                                const next = new Set(previous);
                                if (!next.delete(position)) {
                                    next.add(position);
                                }
                                return next;
                            })
                        }
                        onChange={(fields) => update(position, fields)}
                        onRemove={() => removeRule(position)}
                    />
                ))}
            </div>
            {(dirty || save.error || save.isPending) && (
                <div className="fixed inset-x-0 bottom-0 z-40 border-t border-white/10 bg-zinc-950/90 backdrop-blur">
                    <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
                        <div className="min-w-0 flex-1">
                            {save.error ? (
                                <ErrorBanner>{save.error.message}</ErrorBanner>
                            ) : (
                                <p className="flex items-center gap-2 text-sm text-zinc-300">
                                    <span className="size-2 rounded-full bg-amber-400" />
                                    Unsaved changes
                                </p>
                            )}
                        </div>
                        <div className="flex gap-2">
                            {conflict ? (
                                <button
                                    type="button"
                                    className="btn btn-secondary"
                                    onClick={reload}
                                >
                                    Reload from file
                                </button>
                            ) : (
                                <button
                                    type="button"
                                    className="btn btn-ghost"
                                    disabled={save.isPending || !dirty}
                                    onClick={onDiscard}
                                >
                                    Discard
                                </button>
                            )}
                            <button
                                type="submit"
                                className="btn btn-primary"
                                disabled={save.isPending || !dirty}
                            >
                                {save.isPending && <Spinner />}
                                {save.isPending ? "Saving…" : "Save changes"}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </form>
    );
}

/** Summarize a rule's scope in badges for its collapsed header. */
function RuleSummary({ fields }: { fields: Record<string, FieldValue> }) {
    const regex = fields.domain_regex !== undefined;
    const domains = lines(regex ? fields.domain_regex : fields.domain).filter((item) =>
        item.trim(),
    );
    const paths = [...lines(fields.pathname_pattern), ...lines(fields.pathname_regex)];
    const headers = headerRows(fields.inject_headers).length;
    const methods = lines(fields.methods);
    let methodLabel = "GET, HEAD";
    if (methodMode(fields.methods) === "any") {
        methodLabel = "Any method";
    } else if (methods.length > 0) {
        methodLabel = methods.join(", ");
    }
    let pathLabel = "All paths";
    if (paths.length === 1) {
        pathLabel = paths[0] ?? "";
    } else if (paths.length > 1) {
        pathLabel = `${paths.length} paths`;
    }
    let domainLabel: ReactNode = <span className="text-zinc-500 italic">No domain</span>;
    if (domains.length > 0) {
        domainLabel = (
            <span className="truncate font-mono text-[13px] font-medium text-zinc-100">
                {domains.slice(0, 3).join(", ")}
                {domains.length > 3 && (
                    <span className="text-zinc-500"> +{domains.length - 3} more</span>
                )}
            </span>
        );
    }
    return (
        <span className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1">
            {domainLabel}
            <span className="flex flex-wrap gap-1.5">
                {regex && <span className="badge badge-neutral">Regex</span>}
                {fields.include_subdomains === true && (
                    <span className="badge badge-neutral">+ Subdomains</span>
                )}
                {fields.dns_only === true ? (
                    <span className="badge badge-info">DNS only</span>
                ) : (
                    <>
                        <span className="badge badge-allow">{methodLabel}</span>
                        <span className="badge badge-neutral max-w-[16rem] truncate font-mono">
                            {pathLabel}
                        </span>
                    </>
                )}
                {headers > 0 && (
                    <span className="badge badge-warn">
                        {headers} {headers === 1 ? "header" : "headers"}
                    </span>
                )}
            </span>
        </span>
    );
}

/** One collapsible rule with its summary and full editor. */
function RuleCard({
    number,
    rule,
    open,
    invalid,
    disabled,
    onToggle,
    onChange,
    onRemove,
}: {
    number: number;
    rule: RuleDraft;
    open: boolean;
    invalid: boolean;
    disabled: boolean;
    onToggle: () => void;
    onChange: (fields: Record<string, FieldValue>) => void;
    onRemove: () => void;
}) {
    let ring = "border-white/10";
    if (invalid) {
        ring = "border-rose-500/60";
    } else if (open) {
        ring = "border-white/20";
    }
    return (
        <section
            aria-label={`Rule ${number}`}
            className={`rounded-xl border bg-zinc-900/60 transition ${ring}`}
        >
            <div className="flex items-center gap-2 pr-2">
                <button
                    type="button"
                    aria-expanded={open}
                    aria-controls={`rule-${number}-body`}
                    aria-label={`Rule ${number}`}
                    onClick={onToggle}
                    className="flex min-w-0 flex-1 items-center gap-3 rounded-xl px-4 py-3 text-left focus-visible:ring-2 focus-visible:ring-emerald-400/60 focus-visible:outline-none"
                >
                    <ChevronIcon
                        className={`size-4 shrink-0 text-zinc-500 transition ${open ? "" : "-rotate-90"}`}
                    />
                    <span className="w-6 shrink-0 text-xs font-medium text-zinc-500 tabular-nums">
                        #{number}
                    </span>
                    <RuleSummary fields={rule.fields} />
                </button>
                <button
                    type="button"
                    className="btn btn-icon btn-danger"
                    aria-label={`Remove rule ${number}`}
                    title="Remove rule"
                    disabled={disabled}
                    onClick={onRemove}
                >
                    <TrashIcon />
                </button>
            </div>
            {open && (
                <fieldset
                    id={`rule-${number}-body`}
                    disabled={disabled}
                    className="border-t border-white/10 px-4 py-5 sm:px-5"
                >
                    <RuleFields number={number} fields={rule.fields} onChange={onChange} />
                </fieldset>
            )}
        </section>
    );
}

/** Edit every field of one rule, grouped into domain and HTTP sections. */
function RuleFields({
    number,
    fields,
    onChange,
}: {
    number: number;
    fields: Record<string, FieldValue>;
    onChange: (fields: Record<string, FieldValue>) => void;
}) {
    const name = `Rule ${number}`;
    const regex = fields.domain_regex !== undefined;
    const dnsOnly = fields.dns_only === true;
    const mode = methodMode(fields.methods);

    /** Set or omit one field. */
    function set(key: string, value: FieldValue | undefined) {
        const next = { ...fields };
        if (value === undefined) {
            delete next[key];
        } else {
            next[key] = value;
        }
        onChange(next);
    }

    /** Move the domain list between exact and regex matching. */
    function setDomainKind(kind: "exact" | "regex") {
        if (kind === (regex ? "regex" : "exact")) {
            return;
        }
        const next = { ...fields };
        const value = regex ? fields.domain_regex : fields.domain;
        delete next.domain;
        delete next.domain_regex;
        next[kind === "regex" ? "domain_regex" : "domain"] = value ?? "";
        if (kind === "regex") {
            delete next.include_subdomains;
        }
        onChange(next);
    }

    const domainKey = regex ? "domain_regex" : "domain";
    const hasDomain = lines(fields[domainKey]).some((item) => item.trim());
    return (
        <div className="grid gap-x-8 gap-y-6 lg:grid-cols-2">
            <div className="space-y-4">
                <h3 className="text-sm font-semibold text-white">Domains</h3>
                <div>
                    <div className="mb-2 flex items-center justify-between gap-2">
                        <span className="field-label mb-0">Match</span>
                        <Segmented
                            label={`${name} domain matching`}
                            value={regex ? "regex" : "exact"}
                            options={[
                                { value: "exact", label: "Exact names" },
                                { value: "regex", label: "Regex" },
                            ]}
                            onChange={setDomainKind}
                        />
                    </div>
                    <LinesField
                        key={domainKey}
                        label={regex ? `${name} domain regexes` : `${name} domains`}
                        value={fields[domainKey]}
                        placeholder={
                            regex ? "^.*\\.example\\.com$" : "example.com\napi.example.org"
                        }
                        onChange={(value) => set(domainKey, value ?? "")}
                    />
                    {hasDomain ? (
                        <p className="field-hint">
                            {regex
                                ? "One case-insensitive regex per line."
                                : "One domain or IP address per line."}
                        </p>
                    ) : (
                        <p className="field-hint text-amber-300/90">
                            Add at least one {regex ? "regex" : "domain"}.
                        </p>
                    )}
                </div>
                <Switch
                    label={`${name} include subdomains`}
                    title="Include subdomains"
                    description={
                        regex
                            ? "Not available with regex matching."
                            : "Also match every name below these domains."
                    }
                    checked={fields.include_subdomains === true}
                    disabled={regex}
                    onChange={(checked) => set("include_subdomains", checked ? true : undefined)}
                />
                <Switch
                    label={`${name} DNS only`}
                    title="DNS only"
                    description="Resolve these names but keep blocking HTTP(S) to them."
                    checked={dnsOnly}
                    onChange={(checked) => set("dns_only", checked ? true : undefined)}
                />
            </div>
            <div className={`space-y-4 transition ${dnsOnly ? "opacity-50" : ""}`}>
                <div className="flex items-baseline justify-between gap-2">
                    <h3 className="text-sm font-semibold text-white">HTTP(S) access</h3>
                    {dnsOnly && (
                        <span className="text-xs text-zinc-500">Unused while DNS only is on</span>
                    )}
                </div>
                <div>
                    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                        <span className="field-label mb-0">Methods</span>
                        <Segmented<MethodMode>
                            label={`${name} methods`}
                            value={mode}
                            options={[
                                { value: "default", label: "GET & HEAD" },
                                { value: "any", label: "Any method" },
                                { value: "custom", label: "Custom" },
                            ]}
                            onChange={(next) => {
                                if (next === "default") {
                                    set("methods", undefined);
                                } else if (next === "any") {
                                    set("methods", "ANY");
                                } else if (mode !== "custom") {
                                    set("methods", ["GET", "HEAD"]);
                                }
                            }}
                        />
                    </div>
                    {mode === "custom" && (
                        <MethodPicker
                            label={`${name} custom methods`}
                            methods={lines(fields.methods)}
                            onChange={(methods) => set("methods", methods)}
                        />
                    )}
                </div>
                <div>
                    <label className="field-label" htmlFor={`rule-${number}-patterns`}>
                        Path patterns
                    </label>
                    <LinesField
                        id={`rule-${number}-patterns`}
                        label={`${name} path patterns`}
                        value={fields.pathname_pattern}
                        placeholder={"/api/*\n/items/:id"}
                        onChange={(value) => set("pathname_pattern", value)}
                    />
                </div>
                <div>
                    <label className="field-label" htmlFor={`rule-${number}-regexes`}>
                        Path regexes
                    </label>
                    <LinesField
                        id={`rule-${number}-regexes`}
                        label={`${name} path regexes`}
                        value={fields.pathname_regex}
                        placeholder="^/reports/[0-9]+$"
                        onChange={(value) => set("pathname_regex", value)}
                    />
                    <p className="field-hint">
                        A request matching any pattern or regex is allowed. Leave both empty to
                        allow every path.
                    </p>
                </div>
            </div>
            <div className="lg:col-span-2">
                <HeadersField
                    name={name}
                    headers={headerRows(fields.inject_headers)}
                    onChange={(headers) =>
                        set("inject_headers", headers.length ? headers : undefined)
                    }
                />
            </div>
        </div>
    );
}

/** A textarea that stores one list item per non-empty line. */
function LinesField({
    id,
    label,
    value,
    placeholder,
    onChange,
}: {
    id?: string;
    label: string;
    value: FieldValue | undefined;
    placeholder: string;
    onChange: (value: FieldValue | undefined) => void;
}) {
    const [text, setText] = useState(() => lines(value).join("\n"));
    return (
        <textarea
            id={id}
            className="input resize-y font-mono text-[13px] leading-relaxed"
            aria-label={label}
            rows={Math.min(8, Math.max(2, text.split("\n").length))}
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            value={text}
            placeholder={placeholder}
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
    );
}

/** Toggle explicitly allowed HTTP methods, keeping uncommon ones from the file. */
function MethodPicker({
    label,
    methods,
    onChange,
}: {
    label: string;
    methods: string[];
    onChange: (methods: string[]) => void;
}) {
    const options = [
        ...commonMethods,
        ...methods.filter((method) => !commonMethods.includes(method)),
    ];
    return (
        <div>
            <div role="group" aria-label={label} className="flex flex-wrap gap-1.5">
                {options.map((method) => {
                    const checked = methods.includes(method);
                    return (
                        <button
                            key={method}
                            type="button"
                            role="checkbox"
                            aria-checked={checked}
                            onClick={() =>
                                onChange(
                                    checked
                                        ? methods.filter((item) => item !== method)
                                        : options.filter(
                                              (item) => item === method || methods.includes(item),
                                          ),
                                )
                            }
                            className={`rounded-md border px-2 py-1 font-mono text-xs transition ${
                                checked
                                    ? "border-emerald-400/50 bg-emerald-400/15 text-emerald-200"
                                    : "border-white/10 text-zinc-400 hover:border-white/20 hover:text-zinc-200"
                            }`}
                        >
                            {method}
                        </button>
                    );
                })}
            </div>
            {methods.length === 0 && (
                <p className="field-hint text-amber-300/90">Select at least one method.</p>
            )}
        </div>
    );
}

/** Edit the name/value rows of headers injected into HTTPS requests. */
function HeadersField({
    name,
    headers,
    onChange,
}: {
    name: string;
    headers: InjectedHeader[];
    onChange: (headers: InjectedHeader[]) => void;
}) {
    /** Replace one header row. */
    function edit(position: number, header: InjectedHeader) {
        onChange(headers.map((item, index) => (index === position ? header : item)));
    }
    return (
        <div className="rounded-lg border border-white/10 bg-zinc-950/40 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                    <h3 className="text-sm font-semibold text-white">Injected headers</h3>
                    <p className="text-xs text-zinc-500">
                        Added to matching HTTPS requests before they reach the server.
                    </p>
                </div>
                <button
                    type="button"
                    className="btn btn-sm btn-secondary"
                    onClick={() => onChange([...headers, { name: "", value: "" }])}
                >
                    <PlusIcon className="size-3.5" />
                    Add header
                </button>
            </div>
            {headers.length > 0 && (
                <div className="mt-3 space-y-2">
                    {headers.map((header, index) => (
                        <div key={index} className="flex items-center gap-2">
                            <input
                                className="input flex-1 font-mono text-[13px]"
                                aria-label={`${name} header ${index + 1} name`}
                                placeholder="Header-Name"
                                required
                                value={header.name}
                                onChange={(event) =>
                                    edit(index, { ...header, name: event.target.value })
                                }
                            />
                            <input
                                className="input flex-[2] font-mono text-[13px]"
                                aria-label={`${name} header ${index + 1} value`}
                                placeholder="Value"
                                value={header.value}
                                onChange={(event) =>
                                    edit(index, { ...header, value: event.target.value })
                                }
                            />
                            <button
                                type="button"
                                className="btn btn-icon btn-danger"
                                aria-label={`Remove ${name} header ${index + 1}`}
                                onClick={() =>
                                    onChange(headers.filter((_, position) => position !== index))
                                }
                            >
                                <TrashIcon />
                            </button>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
