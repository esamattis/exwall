import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
    createRootRoute,
    createRoute,
    createRouter,
    Outlet,
    RouterProvider,
} from "@tanstack/react-router";
import "./style.css";

/** Render the first page of the exwall control UI. */
function HelloWorld() {
    return (
        <main className="flex min-h-screen items-center justify-center bg-slate-950 px-6 text-slate-100">
            <div className="w-full max-w-xl rounded-2xl border border-slate-800 bg-slate-900 p-10">
                <p className="mb-8 text-sm font-semibold tracking-widest text-teal-400">exwall</p>
                <h1 className="text-4xl font-semibold tracking-tight">Hello world</h1>
                <p className="mt-4 text-lg text-slate-400">Welcome to the exwall UI.</p>
            </div>
        </main>
    );
}

const rootRoute = createRootRoute({ component: Outlet });
const indexRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/",
    component: HelloWorld,
});
const router = createRouter({ routeTree: rootRoute.addChildren([indexRoute]) });
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
