/**
 * Guards privileged fixture setup against accidental host execution and captures
 * firewall, forwarding, and host state for isolation and restoration checks.
 * @module
 */

import { lstat, readFile, readlink } from "node:fs/promises";
import { runCommand } from "#playwright_helpers/processes.mts";

/** Forwarding settings that production hooks must restore exactly. */
export const forwardingSysctls = [
    "net.ipv4.ip_forward",
    "net.ipv6.conf.all.forwarding",
    "net.ipv4.conf.all.send_redirects",
];

/** Reject hook execution unless fresh network and mount namespaces are verified. */
export async function assertIsolated(): Promise<void> {
    if (process.getuid?.() !== 0)
        throw new Error("Namespace fixtures require namespace-local root");
    for (const kind of ["net", "mnt"]) {
        const original = process.env[`EXWALL_HOST_${kind.toUpperCase()}_NS`];
        if (!original || (await readlink(`/proc/self/ns/${kind}`)) === original) {
            throw new Error(`Refusing firewall hooks without a disposable ${kind} namespace`);
        }
    }
    const interfaces: { ifname: string }[] = JSON.parse(
        await runCommand(["ip", "-j", "link", "show"]),
    );
    if (interfaces.length !== 1 || interfaces[0]?.ifname !== "lo") {
        throw new Error("Refusing fixtures in a namespace with existing network interfaces");
    }
}

/** Capture namespace firewall rules without counters so restoration can be compared. */
export async function firewallSnapshot(): Promise<string[]> {
    const result: string[] = [];
    for (const tool of ["iptables", "ip6tables"]) {
        for (const table of ["filter", "nat"])
            result.push(await runCommand([tool, "-t", table, "-S"]));
    }
    return result;
}

/** Capture forwarding and redirect values changed by the service hooks. */
export async function forwardingSnapshot(): Promise<string> {
    return runCommand(["sysctl", "-n", ...forwardingSysctls]);
}

/** Record host firewall, sysctls, resolver, trust, hosts, and account metadata. */
export async function hostSnapshot(privilege: string[]): Promise<string> {
    const snapshot: unknown[] = [];
    for (const args of [
        ["iptables-save"],
        ["ip6tables-save"],
        ["sysctl", "-n", ...forwardingSysctls],
    ]) {
        const output = await runCommand([...privilege, ...args]);
        snapshot.push(
            output
                .split("\n")
                .filter((line) => !line.startsWith("#"))
                .map((line) => line.replace(/\[\d+:\d+\]/g, "[0:0]"))
                .join("\n"),
        );
    }
    for (const path of [
        "/etc/resolv.conf",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/hosts",
        "/etc/passwd",
    ]) {
        const metadata = await lstat(path);
        snapshot.push({
            content: (await readFile(path)).toString("base64"),
            mode: metadata.mode,
            uid: metadata.uid,
            gid: metadata.gid,
            target: metadata.isSymbolicLink() ? await readlink(path) : null,
        });
    }
    return JSON.stringify(snapshot);
}
