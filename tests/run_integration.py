"""Run protocol and disposable firewall suites while preserving host connectivity."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def run(command, **kwargs):
    """Execute a bounded test or read-only prerequisite command."""
    return subprocess.run(command, check=True, timeout=240, **kwargs)


def host_snapshot(privilege):
    """Record host policy and files that privileged tests must leave unchanged."""
    snapshot = []
    for command in (
        ["iptables-save"],
        ["ip6tables-save"],
        ["sysctl", "-n", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
         "net.ipv4.conf.all.send_redirects"],
    ):
        output = run([*privilege, *command], capture_output=True, text=True).stdout
        # Timestamps and policy packet/byte counters change without policy changes.
        snapshot.append("\n".join(re.sub(r"\[\d+:\d+\]", "[0:0]", line)
                                  for line in output.splitlines()
                                  if not line.startswith("#")))
    for name in ("/etc/resolv.conf", "/etc/ssl/certs/ca-certificates.crt",
                 "/etc/hosts", "/etc/passwd"):
        path = Path(name)
        metadata = path.lstat()
        snapshot.append((path.read_bytes(), metadata.st_mode, metadata.st_uid, metadata.st_gid,
                         os.readlink(path) if path.is_symlink() else None))
    return snapshot


def main():
    """Select available namespace privileges and verify host state around all suites."""
    binary = str(Path(sys.argv[1]).resolve())
    tests = Path(__file__).resolve().parent
    environment = {**os.environ,
                   "RAMAWALL_NAMESPACE_TEST": "1",
                   "RAMAWALL_HOST_NET_NS": os.readlink("/proc/self/ns/net"),
                   "RAMAWALL_HOST_MNT_NS": os.readlink("/proc/self/ns/mnt")}
    # Ambient proxy/CA settings must not send local fixtures to a host service.
    for name in list(environment):
        if name.lower().endswith("_proxy") or name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
            environment.pop(name)
    privilege = [] if os.geteuid() == 0 else ["sudo", "-n"]
    privileged = os.geteuid() == 0 or (
        shutil.which("sudo") is not None
        and subprocess.run([*privilege, "true"], capture_output=True, timeout=5).returncode == 0
    )
    before = host_snapshot(privilege) if privileged else None
    try:
        print("Host access to chatgpt.com/openai.com is preserved: firewall tests use isolated networks.",
              flush=True)
        run([sys.executable, str(tests / "integration.py"), binary], env=environment)
        # sudo clears custom variables; pass the host namespace identities explicitly.
        identities = [f"{name}={environment[name]}"
                      for name in ("RAMAWALL_HOST_NET_NS", "RAMAWALL_HOST_MNT_NS")]
        prefix = [*privilege, "env", *identities,
                  "unshare", "--net", "--mount", "--propagation", "private"]
        if not privileged:
            prefix = ["unshare", "-Urnm", "--propagation", "private"]
        probe = subprocess.run(
            [*prefix, "sh", "-c", "iptables -S >/dev/null && ip6tables -S >/dev/null"],
            capture_output=True, timeout=10)
        if probe.returncode:
            print("SKIP: disposable firewall namespaces unavailable: "
                  + probe.stderr.decode().strip(), flush=True)
            return
        for name in ("firewall_namespace.py", "transparent_namespace.py"):
            run([*prefix, sys.executable, str(tests / name), binary], env=environment)
        if privileged:
            run([*prefix, sys.executable, str(tests / "mitmwall_namespace.py"), binary],
                env=environment)
        else:
            print("SKIP: full mitmwall port needs root or passwordless sudo for multiple UIDs/veth",
                  flush=True)
    finally:
        if before is not None and host_snapshot(privilege) != before:
            raise RuntimeError("integration tests changed host firewall, sysctls, resolver, or trust")
    if before is not None:
        print("PASS: host firewall, sysctls, resolver, trust store, hosts, and accounts unchanged",
              flush=True)


if __name__ == "__main__":
    main()
