"""Reject live firewall tests unless both network and mount isolation are verified."""

import json
import os
import subprocess


def assert_namespace():
    """Require a fresh namespace distinct from the integration launcher's host."""
    for kind in ("net", "mnt"):
        original = os.environ.get(f"EXWALL_HOST_{kind.upper()}_NS")
        current = os.readlink(f"/proc/self/ns/{kind}")
        if not original or current == original:
            raise RuntimeError(f"refusing firewall tests without a disposable {kind} namespace")
    if os.geteuid() != 0:
        raise RuntimeError("namespace firewall tests require namespace-local root")
    interfaces = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    if {entry["ifname"] for entry in interfaces} != {"lo"}:
        raise RuntimeError("refusing tests in a namespace with existing network interfaces")
