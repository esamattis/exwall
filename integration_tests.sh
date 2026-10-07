#!/bin/sh
# Run local protocol tests and isolated Linux firewall lifecycle tests.
set -eu
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$scriptdir"
cargo build --locked
python3 tests/integration.py "$scriptdir/target/debug/ramawall"
if command -v unshare >/dev/null 2>&1 && unshare -Urn sh -c 'iptables -S >/dev/null && ip6tables -S >/dev/null' 2>/dev/null; then
    RAMAWALL_NAMESPACE_TEST=1 unshare -Urnm python3 tests/firewall_namespace.py "$scriptdir/target/debug/ramawall"
    RAMAWALL_NAMESPACE_TEST=1 unshare -Urn python3 tests/transparent_namespace.py "$scriptdir/target/debug/ramawall"
else
    echo 'SKIP: isolated firewall tests require unprivileged user/network namespaces and iptables'
fi
