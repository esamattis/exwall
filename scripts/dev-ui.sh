#!/bin/sh
# Run a throwaway exwall with the web UI on localhost for manual UI checks.
#
# Everything lives in a temporary directory that is removed on exit. Only
# localhost listeners are opened; no installer, hook, or firewall change runs.
#
# Environment overrides:
#   EXWALL_DEV_UI_PORT     web UI port (default 58911)
#   EXWALL_DEV_PROXY_PORT  HTTP(S) proxy port (default 58981)
#   EXWALL_DEV_DNS_PORT    DNS port (default 58983)
#   EXWALL_DEV_SKIP_BUILD  set to 1 to reuse the current ui/dist and binary
set -eu
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$scriptdir/.."

ui_port=${EXWALL_DEV_UI_PORT:-58911}
proxy_port=${EXWALL_DEV_PROXY_PORT:-58981}
dns_port=${EXWALL_DEV_DNS_PORT:-58983}
username=admin
password=dev

if [ "${EXWALL_DEV_SKIP_BUILD:-0}" != 1 ]; then
    mise exec -- pnpm build:ui
    cargo build --locked
fi

directory=$(mktemp -d "${TMPDIR:-/tmp}/exwall-dev-ui.XXXXXX")
pid=
cleanup() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$directory"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$directory/rules"
# The start hook creates the UI-managed rule file in production.
touch "$directory/rules/05-web.toml"
cat > "$directory/config.toml" <<EOF
[ui]
hosts = ["127.0.0.1"]
port = $ui_port
username = "$username"
password = "$password"
sessions_dir = "$directory/sessions/"

[access_log]
path = "$directory/access.log"
EOF
cargo run --locked --quiet -- init-ca --ca-dir "$directory/ca" >/dev/null

cargo run --locked --quiet -- --rules-dir "$directory/rules" serve \
    --config "$directory/config.toml" \
    --listen "127.0.0.1:$proxy_port" \
    --dns-listen "127.0.0.1:$dns_port" \
    --ca-dir "$directory/ca" &
pid=$!

cat <<EOF

exwall dev UI:  http://127.0.0.1:$ui_port/
Login:          $username / $password
Proxy:          127.0.0.1:$proxy_port (CA: $directory/ca/exwall-ca-cert.pem)
DNS:            127.0.0.1:$dns_port
Rules:          $directory/rules
Access log:     $directory/access.log
Press Ctrl-C or send SIGTERM to stop and delete $directory.

EOF
wait "$pid"
