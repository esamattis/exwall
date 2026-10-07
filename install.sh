#!/bin/sh
# Install a previously built debug binary and its systemd integration.
set -eu

# Explain a failed installation prerequisite and stop before further mutations.
die() {
    echo "install.sh: $*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || die "Linux is required"
[ "$(id -u)" -eq 0 ] || die "run as root"
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=${1:-"$scriptdir/target/debug/ramawall"}
[ -x "$binary" ] || die "missing executable: $binary; install.sh requires an existing binary and never builds it"
for command in systemctl iptables ip6tables sysctl openssl update-ca-certificates runuser; do
    command -v "$command" >/dev/null 2>&1 || die "missing dependency: $command"
done
if systemctl is-active --quiet mitmwall.service; then
    die "stop mitmwall.service before installing ramawall; both use the same interception ports"
fi

was_active=0
if systemctl is-active --quiet ramawall.service; then
    was_active=1
    # The existing unit and binary must perform cleanup before being replaced.
    systemctl stop ramawall.service
fi
if ! id ramawall >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin ramawall
fi
install -m 0755 "$binary" /usr/local/bin/ramawall
install -d -o root -g ramawall -m 0750 /etc/ramawall /etc/ramawall/rules.d
install -d -o ramawall -g ramawall -m 0700 /var/lib/ramawall
install -d -o ramawall -g ramawall -m 0700 /var/log/ramawall

# Preserve operator rules and configuration across repeated installs. Existing
# mitmwall TOML can be copied verbatim with its filename precedence intact.
if [ ! -f /etc/ramawall/config.toml ]; then
    config_source=$scriptdir/config-default.toml
    if [ -f /etc/mitmwall/config.toml ]; then
        config_source=/etc/mitmwall/config.toml
    fi
    install -o root -g ramawall -m 0640 "$config_source" /etc/ramawall/config.toml
fi
if [ -d /etc/mitmwall/rules.d ]; then
    for rule in /etc/mitmwall/rules.d/*.toml; do
        [ -f "$rule" ] || continue
        destination=/etc/ramawall/rules.d/$(basename "$rule")
        if [ ! -e "$destination" ]; then
            install -o root -g ramawall -m 0640 "$rule" "$destination"
        fi
    done
fi
if ! find /etc/ramawall/rules.d -maxdepth 1 -name '*.toml' -print -quit | read -r unused; then
    install -o root -g ramawall -m 0640 "$scriptdir/example-rules.toml" /etc/ramawall/rules.d/5-examples.toml
fi
runuser -u ramawall -- /usr/local/bin/ramawall check
runuser -u ramawall -- /usr/local/bin/ramawall init-ca
install -m 0644 /var/lib/ramawall/ramawall-ca-cert.pem /usr/local/share/ca-certificates/ramawall.crt
update-ca-certificates
install -m 0644 "$scriptdir/systemd/ramawall.service" /etc/systemd/system/ramawall.service

# Replace only the environment block owned by this installer.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
if [ -f /etc/environment ]; then
    sed '/^# ramawall-start$/,/^# ramawall-end$/d' /etc/environment > "$tmpdir/environment"
else
    : > "$tmpdir/environment"
fi
cat > "$tmpdir/assignments" <<'ENV'
NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/ramawall.crt
SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV
printf '\n# ramawall-start\n' >> "$tmpdir/environment"
cat "$tmpdir/assignments" >> "$tmpdir/environment"
printf '# ramawall-end\n' >> "$tmpdir/environment"
install -m 0644 "$tmpdir/environment" /etc/environment
printf 'export NODE_EXTRA_CA_CERTS SSL_CERT_FILE REQUESTS_CA_BUNDLE\n' > "$tmpdir/profile"
cat "$tmpdir/assignments" >> "$tmpdir/profile"
install -m 0644 "$tmpdir/profile" /etc/profile.d/ramawall.sh
systemctl daemon-reload
if [ "$was_active" -eq 1 ]; then
    systemctl start ramawall.service
    systemctl is-active --quiet ramawall.service
fi
printf '\nInstalled. Start with: sudo systemctl enable --now ramawall\n'
printf 'Logs: sudo journalctl -u ramawall -f\n'
printf 'Access log: /var/log/ramawall/access.log\n'
printf 'Reload rules: sudo systemctl reload ramawall\n'
printf 'Current shell CA settings: . /etc/profile.d/ramawall.sh\n'
