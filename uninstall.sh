#!/bin/sh
# Remove managed integration; preserve operator configuration and CA unless purged.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "uninstall.sh: run as root" >&2; exit 1; }
case "${1:-}" in
    ""|--purge) ;;
    *) echo "usage: $0 [--purge]" >&2; exit 2 ;;
esac
if systemctl cat ramawall.service >/dev/null 2>&1; then
    systemctl disable --now ramawall.service
fi
# Cleanup is independent of TOML parsing and can also remove a failed start.
if [ -x /usr/local/bin/ramawall ]; then
    /usr/local/bin/ramawall hook stop
fi
rm -f /etc/systemd/system/ramawall.service /usr/local/bin/ramawall
rm -f /usr/local/share/ca-certificates/ramawall.crt /etc/profile.d/ramawall.sh
if [ -f /etc/environment ]; then
    tmpfile=$(mktemp)
    trap 'rm -f "$tmpfile"' EXIT
    sed '/^# ramawall-start$/,/^# ramawall-end$/d' /etc/environment > "$tmpfile"
    install -m 0644 "$tmpfile" /etc/environment
fi
update-ca-certificates
systemctl daemon-reload
if [ "${1:-}" = --purge ]; then
    rm -rf /etc/ramawall /var/lib/ramawall /run/ramawall
    if id ramawall >/dev/null 2>&1; then
        userdel ramawall
    fi
    if getent group ramawall >/dev/null 2>&1; then
        groupdel ramawall
    fi
fi
