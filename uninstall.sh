#!/bin/sh
# Remove managed integration; preserve operator configuration and CA unless purged.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "uninstall.sh: run as root" >&2; exit 1; }
case "${1:-}" in
    ""|--purge) ;;
    *) echo "usage: $0 [--purge]" >&2; exit 2 ;;
esac
if systemctl cat exwall.service >/dev/null 2>&1; then
    systemctl disable --now exwall.service
fi
# Cleanup is independent of TOML parsing and can also remove a failed start.
if [ -x /usr/local/bin/exwall ]; then
    /usr/local/bin/exwall hook stop
fi
rm -f /etc/systemd/system/exwall.service /usr/local/bin/exwall
rm -f /usr/local/share/ca-certificates/exwall.crt /etc/profile.d/exwall.sh
if [ -f /etc/environment ]; then
    tmpfile=$(mktemp)
    trap 'rm -f "$tmpfile"' EXIT
    sed '/^# exwall-start$/,/^# exwall-end$/d' /etc/environment > "$tmpfile"
    install -m 0644 "$tmpfile" /etc/environment
fi
update-ca-certificates
systemctl daemon-reload
if [ "${1:-}" = --purge ]; then
    rm -rf /etc/exwall /var/lib/exwall /var/log/exwall /run/exwall
    if id exwall >/dev/null 2>&1; then
        userdel exwall
    fi
    if getent group exwall >/dev/null 2>&1; then
        groupdel exwall
    fi
fi
