#!/usr/bin/env bash
#
# Installs exwall and its systemd integration.
#
# Usage:
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/esamattis/exwall/refs/heads/main/install.sh)"
#   ./install.sh                  # install the latest release
#   ./install.sh v0.1.0           # install a specific release tag
#   ./install.sh --binary PATH    # install a locally built binary
#
# Release installs download the archive for the host architecture and run the
# install.sh shipped inside it, which installs the binary next to it. The
# system installation runs as root and uses sudo when started as another user.
#
set -euo pipefail

REPO="esamattis/exwall"
BINARY_NAME="exwall"

# Declared at the top level so the EXIT trap (which runs in the global scope,
# not inside a function) can see it under set -u.
TMP_DIR=""

# Print to stderr with a prefix so install progress is distinguishable from
# output of the commands it runs.
err() {
    echo "install: error: $*" >&2
}

# Print an informational progress message.
info() {
    echo "install: $*"
}

# Report a failed prerequisite and stop before any further changes.
die() {
    err "$@"
    exit 1
}

# Remove the temporary directory, if one was created, when the script exits.
cleanup() {
    if [[ -n "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}

# Print the directory containing this script, or nothing when it was passed
# to `bash -c` instead of being run from a file.
script_dir() {
    local source="${BASH_SOURCE[0]:-}"
    if [[ -n "$source" && -f "$source" ]]; then
        (CDPATH="" cd -- "$(dirname -- "$source")" && pwd)
    fi
}

# Check that required tools are present before doing any network work.
require_tools() {
    local missing=()
    for tool in "$@"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done
    if [[ "${#missing[@]}" -gt 0 ]]; then
        die "missing required tools: ${missing[*]}"
    fi
}

# Resolve which release tag to install. The caller can pass an explicit tag;
# otherwise query the GitHub API for the latest release.
resolve_tag() {
    local requested="${1:-}"
    if [[ -n "$requested" ]]; then
        echo "$requested"
        return
    fi

    local api_url="https://api.github.com/repos/${REPO}/releases/latest"
    local tag
    # Field 4 of a `"tag_name": "v0.1.0",` line split on `"` is the tag value.
    if ! tag=$(curl -fsSL "$api_url" | grep -m1 '"tag_name"' | tr -d ' ,' | cut -d'"' -f4); then
        err "failed to fetch latest release from $api_url"
        return 1
    fi

    if [[ -z "$tag" ]]; then
        err "could not parse tag_name from latest release response"
        return 1
    fi
    echo "$tag"
}

# Map the host architecture to the archive name produced by
# .github/workflows/build.yml. Only targets built in CI are supported.
archive_name_for() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64) echo "exwall-x86_64-linux" ;;
        aarch64 | arm64) echo "exwall-aarch64-linux" ;;
        *)
            err "no release asset for arch '$arch' (only x86_64 and aarch64 are built)"
            return 1
            ;;
    esac
}

# Run a command as root, using sudo when the current user is not root.
run_as_root() {
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    else
        require_tools sudo
        sudo "$@"
    fi
}

# Download a release archive for this host and run the installer it contains.
install_release() {
    require_tools curl tar uname grep cut tr

    local tag archive
    tag="$(resolve_tag "${1:-}")" || exit 1
    archive="$(archive_name_for)" || exit 1

    # The GitHub releases download URL redirects to the asset of a specific
    # tag; curl -L follows the redirect.
    local download_url="https://github.com/${REPO}/releases/download/${tag}/${archive}.tar.gz"

    info "installing exwall ${tag} for Linux/$(uname -m)"
    info "downloading ${download_url}"

    TMP_DIR="$(mktemp -d)"
    trap cleanup EXIT

    local archive_path="${TMP_DIR}/${archive}.tar.gz"
    if ! curl -fsSL "$download_url" -o "$archive_path"; then
        die "download failed for ${download_url}"
    fi

    info "extracting archive"
    if ! tar -xzf "$archive_path" -C "$TMP_DIR"; then
        die "extraction failed"
    fi

    local package="${TMP_DIR}/${archive}"
    if [[ ! -x "${package}/${BINARY_NAME}" || ! -f "${package}/install.sh" ]]; then
        die "archive did not contain the '${BINARY_NAME}' binary and its installer"
    fi

    run_as_root bash "${package}/install.sh" --binary "${package}/${BINARY_NAME}"
}

# Install an existing binary with the config, rules, and unit files found in
# the support directory. Must run as root.
install_system() {
    local binary="$1"
    local support_dir="$2"

    [[ -x "$binary" ]] || die "missing executable: $binary; install.sh never builds exwall"
    for file in config-default.toml example-rules.toml systemd/exwall.service; do
        [[ -f "${support_dir}/${file}" ]] || die "missing installer file: ${support_dir}/${file}"
    done
    require_tools systemctl iptables ip6tables sysctl openssl update-ca-certificates runuser useradd
    if systemctl is-active --quiet mitmwall.service; then
        die "stop mitmwall.service before installing exwall; both use the same interception ports"
    fi

    local was_active=0
    if systemctl is-active --quiet exwall.service; then
        was_active=1
        # Stop using the old unit before replacing its binary and service definition.
        systemctl stop exwall.service
    fi
    if ! id exwall >/dev/null 2>&1; then
        useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin exwall
    fi
    install -m 0755 "$binary" /usr/local/bin/exwall
    install -d -o root -g exwall -m 0750 /etc/exwall /etc/exwall/rules.d
    install -d -o exwall -g exwall -m 0700 /var/lib/exwall
    install -d -o exwall -g exwall -m 0700 /var/log/exwall

    # Preserve operator rules and configuration across repeated installs. Existing
    # mitmwall TOML can be copied verbatim with its filename precedence intact.
    if [[ ! -f /etc/exwall/config.toml ]]; then
        local config_source="${support_dir}/config-default.toml"
        if [[ -f /etc/mitmwall/config.toml ]]; then
            config_source=/etc/mitmwall/config.toml
        fi
        install -o root -g exwall -m 0640 "$config_source" /etc/exwall/config.toml
    fi
    if [[ -d /etc/mitmwall/rules.d ]]; then
        local rule destination
        for rule in /etc/mitmwall/rules.d/*.toml; do
            [[ -f "$rule" ]] || continue
            destination="/etc/exwall/rules.d/$(basename "$rule")"
            if [[ ! -e "$destination" ]]; then
                install -o root -g exwall -m 0640 "$rule" "$destination"
            fi
        done
    fi
    if [[ -z "$(find /etc/exwall/rules.d -maxdepth 1 -name '*.toml' -print -quit)" ]]; then
        install -o root -g exwall -m 0640 "${support_dir}/example-rules.toml" /etc/exwall/rules.d/10-examples.toml
    fi
    runuser -u exwall -- /usr/local/bin/exwall check
    runuser -u exwall -- /usr/local/bin/exwall init-ca
    install -m 0644 /var/lib/exwall/exwall-ca-cert.pem /usr/local/share/ca-certificates/exwall.crt
    update-ca-certificates
    install -m 0644 "${support_dir}/systemd/exwall.service" /etc/systemd/system/exwall.service

    # Replace only the environment block owned by this installer.
    TMP_DIR="$(mktemp -d)"
    trap cleanup EXIT
    if [[ -f /etc/environment ]]; then
        sed '/^# exwall-start$/,/^# exwall-end$/d' /etc/environment >"${TMP_DIR}/environment"
    else
        : >"${TMP_DIR}/environment"
    fi
    cat >"${TMP_DIR}/assignments" <<'ENV'
NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/exwall.crt
SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV
    printf '\n# exwall-start\n' >>"${TMP_DIR}/environment"
    cat "${TMP_DIR}/assignments" >>"${TMP_DIR}/environment"
    printf '# exwall-end\n' >>"${TMP_DIR}/environment"
    install -m 0644 "${TMP_DIR}/environment" /etc/environment
    printf 'export NODE_EXTRA_CA_CERTS SSL_CERT_FILE REQUESTS_CA_BUNDLE\n' >"${TMP_DIR}/profile"
    cat "${TMP_DIR}/assignments" >>"${TMP_DIR}/profile"
    install -m 0644 "${TMP_DIR}/profile" /etc/profile.d/exwall.sh
    systemctl daemon-reload
    if [[ "$was_active" -eq 1 ]]; then
        systemctl start exwall.service
        systemctl is-active --quiet exwall.service
    fi
    printf '\nInstalled. Start with: sudo systemctl enable --now exwall\n'
    printf 'Logs: sudo journalctl -u exwall -f\n'
    printf 'Access log: /var/log/exwall/access.log\n'
    printf 'Reload rules: sudo systemctl reload exwall\n'
    printf 'Current shell CA settings: . /etc/profile.d/exwall.sh\n'
}

# Install a local binary, re-running this script through sudo when needed.
install_local() {
    local binary="$1"
    local support_dir
    support_dir="$(script_dir)"
    [[ -n "$support_dir" ]] || die "--binary requires running install.sh from a checkout or release archive"
    [[ -x "$binary" ]] || die "missing executable: $binary; install.sh never builds exwall"
    binary="$(CDPATH="" cd -- "$(dirname -- "$binary")" && pwd)/$(basename -- "$binary")"

    if [[ "${EUID}" -ne 0 ]]; then
        require_tools sudo
        exec sudo bash "${support_dir}/install.sh" --binary "$binary"
    fi
    install_system "$binary" "$support_dir"
}

# Dispatch between release downloads and local binary installs.
main() {
    [[ "$(uname -s)" == Linux ]] || die "exwall only supports Linux"

    case "${1:-}" in
        --binary)
            [[ -n "${2:-}" ]] || die "usage: install.sh --binary PATH"
            install_local "$2"
            ;;
        -h | --help)
            echo "usage: install.sh [TAG | --binary PATH]"
            ;;
        *)
            install_release "${1:-}"
            ;;
    esac
}

main "$@"
