<img src="assets/icon.svg" width="64" height="64" alt="">

# ramawall

A Linux outbound HTTP(S) and DNS firewall implemented in Rust using
[Rama](https://ramaproxy.org/). It reimplements mitmwall's TOML allow rules,
transparent interception, and systemd/iptables integration. There is no web UI.

The service runs as the dedicated `ramawall` user. Privileged systemd hooks redirect
ordinary users' HTTP/HTTPS and UDP/TCP DNS traffic to local listeners and install a
fail-closed output policy for other traffic. The proxy terminates TLS using its
persistent local CA, checks every HTTP request, injects configured headers, and
streams allowed requests and responses upstream. Upstream TLS certificates are
verified against the platform trust store.

## Build and test

Rust 1.96 or newer is required; `rust-toolchain.toml` selects 1.97.1. On Ubuntu,
install build prerequisites (Rama's Linux DNS dependency runs bindgen):

```sh
sudo apt-get install build-essential pkg-config clang libclang-dev
cargo build --release --locked
./test.sh
./integration_tests.sh
```

`test.sh` runs formatting checks, Clippy, and unit tests. The rule tests include
8,160 HTTP and 170 DNS decisions recorded from the original mitmwall Python
implementation. Protocol integration tests use local upstreams and temporary CA
material to exercise HTTP filtering, header injection, TLS interception, CONNECT,
HTTP/2, streaming, UDP/TCP DNS, IPv6 listeners, and successful/rejected reloads.

Where unprivileged user/network/mount namespaces and iptables are available,
`integration_tests.sh` also exercises real IPv4/IPv6 firewall startup, repeated
startup/stop, bypass ordering, original-destination recovery, and exact sysctl
restoration in a disposable namespace. It reports a skip if those prerequisites
are unavailable. Tests never install the service or alter the development host's
firewall, resolver, or trust store. Python 3, curl with HTTP/2, and openssl are
needed for protocol tests; `ip`, `mount`, `unshare`, iptables, and ip6tables are
needed for namespace tests.

## Install on Ubuntu/systemd

Build as your normal user, then install the resulting binary:

```sh
sudo apt-get install iptables openssl ca-certificates
sudo ./install.sh
sudo systemctl enable --now ramawall
sudo journalctl -u ramawall -f
```

The installer creates:

- `/usr/local/bin/ramawall`
- `/etc/ramawall/config.toml` and `/etc/ramawall/rules.d/*.toml`
- `/var/lib/ramawall/ramawall-ca-cert.pem` and a private CA key
- `/etc/systemd/system/ramawall.service`
- `/usr/local/share/ca-certificates/ramawall.crt`
- Managed CA environment settings in `/etc/environment` and `/etc/profile.d/ramawall.sh`

Fresh installs are left stopped. Reinstallation preserves local configuration,
rules, and CA material and restarts the service only if it was previously active.
The shipped config exempts `root` and `_apt`; removing them subjects their traffic
to enforcement. The proxy and system resolver accounts are always exempt.

When `/etc/mitmwall` exists, the installer copies its TOML config and any rule files
that are absent from `/etc/ramawall`. Existing destination files are preserved.
Stop `mitmwall.service` before switching; the two services use the same ports.
The old installation, service, and CA are not removed or modified. ramawall uses a
new CA; applications with custom trust stores must trust `ramawall.crt`.

To load the CA environment settings in an existing shell:

```sh
. /etc/profile.d/ramawall.sh
```

`sudo ./uninstall.sh` stops the service and removes managed system integration,
while retaining configuration, CA material, and the account. Add `--purge` to
also remove those retained files and the dedicated account.

## Compatible TOML policy

The configuration and `[[allow]]` syntax are compatible with mitmwall. See
[config-default.toml](config-default.toml) and
[example-rules.toml](example-rules.toml) for the full format. Files are loaded in
alphabetical filename order; rule tables retain their order within each file.

```toml
[[allow]]
domain = ["example.com", "api.example.com"]
include_subdomains = true
methods = ["GET", "POST"]
pathname_pattern = ["/api/:version/items", "/assets/*"]
pathname_regex = '^/downloads/[^/]+$'
inject_headers = [{ name = "Authorization", value = "Bearer secret" }]
stream = true

[[allow]]
domain_regex = '(^|\.)githubusercontent\.com$'
methods = "ANY"
```

Each rule requires exactly one of `domain` and `domain_regex`. Scalar and array
host/path values are supported. Exact domain matches normalize case, whitespace,
and trailing dots. Subdomains require `include_subdomains = true`. Domain regexes
are case insensitive; pathname regexes are case sensitive partial matches.
Regexes support lookarounds and backreferences through `fancy-regex`, with bounded
backtracking. Python's `\Z` end-of-string spelling is supported; exotic
Python-specific regex syntax outside this engine's capabilities is rejected at
startup instead of silently broadening a rule.

Pathname patterns match the entire path, excluding query strings and fragments.
They support named parameters, quoted parameter names, `*` wildcards, custom
regex groups, `?`/`+`/`*` modifiers, and `{tokens}` groups. Modified parameters
include their preceding slash, so `/books/:id?` matches `/books` and
`/books/123`. Trailing slashes remain strict unless explicitly optional.

Methods default to `GET` and `HEAD`. `methods = "ANY"` allows all methods.
HTTP authorization, header injection, and streaming settings come from the **first
matching rule**, matching the current executable mitmwall implementation. Header
values are never logged. Every response streams, so `stream = true` is accepted
for compatibility without requiring a special buffering mode. Denied HTTP
requests receive 403 instead of mitmproxy's abrupt flow termination.

DNS allows names matched by any rule, ignoring HTTP method/path constraints, and
also allows the local hostname. Other queries receive REFUSED. `block_dns = false`
permits all ordinary DNS queries while retaining firewall redirection. Both UDP
and TCP DNS are supported. Malformed or mismatched upstream replies fail closed.

Unknown config/rule keys and malformed values are rejected. Legacy
`flow_history_clear_interval` and `flow_history_keep_entries` are validated and
accepted; ramawall does not retain mitmproxy flow history. There is no mitmweb
allow-all toggle, flow viewer, capture/replay facility, or WebSocket relay.
WebSocket upgrade requests are rejected rather than forwarded as a raw tunnel.

## Operation and hooks

```sh
ramawall check
ramawall --config /etc/mitmwall/config.toml --rules-dir /etc/mitmwall/rules.d check
sudo systemctl reload ramawall
sudo systemctl restart ramawall
sudo systemctl stop ramawall
ramawall hook --dry-run start
ramawall hook --dry-run stop
```

SIGHUP reloads the config and complete ruleset atomically. Invalid reloads keep the
previous policy. Restart to apply changes to firewall bypasses, resolver
management, or log level. `RUST_LOG` can override logging at process startup.

Defaults are dual-stack HTTP(S) on port **58080**, UDP/TCP DNS on **58053**, and
upstream DNS at **127.0.0.53:53**. `serve --help` exposes alternate listener,
upstream, and CA paths. `serve` alone never changes host networking. The installed
systemd unit pairs it with privileged `hook start` and `hook stop` commands.

The hooks call `iptables`/`ip6tables` with the xtables lock and argv arguments,
using owned `RAMAWALL_OUTPUT` and `RAMAWALL_NAT` chains. Custom TCP network/port
bypasses precede redirects. The output policy preserves reply-direction
established inbound connections, proxy/bypass users, systemd-resolved, installed
NTP users' DNS/NTP, ICMPv6, and loopback/local listeners. All other outbound
traffic is dropped, including original-direction connections predating startup.
Startup uses a temporary guard while rebuilding the policy. Cleanup identifies
owned chains, so changed or malformed config never prevents stopping.

Original forwarding and redirect sysctls are stored privately in
`/run/ramawall/forwarding.json` and restored exactly on stop. Forwarding newly
enabled by the service is guarded against transit traffic. When
`manage_resolv_conf = true` and `/etc/resolv.conf` uses external nameservers, the
hook saves the original file or symlink and temporarily replaces it with
systemd-resolved's loopback stub. Stop restores contents/target, permissions,
and ownership, while preserving replacements made by an administrator. Failed
restoration retains snapshots and guards for repair and retry. The unit's
resolved lifecycle dependencies ensure resolver restoration precedes resolved
shutdown.

The firewall is active during service operation and removed on an intentional
stop, failed-start cleanup, or systemd restart. As in mitmwall, it governs local
processes and relies on unprivileged applications lacking firewall-changing
capabilities. Container forwarding policy that was enabled before startup is
preserved. Historical Python-hook migrations are not run; stop/uninstall the old
service with its own hooks when migrating.

## Local proxy development

```sh
mkdir -p /tmp/ramawall-dev/rules
cp example-rules.toml /tmp/ramawall-dev/rules/5-examples.toml
cargo run -- init-ca --ca-dir /tmp/ramawall-dev/ca
cargo run -- --rules-dir /tmp/ramawall-dev/rules serve \
  --listen 127.0.0.1:58080 --dns-listen 127.0.0.1:58053 \
  --ca-dir /tmp/ramawall-dev/ca
curl --proxy http://127.0.0.1:58080 \
  --cacert /tmp/ramawall-dev/ca/ramawall-ca-cert.pem https://github.com/
```

Explicit HTTP proxy requests and HTTPS CONNECT are supported alongside
transparent traffic. CONNECT performs TLS interception and every inner HTTP
request is filtered; it never grants an unrestricted byte tunnel. Conflicting
request authorities, Host headers, and TLS server names are rejected.
