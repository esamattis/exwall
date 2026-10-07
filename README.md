<img src="assets/icon.svg" width="64" height="64" alt="">

# ramawall

A Linux outbound HTTP(S) and DNS firewall implemented in Rust using
[Rama](https://ramaproxy.org/). It reimplements mitmwall's TOML allow rules,
transparent interception, and systemd/iptables integration. An embedded React UI
provides a starting point for a control interface.

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
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
mise exec -- pnpm build
./test.sh
./integration_tests.sh
```

`test.sh` builds and checks the frontend, then runs Rust formatting checks,
Clippy, and unit tests. The rule tests include
8,160 HTTP and 170 DNS decisions recorded from the original mitmwall Python
implementation. Protocol integration tests use local upstreams and temporary CA
material to exercise HTTP filtering, header injection, TLS interception, CONNECT,
HTTP/2-only upstreams, bidirectional streaming with gRPC trailers, HTTP/1.1
fallback, UDP/TCP DNS, IPv6 listeners, successful/rejected reloads, and
embedded UI assets over both IPv4 and IPv6.

`integration_tests.sh` also exercises real IPv4/IPv6 firewall startup, repeated
startup/stop, bypass ordering, authorized-host routing, and exact sysctl
restoration in disposable network/mount namespaces. With root or passwordless
sudo, it runs all 37 network cases ported from mitmwall, plus seven additional
cases covering control-service access, full IPv6 interception, private hook
state/restoration, corrupt-state rejection, invalid policies, startup failures,
and real automatic restarts under a private systemd manager. These lifecycle
tests require `/usr/lib/systemd/systemd`; unit overrides select temporary paths
and root execution inside the disposable namespaces. The original TOML fixtures
and HTTP case names are retained. Public upstreams are replaced by local HTTP(S),
DNS, SSH, and FTP servers in a second namespace, connected through a veth pair.
Distinct client UIDs verify user bypasses; certificate comparisons verify network
bypasses and their removal. Allowed requests must reach the upstream, and denied
web requests must receive 403.

Tests never install the service or alter the development host's firewall,
resolver, accounts, or trust store. Namespace tests refuse to run in the launcher's
host network/mount namespaces. Their isolated networks have no internet route, so
host access to **chatgpt.com** and **openai.com** remains available even during
deny-all and failed-start tests. The ported rules also allow all methods and
subdomains for those services. The launcher verifies unchanged host firewall,
forwarding sysctls, resolver, and trust bundle after testing.

Python 3, curl with HTTP/2, and openssl are needed for protocol tests; `ip`,
`mount`, `unshare`, `nsenter`, iptables, and ip6tables are needed for namespace
tests. Without root/passwordless sudo, the original namespace cases can use
unprivileged user namespaces, while the full mitmwall port reports a skip. Missing
namespace support is also reported explicitly.

## Web UI development

The Hello world page uses React, TypeScript, TanStack Router and Query, Tailwind
CSS, and Vite. TypeScript is strict with `noUncheckedIndexedAccess`. Oxlint runs
with type-aware checks, and oxfmt formats the frontend. Package versions are
pinned in `package.json` and `pnpm-lock.yaml`. Node and pnpm versions are defined
in `package.json`; `mise.toml` enables mise to read those declarations.
Install [mise](https://mise.jdx.dev/getting-started.html) before the build
commands above, then activate it in your shell or run the test scripts with
`mise exec -- ./test.sh` and `mise exec -- ./integration_tests.sh`.

```sh
mise exec -- pnpm dev          # Vite development server at http://127.0.0.1:5173
mise exec -- pnpm check        # TypeScript, oxlint, and oxfmt checks
mise exec -- pnpm format       # Format frontend files
mise exec -- pnpm build:ui     # Rebuild ui/dist before a direct Cargo command
mise exec -- pnpm build        # Build UI and embed it in the debug Rust binary
```

For release builds, run `mise exec -- pnpm build:ui` followed by
`cargo build --release --locked`. Every build profile embeds all `ui/dist` assets
as bytes; the deployed binary needs neither Node nor external UI files. Cargo
tracks bundle changes and requires a built `ui/dist/index.html` rather than
shipping a placeholder. Rebuild the frontend after changing its source.

The Rust `serve` command also serves the UI at `http://127.0.0.1:58000`.
Configure literal IPv4/IPv6 bind addresses and a shared TCP port in `config.toml`:

```toml
[ui]
hosts = ["127.0.0.1", "::1"]
port = 58000
```

Use `hosts = ["0.0.0.0", "::"]` to bind all interfaces, or `hosts = []` to disable
UI serving. Port zero and duplicate addresses are rejected. UI settings take
effect after restarting; SIGHUP continues to reload policy. The Vite development
server has separate settings in `ui/vite.config.ts`.

## Install on Ubuntu/systemd

Build as your normal user, then install the resulting debug binary. `install.sh`
uses `./target/debug/ramawall` by default and never builds it:

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
- `/var/log/ramawall/`, owned by the service user, for `access.log`
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
Injected headers require upstream HTTPS with certificate verification. Requests
matching an injection rule over plaintext HTTP are denied, including non-secret
headers. Forwarding resolves the authorized hostname through the proxy's system
resolver; a transparent connection's original IP cannot override that route.

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
sudo ramawall hook stop       # intentionally remove enforcement and restore host state
ramawall hook --dry-run start
ramawall hook --dry-run stop
```

SIGHUP reloads the config and complete ruleset atomically. Invalid reloads keep the
previous policy. Restart to apply changes to firewall bypasses, resolver
management, application log level, or access-log settings. Set `log_level = "debug"`
in the TOML config to log all executed firewall and related hook commands with
their arguments. Both the service and hooks use the configured level; `RUST_LOG`
does not override it. Hooks fall back to `info` if configuration cannot be loaded,
so invalid configuration never prevents guarding or cleanup.

Application logs still go to stdout and the systemd journal. Independently of
`log_level`, access logs record every HTTP(S) request handled by the proxy and
every DNS message processed by the DNS service. Rule matches and allow/deny
decisions appear only in the dedicated access log, even at debug level.
Explicit CONNECT requests have
their own entry in addition to the HTTPS requests inside the tunnel. Traffic
that bypasses the proxy is not visible to the access logger.

The default destination is `/var/log/ramawall/access.log`. Each line has exactly
nine columns:

```text
TIMESTAMP PROTOCOL RESULT RULE HTTP_METHOD URL HTTP_STATUS DNS_RCODE ERROR
2026-10-07T12:34:56Z https ALLOW /etc/ramawall/rules.d/5-examples.toml:allow#1 GET https://github.com:443/api 200 - -
2026-10-07T12:34:57Z http DENY - POST http://denied.test/upload 403 - -
2026-10-07T12:34:58Z dns DENY - - dns://denied.test/A - REFUSED -
2026-10-07T12:34:59Z https ALLOW /etc/ramawall/rules.d/5-examples.toml:allow#1 GET https://github.com:443/api 502 - UPSTREAM_TIMEOUT
```

Timestamps are UTC arrival times; entries are written as request handlers finish.
`PROTOCOL` is `dns`, `http`, or `https`. `RESULT` is the policy decision (`ALLOW`
or `DENY`), or `-` if policy was not evaluated. An allowed request keeps `ALLOW`
even if forwarding subsequently fails. `HTTP_STATUS` is the status returned to
an HTTP(S) client, and `DNS_RCODE` is the response code returned to a DNS client;
unused or unavailable response fields are `-`. HTTP status is recorded when
response headers arrive; response bodies remain streamed.

`ERROR` records a processing failure independently of the policy and response:

- `UPSTREAM_FAILURE`: upstream connection, TLS, protocol, or I/O failure.
- `UPSTREAM_TIMEOUT`: the upstream request deadline expired.
- `INVALID_DNS_REPLY`: a malformed or mismatched DNS upstream response.
- `INVALID_REQUEST`: invalid HTTP metadata or an unsupported operation.
- `MALFORMED_DNS`: an incoming DNS packet could not be parsed.
- `CONNECT_SETUP`: the local CONNECT reply service failed.
- `CANCELLED`: the request handler was interrupted before producing a response.
- `OVERLOADED`: a UDP DNS request was dropped at the concurrency limit.
- `-`: no processing failure, including normal policy denials and upstream error
  responses such as HTTP 500 or 502.

For example, an upstream HTTP 502 response logs `HTTP_STATUS=502, ERROR=-`;
a proxy-generated 502 logs `HTTP_STATUS=502` with an upstream failure category.
Application logs retain available diagnostic details about the underlying error.
`RULE` identifies the first matching rule by filename and allow-table number,
or `-` when none matched. DNS exceptions use `@dns-bypass` or `@local-hostname`.
DNS uses `-` for the HTTP method and `dns://hostname/query-type` for the URL;
multi-question messages list their rules and URLs in question order, separated
by commas. Full HTTP URLs include query strings. Whitespace, control characters,
and percent signs in fields are percent-escaped to prevent injected log lines;
headers and bodies are not logged.

The file is owned by a logging actor that receives entries through a mailbox.
Request handlers never wait for file writes or trimming. Shutdown drains the
mailbox, and an access-log I/O failure fails the service instead of silently
discarding subsequent logs. The following settings are configurable in
`config.toml` and take effect after a restart:

```toml
[access_log]
path = "/var/log/ramawall/access.log"
check_interval = 100
max_size_bytes = 10485760 # 10 MiB
keep_entries = 1000
```

Every 100 logged requests, the actor checks the actual file size. If it exceeds
10 MiB, the actor atomically replaces it with the last 1,000 complete entries in
their original order. These are periodic limits: the file can grow between
checks, and the retained entries may themselves exceed the size threshold.
Use `sudo tail -F /var/log/ramawall/access.log` to follow the file across trimming.
The installer and systemd create the default parent directory; for a custom path
or a manual `serve` invocation, create a parent directory writable by the process
user first. New log files are created with mode `0600`.

Defaults are dual-stack HTTP(S) on port **58080**, UDP/TCP DNS on **58053**, and
upstream DNS at **127.0.0.53:53**. `serve --help` exposes alternate listener,
upstream, and CA paths. `serve` alone never changes host networking. The installed
systemd unit runs privileged `hook guard` before validation, then `hook start`.
Upstream TLS negotiates HTTP/2 or HTTP/1.1; streaming bodies and HTTP/2 trailers
are relayed, including gRPC trailers.

The hooks call `iptables`/`ip6tables` with the xtables lock and argv arguments,
using owned `RAMAWALL_OUTPUT`, `RAMAWALL_NAT`, and bootstrap `RAMAWALL_GUARD`
chains. Custom TCP network/port
bypasses precede redirects. The output policy preserves reply-direction
established inbound connections, proxy/bypass users, systemd-resolved, installed
NTP users' DNS/NTP, ICMPv6, and loopback/local listeners. All other outbound
traffic is dropped, including original-direction connections predating startup.
Startup uses a temporary guard while rebuilding the policy. Cleanup identifies
owned chains, so changed or malformed config never prevents explicit cleanup.

Original forwarding and redirect sysctls are stored privately in
`/run/ramawall/forwarding.json` and restored exactly by `hook stop`. Forwarding newly
enabled by the service is guarded against transit traffic. When
`manage_resolv_conf = true` and `/etc/resolv.conf` uses external nameservers, the
hook saves the original file or symlink and temporarily replaces it with
systemd-resolved's loopback stub. `hook stop` restores contents/target, permissions,
and ownership, while preserving replacements made by an administrator. Failed
restoration retains snapshots and guards for repair and retry. The unit's
resolved lifecycle dependencies stop the proxy with the resolver. Enforcement
and saved state remain in place until an explicit `hook stop`.

The firewall survives systemd stops, failed starts, and automatic or manual
restarts. A valid existing policy, including its bypass exceptions, remains
active if configuration or rules cannot be parsed. On first start, `hook guard`
installs a minimal deny policy before parsing, preserving root, the proxy,
resolver, DNS/NTP service exceptions, loopback, inbound replies, and ICMPv6.
An incomplete installation retains guards and the original snapshots for retry.
To intentionally disable enforcement, stop the service and run
`sudo ramawall hook stop`; uninstall does both. Resolver and sysctl restoration
occurs only on that explicit cleanup, which works with malformed TOML.
As in mitmwall, it governs local processes and relies on unprivileged applications lacking firewall-changing
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
