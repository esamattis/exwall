# Using exwall

The service runs as the dedicated `exwall` user. Privileged systemd hooks redirect
ordinary users' HTTP/HTTPS and UDP/TCP DNS traffic to local listeners and install a
fail-closed output policy for other traffic. The proxy terminates TLS using its
persistent local CA, checks every HTTP request, injects configured headers, and
streams allowed requests and responses upstream. Upstream TLS certificates are
verified against the platform trust store.

## Install

```sh
sudo apt-get install iptables openssl ca-certificates
bash -c "$(curl -fsSL https://raw.githubusercontent.com/esamattis/exwall/refs/heads/main/install.sh)"
sudo systemctl enable --now exwall
sudo journalctl -u exwall -f
```

The installer downloads the static release for the host architecture (x86_64 or
aarch64), installs it, and uses `sudo` for the system changes. Pass a tag such as
`v0.1.0` after the command (`bash -c "$(curl ...)" _ v0.1.0`) to install a
specific release.

The installer creates:

- `/usr/local/bin/exwall`
- `/etc/exwall/config.toml` and `/etc/exwall/rules.d/*.toml`
- `/var/lib/exwall/exwall-ca-cert.pem` and a private CA key
- `/var/log/exwall/`, owned by the service user, for `access.log`
- `/etc/systemd/system/exwall.service`
- `/usr/local/share/ca-certificates/exwall.crt`
- Managed CA environment settings in `/etc/environment` and `/etc/profile.d/exwall.sh`

Fresh installs are left stopped. Reinstallation preserves local configuration,
rules, and CA material and restarts the service only if it was previously active.
The shipped config exempts `root` and `_apt`; removing them subjects their traffic
to enforcement. The proxy and system resolver accounts are always exempt.

When `/etc/mitmwall` exists, the installer copies its TOML config and any rule files
that are absent from `/etc/exwall`. Existing destination files are preserved.
Stop `mitmwall.service` before switching; the two services use the same ports.
The old installation, service, and CA are not removed or modified. exwall uses a
new CA; applications with custom trust stores must trust `exwall.crt`.

To load the CA environment settings in an existing shell:

```sh
. /etc/profile.d/exwall.sh
```

Uninstall with
`curl -fsSL https://raw.githubusercontent.com/esamattis/exwall/refs/heads/main/uninstall.sh | sudo sh`.
It stops the service and removes managed system integration,
while retaining configuration, CA material, and the account. Pass `--purge`
(`... | sudo sh -s -- --purge`) to also remove those retained files and the dedicated account.

## Web UI

The Rust `serve` command also serves the UI at `http://127.0.0.1:58000`.
Configure literal IPv4/IPv6 bind addresses and a shared TCP port in `config.toml`:

```toml
[ui]
hosts = ["127.0.0.1", "::1"]
port = 58000
username = "admin"
password = "replace-with-your-password"
sessions_dir = "/var/lib/exwall/ui/sessions/"
```

Use `hosts = ["0.0.0.0", "::"]` to bind all interfaces, or `hosts = []` to disable
UI serving. Port zero and duplicate addresses are rejected. UI settings take
effect after restarting; SIGHUP continues to reload policy. The Vite development
server has separate settings in `ui/vite.config.ts` and proxies `/api` to port 58000.

Set both `username` and `password` to enable API access; empty credentials disable
login. The login page stores a bearer token in the browser's local storage for
the UI's exact origin (scheme, hostname, and port), lasting 365 days. Requests send
it explicitly in the Authorization header; another localhost port receives no
session credentials. Sessions survive restarts as private JSON files in `sessions_dir` (the default is
`/var/lib/exwall/ui/sessions/`). Logout removes the session, and changing credentials
invalidates existing sessions after restart.
Upgrading from cookie sessions requires signing in again. Cookie authentication
and old session files are rejected, including old tokens replayed as bearer tokens.

`exwall hook start` creates `/etc/exwall/rules.d/05-web.toml` (or `05-web.toml`
in `--rules-dir`) without replacing existing contents, and sets ownership to the
proxy account (`exwall` by default) with mode `0600`. The rules directory remains
owned by root; the UI writes this file without needing permission to replace
other rule files.

Opening the UI without a session redirects to the login page, which returns to
the requested page after signing in. The Traffic page (the start page) shows
summary counters and three tabs: Blocked domains, Allowed domains, and Blocked
requests. The domain tabs list domains encountered since startup with DNS, HTTP,
and total counts, ordered by the latest occurrence of their own outcome. Domains
with both outcomes appear in both tabs; new allows do not change a domain's last
denial time or vice versa. Each tab can be filtered by domain. Use the Refresh
button to update all tabs; they do not poll automatically.
HTTP includes HTTPS. Counters and the latest timestamps are retained in memory
and reset when exwall restarts. At most 1000 domains are tracked; when a new
domain arrives at the limit, the domain updated least recently is dropped.
Each blocked domain has three actions. “Allow” saves an exact
domain rule in `05-web.toml` with `methods = "ANY"` and no pathname restrictions,
allowing DNS and every HTTP route and method. “DNS only” instead saves
`dns_only = true`, allowing DNS queries without authorizing HTTP, HTTPS, or CONNECT.
“+ Subdomains” saves `include_subdomains = true` and `methods = "ANY"`,
authorizing the domain and its subdomains for DNS and all HTTP routes and methods.
Adding an HTTP allowance from the Traffic page also removes DNS-only rules in
`05-web.toml` whose entire domain and subdomain scope it covers. Broader DNS-only
rules, multi-domain rules with uncovered domains, and regex rules are retained.

The Rules page lists the allow tables in `05-web.toml` under the configured rules
directory as collapsible cards that summarize each rule's domains, methods, and
paths. Expanding a card shows exact-name or regex domain matching, subdomain and
DNS-only switches, method choices, path patterns and regexes, and injected
header rows. Enter one domain or pattern per line; quotes and TOML escaping are
handled automatically. Edits are collected until saved from the bar at the
bottom of the page, which can also discard them; a rule named in a validation
error is opened and highlighted.
Saving uses `toml_edit` to retain unchanged formatting and comments, validates the
rules, and writes the service-owned file. Concurrent file edits return a conflict;
reload the file before retrying. Other TOML rule files are unaffected. Every save
reloads the complete ruleset before responding, whether or not `watch_rules` is
enabled, so a successful save is already enforced. If another rule file is invalid,
the save is still written but the previous policy stays active: the API returns
HTTP 500 saying the rules could not be activated, and the saved rules take effect
once the complete ruleset loads again.

The Blocked requests tab keeps the latest 100 denied HTTP/HTTPS requests
in memory, newest first, including repeated requests. Refresh it manually.
Each row can allow the exact domain, method, and pathname; query strings are
excluded and pathname metacharacters are matched literally. This list resets
on restart and excludes DNS denials and CONNECT setup.

REST endpoints accept either `Authorization: Bearer <token>` or HTTP Basic credentials:
`POST /api/login`, `GET /api/session`, `POST /api/logout`, `GET /api/domains`, `GET /api/http-denials`, and `GET`/`PUT /api/rules`.
`POST /api/login` returns `username` and `token` on success. Writes require
`Content-Type: application/json`; JSON bodies are limited to 1 MiB and must arrive
within 10 seconds. Body reads do not lock other API requests. `GET /api/rules` returns a
`revision` and `rules` array; send that revision with edited rule fields to `PUT`. Field values are ordinary JSON
strings, arrays, booleans, or header objects, rather than TOML literals.
For example:

```sh
curl --user admin http://127.0.0.1:58000/api/rules
```

## Compatible TOML policy

The configuration and `[[allow]]` syntax are compatible with mitmwall. See
[config-default.toml](../config-default.toml) and
[example-rules.toml](../example-rules.toml) for the full format. Files are loaded in
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
Before matching or injecting headers, the proxy rejects dot traversal segments
(`.` and `..`, including percent-encoded and repeatedly encoded forms), backslashes,
control characters, encoded path delimiters, and ambiguous matrix-style dot
segments. Ordinary encoded filenames and query strings remain supported. Denied
paths receive 403; they are never rewritten into a different permitted route.
They support named parameters, quoted parameter names, `*` wildcards, custom
regex groups, `?`/`+`/`*` modifiers, and `{tokens}` groups. Modified parameters
include their preceding slash, so `/books/:id?` matches `/books` and
`/books/123`. Trailing slashes remain strict unless explicitly optional.

Methods default to `GET` and `HEAD`. `methods = "ANY"` allows all methods.
Set `dns_only = true` on an allow rule to permit only DNS; it never matches
HTTP requests or CONNECT tunnels. The default is `dns_only = false`.
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
accepted; exwall does not retain mitmproxy flow history. There is no mitmweb
allow-all toggle, flow viewer, capture/replay facility, or WebSocket relay.
WebSocket upgrade requests are rejected rather than forwarded as a raw tunnel.

**Isolation limitation:** exwall filters IP traffic; it does not isolate local
IPC. On hosts exposing systemd-resolved's D-Bus or Varlink APIs, an ordinary user
can submit DNS queries directly to the exempt resolver, bypassing `block_dns`.
The firewall therefore does not provide complete DNS confinement for untrusted
local processes. Such workloads need an independently configured isolation
boundary that prevents access to the host resolver's IPC interfaces while sending
their DNS traffic through exwall. Simply removing the resolver exemption causes
a forwarding loop with the default upstream at `127.0.0.53:53`. Global IPC
restrictions are not installed automatically because they can disrupt existing
resolver clients and require host-specific deployment and compatibility testing.

## Operation and hooks

```sh
exwall check
exwall --config /etc/mitmwall/config.toml --rules-dir /etc/mitmwall/rules.d check
sudo systemctl reload exwall
sudo systemctl restart exwall
sudo systemctl stop exwall  # remove enforcement and restore host state
sudo exwall hook stop       # manual cleanup when the unit is not in use
exwall hook --dry-run start
exwall hook --dry-run stop
```

Changes to `rules.d/*.toml` automatically reload the complete ruleset after a short
debounce, including file creation, removal, and atomic replacement. Invalid rules
or an unavailable rules directory keep the previous rules active; fixing the files
triggers another reload. Automatic rule reloads preserve the current configuration.
Monitoring is enabled by default. Set `watch_rules = false` in `config.toml` to
disable it; SIGHUP applies changes to this option without restarting the service.
SIGHUP reloads the config and complete ruleset atomically. Invalid reloads keep the
previous policy. Restart to apply changes to firewall bypasses, resolver
management, application log level, or access-log settings. Set `log_level = "debug"`
in the TOML config to log all executed firewall and related hook commands with
their arguments. Both the service and hooks use the configured level; `RUST_LOG`
does not override it. Hooks fall back to `info` if configuration cannot be loaded,
so invalid configuration never prevents guarding or cleanup.
SIGHUPs received while a reload is pending are merged into it rather than dropped.

`--dry-run` never runs commands or changes files, sysctls, or the resolver. It
prints the iptables commands a hook would execute against a simulated firewall:
`guard` and `start` begin from empty exwall chains, and `stop` assumes installed
chains, so it shows their removal. Account lookups read the account database directly.

Application logs still go to stdout and the systemd journal. Independently of
`log_level`, access logs record every HTTP(S) request handled by the proxy and
every DNS message processed by the DNS service. Rule matches and allow/deny
decisions appear only in the dedicated access log, even at debug level.
Explicit CONNECT requests have
their own entry in addition to the HTTPS requests inside the tunnel. Traffic
that bypasses the proxy is not visible to the access logger.

The default destination is `/var/log/exwall/access.log`. Each line has nine columns,
plus an `xN` suffix when the same message occurs more than once in a batch:

```text
TIMESTAMP PROTOCOL RESULT RULE HTTP_METHOD URL HTTP_STATUS DNS_RCODE ERROR
2026-10-07T12:34:56Z https ALLOW /etc/exwall/rules.d/10-examples.toml:allow#1 GET https://github.com:443/api 200 - -
2026-10-07T12:34:57Z http DENY - POST http://denied.test/upload 403 - -
2026-10-07T12:34:58Z dns DENY - - dns://denied.test/A - REFUSED - x3
2026-10-07T12:34:59Z https ALLOW /etc/exwall/rules.d/10-examples.toml:allow#1 GET https://github.com:443/api 502 - UPSTREAM_TIMEOUT
```

Timestamps are UTC request arrival times. Completed messages are buffered for one
second starting with the first message in each batch. Messages whose fields match
except for the timestamp are combined, with a suffix such as `x3` counting all
three occurrences. Each combined message keeps its first received timestamp and
position: `A, B, A` is written as `A x2, B`. Messages in different batches remain
separate. Domain counters still count every request.
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

The file is owned by a logging actor that receives entries through a mailbox
holding up to 65,536 entries. Request handlers never wait for file writes or
trimming; if the mailbox is full, new entries are dropped and the actor logs a
warning with the number discarded. Shutdown closes the mailbox once in-flight
requests finish or the 10-second graceful limit passes, then writes every queued
entry immediately; requests still running after that limit are not logged. An
access-log I/O failure fails the service instead of silently discarding subsequent
logs. The following settings are configurable in `config.toml` and take effect
after a restart:

```toml
[access_log]
path = "/var/log/exwall/access.log"
check_interval = 100
max_size_bytes = 10485760 # 10 MiB
keep_entries = 1000
```

Every 100 written rows, the actor checks the actual file size. If it exceeds
10 MiB, the actor atomically replaces it with the last 1,000 complete entries in
their original order. These are periodic limits: the file can grow between
checks, and the retained entries may themselves exceed the size threshold.
Use `sudo tail -F /var/log/exwall/access.log` to follow the file across trimming.
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
using owned `EXWALL_OUTPUT`, `EXWALL_NAT`, and bootstrap `EXWALL_GUARD`
chains. Custom TCP network/port
bypasses precede redirects. The output policy preserves reply-direction
established inbound connections, proxy/bypass users, systemd-resolved, installed
NTP users' DNS/NTP, ICMPv6, and loopback/local listeners. All other outbound
traffic is dropped, including original-direction connections predating startup.
Startup uses a temporary guard while rebuilding the policy. Cleanup identifies
owned chains, so changed or malformed config never prevents explicit cleanup.

Original forwarding and redirect sysctls are stored privately in
`/run/exwall/forwarding.json` and restored exactly by `hook stop`. Forwarding newly
enabled by the service is guarded against transit traffic. When
`manage_resolv_conf = true` and `/etc/resolv.conf` uses external nameservers, the
hook saves the original file or symlink and temporarily replaces it with
systemd-resolved's loopback stub. `hook stop` restores contents/target, permissions,
and ownership, while preserving replacements made by an administrator. Failed
restoration retains snapshots and guards for repair and retry. The unit's
resolved lifecycle dependencies stop the proxy with the resolver.

Enforcement lasts only while the unit is active. The unit runs `hook stop` as
`ExecStopPost` whenever it leaves the active state: `systemctl stop`, crashes,
failed starts, and the stop half of a restart all remove the managed chains and
restore the resolver and sysctls. Restarts therefore briefly leave egress
unfiltered between cleanup and the next `hook guard`. On start, `hook guard`
installs a minimal deny policy before parsing, preserving root, the proxy,
resolver, DNS/NTP service exceptions, loopback, inbound replies, and ICMPv6.
If a previous cleanup failed, `hook guard` keeps the remaining policy. Cleanup
works with malformed TOML; `sudo exwall hook stop` can also be run manually,
and uninstall runs it after stopping the service.
As in mitmwall, it governs local processes and relies on unprivileged applications lacking firewall-changing
capabilities. Container forwarding policy that was enabled before startup is
preserved. Historical Python-hook migrations are not run; stop/uninstall the old
service with its own hooks when migrating.
