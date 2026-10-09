# One local user can exhaust shared proxy and DNS connection limits

## Summary

The HTTP proxy and the DNS server each use a single process-wide concurrency
limit that is shared by every client. A single unprivileged local user can hold
all slots open and deny HTTP(S) and DNS service to every other user on the host.
This was present in the old implementation as well.

## Details

- `src/proxy/server.rs`: `CONNECTION_LIMIT = 1024` permits shared by all
  redirected TCP connections. When none are free, new connections are accepted
  and silently dropped. A client only needs to open 1024 connections and keep
  them alive: a CONNECT tunnel or an HTTP/1.1 keep-alive connection holds its
  permit for as long as the client keeps it open. The 10-second first-byte
  timeout only applies before the first byte.
- `src/dns/server.rs`: `CONCURRENCY = 256` permits shared by UDP queries and
  TCP sessions. A TCP session holds its permit until it has been idle for
  `TCP_IDLE_TIMEOUT` (30 s), so 256 TCP connections that each send one query
  every 29 seconds block all DNS, including UDP. UDP queries over the limit are
  logged as `OVERLOADED`. TCP connections over the limit are dropped without
  any log entry.
- `src/ui/server.rs`: `CONNECTION_LIMIT = 128` for the UI. This is a lower
  risk because the UI usually only listens on loopback, but the same pattern
  applies.

Because all exempt users are excluded by iptables, the attacker is any local
account whose traffic is redirected, which is exactly the population exwall is
meant to constrain.

## Possible fixes

- Per-UID limits: redirected clients are local sockets, so the owning UID can
  be looked up in `/proc/net/tcp{,6}` (and `udp{,6}`) by the connection's
  address and port pair. Give each UID a fair share and keep the global limit
  as a backstop.
- Per-source-address limits as a cheaper first step. All local users share
  loopback addresses, so this only helps for forwarded or namespaced clients.
- Lifetime and idle limits for kept-alive proxy connections and CONNECT
  tunnels, and a shorter idle timeout for DNS TCP sessions while the limit is
  under pressure.
- Separate limits for DNS over UDP and DNS over TCP, so TCP sessions cannot
  starve UDP queries.
- Log a rate-limited warning and an access-log entry when connections are
  rejected at the limit, so the condition is visible.

## Acceptance criteria

- One local user holding the maximum number of idle proxy connections or DNS
  TCP sessions does not prevent another user's HTTP(S) requests or DNS queries
  from being served.
- Rejections at a limit are visible in the logs.
- An e2e test in the disposable namespace setup demonstrates both points.
