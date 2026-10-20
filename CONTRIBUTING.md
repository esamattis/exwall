# Contributing

## Build and test

Rust 1.96 or newer is required; `rust-toolchain.toml` selects 1.97.1 and the
musl targets. `.cargo/config.toml` makes every local build, test, and E2E run use
the same static `x86_64-unknown-linux-musl` target as releases, so binaries land
in `target/x86_64-unknown-linux-musl/`. On an aarch64 host, set
`CARGO_BUILD_TARGET=aarch64-unknown-linux-musl`. On Ubuntu, install the build
prerequisites (`musl-tools` provides the `musl-gcc` that ring's C code needs):

```sh
sudo apt-get install build-essential pkg-config musl-tools
mise trust
mise install
mise exec -- pnpm install --frozen-lockfile
mise exec -- pnpm build
./test.sh
./integration_tests.sh
```

`pnpm test` runs both: `pnpm test:unit` (`test.sh`) and then `pnpm test:e2e`.
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
restoration in disposable network/mount namespaces. Through Playwright it runs
the network cases ported from mitmwall, plus cases covering control-service access, full IPv6 interception, private hook
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

The unified Playwright suite requires the pinned Node runtime, Chromium, curl
with HTTP/2, openssl, `ip`, `mount`, `unshare`, `nsenter`, iptables, ip6tables,
`ping`, and `/usr/lib/systemd/systemd`. Root or passwordless sudo and disposable
namespace support are required; missing prerequisites fail the run. Python is
not required.

## Web UI development

The web UI uses React, TypeScript, TanStack Router and Query, Tailwind
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
`cargo build --release --locked`, which produces the static
`target/x86_64-unknown-linux-musl/release/exwall`. Every build profile embeds all `ui/dist` assets
as bytes; the deployed binary needs neither Node nor external UI files. Cargo
tracks bundle changes and requires a built `ui/dist/index.html` rather than
shipping a placeholder. Rebuild the frontend after changing its source.

## Installing a local build

Run without arguments from a git checkout, `install.sh` builds the UI and a
static release binary as your normal user, then installs it together with the
config, rules, and unit files from the checkout:

```sh
./install.sh
```

To install a binary you built yourself, such as a debug build, pass it with
`--binary`; the installer then builds nothing:

```sh
mise exec -- pnpm build
./install.sh --binary target/x86_64-unknown-linux-musl/debug/exwall
```

The installer re-runs itself through `sudo` for the system changes. Never run it
on a development host whose firewall you are not prepared to change; the tests do
not need it.

## Local proxy development

```sh
mkdir -p /tmp/exwall-dev/rules
cp example-rules.toml /tmp/exwall-dev/rules/10-examples.toml
touch /tmp/exwall-dev/rules/05-web.toml  # the start hook creates this in production
cargo run -- init-ca --ca-dir /tmp/exwall-dev/ca
cargo run -- --rules-dir /tmp/exwall-dev/rules serve \
  --listen 127.0.0.1:58080 --dns-listen 127.0.0.1:58053 \
  --ca-dir /tmp/exwall-dev/ca
curl --proxy http://127.0.0.1:58080 \
  --cacert /tmp/exwall-dev/ca/exwall-ca-cert.pem https://github.com/
```

Explicit HTTP proxy requests and HTTPS CONNECT are supported alongside
transparent traffic. CONNECT performs TLS interception and every inner HTTP
request is filtered; it never grants an unrestricted byte tunnel. Conflicting
request authorities, Host headers, and TLS server names are rejected.

## E2E tests

Install Chromium once with
`mise exec -- pnpm exec playwright install --with-deps chromium`.

Run full browser E2E tests with `mise exec -- pnpm test:e2e` (or
`./e2e_tests.sh`). They run the production exwall binary and real hooks in
disposable namespaces, with host Chromium and a restricted TypeScript network
client. The HTTP/2 upstream and all Playwright helpers are `.mts` files under
`tests/playwright_helpers/`, imported through `#playwright_helpers/*`.
Root/passwordless sudo and installed Chromium are required.
`./integration_tests.sh` runs the same unified Playwright suite, including
protocol, rule-file reload, firewall, systemd lifecycle, and browser coverage.
Network tests write a dedicated temporary rules file directly and poll traffic
until the production watcher applies it; browser tests continue to exercise UI
saves. Pass Playwright filters through either script, for example
`./integration_tests.sh --no-build network.spec.ts`.
See [PLAYWRIGHT.md](PLAYWRIGHT.md) for script roles, the namespace flowchart,
helper imports, mock-server usage, assertions, and cleanup.

## Releases

Release from a clean `main` that is in sync with `origin/main`:

```sh
mise exec -- node scripts/release.mts <patch|minor|major>
```

The script bumps the `Cargo.toml` version (starting from the manifest version
until the first `v*` tag exists), commits it, and pushes an annotated `vX.Y.Z`
tag. The `Build and maybe release` workflow then builds static musl binaries for
x86_64 and aarch64 Linux and attaches them, with the installer files, to a
GitHub release.
