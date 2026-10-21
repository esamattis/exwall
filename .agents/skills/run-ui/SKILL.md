---
name: run-ui
description: Use when you need to see a web UI change working in a real browser, take UI screenshots, or call the UI's /api endpoints against a running exwall.
---

# Run the Web UI Locally

`scripts/dev-ui.sh` starts a throwaway exwall with the web UI on localhost. It is the only safe way to run the binary on the development host: it opens localhost listeners and nothing else. Never run `install.sh`, the `hook` subcommands, or a `serve` that uses `/etc/exwall` or `/var/log/exwall` to check a UI change.

## Start

Run it in the background; it keeps running until stopped:

```bash
./scripts/dev-ui.sh
```

It rebuilds `ui/dist` and the debug binary first, so the embedded UI matches the source. Set `EXWALL_DEV_SKIP_BUILD=1` only when both are already current. Wait until its output contains `exwall ready` before connecting; the first build can take a while.

Defaults:

- UI: `http://127.0.0.1:58911/`, login `admin` / `dev`
- Proxy: `127.0.0.1:58981`, DNS: `127.0.0.1:58983`
- Override with `EXWALL_DEV_UI_PORT`, `EXWALL_DEV_PROXY_PORT`, and `EXWALL_DEV_DNS_PORT` if a port is taken.

The script prints its temporary directory, which holds the rules, CA, sessions, and access log. The rules directory starts with an empty `05-web.toml`, so all traffic is blocked until you add rules.

The development host may also run an installed exwall service with its UI on port 58000. Do not stop it, restart it, or use it for testing.

## Use It

Browser: open the UI URL, sign in, and take screenshots.

API, for checking responses without a browser:

```bash
token=$(curl -s -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:58911' \
  -d '{"username":"admin","password":"dev"}' http://127.0.0.1:58911/api/login |
  python3 -c 'import sys, json; print(json.load(sys.stdin)["token"])')
curl -s -H "Authorization: Bearer $token" http://127.0.0.1:58911/api/session
```

Writes (POST/PUT) need the `Content-Type: application/json` and same-origin `Origin` headers shown above.

To generate traffic for the Traffic page, send requests through the proxy with the printed CA:

```bash
curl --proxy http://127.0.0.1:58981 --cacert <ca-dir>/exwall-ca-cert.pem https://example.com/
```

When the development host cannot produce the data a UI state needs, such as public IP addresses, replace `window.fetch` in the page for that one endpoint and wait for the next refetch. Say so when you report the result; screenshots of stubbed data are not evidence that the server returns it.

## Stop

Send SIGTERM or SIGINT to the script, or press Ctrl-C. It stops exwall and deletes its temporary directory. Stop it by PID, not with `pkill -f <pattern>`, because the pattern also matches the shell running `pkill` and kills it.

## Afterward

A manual check supplements the required checks in AGENTS.md; it does not replace them.
