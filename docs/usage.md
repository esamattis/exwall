# Using exwall

exwall blocks all outbound traffic from ordinary local users except HTTP(S) and
DNS requests that match your allow rules. HTTPS is inspected using a local CA that
the installer adds to the system trust store. Blocked web requests get a 403.

## Install

```sh
sudo apt-get install iptables openssl ca-certificates
bash -c "$(curl -fsSL https://raw.githubusercontent.com/esamattis/exwall/refs/heads/main/install.sh)"
sudo systemctl enable --now exwall
```

To install a specific release, append the tag:

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/esamattis/exwall/refs/heads/main/install.sh)" _ v0.1.0
```

Re-running the installer upgrades exwall and keeps your config, rules, and CA.

| Path                                     | Contents                    |
| ---------------------------------------- | --------------------------- |
| `/etc/exwall/config.toml`                | Service configuration       |
| `/etc/exwall/rules.d/*.toml`             | Allow rules                 |
| `/var/log/exwall/access.log`             | Allowed and denied requests |
| `/var/lib/exwall/exwall-ca-cert.pem`     | The interception CA         |

New login sessions pick up the CA settings for Node, Python, and OpenSSL-based
tools automatically. In an already-open shell, run:

```sh
. /etc/profile.d/exwall.sh
```

Applications with their own trust store must be configured to trust
`/usr/local/share/ca-certificates/exwall.crt`.

### Migrating from mitmwall

Stop mitmwall first; both use the same ports. The installer copies
`/etc/mitmwall/config.toml` and `/etc/mitmwall/rules.d/*.toml` if present, and
the rule syntax is the same.

```sh
sudo systemctl disable --now mitmwall
bash -c "$(curl -fsSL https://raw.githubusercontent.com/esamattis/exwall/refs/heads/main/install.sh)"
sudo systemctl enable --now exwall
```

### Uninstall

```sh
# Keep config, rules, and CA
curl -fsSL https://raw.githubusercontent.com/esamattis/exwall/refs/heads/main/uninstall.sh | sudo sh

# Remove everything
curl -fsSL https://raw.githubusercontent.com/esamattis/exwall/refs/heads/main/uninstall.sh | sudo sh -s -- --purge
```

## Allow rules

Put rules in any `*.toml` file under `/etc/exwall/rules.d/`. Changes are applied
automatically within a moment; an invalid file is reported in the journal and the
previous rules stay active. Check your files with `sudo -u exwall exwall check`.

A rule allows both DNS lookups and HTTP(S) requests for its domains. Only `GET`
and `HEAD` are allowed unless you list more methods.

```toml
# github.com only (not api.github.com), GET and HEAD
[[allow]]
domain = "github.com"

# A domain and all of its subdomains
[[allow]]
domain = "example.com"
include_subdomains = true

# Several domains, any method
[[allow]]
domain = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
methods = "ANY"

# Only some paths
[[allow]]
domain = "api.example.com"
methods = ["GET", "POST"]
pathname_pattern = ["/v1/users/:id", "/v1/uploads/*"]

# Match hostnames with a regex
[[allow]]
domain_regex = '(^|\.)githubusercontent\.com$'

# Add a secret header to upstream requests (HTTPS only), so clients never see it
[[allow]]
domain = "api.openai.com"
methods = ["POST"]
inject_headers = [{ name = "Authorization", value = "Bearer sk-..." }]

# Allow DNS lookups but no HTTP(S)
[[allow]]
domain = "ntp.ubuntu.com"
dns_only = true
```

Path patterns match the whole path, ignoring the query string:

| Pattern               | Matches                          |
| --------------------- | -------------------------------- |
| `/users/:id`          | `/users/42`, not `/users/42/x`   |
| `/files/*`            | `/files/a/b/c.txt`               |
| `/books/:id?`         | `/books` and `/books/42`         |
| `/docs{/}?`           | `/docs` and `/docs/`             |

Use `pathname_regex = '^/downloads/[^/]+$'` for anything patterns cannot express.
When several rules match a request, the first one (by file name, then order in
the file) decides its headers.

See [example-rules.toml](../example-rules.toml) for every option.

## Configuration

`/etc/exwall/config.toml` is documented inline; see
[config-default.toml](../config-default.toml). The settings you are most likely to
change:

```toml
# Users whose traffic is never filtered
bypass_users = ["root", "_apt"]

# Let all DNS queries through while still filtering HTTP(S)
block_dns = false

# Let TCP traffic to a network and port skip filtering entirely
[[iptables.bypass]]
network = "192.168.5.0/24"
port = 5432
```

Apply `block_dns` and other rule-related changes with
`sudo systemctl reload exwall`. Changes to bypasses, logging, and the web UI need
`sudo systemctl restart exwall`.

## Web UI

The installer generates a login, stores it in `config.toml`, and prints it with
the UI URLs. To show the login again, or to generate a new password:

```sh
sudo exwall ui-credentials --if-missing     # show the current login
sudo exwall ui-credentials                  # new password, then restart
sudo exwall ui-credentials --username ops   # new username and password
sudo systemctl restart exwall
```

You can also edit `username` and `password` under `[ui]` in `config.toml` directly.

Open <http://localhost:58000>, or port 58000 on the machine's address. The UI
listens on every IPv4 address by default and serves plain HTTP. To keep it
local, set `hosts = ["127.0.0.1"]` under `[ui]` and use an SSH tunnel from
another machine:

```sh
ssh -L 58000:127.0.0.1:58000 your-server
```

- **Traffic** lists blocked and allowed domains with request counts and the
  HTTP(S) body bytes sent up and received down, and the latest blocked
  requests. Allow a blocked domain, its subdomains, a DNS-only lookup, or one
  exact request with a single click.
- **Rules** edits the rules created from the UI. They are stored in
  `/etc/exwall/rules.d/05-web.toml`; your other rule files are never touched.

Counters reset when exwall restarts or when you press **Reset** on the Traffic
page. The same data is available as JSON:

```sh
curl --user admin http://127.0.0.1:58000/api/domains
curl --user admin http://127.0.0.1:58000/api/rules
```

## Day-to-day commands

```sh
sudo systemctl status exwall
sudo journalctl -u exwall -f                    # service log
sudo tail -F /var/log/exwall/access.log         # every request and DNS query
sudo -u exwall exwall check                     # validate config and rules
sudo systemctl reload exwall                    # reload config and rules
sudo systemctl stop exwall                      # stop filtering
```

Stopping the service, or the service crashing, removes all filtering and restores
the network settings until it starts again. If cleanup ever fails,
`sudo exwall hook stop` removes the firewall rules manually.

Access log lines look like this:

```text
TIMESTAMP PROTOCOL RESULT RULE HTTP_METHOD URL HTTP_STATUS DNS_RCODE ERROR
2026-10-07T12:34:56Z https ALLOW /etc/exwall/rules.d/10-examples.toml:allow#1 GET https://github.com:443/api 200 - -
2026-10-07T12:34:57Z http DENY - POST http://denied.test/upload 403 - -
2026-10-07T12:34:58Z dns DENY - - dns://denied.test/A - REFUSED - x3
```

`RULE` is the file and rule number that allowed the request. A trailing `x3`
means the same request was repeated three times within a second. `ERROR` explains
failures such as `UPSTREAM_TIMEOUT` or `UPSTREAM_FAILURE`.

## Limitations

- WebSocket connections are blocked.
- Only processes on this host are filtered, and users who can change the firewall
  (such as root) can turn it off.
- Users can still resolve names through systemd-resolved's D-Bus interface, so
  DNS blocking alone does not stop a determined local user from looking up names.
  HTTP(S) and other outbound traffic remain blocked.
