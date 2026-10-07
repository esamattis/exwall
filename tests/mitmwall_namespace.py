"""Port mitmwall's network/lifecycle cases to real, disposable Linux firewalls.

Public domain and IP fixtures live behind a veth pair with no external route.
The development host retains all access to chatgpt.com and openai.com, including
when a test deliberately installs a deny-all policy or corrupts hook state.
"""

import http.server
import json
import os
from pathlib import Path
import pwd
import select
import stat
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import urlsplit

from integration import EchoHandler, free_port, make_tls_context, start_server, wait_for_ready
from namespace_support import assert_namespace

TESTS = Path(__file__).resolve().parent
SYSCTLS = ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding",
           "net.ipv4.conf.all.send_redirects")
HOSTS = ("github.com", "api.github.com", "ipinfo.io", "httpbin.org", "pie.dev",
         "raw.githubusercontent.com", "esamatti.fi", "www.esamatti.fi", "example.com",
         "ftp.ubuntu-tw.org", "dns.google", "cloudflare-dns.com", "chatgpt.com",
         "openai.com", "api.openai.com", "cdn.chatgpt.com")


def command(*args, check=True):
    """Execute one bounded namespace-local command with captured diagnostics."""
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if check and result.returncode:
        print(result.stdout + result.stderr, file=sys.stderr)
        result.check_returncode()
    return result


def receive_line(process):
    """Read a fixture readiness message without hanging on a failed child."""
    if not select.select([process.stdout], [], [], 10)[0]:
        raise RuntimeError("upstream fixture did not become ready")
    line = process.stdout.readline().strip()
    if not line:
        raise RuntimeError(f"upstream fixture exited: {process.poll()}")
    return line


def stop_process(process):
    """Terminate a fixture and reap it, escalating only after a bounded wait."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


class RamawallNetworkTests(unittest.TestCase):
    """Exercise mitmwall's allow rules and bypass/lifecycle contracts through ramawall."""

    @classmethod
    def setUpClass(cls):
        """Build private accounts/hosts, two networks, upstreams, and a live proxy policy."""
        assert_namespace()
        cls.temporary = tempfile.TemporaryDirectory(prefix="ramawall-mitmwall-port-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.root.chmod(0o755)
        # Ordinary UIDs need no access to the developer's private home directory.
        cls.client_script = cls.root / "mitmwall_client.py"
        for name in ("mitmwall_client.py", "integration.py"):
            helper = cls.root / name
            helper.write_text((TESTS / name).read_text())
            helper.chmod(0o644)
        cls.binary = str(Path(sys.argv[1]).resolve())
        cls.ca = cls.root / "ca"
        command(cls.binary, "init-ca", "--ca-dir", str(cls.ca))
        cls.ca.chmod(0o755)
        cls.cert = cls.ca / "ramawall-ca-cert.pem"
        cls.cert.chmod(0o644)
        make_tls_context(cls.root, cls.ca, "github.com", HOSTS)
        cls.config = cls.root / "config.toml"
        cls.config_text = (TESTS / "fixtures/mitmwall-integration-config.toml").read_text()
        cls.config_text += f"\n[access_log]\npath = {json.dumps(str(cls.root / 'access.log'))}\n"
        cls.config.write_text(cls.config_text)
        cls.rules = cls.root / "rules"
        cls.rules.mkdir()
        (cls.rules / "5-integration.toml").write_text(
            (TESTS / "fixtures/mitmwall-integration-rules.toml").read_text())
        hosts = cls.root / "hosts"
        hosts.write_text("127.0.0.1 localhost\n::1 localhost\n192.0.2.2 " + " ".join(HOSTS) + "\n")
        hosts.chmod(0o644)
        command("mount", "--bind", str(hosts), "/etc/hosts")
        # Account names are fixture-local; no useradd or host account modifications.
        passwd = cls.root / "passwd"
        passwd.write_text("root:x:0:0::/root:/bin/sh\n"
                          "daemon:x:1:1::/nonexistent:/usr/sbin/nologin\n"
                          "nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n"
                          "systemd-resolve:x:990:990::/nonexistent:/usr/sbin/nologin\n")
        passwd.chmod(0o644)
        command("mount", "--bind", str(passwd), "/etc/passwd")
        command("ip", "link", "set", "lo", "up")
        command("sysctl", "-w", "net.ipv4.ping_group_range=65534 65534")
        cls.upstream_log = (cls.root / "upstream.log").open("w")
        cls.addClassCleanup(cls.upstream_log.close)
        cls.upstream = subprocess.Popen(
            ["unshare", "--net", sys.executable, str(TESTS / "mitmwall_upstream.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=cls.upstream_log,
            text=True, bufsize=1)
        cls.addClassCleanup(stop_process, cls.upstream)
        if receive_line(cls.upstream) != "isolated":
            raise RuntimeError("upstream isolation was not verified")
        command("ip", "link", "add", "rw-client", "type", "veth", "peer", "name", "rw-server")
        command("ip", "link", "set", "rw-server", "netns", str(cls.upstream.pid))
        command("ip", "addr", "add", "192.0.2.1/24", "dev", "rw-client")
        command("ip", "-6", "addr", "add", "fd00:7261::1/64", "dev", "rw-client", "nodad")
        command("ip", "link", "set", "rw-client", "up")
        peer = ["nsenter", "-t", str(cls.upstream.pid), "--net"]
        command(*peer, "ip", "link", "set", "lo", "up")
        command(*peer, "ip", "addr", "add", "192.0.2.2/24", "dev", "rw-server")
        command(*peer, "ip", "-6", "addr", "add", "fd00:7261::2/64", "dev", "rw-server", "nodad")
        command(*peer, "ip", "link", "set", "rw-server", "up")
        for address in ("8.8.8.8", "172.64.155.209", "1.1.1.1"):
            command(*peer, "ip", "addr", "add", address + "/32", "dev", "rw-server")
            command("ip", "route", "add", address + "/32", "via", "192.0.2.2")
        cls.upstream.stdin.write(json.dumps({"cert": str(cls.root / "upstream.pem"),
                                            "key": str(cls.root / "upstream.key")}) + "\n")
        cls.upstream.stdin.flush()
        if receive_line(cls.upstream) != "ready":
            raise RuntimeError("upstream servers did not start")
        cls.proxy_port, cls.dns_port = free_port(), free_port()
        cls.state = cls.root / "state"
        cls.hook_args = [cls.binary, "--config", str(cls.config), "--rules-dir", str(cls.rules),
                         "hook", "--proxy-user", "root", "--state-dir", str(cls.state),
                         "--proxy-port", str(cls.proxy_port), "--dns-port", str(cls.dns_port)]
        cls.proxy_log = (cls.root / "proxy.log").open("w")
        cls.addClassCleanup(cls.proxy_log.close)
        cls.proxy = subprocess.Popen(
            [cls.binary, "--config", str(cls.config), "--rules-dir", str(cls.rules), "serve",
             "--listen", f"[::]:{cls.proxy_port}", "--dns-listen", f"[::]:{cls.dns_port}",
             "--dns-upstream", "192.0.2.2:53", "--ca-dir", str(cls.ca)],
            stdout=cls.proxy_log, stderr=subprocess.STDOUT,
            env={**os.environ, "SSL_CERT_FILE": str(cls.cert),
                 "SSL_CERT_DIR": str(cls.root / "empty-trust")})
        cls.addClassCleanup(stop_process, cls.proxy)
        wait_for_ready(cls.proxy, cls.proxy_port)
        # Preserve unrelated filter and NAT rules, including otherwise empty nft tables.
        for tool in ("iptables", "ip6tables"):
            for table in ("filter", "nat"):
                command(tool, "-t", table, "-A", "OUTPUT", "-o", "lo", "-m", "comment",
                        "--comment", "ramawall-integration-admin", "-j", "ACCEPT")
        cls.baseline = cls.firewall_snapshot()
        cls.original_sysctls = cls.sysctl_values()
        cls.addClassCleanup(command, *cls.hook_args, "stop")
        command(*cls.hook_args, "start")

    def tearDown(self):
        """Print proxy/upstream diagnostics on a failed assertion."""
        result = self._outcome.result
        if any(test is self or getattr(test, "test_case", None) is self
               for test, _ in result.failures + result.errors):
            for name in ("proxy.log", "upstream.log"):
                print((self.root / name).read_text(), file=sys.stderr)

    @classmethod
    def firewall_snapshot(cls):
        """Capture complete IPv4/IPv6 filter and NAT policies without counters."""
        return [command(tool, "-t", table, "-S").stdout
                for tool in ("iptables", "ip6tables") for table in ("filter", "nat")]

    @classmethod
    def sysctl_values(cls):
        """Return exact forwarding and redirect values in the client namespace."""
        return [command("sysctl", "-n", name).stdout.strip() for name in SYSCTLS]

    def client(self, operation, user="nobody", **options):
        """Execute a real network operation under a non-bypass or bypass UID."""
        account = pwd.getpwnam(user)
        request = {"operation": operation, "cert": str(self.cert), **options}
        result = subprocess.run(
            [sys.executable, str(self.client_script), json.dumps(request)],
            user=account.pw_uid, group=account.pw_gid, extra_groups=[],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def assert_url_allowed(self, name, url, method="GET"):
        """Require HTTP and HTTPS to reach the expected upstream with status 200."""
        for target in (url, url.replace("https://", "http://", 1)):
            with self.subTest(name=name, url=target, method=method):
                result = self.client("http", url=target, method=method)
                self.assertNotIn("error", result)
                self.assertEqual(result["result"]["status"], 200)
                if method != "HEAD":
                    payload = json.loads(result["result"]["body"])
                    self.assertEqual(payload["fixture"], "ramawall-local-upstream")
                    self.assertEqual(payload["method"], method)
                    parsed = urlsplit(target)
                    self.assertEqual(payload["path"], (parsed.path or "/")
                                     + ("?" + parsed.query if parsed.query else ""))

    def assert_url_blocked(self, name, url, method="GET"):
        """Require an explicit 403 for denied requests instead of accepting network failures."""
        for target in (url, url.replace("https://", "http://", 1)):
            with self.subTest(name=name, url=target, method=method):
                result = self.client("http", url=target, method=method)
                self.assertNotIn("error", result)
                self.assertEqual(result["result"]["status"], 403)

    def _url_reported_headers(self, url):
        """Return normalized headers actually seen by the local HTTPS upstream."""
        result = self.client("http", url=url, headers={"Authorization": "old"})
        self.assertNotIn("error", result)
        self.assertEqual(result["result"]["status"], 200)
        return {name.lower(): value
                for name, value in json.loads(result["result"]["body"])["headers"].items()}

    def test_exact_domain_rule_is_allowed(self) -> None:
        """
        Verify that an exact domain allow rule permits the domain.
        """

        self.assert_url_allowed("exact domain rule", "https://github.com/")

    def test_domain_regex_rule_is_allowed(self) -> None:
        """
        Verify that a domain_regex allow rule permits a matching domain.
        """

        self.assert_url_allowed("domain_regex rule", "https://ipinfo.io/")

    def test_include_subdomains_rule_is_allowed(self) -> None:
        """
        Verify that include_subdomains permits matching subdomains.
        """

        self.assert_url_allowed(
            "include_subdomains rule", "https://raw.githubusercontent.com/"
        )

    def test_subdomain_without_include_subdomains_is_blocked(self) -> None:
        """
        Verify that subdomains are blocked when not explicitly included.
        """

        self.assert_url_blocked(
            "subdomain when include_subdomains=false", "https://www.esamatti.fi/"
        )

    def test_unlisted_domain_is_blocked(self) -> None:
        """
        Verify that domains absent from the allowlist are blocked.
        """

        self.assert_url_blocked("unlisted domain", "https://example.com/")

    def test_methods_rule_allows_get(self) -> None:
        """
        Verify that a methods rule permits an allowed GET request.
        """

        self.assert_url_allowed("methods GET rule", "https://pie.dev/get")

    def test_methods_rule_blocks_post(self) -> None:
        """
        Verify that a methods rule blocks a disallowed POST request.
        """

        self.assert_url_blocked(
            "methods GET rule blocks POST", "https://pie.dev/post", method="POST"
        )

    def test_default_methods_rule_allows_head(self) -> None:
        """
        Verify that default methods include HEAD requests.
        """

        self.assert_url_allowed(
            "default methods rule allows HEAD", "https://github.com/", method="HEAD"
        )

    def test_inject_headers_rule_adds_configured_headers(self) -> None:
        """
        Verify that inject_headers adds the configured request headers.
        """

        headers = self._url_reported_headers("https://pie.dev/headers")

        self.assertEqual(headers.get("authorization"), "Secret")
        self.assertEqual(headers.get("x-mitmwall-test"), "enabled")

    def test_pathname_pattern_rule_allows_matching_post(self) -> None:
        """
        Verify that pathname_pattern permits a matching POST request.
        """

        self.assert_url_allowed(
            "pathname_pattern rule matching POST",
            "https://pie.dev/pathname-pattern/mitmwall/action",
            method="POST",
        )

    def test_pathname_pattern_rule_blocks_wrong_static_segment(self) -> None:
        """
        Verify that pathname_pattern blocks a wrong static path segment.
        """

        self.assert_url_blocked(
            "pathname_pattern rule blocks wrong static segment",
            "https://pie.dev/other/mitmwall/action",
            method="POST",
        )

    def test_pathname_pattern_rule_blocks_extra_path_segment(self) -> None:
        """
        Verify that pathname_pattern blocks an extra path segment.
        """

        self.assert_url_blocked(
            "pathname_pattern rule blocks extra path segment",
            "https://pie.dev/pathname-pattern/nested/mitmwall/action",
            method="POST",
        )

    def test_pathname_pattern_rule_blocks_nonmatching_pathname(self) -> None:
        """
        Verify that pathname_pattern blocks nonmatching paths.
        """

        self.assert_url_blocked(
            "pathname_pattern rule blocks nonmatching pathname",
            "https://pie.dev/pathname-pattern/mitmwall/other",
            method="POST",
        )

    def test_pathname_pattern_array_allows_first_pattern(self) -> None:
        """
        Verify that pathname_pattern array permits a request matching the first pattern.
        """

        self.assert_url_allowed(
            "pathname_pattern array first pattern",
            "https://pie.dev/anything/mitmwall/foo",
            method="POST",
        )

    def test_pathname_pattern_array_allows_second_pattern(self) -> None:
        """
        Verify that pathname_pattern array permits a request matching the second pattern.
        """

        self.assert_url_allowed(
            "pathname_pattern array second pattern",
            "https://pie.dev/anything/mitmwall/bar",
            method="POST",
        )

    def test_pathname_pattern_array_blocks_nonmatching_path(self) -> None:
        """
        Verify that pathname_pattern array blocks a request matching no pattern.
        """

        self.assert_url_blocked(
            "pathname_pattern array blocks nonmatching path",
            "https://pie.dev/anything/mitmwall/baz",
            method="POST",
        )

    def test_pathname_regex_rule_allows_matching_post(self) -> None:
        """
        Verify that pathname_regex permits a matching POST request.
        """

        self.assert_url_allowed(
            "pathname_regex rule matching POST",
            "https://pie.dev/pathname-regex/mitmwall/info",
            method="POST",
        )

    def test_pathname_regex_rule_blocks_wrong_static_segment(self) -> None:
        """
        Verify that pathname_regex blocks a wrong static path segment.
        """

        self.assert_url_blocked(
            "pathname_regex rule blocks wrong static segment",
            "https://pie.dev/other/mitmwall/info",
            method="POST",
        )

    def test_pathname_regex_rule_blocks_nonmatching_pathname(self) -> None:
        """
        Verify that pathname_regex blocks nonmatching paths.
        """

        self.assert_url_blocked(
            "pathname_regex rule blocks nonmatching pathname",
            "https://pie.dev/pathname-regex/mitmwall/info/extra",
            method="POST",
        )

    def test_pathname_regex_array_allows_first_pattern(self) -> None:
        """
        Verify that pathname_regex array permits a request matching the first pattern.
        """

        self.assert_url_allowed(
            "pathname_regex array first pattern",
            "https://pie.dev/regex-array/mitmwall/alpha",
            method="POST",
        )

    def test_pathname_regex_array_allows_second_pattern(self) -> None:
        """
        Verify that pathname_regex array permits a request matching the second pattern.
        """

        self.assert_url_allowed(
            "pathname_regex array second pattern",
            "https://pie.dev/regex-array/mitmwall/beta",
            method="POST",
        )

    def test_pathname_regex_array_blocks_nonmatching_path(self) -> None:
        """
        Verify that pathname_regex array blocks a request matching no pattern.
        """

        self.assert_url_blocked(
            "pathname_regex array blocks nonmatching path",
            "https://pie.dev/regex-array/mitmwall/gamma",
            method="POST",
        )

    def test_pathname_regex_and_pattern_allows_regex_match(self) -> None:
        """
        Verify that a rule with both pathname_regex and pathname_pattern permits
        a request matching the regex.
        """

        self.assert_url_allowed(
            "pathname_regex and pattern allows regex match",
            "https://pie.dev/both/regex/mitmwall",
            method="POST",
        )

    def test_pathname_regex_and_pattern_allows_pattern_match(self) -> None:
        """
        Verify that a rule with both pathname_regex and pathname_pattern permits
        a request matching the pattern.
        """

        self.assert_url_allowed(
            "pathname_regex and pattern allows pattern match",
            "https://pie.dev/both/pattern/mitmwall",
            method="POST",
        )

    def test_pathname_regex_and_pattern_blocks_nonmatching_path(self) -> None:
        """
        Verify that a rule with both pathname_regex and pathname_pattern blocks
        a request matching neither.
        """

        self.assert_url_blocked(
            "pathname_regex and pattern blocks nonmatching path",
            "https://pie.dev/both/other/mitmwall",
            method="POST",
        )

    def test_direct_ssh_to_github_is_blocked(self):
        """Verify a reachable SSH port is dropped for an ordinary client."""
        self.assert_direct_tcp_blocked("github.com", 22)

    def test_direct_ftp_to_allowed_domain_is_blocked(self):
        """Verify DNS allowance does not grant direct FTP access."""
        self.assert_direct_tcp_blocked("ftp.ubuntu-tw.org", 21)

    def assert_direct_tcp_blocked(self, host, port):
        """Use the bypass user as a positive control before requiring a timeout."""
        self.assertEqual(self.client("tcp", user="daemon", host=host, port=port), {"result": True})
        result = self.client("tcp", host=host, port=port)
        self.assertEqual(result.get("error_type"), "TimeoutError", result)

    def test_output_filter_only_accepts_conntrack_reply_direction(self):
        """Check that established original-direction flows receive no general exemption."""
        for tool in ("iptables", "ip6tables"):
            rules = command(tool, "-S", "RAMAWALL_OUTPUT").stdout.splitlines()
            first = next(line for line in rules if line.startswith("-A ")).split()
            self.assertEqual(first[-2:], ["-j", "ACCEPT"])
            self.assertEqual(set(first[first.index("--ctstate") + 1].split(",")),
                             {"ESTABLISHED", "RELATED"})
            self.assertEqual(first[first.index("--ctdir") + 1], "REPLY")

    def test_managed_output_jump_is_first(self):
        """Ensure both filter and NAT jumps precede unrelated administrator rules."""
        for tool in ("iptables", "ip6tables"):
            for table, chain in (("filter", "RAMAWALL_OUTPUT"), ("nat", "RAMAWALL_NAT")):
                rules = command(tool, "-t", table, "-S", "OUTPUT").stdout.splitlines()
                first = next(line for line in rules if line.startswith("-A "))
                self.assertEqual(first, f"-A OUTPUT -j {chain}")

    def test_only_ipv6_filter_allows_control_protocol(self):
        """Require the ICMPv6 exemption before DROP without broad IPv4 allowances."""
        ipv6 = command("ip6tables", "-S", "RAMAWALL_OUTPUT").stdout.splitlines()
        allow = "-A RAMAWALL_OUTPUT -p ipv6-icmp -j ACCEPT"
        self.assertEqual(ipv6.count(allow), 1)
        self.assertLess(ipv6.index(allow), ipv6.index("-A RAMAWALL_OUTPUT -j DROP"))
        ipv4 = command("iptables", "-S", "RAMAWALL_OUTPUT").stdout
        for protocol in ("icmp", "tcp", "udp"):
            self.assertNotIn(f"-A RAMAWALL_OUTPUT -p {protocol} -j ACCEPT", ipv4)

    def test_unprivileged_ipv6_echo_on_loopback(self):
        """Exercise live ICMPv6 locally and over veth under the ordinary client UID."""
        for host in ("::1", "fd00:7261::2"):
            self.assertEqual(self.client("ping", host=host), {"result": True})

    def test_custom_iptables_rule_allows_direct_tcp(self):
        """Confirm a plain IPv4 network exception avoids TLS interception."""
        self.assert_certificate_bypassed("8.8.8.8", "dns.google")

    def test_custom_iptables_rule_allows_direct_tcp_with_cidr_32(self):
        """Confirm a /32 network exception avoids TLS interception."""
        self.assert_certificate_bypassed("172.64.155.209", "dns.google")

    def assert_certificate_bypassed(self, host, hostname):
        """Require ordinary and bypass users to observe the same upstream certificate."""
        direct = self.client("certificate", user="daemon", host=host, port=443, hostname=hostname)
        ordinary = self.client("certificate", host=host, port=443, hostname=hostname)
        self.assertNotIn("error", direct)
        self.assertEqual(ordinary, direct)

    def test_configured_user_bypasses_firewall_and_proxy(self):
        """Require a bypass user's certificate to differ from the intercepted certificate."""
        direct = self.client("certificate", user="daemon", host="1.1.1.1", port=443,
                             hostname="cloudflare-dns.com")
        proxied = self.client("certificate", host="1.1.1.1", port=443,
                              hostname="cloudflare-dns.com")
        self.assertNotIn("error", direct)
        self.assertNotIn("error", proxied)
        self.assertNotEqual(proxied, direct)
        for tool in ("iptables", "ip6tables"):
            for table, chain in (("filter", "RAMAWALL_OUTPUT"), ("nat", "RAMAWALL_NAT")):
                self.assertIn("--uid-owner 1 -j ACCEPT", command(tool, "-t", table, "-S", chain).stdout)

    def test_direct_dns_queries_to_public_resolver_are_proxied(self):
        """Require UDP/TCP DNS redirection in both families, including regex matches."""
        for host in ("192.0.2.2", "fd00:7261::2"):
            for tcp in (False, True):
                for name, expected in (("github.com", 0), ("ipinfo.io", 0),
                                       ("not-allowed.mitmwall.invalid", 5)):
                    with self.subTest(host=host, tcp=tcp, name=name):
                        direct = self.client("dns", user="daemon", host=host, name=name, tcp=tcp)
                        self.assertEqual(direct, {"result": 0})
                        self.assertEqual(self.client("dns", host=host, name=name, tcp=tcp),
                                         {"result": expected})

    def test_tcp_connections_to_localhost_are_allowed(self):
        """Verify ordinary clients can connect to a real loopback listener."""
        server = start_server(http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler))
        try:
            self.assertEqual(self.client("tcp", host="127.0.0.1", port=server.server_port),
                             {"result": True})
        finally:
            server.shutdown()
            server.server_close()

    def test_control_domains_allow_all_methods_and_dns(self):
        """Keep ChatGPT/OpenAI fixture domains and subdomains unrestricted by method/path."""
        for host in ("chatgpt.com", "openai.com", "api.openai.com", "cdn.chatgpt.com"):
            for method in ("GET", "POST", "PATCH"):
                self.assert_url_allowed("control service", f"https://{host}/arbitrary/path", method)
            self.assertEqual(self.client("dns", host="192.0.2.2", name=host), {"result": 0})

    def test_ipv6_transparent_http_and_https(self):
        """Verify the full installed hooks intercept web traffic across IPv6 veth."""
        ipv6_hosts = self.root / "ipv6-hosts"
        ipv6_hosts.write_text("127.0.0.1 localhost\n::1 localhost\nfd00:7261::2 "
                              + " ".join(HOSTS) + "\n")
        ipv6_hosts.chmod(0o644)
        command("mount", "--bind", str(ipv6_hosts), "/etc/hosts")
        try:
            self.assert_url_allowed("IPv6 exact domain", "https://github.com/")
            self.assert_url_blocked("IPv6 denied domain", "https://example.com/")
        finally:
            command("umount", "/etc/hosts")

    def test_z_empty_custom_config_removes_installed_bypasses(self):
        """Refresh both firewall families while preserving unrelated rules and removing bypasses."""
        direct = self.client("certificate", host="8.8.8.8", port=443, hostname="dns.google")
        self.assertNotIn("error", direct)
        self.config.write_text("manage_resolv_conf = false\nbypass_users = ['daemon']\n"
                               "[iptables]\nbypass = []\n")
        try:
            command(*self.hook_args, "start")
            first = self.firewall_snapshot()
            command(*self.hook_args, "start")
            self.assertEqual(self.firewall_snapshot(), first)
            for tool in ("iptables", "ip6tables"):
                for table, chain in (("filter", "RAMAWALL_OUTPUT"), ("nat", "RAMAWALL_NAT")):
                    managed = command(tool, "-t", table, "-S", chain).stdout
                    for network in ("8.8.8.8", "172.64.155.209", "2001:db8::/32", "192.168.5.0/24"):
                        self.assertNotIn(network, managed)
                    self.assertIn("ramawall-integration-admin", command(tool, "-t", table, "-S").stdout)
            proxied = self.client("certificate", host="8.8.8.8", port=443, hostname="dns.google")
            self.assertNotIn("error", proxied)
            self.assertNotEqual(proxied, direct)
        finally:
            self.config.write_text(self.config_text)
            command(*self.hook_args, "start")

    def test_hook_state_permissions_idempotence_and_restoration(self):
        """Port private state, repeated start/stop, and exact forwarding restoration checks."""
        snapshot = self.firewall_snapshot()
        state_file = self.state / "forwarding.json"
        saved = state_file.read_bytes()
        for path, mode in ((self.state, 0o700), (state_file, 0o600)):
            metadata = path.stat()
            self.assertEqual((metadata.st_uid, metadata.st_gid), (0, 0))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), mode)
        command(*self.hook_args, "start")
        self.assertEqual(state_file.read_bytes(), saved)
        self.assertEqual(self.firewall_snapshot(), snapshot)
        self.assertEqual(self.sysctl_values(), ["1", "1", "0"])
        for tool, original in zip(("iptables", "ip6tables"), self.original_sysctls):
            self.assertEqual("ramawall-forwarding-guard" in command(tool, "-S", "FORWARD").stdout,
                             original == "0")
        try:
            command(*self.hook_args, "stop")
            command(*self.hook_args, "stop")
            self.assertEqual(self.sysctl_values(), self.original_sysctls)
            self.assertEqual(self.firewall_snapshot(), self.baseline)
            self.assertFalse(state_file.exists())
        finally:
            command(*self.hook_args, "start")

    def test_corrupt_forwarding_state_fails_without_sysctl_changes(self):
        """Reject corrupt snapshots without changing forwarding or losing diagnostic context."""
        command(*self.hook_args, "stop")
        state_file = self.state / "forwarding.json"
        state_file.write_text("not json\n")
        state_file.chmod(0o600)
        try:
            result = command(*self.hook_args, "start", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("corrupt state", result.stderr)
            self.assertEqual(self.sysctl_values(), self.original_sysctls)
            self.assertEqual(state_file.read_text(), "not json\n")
        finally:
            state_file.unlink()
            command(*self.hook_args, "stop")
            self.assertEqual(self.firewall_snapshot(), self.baseline)
            command(*self.hook_args, "start")


def main():
    """Run all named ported cases and exit unsuccessfully on any failed assertion."""
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RamawallNetworkTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == "__main__":
    main()
