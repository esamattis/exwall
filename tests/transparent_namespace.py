"""Verify transparent HTTP/TLS original destinations inside an isolated namespace."""

import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile

from integration import EchoHandler, free_port, make_tls_context, start_server, wait_for_ready
from namespace_support import assert_namespace


class CountingHandler(EchoHandler):
    """Record requests so routing checks can prove the attacker was never contacted."""

    def do_GET(self):
        """Capture received authorization before returning the normal echo response."""
        self.server.received.append((self.path, self.headers.get("Authorization")))
        super().do_GET()


class IPv6Server(http.server.ThreadingHTTPServer):
    """An IPv6 loopback HTTP upstream for transparent connection tests."""

    address_family = socket.AF_INET6


def command(*args):
    """Execute one operation on namespace-local firewall or certificate state."""
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


def intercepted_request(proxy_port, server, ca_cert, ipv6, tls, path, destination=None):
    """Redirect one scoped client socket while leaving upstream proxy sockets untouched."""
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    address = "::1" if ipv6 else "127.0.0.2"
    tool = "ip6tables" if ipv6 else "iptables"
    connection = socket.socket(family)
    connection.settimeout(3)
    connection.bind((address, 0))
    source_port = connection.getsockname()[1]
    redirect = ["-p",
                "tcp",
                "--sport",
                str(source_port),
                "--dport",
                str(server.server_port),
                "-j",
                "REDIRECT",
                "--to-ports",
                str(proxy_port)]
    command(tool, "-t", "nat", "-I", "OUTPUT", *redirect)
    try:
        connection.connect((destination or address, server.server_port))
        if tls:
            context = ssl.create_default_context(cafile=str(ca_cert))
            connection = context.wrap_socket(connection, server_hostname="allowed-v6.test" if ipv6 else "allowed.test")
        connection.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {'allowed-v6.test' if ipv6 else 'allowed.test'}\r\nConnection: close\r\n\r\n".encode())
        response = http.client.HTTPResponse(connection)
        response.begin()
        return response.status, response.read()
    finally:
        connection.close()
        command(tool, "-t", "nat", "-D", "OUTPUT", *redirect)


def main():
    """Check both address families through the default dual-stack interception listener."""
    assert_namespace()
    command("ip", "link", "set", "lo", "up")
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="ramawall-transparent-") as directory:
        root = Path(directory)
        ca = root / "ca"
        command(binary, "init-ca", "--ca-dir", str(ca))
        cert = ca / "ramawall-ca-cert.pem"
        hosts = root / "hosts"
        hosts.write_text("127.0.0.2 allowed.test\n::1 allowed-v6.test\n")
        command("mount", "--bind", str(hosts), "/etc/hosts")
        config = root / "config.toml"
        config.write_text("manage_resolv_conf = false\n"
                          + f"[access_log]\npath = {json.dumps(str(root / 'access.log'))}\n")
        rules = root / "rules"
        rules.mkdir()
        (rules / "1-test.toml").write_text(
            "[[allow]]\ndomain = ['allowed.test', 'allowed-v6.test']\npathname_pattern = '/secure'\ninject_headers = [{name='Authorization', value='injected'}]\n[[allow]]\ndomain = ['allowed.test', 'allowed-v6.test']\npathname_pattern = '/allowed'\n")
        context = make_tls_context(root, ca, "allowed.test", ("allowed.test", "allowed-v6.test"))
        servers = []
        attackers = []
        for ipv6 in (False, True):
            for tls in (False, True):
                server_class = IPv6Server if ipv6 else http.server.ThreadingHTTPServer
                address = "::1" if ipv6 else "127.0.0.2"
                server = server_class((address, 0), CountingHandler)
                server.received = []
                if tls:
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                servers.append((start_server(server), ipv6, tls))
                if not ipv6:
                    attacker = http.server.ThreadingHTTPServer(("127.0.0.1", server.server_port), CountingHandler)
                    attacker.received = []
                    attackers.append((start_server(attacker), server, tls))
        proxy_port = free_port()
        dns_port = free_port()
        log = root / "proxy.log"
        with log.open("w") as output:
            proxy = subprocess.Popen([binary,
                                      "--config",
                                      str(config),
                                      "--rules-dir",
                                      str(rules),
                                      "serve",
                                      "--listen",
                                      f"[::]:{proxy_port}",
                                      "--dns-listen",
                                      f"[::]:{dns_port}",
                                      "--ca-dir",
                                      str(ca)],
                                     stdout=output,
                                     stderr=subprocess.STDOUT,
                                     env={**os.environ,
                                          "SSL_CERT_FILE": str(cert),
                                          "SSL_CERT_DIR": str(root / "empty-trust")})
            try:
                wait_for_ready(proxy, proxy_port)
                for server, ipv6, tls in servers:
                    status, body = intercepted_request(
                        proxy_port, server, cert, ipv6, tls, "/secure" if tls else "/allowed")
                    assert status == 200, (ipv6, tls, status, body, log.read_text())
                    assert json.loads(body)["authorization"] == ("injected" if tls else None)
                    if not tls:
                        assert intercepted_request(proxy_port, server, cert, ipv6, tls, "/secure")[0] == 403
                    assert intercepted_request(
                        proxy_port, server, cert, ipv6, tls, "/denied")[0] == 403
                for attacker, authorized, tls in attackers:
                    # The socket targets an attacker, but Host authorizes the other IP.
                    status, body = intercepted_request(proxy_port, authorized, cert, False, tls,
                                                       "/secure" if tls else "/allowed",
                                                       destination="127.0.0.1")
                    assert status == 200, (tls, status, body, log.read_text())
                    assert json.loads(body)["authorization"] == ("injected" if tls else None)
                    if not tls:
                        assert intercepted_request(proxy_port, authorized, cert, False, False,
                                                   "/secure", destination="127.0.0.1")[0] == 403
                    assert attacker.received == [], attacker.received
                proxy.terminate()
                assert proxy.wait(timeout=15) == 0
            finally:
                if proxy.poll() is None:
                    proxy.kill()
                    proxy.wait()
                for server, _, _ in servers + attackers:
                    server.shutdown()
                    server.server_close()
    print("PASS: transparent IPv4/IPv6 HTTP and HTTPS through dual-stack listener, original destinations, upstream TLS identity, filtering")


if __name__ == "__main__":
    main()
