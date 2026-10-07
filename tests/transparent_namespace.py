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


class IPv6Server(http.server.ThreadingHTTPServer):
    """An IPv6 loopback HTTP upstream for transparent connection tests."""

    address_family = socket.AF_INET6


def command(*args):
    """Execute one operation on namespace-local firewall or certificate state."""
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


def intercepted_request(proxy_port, server, ca_cert, ipv6, tls, path):
    """Redirect one scoped client socket while leaving upstream proxy sockets untouched."""
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    address = "::1" if ipv6 else "127.0.0.1"
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
        connection.connect((address, server.server_port))
        if tls:
            context = ssl.create_default_context(cafile=str(ca_cert))
            connection = context.wrap_socket(connection, server_hostname="allowed.test")
        connection.sendall(
            f"GET {path} HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n".encode())
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
        config = root / "config.toml"
        config.write_text("manage_resolv_conf = false\n"
                          + f"[access_log]\npath = {json.dumps(str(root / 'access.log'))}\n")
        rules = root / "rules"
        rules.mkdir()
        (rules / "1-test.toml").write_text(
            "[[allow]]\ndomain = 'allowed.test'\npathname_pattern = '/allowed'\ninject_headers = [{name='Authorization', value='injected'}]\n")
        context = make_tls_context(root, ca, "allowed.test")
        servers = []
        for ipv6 in (False, True):
            for tls in (False, True):
                server_class = IPv6Server if ipv6 else http.server.ThreadingHTTPServer
                address = "::1" if ipv6 else "127.0.0.1"
                server = server_class((address, 0), EchoHandler)
                if tls:
                    server.socket = context.wrap_socket(server.socket, server_side=True)
                servers.append((start_server(server), ipv6, tls))
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
                        proxy_port, server, cert, ipv6, tls, "/allowed")
                    assert status == 200, (ipv6, tls, status, body, log.read_text())
                    assert json.loads(body)["authorization"] == "injected"
                    assert intercepted_request(
                        proxy_port, server, cert, ipv6, tls, "/denied")[0] == 403
                proxy.terminate()
                assert proxy.wait(timeout=15) == 0
            finally:
                if proxy.poll() is None:
                    proxy.kill()
                    proxy.wait()
                for server, _, _ in servers:
                    server.shutdown()
                    server.server_close()
    print("PASS: transparent IPv4/IPv6 HTTP and HTTPS through dual-stack listener, original destinations, upstream TLS identity, filtering")


if __name__ == "__main__":
    main()
