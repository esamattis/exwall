"""Serve deterministic HTTP(S), DNS, SSH, and FTP targets in a peer namespace."""

import http.server
import json
import socket
import socketserver
import ssl
import sys

from integration import DnsTcpHandler, DnsUdpHandler, start_server
from namespace_support import assert_namespace


class EchoHandler(http.server.BaseHTTPRequestHandler):
    """Return the path, method, and headers that actually reached the upstream."""

    protocol_version = "HTTP/1.1"

    def respond(self, body=True):
        """Write an identifiable successful response, suppressing the HEAD body."""
        content = json.dumps({"fixture": "ramawall-local-upstream", "path": self.path,
                              "method": self.command, "headers": dict(self.headers)}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        if body:
            self.wfile.write(content)

    def do_GET(self):
        """Echo GET requests without depending on public HTTP services."""
        self.respond()

    def do_HEAD(self):
        """Expose default HEAD authorization with a protocol-correct empty body."""
        self.respond(body=False)

    def do_POST(self):
        """Echo POST requests for method and pathname authorization tests."""
        self.respond()

    def do_PATCH(self):
        """Echo an additional method for unrestricted safety allow rules."""
        self.respond()

    def log_message(self, *_args):
        """Suppress routine upstream request logging."""


class IPv6HttpServer(http.server.ThreadingHTTPServer):
    """Accept HTTP requests on the upstream namespace's IPv6 address."""

    address_family = socket.AF_INET6


class IPv6UdpServer(socketserver.ThreadingUDPServer):
    """Accept upstream IPv6 DNS datagrams."""

    address_family = socket.AF_INET6


class IPv6TcpServer(socketserver.ThreadingTCPServer):
    """Accept upstream IPv6 DNS and direct TCP connections."""

    address_family = socket.AF_INET6


class AcceptHandler(socketserver.BaseRequestHandler):
    """Provide a reachable TCP endpoint for positive controls of blocked traffic."""

    def handle(self):
        """Close accepted sockets without implementing SSH or FTP application protocols."""


def main():
    """Wait for veth setup, then keep local fixture servers alive until stdin closes."""
    assert_namespace()
    # The parent moves the veth here only after this isolation check succeeds.
    print("isolated", flush=True)
    options = json.loads(sys.stdin.readline())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(options["cert"], options["key"])
    servers = []
    for ipv6 in (False, True):
        address = "fd00:7261::2" if ipv6 else "192.0.2.2"
        http_class = IPv6HttpServer if ipv6 else http.server.ThreadingHTTPServer
        tcp_class = IPv6TcpServer if ipv6 else socketserver.ThreadingTCPServer
        udp_class = IPv6UdpServer if ipv6 else socketserver.ThreadingUDPServer
        for port in (80, 443):
            server = http_class((address, port), EchoHandler)
            if port == 443:
                server.socket = context.wrap_socket(server.socket, server_side=True)
            servers.append(start_server(server))
        servers.append(start_server(udp_class((address, 53), DnsUdpHandler)))
        servers.append(start_server(tcp_class((address, 53), DnsTcpHandler)))
        for port in (21, 22):
            servers.append(start_server(tcp_class((address, port), AcceptHandler)))
    for address in ("8.8.8.8", "172.64.155.209", "1.1.1.1"):
        server = http.server.ThreadingHTTPServer((address, 443), EchoHandler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(start_server(server))
    print("ready", flush=True)
    try:
        sys.stdin.read()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
