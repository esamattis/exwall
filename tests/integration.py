"""Exercise the real proxy with local upstreams; never modify host network policy."""

import http.client
import http.server
import json
import os
import re
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


class EchoHandler(http.server.BaseHTTPRequestHandler):
    """Return upstream request metadata or a deliberately delayed response stream."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        """Echo request metadata, preserving streaming timing for /stream."""
        if self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Length", "11")
            self.end_headers()
            self.wfile.write(b"first")
            self.wfile.flush()
            time.sleep(0.5)
            self.wfile.write(b"second")
            return
        body = json.dumps({"path": self.path, "authorization": self.headers.get(
            "Authorization"), "trace": self.headers.get("X-Trace")}).encode()
        status = 502 if self.path == "/allowed?upstream_status=502" else 200
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Upstream-Protocol", self.request_version)
        if isinstance(self.connection, ssl.SSLSocket):
            self.send_header("X-Upstream-ALPN", self.connection.selected_alpn_protocol() or "none")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """Echo POST requests using the same metadata response."""
        self.do_GET()

    def log_message(self, *_args):
        """Keep normal upstream access logs out of test output."""


class DnsUdpHandler(socketserver.BaseRequestHandler):
    """A local UDP upstream returning an empty successful DNS answer."""

    def handle(self):
        """Preserve the query and transaction ID in the response."""
        wire, connection = self.request
        response = wire[:2] + b"\x81\x80" + wire[4:]
        connection.sendto(response, self.client_address)


class DnsTcpHandler(socketserver.BaseRequestHandler):
    """A local TCP upstream implementing the two-byte DNS length prefix."""

    def handle(self):
        """Answer one length-prefixed DNS packet."""
        length = struct.unpack("!H", read_exact(self.request, 2))[0]
        wire = read_exact(self.request, length)
        response = wire[:2] + b"\x81\x80" + wire[4:]
        self.request.sendall(struct.pack("!H", len(response)) + response)


def read_exact(connection, length):
    """Read a complete protocol field or fail if the peer disconnects early."""
    output = b""
    while len(output) < length:
        part = connection.recv(length - len(output))
        if not part:
            raise AssertionError("unexpected EOF")
        output += part
    return output


def free_port():
    """Reserve an ephemeral local port long enough to select a test listener address."""
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def start_server(server):
    """Start a local test upstream on a daemon thread."""
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def query_dns(port, name, tcp=False, ipv6=False):
    """Send one DNS query and return the response code after checking its ID."""
    qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    wire = struct.pack("!HHHHHH", 42, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    address = ("::1" if ipv6 else "127.0.0.1", port)
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
        connection.settimeout(3)
        connection.connect(address)
        if tcp:
            connection.sendall(struct.pack("!H", len(wire)) + wire)
            length = struct.unpack("!H", read_exact(connection, 2))[0]
            response = read_exact(connection, length)
        else:
            connection.send(wire)
            response = connection.recv(65535)
    assert response[:2] == wire[:2]
    return response[3] & 15


def request_http(
        proxy_port,
        upstream_port,
        path,
        method="GET",
        host="127.0.0.1",
        ipv6=False,
        headers=None):
    """Send an absolute-form HTTP request through the explicit proxy listener."""
    connection = http.client.HTTPConnection("::1" if ipv6 else "127.0.0.1", proxy_port, timeout=3)
    connection.request(method, f"http://{host}:{upstream_port}{path}", headers=headers or {})
    response = connection.getresponse()
    result = response.status, response.read()
    connection.close()
    return result


def request_tls(
        proxy_port,
        upstream_port,
        ca_cert,
        path="/secure",
        tunnel=False,
        host="localhost"):
    """Verify CA trust while testing either direct TLS interception or CONNECT."""
    connection = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
    if tunnel:
        connection.sendall(f"CONNECT localhost:{
            upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n".encode())
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            header += read_exact(connection, 1)
        assert header.startswith(b"HTTP/1.1 200"), header
    context = ssl.create_default_context(cafile=str(ca_cert))
    with context.wrap_socket(connection, server_hostname="localhost") as secure:
        secure.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}:{upstream_port}\r\nConnection: close\r\n\r\n".encode())
        response = http.client.HTTPResponse(secure)
        response.begin()
        if response.status == 200:
            assert response.getheader("X-Upstream-Protocol") == "HTTP/1.1"
            assert response.getheader("X-Upstream-ALPN") == "http/1.1"
        return response.status, response.read()


def wait_for_ready(process, port):
    """Wait briefly for proxy startup and fail immediately if it exits."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert process.poll() is None, "proxy exited before becoming ready"
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("proxy did not become ready")


def make_tls_context(root, ca, hostname, dns_names=None):
    """Generate a short-lived test-CA certificate for one or more upstream names."""
    cert = ca / "exwall-ca-cert.pem"
    tls_key = root / "upstream.key"
    csr = root / "upstream.csr"
    tls_cert = root / "upstream.pem"
    extensions = root / "extensions.cnf"
    names = ",".join(f"DNS:{name}" for name in (dns_names or [hostname]))
    extensions.write_text(f"subjectAltName={names}\nextendedKeyUsage=serverAuth\n")
    subprocess.run(["openssl",
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(tls_key),
                    "-out",
                    str(csr),
                    "-subj",
                    f"/CN={hostname}"],
                   check=True,
                   capture_output=True)
    subprocess.run(["openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(csr),
                    "-CA",
                    str(cert),
                    "-CAkey",
                    str(ca / "exwall-ca-key.pem"),
                    "-CAcreateserial",
                    "-out",
                    str(tls_cert),
                    "-days",
                    "1",
                    "-extfile",
                    str(extensions)],
                   check=True,
                   capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tls_cert, tls_key)
    return context


def main():
    """Validate filtering, forwarding, TLS trust, streaming, DNS, and atomic reloads."""
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="exwall-integration-") as directory:
        root = Path(directory)
        ca = root / "ca"
        rules = root / "rules"
        rules.mkdir()
        config = root / "config.toml"
        access_log = root / "access.log"
        ui_port = free_port()
        access_config = (f"[access_log]\npath = {json.dumps(str(access_log))}\n"
                         f"[ui]\nhosts = ['127.0.0.1', '::1']\nport = {ui_port}\n")
        config.write_text("log_level = 'debug'\nblock_dns = true\nmanage_resolv_conf = false\n" + access_config)
        rule_file = rules / "1-test.toml"
        rule_text = '''[[allow]]
domain = ['127.0.0.1', 'localhost']
pathname_pattern = ['/secure']
methods = ['GET']
inject_headers = [{ name = 'Authorization', value = 'replacement' }, { name = 'X-Trace', value = 'injected' }]
stream = true
[[allow]]
domain = ['127.0.0.1', 'localhost']
pathname_pattern = ['/allowed', '/stream']
methods = ['GET']
'''
        rule_file.write_text(rule_text)
        subprocess.run([str(binary), "init-ca", "--ca-dir", str(ca)],
                       check=True, capture_output=True)
        cert = ca / "exwall-ca-cert.pem"

        upstream = start_server(http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler))
        secure_upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
        tls_context = make_tls_context(root, ca, "localhost")
        tls_context.set_alpn_protocols(["http/1.1"])
        secure_upstream.socket = tls_context.wrap_socket(secure_upstream.socket, server_side=True)
        start_server(secure_upstream)
        rogue_ca = root / "rogue-ca"
        subprocess.run([str(binary), "init-ca", "--ca-dir", str(rogue_ca)],
                       check=True, capture_output=True)
        rogue_material = root / "rogue-material"
        rogue_material.mkdir()
        rogue_context = make_tls_context(rogue_material, rogue_ca, "localhost")
        rogue_upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
        rogue_upstream.socket = rogue_context.wrap_socket(rogue_upstream.socket, server_side=True)
        start_server(rogue_upstream)
        dns_udp = start_server(socketserver.ThreadingUDPServer(("127.0.0.1", 0), DnsUdpHandler))
        dns_tcp = start_server(
            socketserver.ThreadingTCPServer(
                dns_udp.server_address,
                DnsTcpHandler))
        proxy_port = free_port()
        dns_port = free_port()
        command = [
            str(binary),
            "--config",
            str(config),
            "--rules-dir",
            str(rules),
            "serve",
            "--listen",
            f"[::]:{proxy_port}",
            "--dns-listen",
            f"[::]:{dns_port}",
            "--dns-upstream",
            f"127.0.0.1:{
                dns_udp.server_address[1]}",
            "--ca-dir",
            str(ca)]
        log = root / "proxy.log"
        with log.open("w") as output:
            process = subprocess.Popen(
                command,
                stdout=output,
                stderr=subprocess.STDOUT,
                env={
                    **os.environ,
                    "SSL_CERT_FILE": str(cert),
                    "SSL_CERT_DIR": str(
                        root /
                        "empty-trust-dir")})
            try:
                wait_for_ready(process, proxy_port)
                wait_for_ready(process, ui_port)
                for address in ("127.0.0.1", "::1"):
                    connection = http.client.HTTPConnection(address, ui_port, timeout=3)
                    connection.request("GET", "/")
                    ui_response = connection.getresponse()
                    assert ui_response.status == 200
                    html = ui_response.read().decode()
                    assert "<title>exwall</title>" in html
                    asset = re.search(r'src="([^"]+\.js)"', html).group(1)
                    connection.request("GET", asset)
                    ui_response = connection.getresponse()
                    assert ui_response.status == 200
                    assert ui_response.getheader("Content-Type").startswith("text/javascript")
                    assert b"Hello world" in ui_response.read()
                    connection.request("GET", "/assets/missing.js")
                    ui_response = connection.getresponse()
                    assert ui_response.status == 404
                    ui_response.read()
                    connection.close()
                port = upstream.server_port
                status, body = request_http(proxy_port, port, "/allowed?query=retained")
                assert status == 200, (status, body)
                echoed = json.loads(body)
                assert echoed == {"path": "/allowed?query=retained",
                                  "authorization": None, "trace": None}, echoed
                assert request_http(proxy_port, port, "/secure")[0] == 403
                assert request_http(proxy_port, port, "/allowed", ipv6=True)[0] == 200
                assert request_http(proxy_port, port, "/allowed?upstream_status=502")[0] == 502
                status, body = request_http(
                    proxy_port, port, "/allowed", headers={"Authorization": "old", "Connection": "Authorization"})
                assert status == 200 and json.loads(body)["authorization"] is None
                assert request_http(
                    proxy_port,
                    port,
                    "/allowed",
                    headers={
                        "Host": "denied.test"})[0] == 421
                assert request_http(
                    proxy_port,
                    port,
                    "/allowed",
                    headers={
                        "Upgrade": "websocket"})[0] == 501
                assert request_http(proxy_port, port, "/denied")[0] == 403
                assert request_http(proxy_port, port, "/allowed", method="POST")[0] == 403
                assert request_http(proxy_port, port, "/allowed", host="denied.test")[0] == 403
                for tunnel in (False, True):
                    status, body = request_tls(
                        proxy_port, secure_upstream.server_port, cert, tunnel=tunnel)
                    assert status == 200, (tunnel, status, body)
                    assert json.loads(body)["authorization"] == "replacement"
                    assert request_tls(
                        proxy_port,
                        secure_upstream.server_port,
                        cert,
                        path="/denied",
                        tunnel=tunnel)[0] == 403
                assert request_tls(
                    proxy_port,
                    secure_upstream.server_port,
                    cert,
                    host="127.0.0.1")[0] == 421
                assert request_tls(proxy_port, rogue_upstream.server_port, cert)[0] == 502

                subprocess.run(["mise", "exec", "--", "node",
                                str(Path(__file__).with_name("http2_upstream.mjs")),
                                str(proxy_port), str(root / "upstream.pem"),
                                str(root / "upstream.key"), str(cert)],
                               check=True, timeout=20)

                # curl's HTTP/2-capable client verifies downstream ALPN and framing.
                result = subprocess.run(["curl",
                                         "--silent",
                                         "--show-error",
                                         "--noproxy",
                                         "",
                                         "--http2",
                                         "--cacert",
                                         str(cert),
                                         "--proxy",
                                         f"http://127.0.0.1:{proxy_port}",
                                         f"https://localhost:{secure_upstream.server_port}/secure",
                                         "--write-out",
                                         "\n%{http_version}"],
                                        capture_output=True,
                                        text=True,
                                        timeout=10)
                assert result.returncode == 0 and result.stdout.endswith(
                    "\n2"), (result.stdout, result.stderr)

                connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=3)
                connection.request("GET", f"http://127.0.0.1:{port}/stream")
                response = connection.getresponse()
                start = time.monotonic()
                assert response.read(5) == b"first"
                assert time.monotonic() - start < 0.4, "proxy buffered the streaming response"
                assert response.read() == b"second"
                connection.close()

                for tcp in (False, True):
                    for ipv6 in (False, True):
                        assert query_dns(dns_port, "localhost", tcp, ipv6) == 0
                        assert query_dns(dns_port, "denied.test", tcp, ipv6) == 5

                rule_file.write_text("")
                deadline = time.monotonic() + 3
                while request_http(proxy_port, port, "/allowed")[0] != 403:
                    assert time.monotonic() < deadline
                    time.sleep(0.05)
                rule_file.write_text(rule_text)
                deadline = time.monotonic() + 3
                while request_http(proxy_port, port, "/allowed")[0] != 200:
                    assert time.monotonic() < deadline
                    time.sleep(0.05)
                rule_file.write_text("[[allow]]\nunknown = true\n")
                time.sleep(0.3)
                assert request_http(proxy_port, port, "/allowed")[0] == 200

                rule_file.write_text(rule_text)
                config.write_text("watch_rules = false\nblock_dns = false\nmanage_resolv_conf = false\n" + access_config)
                process.send_signal(signal.SIGHUP)
                deadline = time.monotonic() + 3
                while query_dns(dns_port, "denied.test") != 0:
                    assert time.monotonic() < deadline
                    time.sleep(0.05)

                rule_file.write_text("")
                time.sleep(0.3)
                assert request_http(proxy_port, port, "/allowed")[0] == 200
                config.write_text("watch_rules = true\nblock_dns = false\nmanage_resolv_conf = false\n" + access_config)
                process.send_signal(signal.SIGHUP)
                deadline = time.monotonic() + 3
                while request_http(proxy_port, port, "/allowed")[0] != 403:
                    assert time.monotonic() < deadline
                    time.sleep(0.05)
                rule_file.write_text(rule_text)
                deadline = time.monotonic() + 3
                while request_http(proxy_port, port, "/allowed")[0] != 200:
                    assert time.monotonic() < deadline
                    time.sleep(0.05)
                process.terminate()
                assert process.wait(timeout=15) == 0
                application_log = log.read_text()
                assert "automatically reloaded rules" in application_log, application_log
                assert "rule reload rejected; keeping previous policy" in application_log, application_log
                for message in ("allowed HTTP request", "blocked HTTP request", "blocked DNS request",
                                "rule regex evaluation failed"):
                    assert message not in application_log, application_log
                rows = [line.split() for line in access_log.read_text().splitlines()]
                assert rows and all(len(row) == 9 for row in rows), rows
                columns = ("timestamp", "protocol", "decision", "rule", "method", "url",
                           "http_status", "dns_rcode", "error")
                entries = [dict(zip(columns, row)) for row in rows]
                matched_rule = str(rule_file) + ":allow#2"
                assert matched_rule not in application_log, application_log
                assert any(entry["protocol"] == "http" and entry["decision"] == "ALLOW"
                           and entry["rule"] == matched_rule and entry["method"] == "GET"
                           and entry["url"].endswith("/allowed?query=retained")
                           and entry["http_status"] == "200" and entry["error"] == "-"
                           for entry in entries)
                assert any(entry["protocol"] == "http" and entry["decision"] == "DENY"
                           and entry["method"] == "POST" and entry["rule"] == "-"
                           and entry["http_status"] == "403" and entry["error"] == "-"
                           for entry in entries)
                for method in ("GET", "CONNECT"):
                    assert any(entry["protocol"] == "https" and entry["decision"] == "ALLOW"
                               and entry["rule"] == str(rule_file) + ":allow#1" and entry["method"] == method
                               and entry["http_status"] == "200" and entry["error"] == "-"
                               for entry in entries)
                assert any(entry["protocol"] == "https" and entry["decision"] == "DENY"
                           and entry["http_status"] == "403" and entry["error"] == "-"
                           for entry in entries)
                assert any(entry["protocol"] == "https" and entry["decision"] == "ALLOW"
                           and entry["http_status"] == "502" and entry["error"] == "UPSTREAM_FAILURE"
                           for entry in entries)
                assert any(entry["protocol"] == "http" and entry["decision"] == "ALLOW"
                           and entry["url"].endswith("/allowed?upstream_status=502")
                           and entry["http_status"] == "502" and entry["error"] == "-"
                           for entry in entries)
                assert any(entry["protocol"] == "dns" and entry["decision"] == "ALLOW"
                           and entry["rule"] == str(rule_file) + ":allow#1" and entry["url"] == "dns://localhost/A"
                           and entry["dns_rcode"] == "NOERROR" and entry["error"] == "-"
                           for entry in entries)
                assert any(entry["protocol"] == "dns" and entry["decision"] == "DENY"
                           and entry["rule"] == "-" and entry["url"] == "dns://denied.test/A"
                           and entry["dns_rcode"] == "REFUSED" and entry["error"] == "-"
                           for entry in entries)
                assert any(entry["protocol"] == "dns" and entry["decision"] == "ALLOW"
                           and entry["rule"] == "@dns-bypass" and entry["dns_rcode"] == "NOERROR"
                           and entry["error"] == "-" for entry in entries)
                assert all(entry["http_status"] == "-" and entry["method"] == "-"
                           for entry in entries if entry["protocol"] == "dns")
                assert all(entry["dns_rcode"] == "-"
                           for entry in entries if entry["protocol"] != "dns")
                assert "replacement" not in access_log.read_text()
                assert "proxy-secret" not in access_log.read_text()
            except BaseException:
                print(log.read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                for server in (upstream, secure_upstream, rogue_upstream, dns_udp, dns_tcp):
                    server.shutdown()
                    server.server_close()
    print("PASS: HTTP filtering, header injection, TLS MITM/CONNECT, HTTP/2, streaming, UDP/TCP DNS, IPv6, reloads, access-log decisions and outcomes")


if __name__ == "__main__":
    main()
