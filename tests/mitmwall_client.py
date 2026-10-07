"""Perform one network operation as the disposable suite's unprivileged client."""

import http.client
import json
import socket
import ssl
import struct
import sys
from urllib.parse import urlsplit

from integration import read_exact


def operate(options):
    """Return JSON-serializable results for HTTP, TCP, TLS, DNS, or ICMPv6."""
    operation = options["operation"]
    if operation == "http":
        url = urlsplit(options["url"])
        if url.scheme == "https":
            context = ssl.create_default_context(cafile=options["cert"])
            connection = http.client.HTTPSConnection(
                url.hostname, url.port or 443, context=context, timeout=3)
        else:
            connection = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=3)
        try:
            path = url.path or "/"
            if url.query:
                path += "?" + url.query
            connection.request(options.get("method", "GET"), path,
                               headers=options.get("headers", {}))
            response = connection.getresponse()
            return {"status": response.status, "body": response.read().decode()}
        finally:
            connection.close()
    if operation in ("tcp", "certificate"):
        with socket.create_connection((options["host"], options["port"]), timeout=0.5) as connection:
            if operation == "tcp":
                return True
            context = ssl.create_default_context(cafile=options["cert"])
            with context.wrap_socket(connection, server_hostname=options["hostname"]) as secure:
                return secure.getpeercert(binary_form=True).hex()
    if operation == "dns":
        name = options["name"]
        qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
        wire = struct.pack("!HHHHHH", 42, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
        tcp = options.get("tcp", False)
        family = socket.AF_INET6 if ":" in options["host"] else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as connection:
            connection.settimeout(3)
            connection.connect((options["host"], options.get("port", 53)))
            if tcp:
                connection.sendall(struct.pack("!H", len(wire)) + wire)
                length = struct.unpack("!H", read_exact(connection, 2))[0]
                response = read_exact(connection, length)
            else:
                connection.send(wire)
                response = connection.recv(65535)
        assert response[:2] == wire[:2], "DNS transaction ID was changed"
        assert len(response) >= 12 and response[2] & 0x80, "not a DNS response"
        return response[3] & 15
    if operation == "ping":
        sequence = 1
        payload = b"exwall-ipv6-control-plane"
        request = struct.pack("!BBHHH", 128, 0, 0, 0, sequence) + payload
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6) as connection:
            connection.settimeout(3)
            connection.sendto(request, (options["host"], 0))
            response = connection.recv(4096)
        message_type, code, _, _, response_sequence = struct.unpack("!BBHHH", response[:8])
        assert (message_type, code, response_sequence) == (129, 0, sequence)
        assert response[8:] == payload
        return True
    raise ValueError(f"unknown client operation: {operation}")


def main():
    """Report connection failures separately from successful network responses."""
    try:
        result = {"result": operate(json.loads(sys.argv[1]))}
    except OSError as error:
        result = {"error": str(error), "error_type": type(error).__name__}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
