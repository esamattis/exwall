"""Test real iptables only inside a disposable user/network namespace."""

import http.client
import http.server
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from integration import EchoHandler, free_port, start_server, wait_for_ready
from namespace_support import assert_namespace


SYSCTLS = [
    "net.ipv4.ip_forward",
    "net.ipv6.conf.all.forwarding",
    "net.ipv4.conf.all.send_redirects"]


def command(*args):
    """Run one namespace-local operation and return its stdout."""
    result = subprocess.run(args, capture_output=True, text=True)
    assert result.returncode == 0, (args, result.stdout, result.stderr)
    return result.stdout


def firewall_snapshot():
    """Capture both namespace firewall families without changing host policy."""
    return [command(tool, "-S") + command(tool, "-t", "nat", "-S")
            for tool in ("iptables", "ip6tables")]


def main():
    """Verify idempotent hook ordering, state restoration, and REDIRECT destination recovery."""
    assert_namespace()
    command("ip", "link", "set", "lo", "up")
    original_sysctls = [command("sysctl", "-n", name) for name in SYSCTLS]
    # Give ramawall an unrelated rule it must preserve across repeated start/stop.
    command(
        "iptables",
        "-A",
        "OUTPUT",
        "-m",
        "comment",
        "--comment",
        "unrelated-test-rule",
        "-j",
        "ACCEPT")
    baseline = firewall_snapshot()
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="ramawall-namespace-") as directory:
        root = Path(directory)
        # A single-user namespace cannot use owner matches for unmapped service
        # UIDs. Bind a private passwd view so those account names map to root.
        passwd = root / "passwd"
        accounts = []
        for line in Path("/etc/passwd").read_text().splitlines():
            fields = line.split(":")
            fields[2:4] = ["0", "0"]
            accounts.append(":".join(fields))
        passwd.write_text("\n".join(accounts) + "\n")
        command("mount", "--bind", str(passwd), "/etc/passwd")
        hosts = root / "hosts"
        hosts.write_text("127.0.0.1 localhost allowed.test\n::1 localhost\n")
        command("mount", "--bind", str(hosts), "/etc/hosts")
        config = root / "config.toml"
        config.write_text(
            "manage_resolv_conf = false\nbypass_users = []\n[[iptables.bypass]]\nnetwork = '192.0.2.19/24'\nport = 443\n")
        rules = root / "rules"
        rules.mkdir()
        rules_file = rules / "test.toml"
        rules_file.write_text("[[allow]]\ndomain = 'allowed.test'\npathname_pattern = '/allowed'\n")
        state = root / "state"
        args = [
            binary,
            "--config",
            str(config),
            "--rules-dir",
            str(rules),
            "hook",
            "--proxy-user",
            "root",
            "--state-dir",
            str(state)]
        try:
            command(*args, "start")
            first = firewall_snapshot()
            saved = (state / "forwarding.json").read_bytes()
            assert [command("sysctl", "-n", name).strip() for name in SYSCTLS] == ["1", "1", "0"]
            assert "RAMAWALL_OUTPUT" in first[0] and "RAMAWALL_OUTPUT" in first[1]
            command(*args, "start")
            assert firewall_snapshot() == first, "repeated start changed the policy"
            assert (state / "forwarding.json").read_bytes() == saved, "repeated start replaced original state"
            for tool in ("iptables", "ip6tables"):
                output = command(tool, "-S", "OUTPUT").splitlines()
                assert output[1] == "-A OUTPUT -j RAMAWALL_OUTPUT", output
                nat = command(tool, "-t", "nat", "-S", "RAMAWALL_NAT")
                assert nat.index("--uid-owner 0") < nat.index("REDIRECT"), nat
            nat4 = command("iptables", "-t", "nat", "-S", "RAMAWALL_NAT")
            assert nat4.index("192.0.2.0/24") < nat4.index("REDIRECT")
            assert "ramawall-forwarding-guard" in command("iptables", "-S", "FORWARD")

            # Stop must work even when the operator leaves malformed TOML on disk.
            config.write_text("not valid TOML")
            rules_file.write_text("not valid TOML")
            command(*args, "stop")
            command(*args, "stop")
            assert firewall_snapshot() == baseline, "cleanup changed unrelated firewall rules"
            assert [command("sysctl", "-n", name) for name in SYSCTLS] == original_sysctls

            # A source-port-scoped redirect lets this single-UID namespace test
            # original destinations without redirecting the proxy's own sockets.
            config.write_text("manage_resolv_conf = false\n"
                          + f"[access_log]\npath = {json.dumps(str(root / 'access.log'))}\n")
            rules_file.write_text("[[allow]]\ndomain='allowed.test'\npathname_pattern='/allowed'\n")
            ca = root / "ca"
            command(binary, "init-ca", "--ca-dir", str(ca))
            upstream = start_server(http.server.ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler))
            proxy_port = free_port()
            dns_port = free_port()
            source_port = free_port()
            redirect = ["-p",
                        "tcp",
                        "--sport",
                        str(source_port),
                        "--dport",
                        str(upstream.server_port),
                        "-j",
                        "REDIRECT",
                        "--to-ports",
                        str(proxy_port)]
            command("iptables", "-t", "nat", "-I", "OUTPUT", *redirect)
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
                                          f"127.0.0.1:{dns_port}",
                                          "--ca-dir",
                                          str(ca)],
                                         stdout=output,
                                         stderr=subprocess.STDOUT)
                try:
                    wait_for_ready(proxy, proxy_port)
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", upstream.server_port, timeout=3, source_address=(
                            "127.0.0.1", source_port))
                    connection.request("GET", "/allowed", headers={"Host": "allowed.test"})
                    response = connection.getresponse()
                    assert response.status == 200, (response.status,
                                                    response.read(), log.read_text())
                    assert json.loads(response.read())["path"] == "/allowed"
                    connection.close()
                    proxy.terminate()
                    assert proxy.wait(timeout=15) == 0
                finally:
                    if proxy.poll() is None:
                        proxy.kill()
                        proxy.wait()
                    upstream.shutdown()
                    upstream.server_close()
                    command("iptables", "-t", "nat", "-D", "OUTPUT", *redirect)
        finally:
            command(*args, "stop")
    print("PASS: real IPv4/IPv6 iptables hooks, idempotence, bypass ordering, sysctl restoration, config-independent cleanup, REDIRECT destination recovery")


if __name__ == "__main__":
    main()
