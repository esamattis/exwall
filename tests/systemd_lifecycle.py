"""Exercise the production service lifecycle with a private systemd user manager.

The caller already owns disposable network/mount namespaces and a multiple-UID
fixture network. Unit overrides select temporary paths and root execution; all
start ordering and restart behavior comes from the production unit.
"""

import os
from pathlib import Path
import shlex
import socket
import subprocess
import time

from integration import free_port, wait_for_ready


def wait_until(predicate, message, timeout=15):
    """Bound polling of service state so lifecycle regressions cannot hang the suite."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(message)


def check_systemd_lifecycle(test):
    """Verify actual failed starts, automatic retries, crashes, stops, and cleanup."""
    directory = test.root / "systemd"
    directory.mkdir()
    runtime = directory / "runtime"
    runtime.mkdir(mode=0o700)
    units = directory / "units"
    units.mkdir()
    for target in ("default", "basic", "shutdown", "network-online"):
        (units / f"{target}.target").write_text(
            "[Unit]\nDescription=Private test target\nDefaultDependencies=no\n")
    (units / "systemd-resolved.service").write_text(
        "[Service]\nExecStart=/bin/sleep infinity\n")
    proxy_port, dns_port = free_port(), free_port()
    service_config = directory / "config.toml"
    service_config.write_text(test.config_text + "\n[ui]\nhosts = []\n")
    config_args = [test.binary, "--config", str(service_config), "--rules-dir", str(test.rules)]
    hook = [*config_args, "hook", "--proxy-user", "root", "--state-dir", str(test.state),
            "--proxy-port", str(proxy_port), "--dns-port", str(dns_port)]
    serve = [*config_args, "serve", "--listen", f"[::]:{proxy_port}",
             "--dns-listen", f"[::]:{dns_port}", "--ca-dir", str(test.ca)]
    production = (Path(__file__).parent.parent / "systemd/exwall.service").read_text()
    lines = []
    for line in production.splitlines():
        if line.startswith(("LogsDirectory=", "LogsDirectoryMode=")):
            continue
        if line == "User=exwall":
            line = "User=root"
        elif line == "Group=exwall":
            line = "Group=root"
        elif line.startswith("ExecStartPre=+"):
            operation = line.rsplit(" ", 1)[1]
            line = "ExecStartPre=+" + shlex.join([*hook, operation])
        elif line.startswith("ExecStartPre="):
            line = "ExecStartPre=" + shlex.join([*config_args, "check"])
        elif line.startswith("ExecStart="):
            line = "ExecStart=" + shlex.join(serve)
        lines.append(line)
        if line == "[Service]":
            lines.extend([f"StandardOutput=append:{directory / 'service.log'}",
                          "StandardError=inherit"])
    (units / "exwall.service").write_text("\n".join(lines) + "\n")
    environment = {**os.environ, "XDG_RUNTIME_DIR": str(runtime),
                   "SYSTEMD_UNIT_PATH": str(units)}

    environment.pop("DBUS_SESSION_BUS_ADDRESS", None)
    environment.pop("DBUS_SESSION_BUS_PID", None)

    def control(*arguments, check=True):
        """Address only the private manager via its dedicated runtime socket."""
        result = subprocess.run(["systemctl", "--user", *arguments], env=environment,
                                capture_output=True, text=True, timeout=20)
        if check and result.returncode:
            raise AssertionError(f"systemctl {arguments}: {result.stdout}{result.stderr}")
        return result

    def property_value(name):
        """Read one lifecycle property from the private production-unit instance."""
        return control("show", "exwall.service", f"--property={name}", "--value").stdout.strip()

    def restricted():
        """Require FTP denial for the ordinary UID and root connectivity as control."""
        test.assertEqual(test.client("tcp", user="root", host="ftp.ubuntu-tw.org", port=21),
                         {"result": True})
        result = test.client("tcp", host="ftp.ubuntu-tw.org", port=21)
        test.assertEqual(result.get("error_type"), "TimeoutError", result)

    rule = test.rules / "5-integration.toml"
    rule_text = rule.read_text()
    with (directory / "manager.log").open("w") as log:
        manager = subprocess.Popen(["/usr/lib/systemd/systemd", "--user"], env=environment,
                                   stdout=log, stderr=subprocess.STDOUT)
        try:
            wait_until(lambda: (runtime / "systemd/private").exists(), "private manager failed")
            control("start", "systemd-resolved.service")
            control("start", "exwall.service")
            wait_until(lambda: property_value("ActiveState") == "active", "proxy did not start")
            wait_for_ready(manager, proxy_port)
            saved = (test.state / "forwarding.json").read_bytes()
            for path in (service_config, rule):
                previous = path.read_text()
                path.write_text("not valid TOML")
                control("restart", "exwall.service", check=False)
                restricted()
                wait_until(lambda: int(property_value("NRestarts")) >= 1,
                           "systemd did not automatically retry invalid policy")
                restricted()
                test.assertEqual((test.state / "forwarding.json").read_bytes(), saved)
                path.write_text(previous)
                control("reset-failed", "exwall.service")
                control("restart", "exwall.service")
                wait_until(lambda: property_value("ActiveState") == "active", "repair failed")
                wait_for_ready(manager, proxy_port)
            # SIGKILL exercises Restart=on-failure and the real unit's cleanup path.
            restarts = int(property_value("NRestarts"))
            control("kill", "--signal=KILL", "--kill-whom=main", "exwall.service")
            restricted()
            wait_until(lambda: int(property_value("NRestarts")) > restarts
                       and property_value("ActiveState") == "active", "crash was not restarted")
            wait_for_ready(manager, proxy_port)
            restricted()
            # Occupy the HTTP port to fail ExecStart after successful privileged hooks.
            control("stop", "exwall.service")
            with socket.socket() as occupied:
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                occupied.bind(("127.0.0.1", proxy_port))
                occupied.listen()
                control("start", "exwall.service", check=False)
                wait_until(lambda: property_value("ExecMainStatus") == "1", "startup failure missing")
                restricted()
            control("stop", "exwall.service")
            # Stopping the proxy is fail closed; explicit cleanup restores host state.
            restricted()
            subprocess.run([*hook, "stop"], check=True, capture_output=True, timeout=20)
            test.assertEqual(test.firewall_snapshot(), test.baseline)
            test.assertEqual(test.sysctl_values(), test.original_sysctls)
        except BaseException:
            print((directory / "manager.log").read_text())
            if (directory / "service.log").exists():
                print((directory / "service.log").read_text())
            raise
        finally:
            test.config.write_text(test.config_text)
            rule.write_text(rule_text)
            control("stop", "exwall.service", "systemd-resolved.service", check=False)
            # A minimal unit path has no exit.target; reap the private manager directly.
            manager.kill()
            manager.wait(timeout=5)
            subprocess.run([*test.hook_args, "start"], check=True, capture_output=True, timeout=20)
