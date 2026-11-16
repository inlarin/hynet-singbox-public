#!/usr/bin/env python3
"""Read-only VPN health snapshot for the selective sing-box stack on RB4011."""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
PROJECT = Path(os.environ.get("MONITORING_DIR", str(HERE.parents[2])))
RSH_DEFAULT = PROJECT / "tools/rsh.py"
CONTAINER = '/container/shell [find where name~"hynet"]'


class Rsh:
    def __init__(self, path, target):
        self.path = Path(path)
        self.target = target
        if not self.path.is_file():
            raise ValueError(f"tools/rsh.py not found: {self.path}")

    def run(self, command, timeout=60):
        result = subprocess.run(
            [sys.executable, str(self.path), "--timeout", str(timeout), self.target, command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 10,
            env=dict(os.environ, MSYS_NO_PATHCONV="1", PYTHONUTF8="1"),
        )
        output = result.stdout + (("\n" + result.stderr.strip()) if result.stderr.strip() else "")
        if result.returncode:
            raise RuntimeError(f"rsh rc={result.returncode}: {output[-2000:]}")
        return result.stdout

    def shell(self, script, timeout=60):
        encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
        command = f'{CONTAINER} cmd="printf \'%s\' \'{encoded}\' | base64 -d | sh"'
        return self.run(command, timeout=timeout)

    def clash(self, path):
        script = (
            "S=$(sed -n 's/^[[:space:]]*\"secret\": \"\\([^\"]*\\)\".*/\\1/p' /tmp/config.json); "
            f"wget -qO- --header=\"Authorization: Bearer $S\" \"http://172.20.0.2:9090{path}\""
        )
        return self.shell(script)


def resolve_exit(rsh):
    tag = "select"
    for _ in range(6):
        data = json.loads(rsh.clash(f"/proxies/{quote(tag, safe='')}"))
        if not data.get("all"):
            return tag
        now = data.get("now")
        if not now and tag == "select":
            tag = "urltest-all"
            continue
        if not now:
            raise ValueError(f"Clash group {tag} has an empty 'now'")
        tag = now
    raise ValueError("too many nested Clash selector groups")


def probe_exit(rsh, tag):
    path = f"/proxies/{quote(tag, safe='')}/delay?timeout=5000&url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
    data = json.loads(rsh.clash(path))
    if not isinstance(data.get("delay"), (int, float)):
        raise ValueError(str(data))
    return int(data["delay"])


def collect(rsh):
    sections = {}
    commands = {
        "resource": "/system resource print",
        "container": "/container print",
        "routes": "/ip route print detail where routing-table=via-hynet",
        "mangle": "/ip firewall mangle print detail where comment~\"hynet\"",
        "clients": "/ip firewall address-list print detail where list=hynet-clients",
        "address_count": "/ip firewall address-list print count-only where list=hynet",
        "logs": f'{CONTAINER} cmd="tail -12 /tmp/healthcheck.log; tail -8 /tmp/sing-box.log"',
    }
    for name, command in commands.items():
        sections[name] = rsh.run(command)
    return sections


def verdict(sections, tag, delay, error):
    container_ok = re.search(r"^\s*\d+\s+H\s+hynet-singbox\b", sections["container"], re.M) is not None
    gateway_ok = ";;; hynet container" in sections["routes"] and "172.20.0.2" in sections["routes"]
    kill_switch = ";;; hynet killswitch" in sections["routes"] and "blackhole" in sections["routes"]
    if not container_ok or not gateway_ok or not kill_switch:
        return "DOWN -- container/gateway/kill-switch wiring is incomplete"
    if error:
        return f"DEGRADED -- selected exit {tag or '?'} failed the live probe: {error}"
    return f"VPN UP -- {tag} alive ({delay} ms); container healthy; kill-switch present"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=("rb4011", "rb4011-zt"), default="rb4011")
    parser.add_argument("--rsh", type=Path, default=RSH_DEFAULT)
    args = parser.parse_args(argv)
    try:
        rsh = Rsh(args.rsh, args.target)
        sections = collect(rsh)
        tag = None
        delay = None
        error = None
        try:
            tag = resolve_exit(rsh)
            delay = probe_exit(rsh, tag)
        except (ValueError, KeyError, RuntimeError, json.JSONDecodeError) as exc:
            error = str(exc)
        result = verdict(sections, tag, delay, error)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        sections = {}
        result = f"CHECK -- {exc}"

    lines = []
    for name, text in sections.items():
        lines.extend((f"===== {name.upper()} =====", text.rstrip(), ""))
    lines.extend(("=== VERDICT ===", result))
    report = "\n".join(lines) + "\n"
    cache = Path(tempfile.gettempdir()) / "mikrotik-vpn-check.txt"
    cache.write_text(report, encoding="utf-8", newline="\n")
    print(report, end="")
    print(f"Full report: {cache}")
    return 0 if result.startswith("VPN UP") else 1


if __name__ == "__main__":
    sys.exit(main())
