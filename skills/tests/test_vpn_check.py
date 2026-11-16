from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SKILL_PATH = Path(__file__).parents[1] / "mikrotik-vpn-check/check.py"
spec = importlib.util.spec_from_file_location("mikrotik_vpn_check", SKILL_PATH)
skill = importlib.util.module_from_spec(spec)
spec.loader.exec_module(skill)


class FakeClash:
    def clash(self, path):
        if path == "/proxies/select":
            return json.dumps({"all": ["urltest-all"], "now": ""})
        if path == "/proxies/urltest-all":
            return json.dumps({"all": ["node-a"], "now": "node-a"})
        if path == "/proxies/node-a":
            return json.dumps({"name": "node-a", "type": "Vless"})
        if path.startswith("/proxies/node-a/delay"):
            return json.dumps({"delay": 217})
        raise AssertionError(path)


def test_empty_select_falls_back_to_urltest_and_probes_node():
    clash = FakeClash()
    tag = skill.resolve_exit(clash)
    assert tag == "node-a"
    assert skill.probe_exit(clash, tag) == 217


def test_verdict_requires_wiring_and_live_exit():
    sections = {
        "container": "0 H hynet-singbox  /disk1/containers/hynet-v310",
        "routes": ";;; hynet container\n gateway=172.20.0.2\n;;; hynet killswitch\n blackhole",
    }
    assert skill.verdict(sections, "node-a", 217, None).startswith("VPN UP --")
    assert skill.verdict(sections, "node-a", None, "timeout").startswith("DEGRADED --")
    broken = dict(sections, routes=";;; hynet container\n gateway=172.20.0.2")
    assert skill.verdict(broken, "node-a", 217, None).startswith("DOWN --")
