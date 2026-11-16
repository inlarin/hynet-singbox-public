from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml


SKILLS = Path(__file__).parents[1]
PROJECT = SKILLS.parents[1]
EXPECTED = {"mikrotik-route-domain", "mikrotik-vpn-check"}


def test_manifest_and_junctions():
    actual = {path.name for path in SKILLS.iterdir()
              if path.is_dir() and not path.name.startswith(("__", ".")) and path.name != "tests"}
    assert actual == EXPECTED
    agents = PROJECT / ".agents/skills"
    for name in sorted(EXPECTED):
        directory = SKILLS / name
        text = (directory / "SKILL.md").read_text(encoding="utf-8")
        match = re.match(r"^---\r?\n(.*?)\r?\n---\r?\n", text, re.S)
        assert match, name
        assert yaml.safe_load(match.group(1))["name"] == name
        assert "<!-- QUICKREF -->" in text
        ast.parse((directory / "check.py").read_text(encoding="utf-8"))
        assert (PROJECT / ".claude/skills" / name).resolve() == directory.resolve()
        assert (PROJECT / ".qwen/skills" / name).resolve() == directory.resolve()
        assert (agents / name).resolve() == directory.resolve()


def test_no_hardcoded_monitoring_path_or_secret_files():
    forbidden = "PycharmProjects" + "/" + "monitoring"
    for path in SKILLS.glob("*/check.py"):
        assert forbidden not in path.read_text(encoding="utf-8").replace("\\", "/")
    for path in SKILLS.rglob("*"):
        if path.is_file():
            assert path.suffix.lower() not in {".pw", ".pem", ".key", ".env"}
