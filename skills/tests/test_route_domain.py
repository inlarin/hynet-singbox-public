from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


SKILL_PATH = Path(__file__).parents[1] / "mikrotik-route-domain/check.py"


@pytest.fixture()
def skill():
    spec = importlib.util.spec_from_file_location("mikrotik_route_domain", SKILL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def catalog_files(tmp_path):
    config = tmp_path / "config"
    scripts = tmp_path / "scripts"
    config.mkdir()
    scripts.mkdir()
    catalog = {
        "schema_version": 1,
        "catalog_version": "1.0.0",
        "upstream_policy": "review-only",
        "dns_forward_to": "77.88.8.8",
        "healthcheck_fqdn": "speed.cloudflare.com",
        "services": [
            {
                "id": "youtube",
                "name": "YouTube",
                "category": "Video",
                "fqdn": ["youtube.com"],
                "ipv4_cidr": [],
                "fqdn_extra": [],
                "ipv4_cidr_extra": [],
                "dns_subdomains": ["youtube.com"],
            },
            {
                "id": "other",
                "name": "Other service",
                "category": "Other",
                "fqdn": ["other.example.com"],
                "ipv4_cidr": [],
                "fqdn_extra": [],
                "ipv4_cidr_extra": [],
                "dns_subdomains": ["other.example.com"],
            },
        ],
    }
    catalog_path = config / "services.json"
    selection_path = config / "services.txt"
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    selection_path.write_text("# enabled\nyoutube\n", encoding="utf-8")
    return catalog_path, selection_path


def make_candidate(skill, files, categories=(), service_id="youtube", domains=("gvt1.com",)):
    catalog_path, selection_path = files
    return skill.build_candidate(
        catalog_path,
        selection_path,
        list(categories),
        service_id,
        list(domains),
        None,
        "Other",
    )


def test_normalize_domains(skill):
    assert skill.normalize_domains(["*.Example.COM.", "example.com", "gvt1.com"]) == [
        "example.com",
        "gvt1.com",
    ]
    with pytest.raises(ValueError):
        skill.normalize_domains(["https://example.com"])


def test_domain_diff_is_scoped_and_ignores_unrelated_drift(skill, catalog_files):
    candidate = make_candidate(skill, catalog_files)
    diff, summary = skill.scoped_plan(candidate, "")
    assert summary["add_static"] == [("youtube", "gvt1.com")]
    assert summary["add_fwd"] == [("youtube", "gvt1.com")]
    assert "youtube.com" not in diff
    assert "other.example.com" not in diff
    assert candidate.catalog["catalog_version"] == "1.0.1"


def test_enabling_category_adds_only_that_category(skill, catalog_files):
    candidate = make_candidate(skill, catalog_files, categories=("other",), service_id=None, domains=())
    _, summary = skill.scoped_plan(candidate, "")
    assert summary["add_static"] == [("other", "other.example.com")]
    assert summary["add_fwd"] == [("other", "other.example.com")]
    assert candidate.append_selection == ["other"]


def test_new_category_is_created_in_candidate_only(skill, catalog_files):
    catalog_path, _ = catalog_files
    before = catalog_path.read_bytes()
    candidate = make_candidate(
        skill,
        catalog_files,
        service_id="custom",
        domains=("example.org", "cdn.example.org"),
    )
    assert candidate.services["custom"]["fqdn_extra"] == ["example.org", "cdn.example.org"]
    assert candidate.services["custom"]["dns_subdomains"] == ["example.org", "cdn.example.org"]
    assert candidate.append_selection == ["custom"]
    assert catalog_path.read_bytes() == before


class FakeRsh:
    commits = 0

    def __init__(self, _path, target):
        self.target = target
        self.entries = []
        self.commits = 0

    def current(self):
        return "\n".join(self.entries)

    def run(self, arguments, timeout=120):
        if arguments[0] == "--safe":
            script = Path(arguments[2]).read_text(encoding="utf-8")
            for line in script.splitlines():
                if "/ip firewall address-list add" in line:
                    address = line.split('address="', 1)[1].split('"', 1)[0]
                    comment = line.split('comment="', 1)[1].split('"', 1)[0]
                    self.entries.append(
                        f"/ip firewall address-list add address={address} comment={comment} list=hynet"
                    )
                elif "/ip dns static add" in line:
                    name = line.split('name="', 1)[1].split('"', 1)[0]
                    comment = line.split('comment="', 1)[1].split('"', 1)[0]
                    self.entries.append(f"/ip dns static add name={name} type=FWD comment={comment}")
            self.commits += 1
            return "=== SAFE SESSION: COMMITTED\n"
        if arguments[1].startswith("/file print count-only"):
            return "1\n"
        return ""


def test_dry_run_does_not_write_local_files(skill, catalog_files, monkeypatch, capsys, tmp_path):
    catalog_path, selection_path = catalog_files
    before = (catalog_path.read_bytes(), selection_path.read_bytes())
    monkeypatch.setattr(skill, "Rsh", FakeRsh)
    monkeypatch.setattr(skill.tempfile, "gettempdir", lambda: str(tmp_path))
    rc = skill.main([
        "--domains", "gvt1.com", "--id", "youtube",
        "--catalog", str(catalog_path), "--services", str(selection_path), "--rsh", "unused",
    ])
    assert rc == 0
    assert "PLAN --" in capsys.readouterr().out
    assert (catalog_path.read_bytes(), selection_path.read_bytes()) == before


def test_apply_chunks_and_updates_local_catalog(skill, catalog_files, monkeypatch, capsys):
    catalog_path, selection_path = catalog_files
    monkeypatch.setattr(skill, "Rsh", FakeRsh)
    domains = [f"host{index}.example.org" for index in range(41)]
    rc = skill.main([
        "--domains", ",".join(domains), "--id", "youtube", "--apply",
        "--catalog", str(catalog_path), "--services", str(selection_path), "--rsh", "unused",
    ])
    assert rc == 0
    output = capsys.readouterr().out
    assert "Safe Mode chunk 1: COMMITTED (80 commands)" in output
    assert "Safe Mode chunk 2: COMMITTED (2 commands)" in output
    assert "OK -- applied and verified 82 router changes" in output
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    youtube = next(service for service in catalog["services"] if service["id"] == "youtube")
    assert youtube["fqdn_extra"] == domains
    assert youtube["dns_subdomains"] == ["youtube.com", *domains]
    generated = (catalog_path.parent.parent / "scripts/routeros-services.rsc").read_text(encoding="utf-8")
    assert "host40.example.org" in generated
