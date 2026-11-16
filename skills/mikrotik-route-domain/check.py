#!/usr/bin/env python3
"""Add FQDNs or service categories to selective VPN routing on RB4011."""
from __future__ import annotations

import argparse
import copy
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = Path(os.environ.get("MONITORING_DIR", str(HERE.parents[2])))
REPO = PROJECT / "hynet-container"
sys.path.insert(0, str(REPO / "scripts"))
import generate_routeros_services as core  # noqa: E402

EXPORT_ADDRESS = '/ip firewall address-list export terse where comment~"hynet:"'
EXPORT_DNS = '/ip dns static export terse where comment~"hynet:"'
MAX_SAFE_COMMANDS = 80
ADD_ACTIONS = ("add_static", "add_fwd", "add_a")
EMPTY_ACTIONS = ("remove_static", "remove_fwd", "remove_a")


@dataclass
class Candidate:
    catalog: dict
    services: dict
    selected: list[str]
    scope: set[str]
    domains: list[str]
    service_id: str | None
    newly_selected: set[str]
    append_selection: list[str]
    catalog_changed: bool

    @property
    def selection_changed(self):
        return bool(self.append_selection)


class ApplyFailure(RuntimeError):
    def __init__(self, message, partial=False):
        super().__init__(message)
        self.partial = partial


class Rsh:
    def __init__(self, path, target):
        self.path = Path(path)
        self.target = target
        if not self.path.is_file():
            raise ValueError(f"tools/rsh.py not found: {self.path}")

    def run(self, arguments, timeout=120):
        env = dict(os.environ, MSYS_NO_PATHCONV="1", PYTHONUTF8="1")
        result = subprocess.run(
            [sys.executable, str(self.path), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
        output = result.stdout + (("\n" + result.stderr.strip()) if result.stderr.strip() else "")
        if result.returncode:
            raise RuntimeError(f"rsh rc={result.returncode}: {output[-2500:]}")
        return result.stdout

    def current(self):
        outputs = [self.run([self.target, command], timeout=60) for command in (EXPORT_ADDRESS, EXPORT_DNS)]
        return "\n".join(outputs)


def split_values(*values):
    result = []
    for value in values:
        for item in (value or "").split(","):
            item = item.strip()
            if item:
                result.append(item)
    return result


def normalize_domains(values):
    result = []
    for value in values:
        domain = value.strip().lower().rstrip(".")
        if domain.startswith("*."):
            domain = domain[2:]
        core.validate_domain(domain)
        if domain not in result:
            result.append(domain)
    if not result:
        raise ValueError("at least one domain is required")
    return result


def bump_version(version):
    head, separator, tail = version.rpartition(".")
    if separator and tail.isdigit():
        return f"{head}.{int(tail) + 1}"
    return version + ".1"


def build_candidate(catalog_path, selection_path, category_ids, service_id, domains, name, category):
    original_catalog, original_services = core.load_catalog(catalog_path)
    original_selected = core.load_selection(selection_path, original_services)
    catalog = copy.deepcopy(original_catalog)
    services = {service["id"]: service for service in catalog["services"]}
    selected = list(original_selected)
    append_selection = []
    newly_selected = set()
    catalog_changed = False

    for sid in category_ids:
        if sid not in services:
            raise ValueError(f"unknown category: {sid}")
        if sid not in selected:
            selected.append(sid)
            append_selection.append(sid)
            newly_selected.add(sid)

    if service_id:
        if not core.ID_RE.fullmatch(service_id):
            raise ValueError(f"invalid category id: {service_id}")
        if service_id not in services:
            service = {
                "id": service_id,
                "name": name or service_id,
                "category": category,
                "description": name or service_id,
                "fqdn": [],
                "ipv4_cidr": [],
                "fqdn_extra": [],
                "ipv4_cidr_extra": [],
                "dns_subdomains": [],
            }
            catalog["services"].append(service)
            services[service_id] = service
            catalog_changed = True
        service = services[service_id]
        extra = service.setdefault("fqdn_extra", [])
        dns = service.setdefault("dns_subdomains", [])
        for domain in domains:
            if domain not in core.service_fqdn(service):
                extra.append(domain)
                catalog_changed = True
            if domain not in dns:
                dns.append(domain)
                catalog_changed = True
        if service_id not in selected:
            selected.append(service_id)
            append_selection.append(service_id)
            newly_selected.add(service_id)

    if catalog_changed:
        catalog["catalog_version"] = bump_version(catalog["catalog_version"])
    return Candidate(
        catalog=catalog,
        services=services,
        selected=selected,
        scope=set(category_ids) | ({service_id} if service_id else set()),
        domains=domains,
        service_id=service_id,
        newly_selected=newly_selected,
        append_selection=append_selection,
        catalog_changed=catalog_changed,
    )


def scoped_plan(candidate, current_text):
    _, full = core.render_diff(candidate.catalog, candidate.services, candidate.selected, current_text)
    summary = {action: [] for action in (*ADD_ACTIONS, *EMPTY_ACTIONS)}
    for action in ADD_ACTIONS:
        for item in full[action]:
            sid, value = item[0], item[1]
            if sid not in candidate.scope:
                continue
            if (
                candidate.service_id == sid
                and sid not in candidate.newly_selected
                and value not in candidate.domains
            ):
                continue
            summary[action].append(item)

    lines = [
        f'# Scoped diff from config/services.json {candidate.catalog["catalog_version"]}.',
        "# Additions only; unrelated catalog drift is deliberately excluded.",
    ]
    for sid, address in summary["add_static"]:
        lines.append(core.static_add(sid, address))
    for sid, domain in summary["add_fwd"]:
        lines.append(core.fwd_add(sid, domain, candidate.catalog["dns_forward_to"]))
    for sid, domain, address in summary["add_a"]:
        lines.append(core.a_record_add(sid, domain, address))
    return "\n".join(lines) + "\n", summary


def change_count(summary):
    return sum(len(summary[action]) for action in ADD_ACTIONS)


def print_summary(summary):
    for action in ADD_ACTIONS:
        print(f"{action}: {len(summary[action])}")
        for item in summary[action]:
            print("  " + ": ".join(item))
    print(f"Total changes: {change_count(summary)}")


def commands_from_diff(text):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def atomic_write(path, text):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_local(candidate, catalog_path, selection_path):
    if candidate.catalog_changed:
        atomic_write(
            catalog_path,
            json.dumps(candidate.catalog, ensure_ascii=False, indent=2) + "\n",
        )
    if candidate.selection_changed:
        current = selection_path.read_text(encoding="utf-8")
        if current and not current.endswith("\n"):
            current += "\n"
        atomic_write(selection_path, current + "\n".join(candidate.append_selection) + "\n")
    if candidate.catalog_changed or candidate.selection_changed:
        full = core.render_full(candidate.catalog, candidate.services, candidate.selected)
        atomic_write(Path(catalog_path).parent.parent / "scripts/routeros-services.rsc", full)


def apply_plan(rsh, candidate, diff_text, summary, catalog_path, selection_path):
    commands = commands_from_diff(diff_text)
    backup = None
    committed = 0
    if commands:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        backup = f"hynet-route-domain-{stamp}"
        try:
            rsh.run([rsh.target, f"/export show-sensitive file={backup}"], timeout=90)
            count = rsh.run([rsh.target, f'/file print count-only where name="{backup}.rsc"'], timeout=60)
            if not re.search(r"^1$", count, re.M):
                raise RuntimeError("backup file was not found after export")
        except Exception as exc:
            raise ApplyFailure(f"backup failed; nothing applied: {exc}") from exc

        try:
            with tempfile.TemporaryDirectory(prefix="mikrotik-route-domain-") as directory:
                for offset in range(0, len(commands), MAX_SAFE_COMMANDS):
                    chunk = commands[offset:offset + MAX_SAFE_COMMANDS]
                    path = Path(directory) / f"chunk-{offset // MAX_SAFE_COMMANDS + 1}.rsc"
                    path.write_text("\n".join(chunk) + "\n", encoding="utf-8", newline="\n")
                    rsh.run(
                        ["--safe", "--script", str(path), rsh.target],
                        timeout=max(180, len(chunk) * 35),
                    )
                    committed += 1
                    print(f"Safe Mode chunk {committed}: COMMITTED ({len(chunk)} commands)")
            rsh.run([rsh.target, "/ip dns cache flush"], timeout=60)
        except Exception as exc:
            raise ApplyFailure(
                f"Safe Mode failed after {committed} committed chunks; backup={backup}.rsc: {exc}",
                partial=committed > 0,
            ) from exc

    try:
        _, remaining = scoped_plan(candidate, rsh.current())
        if change_count(remaining):
            raise RuntimeError(f"verification still sees {change_count(remaining)} missing changes")
        write_local(candidate, catalog_path, selection_path)
    except Exception as exc:
        raise ApplyFailure(
            f"router applied but verification/local save failed; backup={backup}.rsc: {exc}",
            partial=bool(commands),
        ) from exc
    return backup


def show_categories(catalog_path, selection_path):
    _, services = core.load_catalog(catalog_path)
    selected = set(core.load_selection(selection_path, services))
    for sid, service in services.items():
        marker = "*" if sid in selected else " "
        print(
            f"{marker} {sid:24} {service['category']:14} "
            f"FQDN={len(core.service_fqdn(service)):3} DNS={len(service.get('dns_subdomains', [])):3}  {service['name']}"
        )
    print("=== VERDICT ===\nSTATUS ONLY -- * means enabled for VPN")


def show_category(catalog_path, selection_path, sid):
    _, services = core.load_catalog(catalog_path)
    selected = set(core.load_selection(selection_path, services))
    if sid not in services:
        raise ValueError(f"unknown category: {sid}")
    service = services[sid]
    print(f"{sid}: {service['name']} ({service['category']})")
    print(f"Enabled: {'yes' if sid in selected else 'no'}")
    print("FQDN/CIDR:")
    for value in core.service_fqdn(service) + core.service_cidr(service):
        print(f"  {value}")
    print("DNS subdomains:")
    for value in service.get("dns_subdomains", []):
        print(f"  *.{value}")
    print("=== VERDICT ===\nSTATUS ONLY -- category details")


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--list", action="store_true", help="list categories; no router access")
    result.add_argument("--show", metavar="ID", help="show one category; no router access")
    result.add_argument("--categories", help="comma-separated existing categories to enable")
    result.add_argument("--domains", help="comma-separated FQDNs; *. prefix is optional")
    result.add_argument("--domain", action="append", default=[], help="additional FQDN; repeatable")
    result.add_argument("--id", help="category id for --domains; created if absent")
    result.add_argument("--name", help="display name for a new category")
    result.add_argument("--category", default="Other", help="catalog section for a new category")
    result.add_argument("--apply", action="store_true", help="write catalog and router; default is dry-run")
    result.add_argument("--target", choices=("rb4011", "rb4011-zt"), default="rb4011")
    result.add_argument("--catalog", type=Path, default=REPO / "config/services.json")
    result.add_argument("--services", type=Path, default=REPO / "config/services.txt")
    result.add_argument("--rsh", type=Path, default=PROJECT / "tools/rsh.py")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    if not any((args.list, args.show, args.categories, args.domains, args.domain)):
        args.list = True
    modes = sum(bool(value) for value in (args.list, args.show, args.categories, args.domains or args.domain))
    if modes != 1:
        parser().error("choose exactly one: --list, --show, --categories, or --domains/--domain")
    if args.domains or args.domain:
        if not args.id:
            parser().error("--domains requires an explicit --id")
    elif args.id or args.name:
        parser().error("--id/--name are only valid with --domains")
    if args.apply and (args.list or args.show):
        parser().error("--apply is only valid with --domains or --categories")

    try:
        if args.list:
            show_categories(args.catalog, args.services)
            return 0
        if args.show:
            show_category(args.catalog, args.services, args.show)
            return 0

        domains = normalize_domains(split_values(args.domains, *args.domain)) if (args.domains or args.domain) else []
        category_ids = list(dict.fromkeys(split_values(args.categories)))
        candidate = build_candidate(
            args.catalog,
            args.services,
            category_ids,
            args.id if domains else None,
            domains,
            args.name,
            args.category,
        )
        rsh = Rsh(args.rsh, args.target)
        diff_text, summary = scoped_plan(candidate, rsh.current())
        total = change_count(summary)
        local_changes = candidate.catalog_changed or candidate.selection_changed
        if not total and not local_changes:
            print("=== VERDICT ===\nALREADY ROUTED -- requested domains/categories are already configured")
            return 0

        print_summary(summary)
        plan_path = Path(tempfile.gettempdir()) / "mikrotik-route-domain-plan.rsc"
        plan_path.write_text(diff_text, encoding="utf-8", newline="\n")
        print(f"Scoped diff: {plan_path}")
        if not args.apply:
            print("=== VERDICT ===")
            print(f"PLAN -- {total} router changes; local files unchanged; rerun with --apply")
            return 0

        backup = apply_plan(rsh, candidate, diff_text, summary, args.catalog, args.services)
        print("=== VERDICT ===")
        suffix = f"; backup={backup}.rsc" if backup else "; router already matched, local catalog updated"
        print(f"OK -- applied and verified {total} router changes{suffix}")
        return 0
    except ApplyFailure as exc:
        print("=== VERDICT ===")
        print(f"{'PARTIAL' if exc.partial else 'FAIL'} -- {exc}")
        return 1
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("=== VERDICT ===")
        print(f"FAIL -- {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
