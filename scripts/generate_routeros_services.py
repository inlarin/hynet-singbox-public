#!/usr/bin/env python3
import argparse
import ipaddress
import json
import re
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ID_RE = re.compile(r'^[a-z][a-z0-9_]*$')
DOMAIN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
)


def service_fqdn(service):
    return service.get('fqdn', []) + service.get('fqdn_extra', [])


def service_cidr(service):
    return service.get('ipv4_cidr', []) + service.get('ipv4_cidr_extra', [])


def load_catalog(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version') != 1:
        raise ValueError('catalog schema_version must be 1')
    ipaddress.ip_address(data['dns_forward_to'])
    validate_domain(data['healthcheck_fqdn'])
    services = {}
    for service in data['services']:
        sid = service['id']
        if not ID_RE.fullmatch(sid):
            raise ValueError(f'invalid service id: {sid!r}')
        if sid in services:
            raise ValueError(f'duplicate service id: {sid}')
        values = set()
        for domain in service_fqdn(service):
            validate_domain(domain)
            if domain in values:
                raise ValueError(f'{sid}: duplicate FQDN {domain}')
            values.add(domain)
        values = set()
        for domain in service.get('dns_subdomains', []):
            validate_domain(domain)
            if domain in values:
                raise ValueError(f'{sid}: duplicate DNS root {domain}')
            values.add(domain)
        for domain, address in service.get('dns_a_overrides', {}).items():
            validate_domain(domain)
            if ipaddress.ip_address(address).version != 4:
                raise ValueError(f'{sid}: DNS A override must use IPv4: {domain}')
        values = set()
        for network in service_cidr(service):
            parsed = ipaddress.ip_network(network)
            if parsed.version != 4 or network in values:
                raise ValueError(f'{sid}: invalid or duplicate IPv4 network {network}')
            values.add(network)
        services[sid] = service
    return data, services


def validate_domain(domain):
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError(f'invalid or unreviewed domain: {domain!r}')


def load_selection(path, services):
    selected = []
    for raw in path.read_text(encoding='utf-8').splitlines():
        sid = raw.split('#', 1)[0].strip()
        if not sid:
            continue
        if sid not in services:
            raise ValueError(f'unknown service in {path}: {sid}')
        if sid in selected:
            raise ValueError(f'duplicate selected service: {sid}')
        selected.append(sid)
    return selected


def desired_state(catalog, services, selected):
    static = set()
    fwd = set()
    a_records = set()
    for sid in selected:
        service = services[sid]
        for address in service_fqdn(service) + service_cidr(service):
            static.add((sid, address))
        for domain in service.get('dns_subdomains', []):
            fwd.add((sid, domain))
        for domain, address in service.get('dns_a_overrides', {}).items():
            a_records.add((sid, domain, address))
            static.add((sid, f'{address}/32'))
    static.add(('healthcheck', catalog['healthcheck_fqdn']))
    return static, fwd, a_records


def static_add(sid, address, variable=None):
    value = f'${variable}' if variable else f'"{address}"'
    comment = f'hynet:{sid}'
    condition = (
        f'[:len [/ip firewall address-list find where list=hynet '
        f'address={value} comment="{comment}"]] = 0'
    )
    if sid == 'healthcheck':
        condition = f'[:len [/ip firewall address-list find where list=hynet address={value}]] = 0'
    return (
        f':if ({condition}) do={{ /ip firewall address-list add list=hynet '
        f'address={value} comment="{comment}" }}'
    )


def fwd_add(sid, domain, forward_to):
    comment = f'hynet:{sid}-subdomains'
    condition = (
        f'[:len [/ip dns static find where type=FWD name="{domain}" '
        f'comment="{comment}"]] = 0'
    )
    return (
        f':if ({condition}) do={{ /ip dns static add type=FWD name="{domain}" '
        f'match-subdomain=yes address-list=hynet forward-to={forward_to} '
        f'ttl=1d disabled=no comment="{comment}" }}'
    )


def a_record_add(sid, domain, address):
    comment = f'hynet:{sid}-a'
    condition = (
        f'[:len [/ip dns static find where type=A name="{domain}" '
        f'address={address} comment="{comment}"]] = 0'
    )
    return (
        f':if ({condition}) do={{ /ip dns static add type=A name="{domain}" '
        f'address={address} ttl=1d disabled=no comment="{comment}" }}'
    )


def chunks(values, size=30):
    values = sorted(values)
    for offset in range(0, len(values), size):
        yield values[offset:offset + size]


def render_static_group(sid, addresses):
    lines = []
    for group in chunks(addresses):
        values = ';'.join(f'"{address}"' for address in group)
        lines.append(
            f':foreach d in={{{values}}} do={{ {static_add(sid, "", "d")} }}'
        )
    return lines


def render_full(catalog, services, selected):
    static, fwd, a_records = desired_state(catalog, services, selected)
    lines = [
        f'# Generated from config/services.json {catalog["catalog_version"]}; do not edit.',
        '# Idempotent: existing managed entries are not added again.',
        static_add('healthcheck', catalog['healthcheck_fqdn']),
    ]
    for sid in selected:
        addresses = [address for service, address in static if service == sid]
        lines.extend(render_static_group(sid, addresses))
    for sid, domain in sorted(fwd):
        lines.append(fwd_add(sid, domain, catalog['dns_forward_to']))
    for sid, domain, address in sorted(a_records):
        lines.append(a_record_add(sid, domain, address))
    return '\n'.join(lines) + '\n'


def properties(tokens):
    result = {}
    for token in tokens:
        if '=' in token:
            key, value = token.split('=', 1)
            result[key] = value
    return result


def parse_current(text, known_services):
    static = set()
    fwd = set()
    a_records = set()
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('/ip firewall address-list add '):
            section = 'static'
            line = line.removeprefix('/ip firewall address-list ')
        elif line.startswith('/ip dns static add '):
            section = 'dns'
            line = line.removeprefix('/ip dns static ')
        elif line == '/ip firewall address-list':
            section = 'static'
            continue
        elif line == '/ip dns static':
            section = 'dns'
            continue
        elif line.startswith('/'):
            section = None
            continue
        if not line.startswith('add '):
            continue
        props = properties(shlex.split(line, posix=True)[1:])
        comment = props.get('comment', '')
        match = re.fullmatch(r'hynet:([a-z][a-z0-9_]*)(-subdomains|-a)?', comment)
        if not match:
            continue
        sid, suffix = match.groups()
        if section == 'static' and not suffix and props.get('list') == 'hynet':
            address = props.get('address', '')
            try:
                if ipaddress.ip_address(address).version == 4:
                    address += '/32'
            except ValueError:
                pass
            static.add((sid, address))
        elif section == 'dns' and suffix == '-subdomains' and props.get('type') == 'FWD':
            fwd.add((sid, props.get('name', '')))
        elif section == 'dns' and suffix == '-a' and props.get('type') == 'A':
            a_records.add((sid, props.get('name', ''), props.get('address', '')))
        if sid not in known_services and sid != 'healthcheck':
            raise ValueError(f'unknown managed service in current export: {sid}')
    return static, fwd, a_records


def render_diff(catalog, services, selected, current_text):
    desired_static, desired_fwd, desired_a = desired_state(catalog, services, selected)
    current_static, current_fwd, current_a = parse_current(current_text, services)
    healthcheck = catalog['healthcheck_fqdn']
    has_healthcheck = any(address == healthcheck for _, address in current_static)
    add_static = sorted(desired_static - current_static)
    if has_healthcheck:
        add_static = [item for item in add_static if item[0] != 'healthcheck']
    add_fwd = sorted(desired_fwd - current_fwd)
    add_a = sorted(desired_a - current_a)
    remove_static = sorted(
        item for item in current_static - desired_static
        if item[1] and item[1] != healthcheck
    )
    remove_fwd = sorted(item for item in current_fwd - desired_fwd if item[1])
    remove_a = sorted(item for item in current_a - desired_a if item[1] and item[2])
    lines = [
        f'# Dry-run diff from config/services.json {catalog["catalog_version"]}.',
        '# Additions precede removals. Review before applying in Safe Mode.',
    ]
    for sid, address in add_static:
        lines.append(static_add(sid, address))
    for sid, domain in add_fwd:
        lines.append(fwd_add(sid, domain, catalog['dns_forward_to']))
    for sid, domain, address in add_a:
        lines.append(a_record_add(sid, domain, address))
    for sid, address in remove_static:
        lines.append(
            f'/ip firewall address-list remove [find where list=hynet '
            f'address="{address}" comment="hynet:{sid}"]'
        )
    for sid, domain in remove_fwd:
        lines.append(
            f'/ip dns static remove [find where type=FWD name="{domain}" '
            f'comment="hynet:{sid}-subdomains"]'
        )
    for sid, domain, address in remove_a:
        lines.append(
            f'/ip dns static remove [find where type=A name="{domain}" '
            f'address={address} comment="hynet:{sid}-a"]'
        )
    summary = {
        'add_static': add_static,
        'add_fwd': add_fwd,
        'add_a': add_a,
        'remove_static': remove_static,
        'remove_fwd': remove_fwd,
        'remove_a': remove_a,
    }
    return '\n'.join(lines) + '\n', summary


def write_or_print(text, output):
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding='utf-8', newline='\n')
    else:
        sys.stdout.write(text)


def main():
    parser = argparse.ArgumentParser(description='Generate reviewed RouterOS service steering rules.')
    parser.add_argument('--catalog', type=Path, default=ROOT / 'config/services.json')
    parser.add_argument('--services', type=Path, default=ROOT / 'config/services.txt')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('list', help='show available and selected services')
    generate = commands.add_parser('generate', help='generate an idempotent full configuration')
    generate.add_argument('--output', type=Path)
    diff = commands.add_parser('diff', help='generate changes against a RouterOS terse export')
    diff.add_argument('--current', type=Path, required=True, action='append')
    diff.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        catalog, services = load_catalog(args.catalog)
        selected = load_selection(args.services, services)
        if args.command == 'list':
            for sid, service in services.items():
                mark = '*' if sid in selected else ' '
                count = len(service_fqdn(service)) + len(service_cidr(service))
                print(f'{mark} {sid:20} {count:4} entries  {service["name"]}')
            return
        if args.command == 'generate':
            write_or_print(render_full(catalog, services, selected), args.output)
            return
        current_text = '\n'.join(
            path.read_text(encoding='utf-8') for path in args.current
        )
        text, summary = render_diff(catalog, services, selected, current_text)
        write_or_print(text, args.output)
        for action in ('add_static', 'add_fwd', 'add_a', 'remove_static', 'remove_fwd', 'remove_a'):
            print(f'{action}: {len(summary[action])}')
            for item in summary[action]:
                print('  ' + ': '.join(item))
        total = sum(len(values) for values in summary.values())
        print(f'Total changes: {total}')
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.exit(2, f'error: {exc}\n')


if __name__ == '__main__':
    main()
