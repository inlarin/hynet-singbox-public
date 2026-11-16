---
name: mikrotik-vpn-check
description: 'Read-only health snapshot for selective sing-box VPN on RB4011. Checks container health, via-hynet gateway and blackhole kill-switch, mangle and client lists, address-list size, recent logs, resolves select/urltest groups through Clash API and actively probes the selected exit. Use when the user says "проверь VPN на 4011", "статус sing-box на микротике", "не работает VPN на RB4011", or "/mikrotik-vpn-check". NOT for Keenetic (use keenetic-vpn-check) and not for adding domains (use mikrotik-route-domain).'
---

<!-- QUICKREF -->
## ⚡ Quick reference (canonical — do not paraphrase)
- **Invocation:** from the `monitoring` root: `python .claude/skills/mikrotik-vpn-check/check.py [--target rb4011|rb4011-zt]`
- **Defaults:** target `rb4011`; Clash API `172.20.0.2:9090`, secret read inside the container from `/tmp/config.json` and never printed
- **Creds:** inherited from `tools/rsh.py`: `~/.claude/.secrets/hynet-rb4011`, pinned host-key, plink `-batch`; no prompts
- **Mutation gate:** read-only. RouterOS print commands, container log reads, Clash GET `/proxies*` and one active `/delay` probe. No PUT, restart, file or configuration changes
- **VERDICT values (verbatim):** `VPN UP --` / `DEGRADED --` / `DOWN --` / `CHECK --`
- **Headless:** all defaults; never prompts
- **Key caveat:** an empty `select.now` falls back to `urltest-all`; dead background sweep nodes do not prove the selected exit is down. The selected exit's active `/delay` is authoritative. Full report: `%TEMP%\mikrotik-vpn-check.txt`
<!-- QUICKREF -->

## How to invoke

```bash
cd /path/to/monitoring
python .claude/skills/mikrotik-vpn-check/check.py

# Same RB4011 through ZeroTier
python .claude/skills/mikrotik-vpn-check/check.py --target rb4011-zt
```

## What it reports

- RouterOS version, memory, CPU and disk.
- `hynet-singbox` container health and resource use.
- Active `172.20.0.2` route and `blackhole` kill-switch in `via-hynet`.
- Mangle wiring, `hynet-clients`, address-list size and recent healthcheck/sing-box logs.
- Current concrete exit after resolving nested `select`/`urltest-*` groups and its active delay.

## VERDICT

- **VPN UP** — container is healthy, gateway and kill-switch are present, selected exit answers the live probe.
- **DEGRADED** — routing/container wiring exists, but the selected exit is empty or fails the probe.
- **DOWN** — container, active gateway or kill-switch is missing.
- **CHECK** — transport, parsing or API access prevented a complete snapshot.

Related: `mikrotik-route-domain` for domains/categories, `router-disk-hygiene` for disk state, `keenetic-vpn-check` for Keenetic.
