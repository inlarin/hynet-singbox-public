---
name: mikrotik-route-domain
description: 'Add FQDNs or whole service categories to selective VPN routing on RB4011. Safe by default: reads the live RouterOS exports and prints a scoped dry-run diff; --apply takes a backup, applies additions in Safe Mode chunks, verifies them, updates hynet-container/config/services.json and services.txt, and regenerates routeros-services.rsc. Use when the user says "добавь домен в VPN на 4011", "включи категорию/сервис на микротике", "заверни сайт через VPN на RB4011", "route domain through MikroTik VPN", or "/mikrotik-route-domain". NOT for Keenetic (use keenetic-route-domain), not for removal, and not for VPN health. To MODIFY, read REFERENCE.md here first.'
---


<!-- QUICKREF -->
## ⚡ Quick reference (canonical — do not paraphrase)
- **Invocation:** `python .claude/skills/mikrotik-route-domain/check.py [--list] [--show ID] [--categories ID[,ID]] [--domains a,b --id ID [--name "Label"] [--category Cat]] [--apply] [--target rb4011|rb4011-zt]` — repeated `--domain x` is also accepted; no arguments = `--list`
- **Defaults:** target `rb4011`; every added domain also matches all its subdomains; a new `--id` creates a custom category (`--category Other` unless overridden); an existing `--id` extends that category
- **Creds:** inherited from `tools/rsh.py`: `~/.claude/.secrets/hynet-rb4011`, pinned host-key, plink `-batch`; no password flags or prompts
- **Mutation gate:** without `--apply` neither router nor local catalog changes. The skill makes two read-only exports and writes only `%TEMP%\mikrotik-route-domain-plan.rsc`. `--apply` is required for backup, Safe Mode, DNS-cache flush, local catalog writes and generated-RSC refresh
- **Diff scope:** additions only, restricted to the requested domains/categories. Unrelated router/catalog drift is never applied. Adding a domain to a disabled category enables that whole category; enabling an already-selected category repairs its missing entries
- **Apply mechanics:** `/export show-sensitive file=hynet-route-domain-<UTC>`; chunks of at most 80 commands through `rsh.py --safe`; re-export verification; then local catalog/selection/full-RSC update. No automatic git commit/push
- **VERDICT values (verbatim):** `STATUS ONLY --` / `PLAN --` / `ALREADY ROUTED --` / `OK --` / `PARTIAL --` / `FAIL --`
- **Headless:** all defaults; never prompts
- **Key caveat:** use the exact `--id` from `--list` to extend an existing category. Clients must resolve through RouterOS DNS; DoH/hardcoded DNS bypasses FWD-based steering. This skill adds/enables only — it does not remove domains or disable categories
<!-- QUICKREF -->

## How to invoke

```bash
# List categories; * means enabled. No router access.
python .claude/skills/mikrotik-route-domain/check.py

# Inspect one category.
python .claude/skills/mikrotik-route-domain/check.py --show youtube

# Dry-run: add a domain and all its subdomains to YouTube.
python .claude/skills/mikrotik-route-domain/check.py \
    --id youtube --domains gvt1.com

# Apply the same scoped change with backup + Safe Mode.
python .claude/skills/mikrotik-route-domain/check.py \
    --id youtube --domains gvt1.com --apply

# Create and enable a custom category.
python .claude/skills/mikrotik-route-domain/check.py \
    --id my_service --name "My service" --category Other \
    --domains example.com,cdn.example.com --apply

# Enable existing categories (dry-run first, then --apply).
python .claude/skills/mikrotik-route-domain/check.py \
    --categories youtube,telegram
```

## What --apply changes

1. Builds a candidate catalog in memory and reads two live exports from RB4011.
2. Prints a scoped additions-only diff. Other missing/stale managed entries are excluded.
3. Creates `hynet-route-domain-<UTC>.rsc` on the router and checks that the backup exists.
4. Applies at most 80 commands per Safe Mode session. A failed session rolls back that chunk; earlier committed chunks are reported as `PARTIAL` with the backup name.
5. Flushes RouterOS DNS cache, re-reads both exports and verifies that the scoped diff is empty.
6. Updates `hynet-container/config/services.json`, `config/services.txt` and generated `scripts/routeros-services.rsc`. The files are left for review; git commit/push requires a separate explicit request.

## Interpreting the VERDICT

- **STATUS ONLY** — local category list/details; no router access.
- **PLAN** — dry-run found changes; router and local catalog are untouched. Full RouterOS commands are in `%TEMP%\mikrotik-route-domain-plan.rsc`.
- **ALREADY ROUTED** — requested state already exists locally and on the router.
- **OK** — router changes verified and local files updated. If the router already matched, only local catalog synchronization was needed.
- **PARTIAL** — at least one Safe Mode chunk committed, or the router changed but verification/local save failed. Read the backup name in the message; do not blindly rerun a large diff.
- **FAIL** — validation, export, backup, first Safe Mode chunk or transport failed before a confirmed partial apply.

Related: `keenetic-route-domain` for Keenetic, `hynet-container/scripts/mikrotik_service_manager.py` for the desktop selector, `tools/rsh.py` for raw read-only RouterOS inspection.
