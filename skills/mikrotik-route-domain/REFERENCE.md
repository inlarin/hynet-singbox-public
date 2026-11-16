# mikrotik-route-domain — internals and modification rules

Read before editing `check.py`.

## Architecture

The skill is an orchestrator, not another RouterOS rules generator. It imports `hynet-container/scripts/generate_routeros_services.py` as `core` and reuses:

- catalog/selection loading and domain validation;
- desired-state and diff calculation;
- `static_add`, `fwd_add`, `a_record_add` command rendering;
- full `scripts/routeros-services.rsc` generation.

All SSH, credentials, host keys and Safe Mode behavior stay in `tools/rsh.py`. Do not add paramiko, direct plink password handling or a second RouterOS transport.

## Scoped additions

`build_candidate()` edits only an in-memory copy. Domains go to `fqdn_extra` and `dns_subdomains`, so each domain gets a static FQDN and an FWD rule covering subdomains. A new service gets the same fields as the reviewed catalog. Any catalog content change increments the patch component of `catalog_version`.

`scoped_plan()` calls `core.render_diff()` but retains additions only for the requested IDs. For a domain added to an already-enabled category it retains only that domain. For a newly enabled category it retains the whole category so local selection and router state converge. It always discards removals and unrelated drift. This is deliberate: the live router had an unrelated `ntc.party` difference that a full diff would have applied.

There is no removal path. Do not add one without defining catalog-extra vs upstream-FQDN ownership, dynamic-entry cleanup, rollback and verification semantics.

## Apply ordering and failure boundaries

- Without `--apply`, only two read-only exports and a plan file in `%TEMP%` are produced.
- Router changes precede local writes. The backup is verified with `/file print count-only` before Safe Mode.
- Each chunk is a separate `rsh.py --safe` transaction of at most 80 commands. Safe Mode can roll back only its own chunk; a later failure after earlier commits is `PARTIAL`, never reported as fully rolled back.
- After all chunks, DNS cache is flushed and fresh exports must produce an empty scoped diff.
- Only then are local JSON/selection/full RSC written atomically. A local failure after router success is also `PARTIAL`.
- The skill never commits or pushes git changes.

## Tests

```bash
cd /path/to/monitoring/hynet-container
python -m pytest skills/tests -q
```

The tests use a synthetic catalog and a fake `Rsh`: they verify scoped diffs, custom-category creation, dry-run file immutability, two-chunk apply and local generated-RSC refresh without touching a router.

For a live read-only check use a nonexistent test domain without `--apply`; confirm `PLAN --` and verify that neither local file changes. Do not live-test `--apply` unless the user explicitly requested that specific router mutation.

After editing `SKILL.md`, run `python -m pytest skills/tests -q` from `hynet-container`; the manifest covers all 13 project skills through both junctions.
