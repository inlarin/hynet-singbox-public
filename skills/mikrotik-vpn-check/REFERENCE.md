# mikrotik-vpn-check — internals

Read before editing `check.py`.

## Transport and secret handling

All RouterOS commands go through `tools/rsh.py`. Container shell snippets are base64-encoded locally and decoded inside the container to avoid RouterOS/SSH quoting problems. Clash credentials are extracted inside the container from `/tmp/config.json`; neither the secret nor `/container print detail` is printed.

Only GET endpoints are used. `/delay` actively probes the concrete selected outbound but does not change selectors or user traffic.

## Selector traversal

Clash selector and urltest groups have `all` and `now`; individual outbounds do not. Stop traversing when `all` is absent. The current canary may expose an empty `select.now`: in that case try `urltest-all` before declaring a failure. Delay uses the proven endpoint form `timeout=5000&url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204`.

## Verdict boundaries

- Wiring checks require a healthy container, the `172.20.0.2` gateway and the `blackhole` route.
- A selected-exit probe failure is `DEGRADED`, not proof that the whole container is down.
- Transport or JSON/API errors that prevent a complete snapshot are `CHECK`.
- Background sweep errors are included as context only; they do not override the active selected-exit result.

The complete raw report is written to `%TEMP%/mikrotik-vpn-check.txt`; re-read it instead of repeating the live probes for follow-up details.
