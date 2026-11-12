# hynet-singbox

[Читать по-русски](README.ru.md)

Self-contained [sing-box](https://github.com/SagerNet/sing-box) container that takes a v2ray-style subscription URL and exposes the resulting tunnel on a TUN inside the container. Designed for **MikroTik RouterOS containers** (RB4011 / RB5009 / hAP ax) where you have no USB stick and want zero NAND wear at runtime — all state lives on tmpfs.

Fill any combination of `SUBSCRIPTION_1…5` and optional `HW_ID_1…5`; at least one subscription is required. Every provider is equal: nodes are extracted independently into one pool and the healthcheck selects the best exit. No Base64 or manual VLESS fallback nodes.

## What's inside

| Component | Purpose |
|---|---|
| [`sing-box`](https://github.com/SagerNet/sing-box) 1.15.0-alpha.13 (canary, slim, built from source in the Dockerfile, `ARG SINGBOX_VERSION`) | Proxy runtime, owns the TUN. Build tags: `with_quic,with_grpc,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0`. Go 1.26.10, `CGO_ENABLED=0`, upstream release LDFLAGS plus version and strip flags. |
| `sub_to_singbox.py` + `merge-subscriptions.py` | Parse the main subscription and independent extra providers, preserving each provider's URL, UA and HWID. Failed providers keep their last known good nodes. Emit one TUN, one `select`, per-country groups and isolated probe ports. |
| `entrypoint.sh` | Initial fetch+render, background daily refresh, foreground sing-box respawn loop, hourly log/state maintenance. |
| `sub-refresh.sh` | curl (dual-mirror, direct-WAN proxy) → convert/merge → `sing-box check` → atomic swap → SIGTERM. Restores `select.now` and rolls back if the new config does not start. |
| `healthcheck` (Go binary) | Real-data probe daemon. Periodic 100 KB downloads through each pool outbound, ranks by latency, auto-pins fastest live, rotates on failure. Catches handshake-OK / data-reset servers that fool sing-box's HEAD probe. |

## Tags

| Tag | Architecture | RouterOS hardware |
|---|---|---|
| `:armv7` | linux/arm/v7 | RB4011 (verified), RB1100AHx4/Dx4 and other 32-bit ARM boards — `/system/resource/print` → `architecture-name: arm` |
| `:arm64` | linux/arm64 | RB5009 (verified), hAP ax2/ax3, CCR2004, CCR2116 and other `architecture-name: arm64` boards |
| `:latest` | arm/arm64 manifest | auto-resolved by Docker / RouterOS based on host arch. **No amd64 layer** — won't run on x86 without a rebuild |

For RouterOS, prefer the explicit per-arch tag — it's one less round-trip in `/container/add` and avoids any manifest-resolution surprises.
Check your board's architecture in `/system/resource/print` (`architecture-name`) rather than by model name: MIPS boards (hEX S, hAP ac² etc.)
cannot run containers at all — per the docs the Container package exists only for arm, arm64 and x86.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `REFRESH_INTERVAL` | `86400` | Seconds between auto-refreshes. |
| `SINGBOX_TUN_NAME` | `opkgtun0` | TUN interface name inside the container netns. |
| `TUN_ADDR` | `172.19.0.1` | TUN IPv4 address; `/30` is emitted. |
| `TUN_MTU` | `1420` | TUN MTU. |
| `SINGBOX_TUN_STACK` | `none` | Omit `stack` to use sing-tun's own 1.15 stack. `system` is the legacy kernel option; gVisor tags are deliberately not built. |
| `CLASH_ADDR` | `172.20.0.2:9090` | Clash API listen address, restricted to the isolated veth rather than `0.0.0.0`. |
| `CLASH_SECRET` | *(required)* | Bearer token for Clash API. |
| `SUBSCRIPTION_1` … `SUBSCRIPTION_5` | at least one required | Up to five equal subscriptions. Empty variables are skipped; the provider is identified by URL. |
| `HW_ID_1` … `HW_ID_5` | *(empty)* | HWID for the matching subscription. Empty is fully supported: no `x-hwid` header is sent. |
| `UA_1` … `UA_5` | `ClashforAndroid/2.5.12` for №1, `sing-box` for the rest | Optional User-Agent override for a particular panel. |
| `SINGBOX_NODE_RESOLVER` | `172.20.0.1` | Direct DNS resolver for outbound server names; RouterOS on `br-hynet`, avoiding unreliable external UDP/53. |
| `SINGBOX_UTLS_FINGERPRINT` | `chrome` | Normalises subscription-specific uTLS fingerprints rejected by newer sing-box versions. |
| `EXCLUDE_AUTO_CC` | `RU` | Comma-separated country codes excluded from `urltest-all` auto-pick AND from the healthcheck daemon's probe pool. Servers stay selectable manually via Clash API / MetaCubeXD. Set empty to disable. |
| `HEALTHCHECK_ENABLED` | `1` | Run the real-data healthcheck daemon. Set to `0` to disable and rely on sing-box's built-in urltest only (HEAD probe, fooled by handshake-OK/data-reset servers). |
| `LIVENESS_URL` | `https://speed.cloudflare.com/__down?bytes=100000` | Real-data probe URL — must serve exactly `LIVENESS_BYTES`. Daemon counts the bytes downloaded; partial = fail. |
| `LIVENESS_BYTES` | `100000` | Bytes the daemon expects from `LIVENESS_URL`. |
| `LIVENESS_INTERVAL` | `30s` | Cadence between liveness probes (Go duration syntax: `30s`, `1m`, etc.). |
| `RANK_INTERVAL` | `10m` | Cadence of full ranking sweeps. Each outbound is probed through its dedicated probe port (`127.0.0.1:7900+N`), so sweeps don't touch `select.now` and don't disrupt user traffic. Sweep duration ≈ avg-RTT × pool-size; for ~40 outbounds expect 3–6 min wall-clock. |
| `PROBE_TIMEOUT` | `12s` | Per-probe wall-clock timeout. Implies a speed floor of ≈8 KB/s with the default 100 KB payload. |
| `FAIL_THRESHOLD` | `2` | Consecutive liveness failures before rotating `select.now`. |
| `HYSTERESIS_PCT` | `15` | Minimum response-time improvement required before switching to a faster server. |
| `SEVERE_IMPROVE_PCT` | `50` | Improvement large enough to bypass dwell and repeated confirmation after a fresh sweep. |
| `FAILOVER_CANDIDATES` | `5` | Best-ranked candidates freshly measured before failure-driven rotation; the fastest live result wins. |
| `PROBE_CONCURRENCY` | `4` | Concurrent probes. The current server goes first and every result is persisted immediately. |
| `MIN_SWITCH_INTERVAL` | `15m` | Minimum dwell before switching for lower latency; failure-driven rotation remains immediate. |
| `IMPROVE_CONFIRMATIONS` | `2` | Consecutive sweeps required to confirm a latency improvement. |
| `AUTO_PIN` | `1` | `0` keeps probing but never overrides the manual `select.now` choice. |
| `RANK_STALE_AFTER` | `25m` | Ignore ranking entries older than this interval. |
| `TELEGRAM_HEALTHCHECK` | `1` | Require Telegram API + MTProto CONNECT from every automatic candidate, without a separate Telegram selector. |
| `TELEGRAM_API_URL` / `MTPROTO_ADDRESS` | `https://api.telegram.org` / `149.154.167.50:80` | Targets for the general pool's Telegram checks. |
| `ROTATIONS_BEFORE_FORCE_SWEEP` | `3` | Consecutive `select.now` rotations without success before a forced full sweep. |
| `STATE_DIR` / `PROBE_PORTS` | `/tmp/healthcheck` / `/tmp/probe_ports.json` | Healthcheck state paths on tmpfs. Telegram uses the general `select` pool; no dedicated HY2 outbound is injected. |

## RouterOS setup

The container terminates the proxy tunnel on its own TUN. RouterOS routes selected traffic to the container's veth IP as a next-hop; the container kernel forwards into the TUN, sing-box egresses out via the veth back through ROS WAN.

> **Before touching a remote production router — enter Safe Mode.**
>
> SSH/WinBox into the router, then in the CLI press **`Ctrl+X`** (or **`F4`**). The prompt turns into `[Safe Mode taken]`. Every change made from this session (and from any other login while you hold safe mode) is journaled.
>
> If the SSH/WinBox connection is cut — TCP timeout (~9 minutes) — RouterOS automatically rolls back **everything** done since `Ctrl+X`. So if your firewall rule or routing change locks you out, just wait it out, the router heals itself.
>
> When the work is done and you're sure nothing broke, press **`Ctrl+X`** again to commit (releases safe mode, changes become permanent). To abort manually: **`Ctrl+D`** undoes everything and exits. `/quit` does NOT undo — only the abnormal-exit / explicit-Ctrl+D paths trigger rollback. (Per [Console docs](https://help.mikrotik.com/docs/spaces/ROS/pages/8978498/Console#Console-SafeMode), the safe-mode buffer holds 100 actions; if you exceed that mid-session you get silently dropped out of safe mode with a warning. Stage commits in small batches.)

### 0. Enable container mode (one-time)

If `/container` sub-menu is missing, the device-mode hasn't been switched yet:

```routeros
/system/device-mode/update container=yes
```

RouterOS waits for a physical confirmation — press the reset button within 5 minutes (or cold-reboot on x86). Once confirmed **the router reboots** (per the device-mode docs — plan a window), then `/container/*` becomes available. Already enabled if `/system/device-mode/print` shows `container: yes`.

### 1. Networking — bridge + veth

Per the canonical MikroTik [Container](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container) examples (Pi-hole, Postgres, HomeAssistant — all of them), the router-side IP lives on a **bridge**, and the veth is attached to the bridge as a port. `address=`/`gateway=` on `/interface/veth add` configure the **container's** end of the link (its `eth0` IP and default route inside the container netns).

```routeros
/interface/bridge add name=br-hynet
/ip/address add address=172.20.0.1/30 interface=br-hynet
/interface/veth add name=veth-hynet address=172.20.0.2/30 gateway=172.20.0.1
/interface/bridge/port add bridge=br-hynet interface=veth-hynet
```

Result: bridge `br-hynet` holds `172.20.0.1` (RouterOS-side gateway), the container's `eth0` gets `172.20.0.2` and points its default route at `172.20.0.1`. The veth is L2-bridged into `br-hynet`, so traffic routed to `172.20.0.2` resolves via ARP on `br-hynet` and reaches the container.

**Allow the container to reach the router itself.** RouterOS defconf has an `input` chain rule (`drop all not coming from LAN`). `br-hynet` deliberately stays out of `interface-list=LAN` (so mangle marking on LAN-sourced traffic doesn't loop back through the container), so without an explicit accept the container can't query the router for DNS or anything else on a service port:

```routeros
/ip/firewall/filter add chain=input action=accept in-interface=br-hynet \
    comment="accept input from hynet container" \
    place-before=[find where comment="defconf: drop all not coming from LAN"]
```

If your defconf comment is different (`drop incoming from !LAN` etc), use the matching `[find]` lookup. The point is: place this `accept` BEFORE the catch-all drop.

### 2. Container — config, env, image

Pick a storage device for the image rootfs (~70 MB). On most MikroTiks this is internal flash (`disk1`) or USB (`usb1`) — visible in `/file/print`. The placeholder `<storage>` below is just that, a placeholder. MikroTik's docs recommend an external drive ("not recommended to use internal storage for Containers") — internal flash is used here deliberately: only the rootfs is written to flash at pull time, all runtime state lives on tmpfs (see below).

```routeros
# registry-url is a router-wide setting; only set it if you don't already
# have it pointed where you need. Leave alone if you have other containers.
# tmpdir is where remote-image is extracted on pull; without it extraction
# happens in RAM (docs: "requires a lot of free space in main memory"). The
# live boxes always had it set (RB4011: disk1/tmp).
/container/config/set registry-url=https://ghcr.io tmpdir=<storage>/tmp

# Generate a random Clash API secret in RouterOS scripting (paste output as CLASH_SECRET below):
:global hex "0123456789abcdef"; :global s ""; :for i from=1 to=48 do={ :set s ($s . [:pick $hex [:rndnum from=0 to=15]]) }; :put $s

/container/envs/add list=hynet key=SUBSCRIPTION_1 value="https://your-provider/sub?token=..."
/container/envs/add list=hynet key=HW_ID_1 value=""
/container/envs/add list=hynet key=CLASH_SECRET value="<paste-the-48-hex-chars-from-above>"
# Additional providers; HW_ID may stay empty:
/container/envs/add list=hynet key=SUBSCRIPTION_2 value="https://provider.example/second"
/container/envs/add list=hynet key=HW_ID_2 value="<hwid-or-empty>"
/container/envs/add list=hynet key=SUBSCRIPTION_3 value="https://provider.example/third"
/container/envs/add list=hynet key=HW_ID_3 value="<hwid-or-empty>"
# To rotate, set a new URL via /container/envs/set [find where list=hynet and key=SUBSCRIPTION_2] value="https://new-url" and restart the container.

# armv7 for RB4011 / hAP / hEX; use :arm64 for RB5009 / CCR2004
#
# dns= is REQUIRED — without it /etc/resolv.conf inside the container is empty
# and the very first curl for SUBSCRIPTION_1 fails with "unable to resolve
# host", entrypoint loops on retry forever.
#
# Use the router's br-hynet IP (172.20.0.1) — most reliable. We saw on a live
# RB4011/7.21.2 that UDP/53 from the container to external resolvers (1.1.1.1,
# 8.8.8.8) silently dies — same conntrack/route path TCP works through, but
# UDP doesn't. The router-as-DNS path goes input→accept (the rule we added in
# section 1) and stays inside the router, no external UDP traversal needed.
/container/add remote-image=ghcr.io/inlarin/hynet-singbox-public:armv7 \
    interface=veth-hynet envlist=hynet \
    root-dir=<storage>/containers/hynet \
    dns=172.20.0.1 \
    memory-high=500MiB \
    start-on-boot=yes logging=yes
```

> `/dev/net/tun` is auto-exposed to RouterOS containers — no explicit mount is needed (the device is included in the default `/dev/` set per [MikroTik docs](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container)).
>
> **No host-side bind mount needed.** The container self-mounts `tmpfs` on its own `/tmp` from `entrypoint.sh` at start (64 MB, `mode=1777`), so all runtime state (subscription, generated config, country cache, healthcheck rankings, sing-box log) stays in RAM. NAND wear at runtime: 0 writes (the container's own tmpfs intercepts everything before the host's overlay sees it). On hosts that deny `CAP_SYS_ADMIN` to the container the tmpfs mount fails silently and `/tmp` falls back to the overlay (the entrypoint logs a `WARN` line) — functionally fine, just writes to NAND.
>
> **`memory-high=500MiB` is mandatory, not optional.** sing-box's TUN inbound with `auto_route=true` catches every connection in the container netns. Under real LAN load (browser opens YouTube + several apps simultaneously) the per-connection state can balloon if anything regresses (we saw a single misconfiguration eat 1 GB of RAM in seconds and reboot the router). With the cap the kernel kills the container before it kills the host. Default safe value: half of router RAM. If your router has 256 MB RAM total, lower this to `memory-high=120MiB`.

#### Version compatibility

| RouterOS | Status |
|---|---|
| 7.13–7.21.x | ✓ works |
| **7.22, 7.22.x** | ✓ works (verified end-to-end on RB4011iGS+5HacQ2HnD/7.22.2). Behind the scenes: `entrypoint.sh` detects the regression where MikroTik changed default `ip rule` priorities in the container netns (1/2/3 instead of 200/2147483646/2147483647 — would break every TUN-based proxy) and re-installs the historical priorities before starting sing-box. If you skip the entrypoint or run sing-box directly on 7.22.x, you'll need the fix yourself. |
| 7.23rc2+ | ✓ fixed upstream (release note: *"route — revert to old routing rule priorities for containers"*) |
| 7.23.2 | ✓ RB4011 + RB5009 ran on it until 2026-08-31 (stack removed by the owner's decision, not because of problems) |
| 7.24.x | untested (7.24.1 changelog for containers: only *"improve host isolation when privileged=yes"*) |

### 3. Steering — what goes through the tunnel

Two complementary mechanisms, both populating the same `address-list=hynet`:

#### 3a. Static FQDN / CIDR entries

For services with stable infrastructure — apex domains that have an A record, plus raw-IP services like Telegram MTProto. RouterOS accepts DNS names directly in `/ip firewall address-list` and resolves them periodically (per [Address-lists docs](https://help.mikrotik.com/docs/spaces/ROS/pages/130220135/Address-lists), the `address` field accepts `DNS Name | IP address/netmask | IP-IP`).

Bulk-import via `:foreach` array literal — one SSH session, dozens of entries:

```routeros
# Telegram FQDN apexes
:foreach d in={"t.me";"telegram.org";"telegram.me";"telegra.ph";"telesco.pe";"tdesktop.com";"web.telegram.org";"core.telegram.org";"api.telegram.org";"my.telegram.org"} do={
    /ip firewall address-list add list=hynet address=$d comment=telegram
}

# Telegram MTProto raw-IP CIDRs (mandatory — clients connect by IP, no DNS)
:foreach c in={"91.108.4.0/22";"91.108.8.0/22";"91.108.12.0/22";"91.108.16.0/22";"91.108.20.0/22";"91.108.56.0/22";"91.105.192.0/23";"149.154.160.0/20";"185.76.151.0/24"} do={
    /ip firewall address-list add list=hynet address=$c comment=telegram-mtproto
}
# Re-fetch the canonical list periodically: https://core.telegram.org/resources/cidr.txt

# Claude / Anthropic
:foreach d in={"claude.ai";"claude.com";"anthropic.com";"www.claude.ai";"cdn.claude.ai";"assets.claude.ai";"www.anthropic.com";"api.anthropic.com";"console.anthropic.com";"docs.anthropic.com";"support.anthropic.com";"status.anthropic.com";"claudeusercontent.com";"clau.de";"claudemcpclient.com";"servd-anthropic-website.b-cdn.net"} do={
    /ip firewall address-list add list=hynet address=$d comment=claude
}

# YouTube static apexes — full canonical list at v2fly/domain-list-community/data/youtube
# (~180 entries when expanded — adapt to taste)
:foreach d in={"youtube.com";"www.youtube.com";"m.youtube.com";"youtu.be";"ytimg.com";"i.ytimg.com";"s.ytimg.com";"googlevideo.com";"ggpht.com";"youtubei.googleapis.com"} do={
    /ip firewall address-list add list=hynet address=$d comment=youtube
}

# WhatsApp apexes (Meta-side CDN handled by regex below)
:foreach d in={"wa.me";"whatsapp.com";"whatsapp.net";"whatsapp.org";"whatsapp.cc";"whatsapp.info";"whatsapp.tv";"whatsappbrand.com"} do={
    /ip firewall address-list add list=hynet address=$d comment=whatsapp
}
```

#### 3b. DNS-FWD-with-regex for CDN apexes without A records

This is the part that matters for video playback, image previews, and avatar loading. Several services use a *random-subdomain CDN pattern* where the apex (`googlevideo.com`, `ytimg.com`, `ggpht.com`, etc.) has **no A record** at all — only `r1---sn-aigl6n7l.googlevideo.com` and friends do. Adding the apex to address-list does nothing because RouterOS resolves it and gets `dns name exists, but no appropriate record`.

Solution: `/ip dns static type=FWD` entries with regex matching subdomains AND `address-list=hynet` — RouterOS catches the query as it comes in, forwards to upstream, AND adds the resolved IP to `hynet` so subsequent connections to that IP get marked by mangle.

```routeros
# YouTube CDN — video segments, thumbnails, avatars
/ip dns static add type=FWD regexp=".*\\.googlevideo\\.com\$"               address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn
/ip dns static add type=FWD regexp=".*\\.ytimg\\.com\$"                      address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn
/ip dns static add type=FWD regexp=".*\\.ggpht\\.com\$"                      address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn
/ip dns static add type=FWD regexp=".*\\.youtube\\.com\$"                    address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn
/ip dns static add type=FWD regexp="^yt[0-9]+\\.googleusercontent\\.com\$"   address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=youtube-cdn

# WhatsApp media via Meta CDN — narrow regex (only WhatsApp prefix on fbcdn.net,
# leaves regular Facebook/Instagram scontent-* alone)
/ip dns static add type=FWD regexp=".*\\.whatsapp\\.com\$"                   address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=whatsapp
/ip dns static add type=FWD regexp=".*\\.whatsapp\\.net\$"                   address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=whatsapp
/ip dns static add type=FWD regexp="^whatsapp-.*\\.fbcdn\\.net\$"            address-list=hynet forward-to=<upstream-DNS> ttl=1d comment=whatsapp

/ip dns cache flush
```

`<upstream-DNS>` — use whatever your router itself uses (visible in `/ip dns print`, `servers=` field). **Do not** use `1.1.1.1` / `8.8.8.8` directly here — pick one of the resolvers your provider routes you to or your own. Avoid the router's own LAN IP (creates a forwarding loop).

> **regex vs `match-subdomain=yes`** — both work for catching subdomains, but regex is preferred here because it can *exclude the apex* (`.*\.X\.com$` requires a leading `<something>.`, won't match bare `X.com`). The apex has no A record, so matching it just produces NXDOMAIN responses that some clients cache and use to fail-fast — bad. Per [DNS docs](https://help.mikrotik.com/docs/spaces/ROS/pages/37748767/DNS) regex matching is "significantly slower than plain text entries" — fine for ~10 rules, watch CPU if you scale to 50+.

> **Caveat: native mobile apps may bypass the router's DNS** via DoH or hardcoded resolvers. The Android YouTube and WhatsApp apps mostly use system DNS, but some apps use Google's own DNS over QUIC. If steering doesn't work for an app, browser-mode usually does (and its DNS goes through the router).

### 4. Routing-mark + kill-switch

```routeros
/routing/table add name=via-hynet fib

# Pin the Tenda DHCP lease first; all clients behind its NAT share this source IP.
/ip dhcp-server lease make-static [find where address=<TENDA-NAT-IP> and mac-address=<TENDA-MAC>]
:foreach c in={"10.0.0.0/8";"172.16.0.0/12";"192.168.0.0/16"} do={ /ip firewall address-list add list=hynet-direct address=$c comment="hynet:direct-private" }
/ip/firewall/mangle add chain=prerouting src-address=<TENDA-NAT-IP> \
    dst-address-list=hynet-direct action=accept passthrough=yes
/ip/firewall/mangle add chain=prerouting src-address=<TENDA-NAT-IP> \
    dst-address-type=local action=accept passthrough=yes
/ip/firewall/mangle add chain=prerouting src-address=<TENDA-NAT-IP> \
    connection-state=new dst-address-list=hynet \
    action=mark-connection new-connection-mark=hynet-cm passthrough=yes
/ip/firewall/mangle add chain=prerouting src-address=<TENDA-NAT-IP> \
    connection-mark=hynet-cm \
    action=mark-routing new-routing-mark=via-hynet passthrough=no

/ip/route add dst-address=0.0.0.0/0 gateway=172.20.0.2 routing-table=via-hynet \
    distance=1 check-gateway=ping comment="hynet container"
/ip/route add dst-address=0.0.0.0/0 blackhole          routing-table=via-hynet \
    distance=10                  comment="killswitch"

# MSS clamping — the proxy adds TLS+protocol overhead on top of every TCP segment,
# so the effective inside-tunnel MSS is ~40 bytes lower than what the LAN client
# negotiates. Without clamping, large segments get dropped silently somewhere in
# the chain and YouTube/etc starts veeery slowly (PMTU black-holing). With this
# rule MikroTik rewrites SYN's MSS option to clamp-to-pmtu before it goes into the
# container, so the LAN→remote TCP session uses a safe segment size end-to-end.
/ip firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu \
    protocol=tcp tcp-flags=syn out-interface=br-hynet \
    comment="hynet MSS clamp"

# FastTrack is incompatible with routing marks: per the mangle docs "Do not apply
# any other routing marks besides main for the packets processed by FastTrack".
# On a defconf router the `defconf: fasttrack` rule is enabled — after the first
# packet the marked connections stop landing in via-hynet. Exclude them from
# FastTrack (or disable it entirely: ... disabled=yes). On the production
# RB4011/RB5009 steering only worked because fasttrack was absent / disabled.
/ip firewall filter set [find where action=fasttrack-connection] connection-mark=no-mark

# VERIFY (mandatory): via-hynet must hold TWO routes — the active gateway
# 172.20.0.2 distance=1 and the blackhole distance=10. On the production boxes
# the blackhole had never been added (noticed 2026-08-31): a dead container would
# have leaked the marked traffic to the WAN in the clear.
/ip route print detail where routing-table=via-hynet
```

Two-layer fail-closed:

- **sing-box dies → TUN gone → forwarded packets get ICMP-unreach inside container netns → ROS sees unreach, drops.**
- **Whole container dies → veth peer down, `check-gateway=ping` fails, distance=1 route deactivates, blackhole at distance=10 takes over.**

Don't add `veth-hynet` or `br-hynet` to LAN list — that creates a routing loop on container egress.

### 5. Switching countries / picking specific server

The Clash API at `:9090` exposes a `select` group with all parsed outbounds plus per-country `urltest-<cc>` groups. Drop [MetaCubeXD](https://metacubex.github.io/) on your LAN somewhere and point it at `http://172.20.0.2:9090` with the Clash secret, or call the API directly:

```bash
curl -H "Authorization: Bearer $CLASH_SECRET" \
     -X PUT -H 'Content-Type: application/json' \
     -d '{"name":"urltest-tr"}' \
     http://172.20.0.2:9090/proxies/select
```

**Auto-best vs manual pick:**

- `select` defaults to `urltest-all`. With the healthcheck daemon enabled (default), the **daemon** drives auto-pick using real-data probes and can override `urltest-all`'s built-in HEAD-probe choice when it's wrong (see Failover section below). With `HEALTHCHECK_ENABLED=0`, sing-box's built-in urltest takes over: HEAD `/generate_204` every 3 min, picks the fastest. RU servers are excluded from auto-pick by default (`EXCLUDE_AUTO_CC=RU`) — RU transit DPI silently drops Telegram MTProto regardless of which proxy bridges it. RU servers still appear in the `select` dropdown for manual pin (Yandex / госуслуги).
- `urltest-<cc>` per-country auto-best groups — `urltest-tr`, `urltest-nl`, `urltest-ru` etc. Pick from MetaCubeXD when you want auto-best within a specific country.
- Individual server tags like `sub1-vless-example` for hard pinning.

**Failover and real-data probing:**

The container ships a sidecar healthcheck daemon (Go, runs as a child of `entrypoint.sh`) that supplements sing-box's built-in urltest. Sing-box urltest probes HEAD `/generate_204` — that catches "server is unreachable" but is fooled by servers that pass TLS handshake then silently drop application data. The daemon fixes this without disrupting user traffic.

**How probing works.** The converter generates one localhost-only HTTP-proxy inbound per non-excluded outbound (port `7900 + N`), each statically routed to its corresponding outbound via a sing-box route rule. The daemon connects to `127.0.0.1:<port>` as an HTTP proxy and downloads `LIVENESS_BYTES` from `LIVENESS_URL` — the request goes through that specific outbound. **`select.now` is never touched during a probe**, so user traffic continues uninterrupted via whatever the user (or auto-pin) had selected. Tag→port map written to `/tmp/probe_ports.json` on each `sub-refresh`.

| Loop | Cadence | What it does |
|---|---|---|
| Liveness | every `LIVENESS_INTERVAL` (30 s) | Resolves `select.now` (recursing through `urltest-*` groups), probes that specific outbound via its dedicated port and refreshes its ranking entry. Real-data download — partial response = fail. After `FAIL_THRESHOLD` (2) consecutive failures, freshly measure up to `FAILOVER_CANDIDATES` best-ranked alternatives and rotate to the fastest live result. After `ROTATIONS_BEFORE_FORCE_SWEEP` (3) rotations w/o success → force a full sweep. |
| Ranking sweep | every `RANK_INTERVAL` (10 min) | Probes every outbound, up to 4 concurrently. RU is excluded via `/tmp/probe_countries.json`. Every result is persisted immediately; entries older than `RANK_STALE_AFTER` are ignored. **`select.now` is not changed during measurement**. |
| Auto-pin | after the first probes and every sweep | `select.now` ← fastest alive server. An ordinary improvement ≥15% needs `IMPROVE_CONFIRMATIONS` confirmations and `MIN_SWITCH_INTERVAL` dwell. An improvement ≥`SEVERE_IMPROVE_PCT` bypasses both after the fresh sweep. Failure rotation is immediate and uses fresh candidate measurements. `AUTO_PIN=0` preserves manual selection. |

**`select.now` changes after a confirmed current-server failure, a severe freshly measured improvement, or a sustained, repeatedly confirmed ordinary improvement.** Telegram API and MTProto CONNECT are part of every candidate's general health probe; no separate Telegram pool is created.

The daemon's log is `/tmp/healthcheck.log`, the sing-box log `/tmp/sing-box.log` (level warn), the config `/tmp/config.json` (all on the container's 64 MB tmpfs). Set `HEALTHCHECK_ENABLED=0` to skip the daemon and fall back to sing-box's built-in HEAD-probe urltest (no disruption either, but back to the handshake-OK / data-reset fooler problem).

## Standalone Docker (for testing)

```bash
docker run --rm -it \
    --cap-add=NET_ADMIN --device /dev/net/tun \
    -e SUBSCRIPTION_1='https://your-provider/sub' \
    -e CLASH_SECRET='replace-with-random' \
    -e CLASH_ADDR=0.0.0.0:9090 \
    -p 9090:9090 \
    ghcr.io/inlarin/hynet-singbox-public:armv7
```

The image is built for arm/v7 and arm64 only — on an x86 host you need QEMU (`docker run --platform linux/arm64 …`) or build an amd64 image yourself (`--platform linux/amd64` in the command below).

## Build from source

```bash
git clone https://github.com/inlarin/hynet-singbox-public
cd hynet-singbox
docker buildx build --platform linux/arm/v7 --provenance=false --sbom=false --load -t hynet-singbox:armv7 .
```

## Resource use on RB4011

| Resource | Idle | Active (single TCP stream) |
|---|---|---|
| RAM (container) | ~50 MB | ~90–140 MB |
| Image on disk | rootfs ≤70 MB (~22 MB compressed pull after the slim build) | — |
| NAND writes/day at runtime | **0** (all state on tmpfs inside the container) | — |

## Operational notes — refresh, deploys, reading health

The sharp edges an operator (or an automated agent) hits in practice.

### Subscription fetch is dual-mirror and direct-WAN

Every `sub1…sub5` refreshes independently with its own URL, UA and optional HWID, including the `hynet-connect.com`/`hynet.cloud` mirror when applicable. The converter rejects HTML error pages. A failed provider keeps nodes from the current running config while all other pools update. There are no manual fallback URIs.

Before sing-box starts, fetches use the ordinary container default route. While the TUN is active, curl uses the loopback HTTP inbound `refresh-direct` at `127.0.0.1:7899`, statically routed to the `direct` outbound. `route.auto_detect_interface=true` binds that egress to veth and prevents a TUN loop. Thus subscription updates do not depend on a working VPN exit and need no host mount.

Monitor `/tmp/config.json`, `/tmp/sub-refresh.log`, `df /tmp` and process memory, not just `select.now`. The maintenance loop trims `sing-box.log`, `healthcheck.log` and `sub-refresh.log` to the last 500 lines hourly and reports config age, tmpfs and RSS.

### Known limitations

- **Probe traffic ≈ 0.65 GB/day with 25 nodes** (liveness 100 KB every 30 s ≈ 288 MB + sweep 25 × 100 KB
  every 10 min ≈ 360 MB). On a metered / LTE WAN lower `LIVENESS_BYTES` (e.g. `10000` with a matching
  `LIVENESS_URL`) or raise `RANK_INTERVAL`.
- **Logs are capped hourly, not on every write**: an unusually noisy hour can still fill the 64 MB tmpfs. Check the maintenance output and `df /tmp` when diagnosing refresh failures.
- **Telegram IPv6 is not covered**: steering is `/ip` only; Telegram's IPv6 prefixes
  (`2001:b28:f23d::/48`, `2001:b28:f23f::/48`, `2001:67c:4e8::/48`, `2001:b28:f23c::/48`, `2a0a:f280::/32`)
  bypass the tunnel if the LAN hands out IPv6. The IPv4 list in §3a was checked against
  `core.telegram.org/resources/cidr.txt` on 2026-08-31 (9 prefixes, identical).
- **Geo lookups (ip-api.com) go in-band**: with a dead tunnel new servers get country `ZZ`
  (seen 2026-07-06); the seed cache `/etc/hynet/country_cache.json` baked into the image softens it.
- **Dynamic `created for …` entries** in `address-list=hynet` produced by the FWD rules did not expire by
  TTL in practice (2026-06-18) — clean them by hand when retiring a service:
  `/ip firewall address-list remove [find list=hynet dynamic=yes comment~"created"]`.

### Some WAN lines DPI-break foreign gRPC — those dead nodes are benign

On certain ISP lines the `*-2053-grpc` outbounds to *foreign* servers fail: TCP connects,
then the gRPC/REALITY handshake is reset (even a tiny probe fails — it is **not** MTU). The
same servers' `:8444` vision / vmess / trojan / ss work, and RU grpc works. This is
**line-specific DPI, not a server or sing-box fault** — the selector simply never picks the
dead grpc nodes. Don't restart or reconfigure for them.

### Deploying a script edit to a running container

Edits to `/usr/local/bin/*.sh` in a running container persist across container restart but
are **lost on image re-pull** — the durable path is commit + CI image rebuild. When pushing a
file from a Windows checkout, **strip CRLF first** (`tr -d '\r'`): busybox-ash dies with
`syntax error: unexpected word (expecting "in")` on a `case`/`for` line carrying a trailing
`\r`. The repo enforces LF via `.gitattributes` (`*.sh text eol=lf`).

### Reading health

Read-only snapshot with plain RouterOS commands (the `mikrotik-vpn-check` skill is gone — deleted
2026-08-31 together with the stack; from the `monitoring` project the same commands go through `tools/rsh.py rb4011 "…"`):

```routeros
/container/print
/ip route print where routing-table=via-hynet
/ip firewall address-list print count-only where list=hynet
/container/shell [find where name~"hynet"] cmd="tail -20 /tmp/healthcheck.log"
/container/shell [find where name~"hynet"] cmd="ls -l /tmp/config.json; df /tmp"
```

Clash API from the router or the LAN: `curl -H "Authorization: Bearer $CLASH_SECRET" http://172.20.0.2:9090/proxies/select`.

VPN is **UP iff** the container runs, `select.now` has a recent delay, and the `via-hynet` route
is active — *regardless of the dead-node count*. Dead `*-grpc` entries can be benign DPI on a
particular WAN; never restart just because some nodes are dead. **Separately check the config age**
and `/tmp/sub-refresh.log`: repeated fetch, DNS or tmpfs errors mean refresh is broken even when
the current VPN exit is alive. Run `sub-refresh.sh` manually and inspect its error before restarting.

## License

MIT.
