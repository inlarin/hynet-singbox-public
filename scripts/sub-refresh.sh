#!/bin/sh
set -u

ONLY=""
DROP=""
while [ $# -gt 0 ]; do
    case "$1" in
        --only) ONLY="${2:-}"; shift 2 ;;
        --only=*) ONLY="${1#--only=}"; shift ;;
        --drop) DROP="${2:-}"; shift 2 ;;
        --drop=*) DROP="${1#--drop=}"; shift ;;
        *) echo "usage: $0 [--only sub1[,sub2,...]] [--drop sub1[,sub2,...]]" >&2; exit 64 ;;
    esac
done
case "$ONLY$DROP" in *[!a-z0-9,]*)
    echo "FAIL: --only/--drop take lowercase names separated by commas" >&2; exit 64 ;;
esac
MERGE_ONLY="$ONLY"
if [ -z "$MERGE_ONLY" ] && [ -n "$DROP" ]; then
    MERGE_ONLY=none
fi

DIR=/opt/share/sing-box
CONV="$DIR/sub_to_singbox.py"
MERGE_SUBS="$DIR/merge-subscriptions.py"
ACTIVE=/tmp/config.json
CACHE=/tmp/country_cache.json
LOG=/tmp/sub-refresh.log
CLASH_ADDR="${CLASH_ADDR:-172.20.0.2:9090}"
CLASH_API="${CLASH_API:-http://$CLASH_ADDR}"
ROUTER_HOST="${ROUTER_HOST:-172.20.0.1}"
CLASH_SECRET="${CLASH_SECRET:?CLASH_SECRET must be set}"
SINGBOX_HEALTHCHECK_SECRET="$CLASH_SECRET"
SINGBOX_SUBS_DIR="${SINGBOX_SUBS_DIR:-/tmp/sing-box/subscriptions.d}"
SINGBOX_ENV_FILE="${SINGBOX_ENV_FILE:-/tmp/sing-box/env}"
SINGBOX_CONVERTER="$CONV"
SINGBOX_LEGACY_PROVIDER=""
SINGBOX_LEGACY_PREFIX=""
export CLASH_ADDR SINGBOX_HEALTHCHECK_SECRET SINGBOX_SUBS_DIR SINGBOX_ENV_FILE
export SINGBOX_CONVERTER SINGBOX_LEGACY_PROVIDER SINGBOX_LEGACY_PREFIX
export SINGBOX_EXCLUDE_AUTO_PROTO SINGBOX_TLS_FRAGMENT SINGBOX_TLS_FRAGMENT_REALITY
export SINGBOX_MUX SINGBOX_COUNTRY_URLTESTS SINGBOX_UTLS_FINGERPRINT
export SINGBOX_CONNECT_TIMEOUT SINGBOX_NODE_RESOLVER SINGBOX_TUN_STACK SINGBOX_TUN_NAME

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { printf '[%s] %s\n' "$(ts)" "$*" | tee -a "$LOG"; }

[ -f "$MERGE_SUBS" ] || { log "FAIL: subscription merger is not installed"; exit 1; }
LOCK=/tmp/sub-refresh.lock
if ! mkdir "$LOCK" 2>/dev/null; then
    _lp=$(cat "$LOCK/pid" 2>/dev/null)
    if [ -n "$_lp" ] && kill -0 "$_lp" 2>/dev/null; then
        log "BUSY: another refresh (pid $_lp) is running"
        exit 75
    fi
    rm -rf "$LOCK"
    mkdir "$LOCK" 2>/dev/null || exit 75
fi
echo $$ > "$LOCK/pid"
TMP=$(mktemp -d /tmp/subrefresh.XXXXXX)
trap 'rm -rf "$TMP" "$LOCK"' EXIT

if pidof sing-box >/dev/null 2>&1 && [ -f "$ACTIVE" ]; then
    SINGBOX_REFRESH_PROXY=http://127.0.0.1:7899
    export SINGBOX_REFRESH_PROXY
    log "subscription traffic pinned to direct WAN via refresh-direct"
else
    unset SINGBOX_REFRESH_PROXY
fi

cp -f "$CACHE" "$TMP/country_cache.json" 2>/dev/null || \
    cp -f "$DIR/country_cache.json" "$TMP/country_cache.json" 2>/dev/null || true
cp -f "$CONV" "$TMP/sub_to_singbox.py"
cd "$TMP" || exit 1
if ! python3 sub_to_singbox.py --empty-config --out new.json \
        --secret "$CLASH_SECRET" --router-ip "$ROUTER_HOST" >> "$LOG" 2>&1; then
    log "FAIL: empty config generation failed"
    exit 1
fi

set -- "$TMP/new.json"
[ -n "$MERGE_ONLY" ] && set -- "$@" --only "$MERGE_ONLY"
[ -n "$DROP" ] && set -- "$@" --drop "$DROP"
SINGBOX_ACTIVE_CONFIG="$ACTIVE" SINGBOX_COUNTRY_CACHE="$TMP/country_cache.json" \
    SINGBOX_COUNTRIES_OUT="$TMP/probe_countries.json" \
    python3 "$MERGE_SUBS" "$@" >> "$LOG" 2>&1
MRC=$?
case "$MRC" in
    0) ;;
    2) log "WARN: a subscription failed; its running nodes were kept" ;;
    *) log "FAIL: subscription merge failed (rc=$MRC); keeping current config"; exit 1 ;;
esac

if ! python3 - "$TMP/new.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(0 if any(o.get("server") for o in c.get("outbounds", [])) else 1)
PY
then
    log "FAIL: no usable outbounds from any subscription; keeping current config"
    exit 1
fi
if ! /usr/local/bin/sing-box check -c "$TMP/new.json" >> "$LOG" 2>&1; then
    log "FAIL: sing-box check rejected new config; keeping old"
    exit 2
fi
cp -f "$TMP/country_cache.json" "$CACHE.new" 2>/dev/null && mv -f "$CACHE.new" "$CACHE" || true
if [ -f "$TMP/probe_countries.json" ]; then
    cp -f "$TMP/probe_countries.json" /tmp/probe_countries.json.new && \
        mv -f /tmp/probe_countries.json.new /tmp/probe_countries.json
fi

python3 - "$TMP/new.json" /tmp/probe_ports.json.new <<'PY'
import json, sys
c = json.load(open(sys.argv[1], encoding="utf-8"))
out = {}
for inbound in c.get("inbounds", []):
    tag = str(inbound.get("tag", ""))
    if not tag.startswith("probe-"):
        continue
    for rule in c.get("route", {}).get("rules", []):
        if rule.get("inbound") == [tag] and rule.get("outbound"):
            out[rule["outbound"]] = inbound["listen_port"]
json.dump(out, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY

POOL_SAME=$(ACTIVE="$ACTIVE" NEWCFG="$TMP/new.json" python3 - <<'PY'
import json, os

def pool(path):
    try:
        c = json.load(open(path, encoding="utf-8"))
    except Exception:
        return None
    def norm(o):
        d = {k: v for k, v in o.items() if k != "tag"}
        if len(str(o.get("tag") or "").split("-", 1)[0]) != 2 and isinstance(d.get("tls"), dict):
            d["tls"] = {k: v for k, v in d["tls"].items() if k != "server_name"}
        return json.dumps(d, sort_keys=True, separators=(",", ":"))
    obs = sorted(norm(o) for o in c.get("outbounds", []) if o.get("server"))
    meta = sorted((o.get("type"), len(o.get("outbounds") or []))
                  for o in c.get("outbounds", []) if o.get("type") in ("selector", "urltest"))
    rest = {k: v for k, v in c.items() if k not in ("outbounds", "inbounds", "route")}
    inb = sorted(json.dumps(i, sort_keys=True, separators=(",", ":"))
                 for i in c.get("inbounds", []) if not str(i.get("tag") or "").startswith("probe-"))
    rules = sorted(json.dumps(r, sort_keys=True, separators=(",", ":"))
                   for r in (c.get("route") or {}).get("rules", [])
                   if not str((r.get("inbound") or [""])[0]).startswith("probe-"))
    route_rest = {k: v for k, v in (c.get("route") or {}).items() if k != "rules"}
    return json.dumps([obs, meta, inb, rules, route_rest, rest], sort_keys=True, separators=(",", ":"))

a, b = pool(os.environ["ACTIVE"]), pool(os.environ["NEWCFG"])
print("yes" if a is not None and a == b else "no")
PY
)
if [ "$POOL_SAME" = yes ]; then
    log "pool identical; keeping running config, no restart"
    rm -f /tmp/probe_ports.json.new
    exit 0
fi

PICKS="$TMP/picks"
: > "$PICKS"
if [ -f "$ACTIVE" ]; then
    curl -fsS --max-time 5 -H "Authorization: Bearer $CLASH_SECRET" \
        "$CLASH_API/proxies/select" 2>/dev/null | \
        sed -n 's/.*"now": *"\([^"]*\)".*/\1/p' > "$PICKS" || true
fi

[ -f "$ACTIVE" ] && cp -f "$ACTIVE" "$ACTIVE.prev"
cp -f "$TMP/new.json" "$ACTIVE.staged" && chmod 600 "$ACTIVE.staged" && mv -f "$ACTIVE.staged" "$ACTIVE"
mv -f /tmp/probe_ports.json.new /tmp/probe_ports.json
log "config replaced; restarting sing-box"
WAS_RUNNING=0
if pidof sing-box >/dev/null 2>&1; then
    WAS_RUNNING=1
    kill -TERM $(pidof sing-box) 2>/dev/null || true
fi

ready=0
i=0
while [ "$WAS_RUNNING" -eq 1 ] && [ $i -lt 30 ]; do
    if curl -fsS --max-time 2 -H "Authorization: Bearer $CLASH_SECRET" "$CLASH_API/version" >/dev/null 2>&1; then
        ready=1
        break
    fi
    i=$((i + 1))
    sleep 1
done
if [ "$ready" -ne 1 ] && [ -f "$ACTIVE.prev" ]; then
    log "FAIL: new config did not start; restoring previous config"
    mv -f "$ACTIVE" "$ACTIVE.failed"
    mv -f "$ACTIVE.prev" "$ACTIVE"
    kill -TERM $(pidof sing-box) 2>/dev/null || true
    exit 2
fi

if [ -s "$PICKS" ]; then
    tag=$(cat "$PICKS")
    if curl -fsS --max-time 5 -X PUT -H "Authorization: Bearer $CLASH_SECRET" \
           -H 'Content-Type: application/json' -d "{\"name\":\"$tag\"}" \
           "$CLASH_API/proxies/select" >/dev/null 2>&1; then
        log "restored select.now"
    else
        log "previous select.now is no longer available"
    fi
fi
log "=== refresh done ==="
exit 0
