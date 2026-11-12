#!/bin/sh
set -u

: "${CLASH_SECRET:?CLASH_SECRET must be set}"
: "${REFRESH_INTERVAL:=86400}"
: "${CLASH_ADDR:=172.20.0.2:9090}"
: "${TMPFS_SIZE:=64M}"

STATE=/tmp
CONFIG="$STATE/config.json"
SECRETS="$STATE/sing-box"

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log() { echo "[$(ts)] entrypoint: $*"; }

if [ -z "${SUBSCRIPTION_1:-}${SUBSCRIPTION_2:-}${SUBSCRIPTION_3:-}${SUBSCRIPTION_4:-}${SUBSCRIPTION_5:-}" ]; then
    log "at least one SUBSCRIPTION_1..5 must be set"
    exit 3
fi

if mount -t tmpfs -o "size=$TMPFS_SIZE,mode=1777" tmpfs /tmp 2>/dev/null; then
    log "tmpfs mounted on /tmp ($TMPFS_SIZE)"
else
    log "WARN: tmpfs mount failed, /tmp falls through to container overlay"
fi
mkdir -p "$SECRETS/subscriptions.d"
chmod 700 "$SECRETS"

write_provider() {
    index="$1"
    url="$2"
    hwid="$3"
    ua="$4"
    [ -n "$url" ] || return 0
    {
        printf 'PREFIX=sub%s\n' "$index"
        printf 'URL=%s\n' "$url"
        [ -z "$hwid" ] || printf 'HWID=%s\n' "$hwid"
        printf 'UA=%s\n' "$ua"
        printf 'MAX=0\n'
        printf 'MARK=auto\n'
    } > "$SECRETS/subscriptions.d/sub${index}.conf"
    chmod 600 "$SECRETS/subscriptions.d/sub${index}.conf"
}
write_provider 1 "${SUBSCRIPTION_1:-}" "${HW_ID_1:-}" "${UA_1:-ClashforAndroid/2.5.12}"
write_provider 2 "${SUBSCRIPTION_2:-}" "${HW_ID_2:-}" "${UA_2:-sing-box}"
write_provider 3 "${SUBSCRIPTION_3:-}" "${HW_ID_3:-}" "${UA_3:-sing-box}"
write_provider 4 "${SUBSCRIPTION_4:-}" "${HW_ID_4:-}" "${UA_4:-sing-box}"
write_provider 5 "${SUBSCRIPTION_5:-}" "${HW_ID_5:-}" "${UA_5:-sing-box}"

export SINGBOX_SUBS_DIR="$SECRETS/subscriptions.d"
export SINGBOX_LEGACY_PROVIDER=""
export SINGBOX_LEGACY_PREFIX=""
export SINGBOX_HEALTHCHECK_SECRET="$CLASH_SECRET"

if ip rule list 2>/dev/null | grep -qE '^1:[[:space:]]'; then
    log "reverting RouterOS 7.22 container ip-rule layout"
    ip rule del pref 1 2>/dev/null || true
    ip rule del pref 2 2>/dev/null || true
    ip rule del pref 3 2>/dev/null || true
    ip rule add pref 200 from all lookup local 2>/dev/null || true
    ip rule add pref 2147483646 from all lookup main 2>/dev/null || true
    ip rule add pref 2147483647 from all lookup default 2>/dev/null || true
fi

log "--- network diag ---"
sed 's/^/  /' /etc/resolv.conf 2>/dev/null || true
ip a 2>/dev/null | grep -E "^[0-9]+:|inet " | sed 's/^/  /' || true
ip route 2>/dev/null | sed 's/^/  /' || true
log "--- end diag ---"

attempt=1
until /usr/local/bin/sub-refresh.sh; do
    log "initial subscription fetch failed (attempt $attempt); retrying in 30s"
    attempt=$((attempt + 1))
    sleep 30
done

(
    while sleep "$REFRESH_INTERVAL"; do
        /usr/local/bin/sub-refresh.sh || log "refresh attempt failed"
    done
) &

rotate_log() {
    f="$1"
    [ -f "$f" ] || return 0
    tail -n 500 "$f" > "$f.rotate" 2>/dev/null && cat "$f.rotate" > "$f"
    rm -f "$f.rotate"
}
(
    while sleep 3600; do
        rotate_log /tmp/sing-box.log
        rotate_log /tmp/healthcheck.log
        rotate_log /tmp/sub-refresh.log
        ls -l "$CONFIG" 2>/dev/null || true
        df -m /tmp 2>/dev/null || true
        ps -o pid,rss,comm 2>/dev/null | grep -E 'sing-box|healthcheck|PID' || true
    done
) &

if [ "${HEALTHCHECK_ENABLED:-0}" = "1" ]; then
    log "starting healthcheck daemon"
    (
        export CLASH_API="http://$CLASH_ADDR"
        /usr/local/bin/healthcheck >> "$STATE/healthcheck.log" 2>&1
    ) &
fi

SB_PID=0
trap 'log "TERM, killing sing-box"; kill "$SB_PID" 2>/dev/null; exit 0' TERM INT

while true; do
    log "starting sing-box"
    /usr/local/bin/sing-box run -c "$CONFIG" &
    SB_PID=$!
    wait "$SB_PID"
    rc=$?
    log "sing-box exited rc=$rc; respawning in 5s"
    sleep 5
done
