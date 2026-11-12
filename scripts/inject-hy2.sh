#!/bin/sh
# inject-hy2.sh — append a Hysteria2 outbound from HY2_URI env into a sing-box
# config (post-processed after sub2singbox writes /tmp/config.json.new).
# Reserves hy2 for Telegram ONLY: routes Telegram destination CIDRs through a
# `tg-select` SELECTOR with two members — hy2 (default) and a `tg-failover`
# URLTEST group built from EVERY non-RU server outbound in the config
# (dynamic — survives subscription rotation; RU excluded — RU transit breaks
# Telegram MTProto). The healthcheck daemon's tgManage loop keeps tg-select on
# hy2 whenever hy2 is alive and, when hy2 dies, switches it to `tg-failover` —
# sing-box's urltest then continuously health-checks the non-RU pool and
# auto/reactively fails over to a live node itself (no stale single-node pick
# that could strand Telegram on a node that died since the last sweep). hy2 is
# deliberately NOT added to select/urltest-all and is NOT select.default: all
# other tunneled traffic stays on the general `select` pool. hy2 also gets NO
# probe inbound — its liveness is measured by tgManage via the Clash delay API,
# so it stays out of the general probe/rank/pin path.
#
# Why hy2 for Telegram: the panel subscription ships TCP-only outbounds
# (vless+vision/grpc, vmess+http/tcp, trojan+ws, ss+tcp). UDP-over-XUDP-over-
# TCP/TLS adds head-of-line blocking that destroys Telegram voice and other
# real-time UDP. A native UDP (QUIC) outbound like hysteria2 sidesteps that.
#
# Usage:   inject-hy2.sh <config.json>
# Env:     HY2_URI  hy2://user:pass@host:port?obfs=…&obfs-password=…&sni=…&insecure=1[#fragment]
#
# Note: pinSHA256 is parsed but NOT applied — sing-box has no native cert-pin
# mode. With insecure=1 we skip TLS verification entirely (the URI itself
# requested this). Don't drop insecure=1 from the URI without supplying the
# full server certificate via tls.certificate.
#
# Idempotent: if TAG already in the config's .outbounds, exits 0 without
# touching anything; otherwise stale tg-select / tg-failover / hy2 route rules
# are rebuilt.
set -u

CFG="${1:-/tmp/config.json}"

if [ -z "${HY2_URI:-}" ]; then
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "[inject-hy2] FAIL: jq not installed" >&2
    exit 1
fi

URI="$HY2_URI"
URI="${URI#hy2://}"
URI="${URI#hysteria2://}"

# Fragment (label)
FRAG=""
case "$URI" in
    *\#*) FRAG="${URI##*#}"; URI="${URI%%#*}" ;;
esac

# Query
QUERY=""
case "$URI" in
    *\?*) QUERY="${URI#*\?}"; URI="${URI%%\?*}" ;;
esac

# user:pass@host:port  — auth may itself contain ':'
case "$URI" in
    *@*) AUTH="${URI%@*}"; HOSTPORT="${URI##*@}" ;;
    *)   AUTH=""; HOSTPORT="$URI" ;;
esac
HOST="${HOSTPORT%:*}"
PORT="${HOSTPORT##*:}"

if [ -z "$HOST" ] || [ -z "$PORT" ] || [ -z "$AUTH" ]; then
    echo "[inject-hy2] FAIL: malformed HY2_URI (need user:pass@host:port)" >&2
    exit 1
fi

q_get() {
    echo "$QUERY" | tr '&' '\n' | awk -F= -v k="$1" '$1==k {print substr($0, length(k)+2); exit}'
}
url_decode() {
    # POSIX %hex decode via printf
    printf '%b' "$(echo "$1" | sed 's/+/ /g; s/%/\\x/g')"
}

OBFS="$(url_decode "$(q_get obfs)")"
OBFS_PW="$(url_decode "$(q_get obfs-password)")"
SNI="$(url_decode "$(q_get sni)")"
INSECURE="$(q_get insecure)"

# Tag — derive from fragment, else host-port
RAW_TAG="${FRAG:-${HOST}-${PORT}}"
TAG="hy2-$(echo "$RAW_TAG" | tr -c 'A-Za-z0-9-' '-' | sed 's/-\{2,\}/-/g; s/^-//; s/-$//')"

# Insecure → bool
case "$INSECURE" in 1|true|yes|on) INS_BOOL=true ;; *) INS_BOOL=false ;; esac

# Build hy2 outbound JSON
if [ -n "$OBFS" ]; then
    OUTBOUND=$(jq -n \
        --arg tag "$TAG" --arg server "$HOST" --argjson port "$PORT" \
        --arg pw "$AUTH" --arg obfs "$OBFS" --arg obfs_pw "$OBFS_PW" \
        --arg sni "$SNI" --argjson insecure "$INS_BOOL" \
        '{type:"hysteria2", tag:$tag, server:$server, server_port:$port, password:$pw,
          obfs:{type:$obfs, password:$obfs_pw},
          tls:{enabled:true, server_name:$sni, insecure:$insecure}}')
else
    OUTBOUND=$(jq -n \
        --arg tag "$TAG" --arg server "$HOST" --argjson port "$PORT" \
        --arg pw "$AUTH" --arg sni "$SNI" --argjson insecure "$INS_BOOL" \
        '{type:"hysteria2", tag:$tag, server:$server, server_port:$port, password:$pw,
          tls:{enabled:true, server_name:$sni, insecure:$insecure}}')
fi

# Idempotency: if TAG already in config, skip
if jq -e --arg t "$TAG" '.outbounds | map(.tag) | index($t)' "$CFG" >/dev/null; then
    echo "[inject-hy2] $TAG already present in $CFG, skipping"
    exit 0
fi

# Telegram destination CIDRs (IPv4+IPv6). Telegram traffic that enters the
# tunnel is routed through the tg-select selector; everything else falls
# through to route.final = "select" (the general pool, daemon-managed).
TG_CIDRS='["91.108.0.0/16","149.154.160.0/20","95.161.64.0/20","91.105.192.0/23","2001:b28:f23d::/48","2001:b28:f23f::/48","2001:b28:f242::/48","2001:67c:4e8::/48"]'

# tg-failover urltest members = EVERY non-RU server outbound currently present
# (dynamic → auto-survives subscription rotation). RU (ru-*) excluded: RU
# transit breaks Telegram MTProto.
#
# Per-site knobs (container envs, read here at every config regen):
#   TG_HYSTERIA (default yes) — yes: tg-select default/primary = hy2 (daemon
#       returns to it whenever alive). no: hy2 is injected but UNREFERENCED —
#       tg-select = tg-failover + direct members only, default tg-failover —
#       so a flapping hy2 can neither carry nor interrupt Telegram, and
#       flipping back to yes on the next refresh restores hy2-primary without
#       re-entering the URI. For lines where hy2 is DPI-flaky
#       (Keenetic decision 2026-07-04; RB4011 2026-07-18).
#   TG_EXCLUDE_RE (default "") — jq regex; matching tags are dropped from the
#       tg-failover urltest AND from tg-select's direct members. For transports
#       whose DATA path is DPI-killed on a given line while the tiny HEAD
#       urltest probe still passes and keeps them ranked "fast" (sing-box
#       urltest = HTTP HEAD, body never read — verified v1.13.11
#       common/urltest/urltest.go). RB4011: "-trojan-|-grpc$".
#
# tg-select members = [hy2?, tg-failover] + every kept direct outbound —
# membership == pin eligibility: the daemon's tgManage re-pins tg-select to a
# ranking-ordered, verified-live DIRECT member when the active path dies
# (Clash PUT rejects non-members, so eligibility is exactly this list).
# If the sub has zero non-RU outbounds, tg-failover is omitted and tg-select
# is just [hy2] (keeps `sing-box check` happy on an empty urltest). hy2 stays
# OUT of select/urltest-all (Telegram-only) and gets no probe inbound.
case "${TG_HYSTERIA:-yes}" in
    no|0|false|off|NO|No) TG_HY2_PRIMARY=false ;;
    *)                    TG_HY2_PRIMARY=true ;;
esac
TG_EXCLUDE_RE="${TG_EXCLUDE_RE:-}"

TMP="$CFG.injtmp"
jq --argjson outbound "$OUTBOUND" --arg tag "$TAG" --argjson tg "$TG_CIDRS" \
   --arg xre "$TG_EXCLUDE_RE" --argjson hy2primary "$TG_HY2_PRIMARY" '
    ([ .outbounds[]
       | select((.type=="vless" or .type=="vmess" or .type=="trojan" or .type=="shadowsocks")
                and (.tag | startswith("ru-") | not)
                and (if $xre == "" then true else ((.tag | test($xre)) | not) end))
       | .tag ]) as $nonru
    | .outbounds += [$outbound]
    | .outbounds |= map(select(.tag != "tg-select" and .tag != "tg-failover"))
    | (if ($nonru | length) > 0
       then .outbounds += [ {type:"urltest", tag:"tg-failover", outbounds:$nonru,
                             url:"https://www.gstatic.com/generate_204",
                             interval:"1m0s", tolerance:50, idle_timeout:"30m0s"} ]
            | (if $hy2primary
               then .outbounds += [ {type:"selector", tag:"tg-select",
                                     outbounds:([$tag, "tg-failover"] + $nonru), default:$tag} ]
               else .outbounds += [ {type:"selector", tag:"tg-select",
                                     outbounds:(["tg-failover"] + $nonru), default:"tg-failover"} ]
               end)
       else .outbounds += [ {type:"selector", tag:"tg-select",
                            outbounds:[$tag], default:$tag} ]
       end)
    | .route.rules = ((.route.rules // [])
        | map(select((.outbound // "") != $tag and (.outbound // "") != "tg-select" and (.outbound // "") != "tg-failover"))
        + [{"ip_cidr": $tg, "outbound": "tg-select"}])
' "$CFG" > "$TMP" && mv "$TMP" "$CFG"

NMEM=$(jq -r '[.outbounds[]|select(.tag=="tg-failover").outbounds[]]|length' "$CFG" 2>/dev/null)
if [ "$TG_HY2_PRIMARY" = true ]; then
    MODE="hy2-primary (tg-select default=$TAG)"
else
    MODE="no-hysteria ($TAG kept unreferenced, tg-select default=tg-failover)"
fi
[ -n "$TG_EXCLUDE_RE" ] && MODE="$MODE, excluded: $TG_EXCLUDE_RE"
echo "[inject-hy2] injected $TAG ($HOST:$PORT); $MODE; tg-failover urltest = ${NMEM:-0} nodes; tg-select = group + direct members (daemon verified-live re-pin); general traffic stays on select"
