"""Convert a v2ray-style base64 subscription (vless/vmess/trojan/ss URIs)
into a **single-pool** sing-box config for Keenetic (one TUN, one `select`).

Architecture (since 2026-04-28; see ARCHITECTURE.md):
- Each subscription server becomes an outbound with a **stable tag**
  ``<cc>-<proto>-<host>-<port>-<transport>`` so ranking and manual `select`
  pins survive subscription rotation. Country codes come from ip-api.com and
  are cached on disk in ``country_cache.json`` (manual edit OK; auto-extends).
- ONE TUN inbound ``opkgtun0`` (``172.19.0.1/30`` -- sing-box >= 1.14 rejects
  a /32 TUN address) that NDM registers as ``OpkgTun0``; ``--ndm-setup`` emits
  the ndmc commands for it. The per-country ``OpkgTunN`` pools of 2026-04 were
  dropped (each TUN cost ~10-15 MiB RSS; selector switching covers the use case).
- One ``select`` selector over all nodes plus ``urltest-all``; per-country
  ``urltest-<cc>`` groups only with ``--country-urltests on``. The healthcheck
  daemon (S99singbox-healthcheck) owns ``select.now``; urltest groups exist
  for MetaCubeXD switching.
- A localhost HTTP-proxy inbound per outbound (``127.0.0.1:<probe_base_port+N>``,
  default 7900) with a matching route rule, so the daemon can probe a node
  without touching the live selection.
- Optional anti-DPI knobs: ``--tls-fragment record|tcp`` (reality nodes skipped
  unless ``--tls-fragment-reality include``), ``--mux``, and
  ``--exclude-auto-proto`` (protocols kept out of ``urltest-all``).

Usage:
    python sub_to_singbox.py <subscription_url> [--out config.json] [--ndm-setup ndm_setup.cmd]
    python sub_to_singbox.py --file dump.txt --out outbounds.json

Environment knobs (on the router they come from /opt/etc/sing-box/.env via
sub-refresh.sh): ROUTER_HOST, SINGBOX_HEALTHCHECK_SECRET,
SINGBOX_EXCLUDE_AUTO_PROTO, SINGBOX_TLS_FRAGMENT, SINGBOX_TLS_FRAGMENT_REALITY,
SINGBOX_MUX, SINGBOX_COUNTRY_URLTESTS, SINGBOX_TUN_STACK.

SINGBOX_TUN_STACK picks the TUN network stack: unset -> "gvisor" (what every
1.13/1.14 deploy needs, since system/mixed do not forward under auto_route=false),
"none"/"off"/empty -> the key is omitted, which is how sing-box >= 1.15 is asked
to use its own TCP/IP stack (3-4x faster on the reference box, measured 2026-09-16).

Side artefact created next to this script: ``country_cache.json`` (IP->cc).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request
from typing import Any

# ── State file (cached country lookups) ─────────────────────────────────────

_HERE = os.path.dirname(os.path.abspath(__file__))
COUNTRY_CACHE_PATH = os.path.join(_HERE, "country_cache.json")


def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _save_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)


# ── Subscription fetch + base64 decode helpers ──────────────────────────────

def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ClashforAndroid/2.5.12"})
    return urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace").strip()


def b64decode_loose(s: str) -> str:
    s = s.strip()
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + "=" * pad).decode("utf-8", "replace")


# ── GeoIP via ip-api.com (cached on disk) ───────────────────────────────────
#
# The subscription has at most a few dozen unique IPs; ip-api.com's free tier
# (45 req/min) handles this trivially. Cache permanently — VPS IPs don't
# wander between countries. To force refresh: delete country_cache.json.

def resolve_country(host: str, cache: dict[str, str]) -> str:
    if host in cache:
        return cache[host]
    try:
        ip = socket.gethostbyname(host) if not _is_ip(host) else host
    except OSError:
        ip = host
    if ip in cache:
        cache[host] = cache[ip]
        return cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=countryCode"
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        cc = (data.get("countryCode") or "ZZ").upper()
    except Exception as e:
        print(f"[geoip] {host} failed: {e}", file=sys.stderr)
        cc = "ZZ"
    cache[host] = cc
    cache[ip] = cc
    return cc


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_ip(s: str) -> bool:
    return bool(_IP_RE.match(s or ""))


# ── Stable tag generation ───────────────────────────────────────────────────

def stable_tag(cc: str, proto: str, host: str, port: int, transport: str,
               extra: str = "") -> str:
    """``<cc>-<proto>-<host>-<port>-<transport>[-<extra>]``. Sing-box accepts
    most ASCII in tags but we stick to ``[a-z0-9._-]`` for safety."""
    parts = [cc.lower(), proto, host.replace(":", ""), str(port), transport]
    if extra:
        parts.append(extra)
    raw = "-".join(parts)
    return re.sub(r"[^a-z0-9._-]+", "-", raw.lower()).strip("-")


# ── Per-protocol parsers (return outbound dict, country resolved later) ─────

# Xray-only transports. sing-box has no such transport (v2ray-transport.md lists
# http, ws, quic, grpc, httpupgrade). Dropping `type=` would leave a plain-TCP
# outbound that loads fine and can never connect -- measured 2026-09-14: a
# Remnawave panel's `type=xhttp` node became `vless tcp tls` in the pool.
XRAY_ONLY_TRANSPORTS = ("xhttp", "splithttp")


class SkipNode(Exception):
    """A node this converter deliberately leaves out (not a parse error)."""


def _refuse_xray_only(ttype: str, uri: str) -> None:
    if ttype in XRAY_ONLY_TRANSPORTS:
        host = urllib.parse.urlparse(uri).hostname
        raise SkipNode(f"{host}: transport '{ttype}' is Xray-only, sing-box cannot use it")


def parse_vless(uri: str) -> dict[str, Any]:
    p = urllib.parse.urlparse(uri)
    qs = dict(urllib.parse.parse_qsl(p.query))
    ttype = qs.get("type", "tcp")
    _refuse_xray_only(ttype, uri)
    flow = qs.get("flow") or ""
    extra = "vision" if "vision" in flow else ""
    o: dict[str, Any] = {
        "type": "vless",
        "_host": p.hostname, "_port": int(p.port),
        "_transport": ttype, "_extra": extra,
        "server": p.hostname,
        "server_port": int(p.port),
        "uuid": p.username,
        "flow": flow,
        "packet_encoding": "xudp",
    }
    sec = qs.get("security", "")
    if sec == "reality":
        o["tls"] = {
            "enabled": True,
            "server_name": qs.get("sni", ""),
            "utls": {"enabled": True, "fingerprint": qs.get("fp", "chrome")},
            "reality": {
                "enabled": True,
                "public_key": qs.get("pbk", ""),
                "short_id": qs.get("sid", ""),
            },
        }
    elif sec == "tls":
        o["tls"] = {
            "enabled": True,
            "server_name": qs.get("sni", p.hostname or ""),
            "utls": {"enabled": True, "fingerprint": qs.get("fp", "chrome")},
        }
    if ttype == "grpc":
        o["transport"] = {"type": "grpc", "service_name": qs.get("serviceName", "")}
    elif ttype == "ws":
        o["transport"] = {"type": "ws", "path": qs.get("path", "/"),
                          "headers": {"Host": qs.get("host", "")} if qs.get("host") else {}}
    elif ttype == "http":
        o["transport"] = {"type": "http", "path": qs.get("path", "/"),
                          "host": [qs.get("host")] if qs.get("host") else []}
    return o


def parse_vmess(uri: str) -> dict[str, Any]:
    payload = uri[len("vmess://"):]
    j = json.loads(b64decode_loose(payload))
    net = j.get("net", "tcp")
    extra = "http" if (net == "tcp" and j.get("type") == "http") else ""
    o: dict[str, Any] = {
        "type": "vmess",
        "_host": j.get("add"), "_port": int(j.get("port", 0)),
        "_transport": net, "_extra": extra,
        "server": j.get("add"),
        "server_port": int(j.get("port", 0)),
        "uuid": j.get("id"),
        "alter_id": int(j.get("aid") or 0),
        "security": j.get("scy") or "auto",
        "packet_encoding": "xudp",
    }
    if j.get("tls") == "tls":
        o["tls"] = {"enabled": True, "server_name": j.get("sni") or j.get("host") or j.get("add")}
    if net == "ws":
        o["transport"] = {"type": "ws", "path": j.get("path") or "/",
                          "headers": {"Host": j.get("host")} if j.get("host") else {}}
    elif net == "grpc":
        o["transport"] = {"type": "grpc", "service_name": j.get("path") or ""}
    elif net == "tcp" and j.get("type") == "http":
        o["transport"] = {"type": "http", "path": j.get("path") or "/",
                          "host": [j.get("host")] if j.get("host") else []}
    return o


def parse_trojan(uri: str) -> dict[str, Any]:
    p = urllib.parse.urlparse(uri)
    qs = dict(urllib.parse.parse_qsl(p.query))
    ttype = qs.get("type", "tcp")
    _refuse_xray_only(ttype, uri)
    o: dict[str, Any] = {
        "type": "trojan",
        "_host": p.hostname, "_port": int(p.port),
        "_transport": ttype, "_extra": "",
        "server": p.hostname,
        "server_port": int(p.port),
        "password": urllib.parse.unquote(p.username or ""),
        "tls": {"enabled": True,
                "server_name": qs.get("sni", p.hostname or ""),
                "utls": {"enabled": True, "fingerprint": qs.get("fp") or "chrome"}},
    }
    if ttype == "ws":
        o["transport"] = {"type": "ws", "path": qs.get("path", "/"),
                          "headers": {"Host": qs.get("host", "")} if qs.get("host") else {}}
    elif ttype == "grpc":
        o["transport"] = {"type": "grpc", "service_name": qs.get("serviceName", "")}
    return o


def parse_ss(uri: str) -> dict[str, Any]:
    p = urllib.parse.urlparse(uri)
    method = password = host = port = None
    if p.username and p.hostname and p.port:
        creds = b64decode_loose(p.username) if not p.password else f"{p.username}:{p.password}"
        if ":" in creds:
            method, password = creds.split(":", 1)
        host, port = p.hostname, int(p.port)
    else:
        body = uri[len("ss://"):].split("#", 1)[0]
        decoded = b64decode_loose(body)
        m = re.match(r"([^:]+):([^@]+)@([^:]+):(\d+)", decoded)
        if not m:
            raise ValueError(f"unparsable ss URI: {uri}")
        method, password, host, port = m.group(1), m.group(2), m.group(3), int(m.group(4))
    return {
        "type": "shadowsocks",
        "_host": host, "_port": port, "_transport": "tcp", "_extra": "",
        "server": host, "server_port": port,
        "method": method, "password": password,
    }



def parse_hysteria2(uri: str) -> dict[str, Any]:
    """hysteria2://password@host:port?sni=&obfs=&obfs-password=&insecure=#name

    Outbound shape from the official manual (proxy-protocol/hysteria2.md):
    type/server/server_port/password/tls, plus the optional obfs object
    documented in inbound/hysteria2 (`salamander` or `gecko`).
    """
    pu = urllib.parse.urlparse(uri)
    qs = dict(urllib.parse.parse_qsl(pu.query))
    host, port = pu.hostname, int(pu.port or 443)
    o: dict[str, Any] = {
        "type": "hysteria2",
        "_host": host, "_port": port, "_transport": "quic", "_extra": "",
        "server": host, "server_port": port,
        "password": urllib.parse.unquote(pu.username or qs.get("password", "")),
        "tls": {
            "enabled": True,
            "server_name": qs.get("sni") or qs.get("peer") or host or "",
            "insecure": qs.get("insecure", "0") in ("1", "true", "True"),
        },
    }
    if qs.get("alpn"):
        o["tls"]["alpn"] = qs["alpn"].split(",")
    obfs = qs.get("obfs")
    if obfs and obfs.lower() != "none":
        o["obfs"] = {"type": obfs, "password": qs.get("obfs-password", "")}
    # Bandwidth hints are optional; sing-box falls back to BBR without them.
    for k_uri, k_out in (("upmbps", "up_mbps"), ("downmbps", "down_mbps")):
        if qs.get(k_uri, "").isdigit():
            o[k_out] = int(qs[k_uri])
    return o


def parse_tuic(uri: str) -> dict[str, Any]:
    """tuic://uuid:password@host:port?sni=&congestion_control=&alpn=#name

    Fields per configuration/outbound/tuic.md.
    """
    pu = urllib.parse.urlparse(uri)
    qs = dict(urllib.parse.parse_qsl(pu.query))
    host, port = pu.hostname, int(pu.port or 443)
    o: dict[str, Any] = {
        "type": "tuic",
        "_host": host, "_port": port, "_transport": "quic", "_extra": "",
        "server": host, "server_port": port,
        "uuid": urllib.parse.unquote(pu.username or ""),
        "password": urllib.parse.unquote(pu.password or ""),
        "tls": {
            "enabled": True,
            "server_name": qs.get("sni") or host or "",
            "insecure": qs.get("allow_insecure", "0") in ("1", "true", "True"),
        },
    }
    if qs.get("alpn"):
        o["tls"]["alpn"] = qs["alpn"].split(",")
    if qs.get("congestion_control"):
        o["congestion_control"] = qs["congestion_control"]
    if qs.get("udp_relay_mode"):
        o["udp_relay_mode"] = qs["udp_relay_mode"]
    return o


PARSERS = {
    "vless": parse_vless,
    "vmess": parse_vmess,
    "trojan": parse_trojan,
    "ss": parse_ss,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "tuic": parse_tuic,
}



# ── Accept whatever the provider hands over ─────────────────────────────────
# A subscription URL can answer with any of these, and which one you get can
# even depend on the User-Agent you sent (measured 2026-09-08: one provider
# returns a base64 URI list to `SFI/1.10.0` and a JSON array of Xray configs to
# `v2rayNG/1.9.14`). Rather than demanding one shape, work out what arrived.
_PROTO_FROM_SINGBOX = {"vless", "vmess", "trojan", "shadowsocks", "hysteria2",
                       "tuic", "shadowtls", "socks", "http"}


def _norm_singbox_outbound(o: dict[str, Any]) -> dict[str, Any] | None:
    """A node already in sing-box shape (a sing-box config, or a Clash/Xray one
    we converted). Keep it, and add the private fields the pipeline needs."""
    if not isinstance(o, dict) or o.get("type") not in _PROTO_FROM_SINGBOX:
        return None
    if not o.get("server") or not o.get("server_port"):
        return None
    out = {k: v for k, v in o.items() if k != "tag"}
    out["_name"] = str(o.get("tag") or "")
    out["_host"] = o["server"]
    out["_port"] = int(o["server_port"])
    tr = (o.get("transport") or {}).get("type")
    out["_transport"] = tr or ("quic" if o["type"] in ("hysteria2", "tuic") else "tcp")
    out["_extra"] = "vision" if "vision" in str(o.get("flow") or "") else ""
    return out


def _from_xray(el: dict[str, Any]) -> dict[str, Any] | None:
    """One element of a v2rayN/Xray JSON array (Remnawave hands these out).
    The interesting part is the outbound tagged `proxy`."""
    obs = el.get("outbounds") if isinstance(el, dict) else None
    if not isinstance(obs, list):
        return None
    ob = next((o for o in obs if isinstance(o, dict) and o.get("tag") == "proxy"), None)
    if not ob:
        return None
    proto = ob.get("protocol")
    st = ob.get("streamSettings") or {}
    settings = ob.get("settings") or {}
    vnext = (settings.get("vnext") or settings.get("servers") or [{}])[0]
    host, port = vnext.get("address"), vnext.get("port")
    if not host or not port:
        return None
    net = st.get("network", "tcp")
    sec = st.get("security", "")
    tls_s = st.get("tlsSettings") or st.get("realitySettings") or {}
    user = (vnext.get("users") or [{}])[0]
    o: dict[str, Any] = {"server": host, "server_port": int(port)}
    if proto == "vless":
        o.update({"type": "vless", "uuid": user.get("id", ""),
                  "flow": user.get("flow", ""), "packet_encoding": "xudp"})
    elif proto == "vmess":
        o.update({"type": "vmess", "uuid": user.get("id", ""),
                  "security": user.get("security", "auto"),
                  "alter_id": int(user.get("alterId") or 0)})
    elif proto == "trojan":
        o.update({"type": "trojan", "password": vnext.get("password", "")})
    elif proto == "shadowsocks":
        o.update({"type": "shadowsocks", "method": vnext.get("method", ""),
                  "password": vnext.get("password", "")})
    else:
        return None
    if sec in ("tls", "reality"):
        o["tls"] = {"enabled": True,
                    "server_name": tls_s.get("serverName") or host,
                    "utls": {"enabled": True,
                             "fingerprint": tls_s.get("fingerprint") or "chrome"}}
        if sec == "reality":
            o["tls"]["reality"] = {"enabled": True,
                                   "public_key": tls_s.get("publicKey", ""),
                                   "short_id": tls_s.get("shortId", "")}
    if net == "ws":
        ws = st.get("wsSettings") or {}
        o["transport"] = {"type": "ws", "path": ws.get("path", "/"),
                          "headers": ws.get("headers") or {}}
    elif net == "grpc":
        g = st.get("grpcSettings") or {}
        o["transport"] = {"type": "grpc", "service_name": g.get("serviceName", "")}
    elif net in ("xhttp", "splithttp"):
        # sing-box has no such transport (v2ray-transport.md lists http, ws,
        # quic, grpc, httpupgrade). Skip loudly rather than emit a config that
        # sing-box will refuse to load.
        print(f"[skip] {host}:{port}: transport '{net}' is Xray-only, sing-box cannot use it",
              file=sys.stderr)
        return None
    out = _norm_singbox_outbound(o)
    if out is not None:
        out["_name"] = str(el.get("remarks") or "")
    return out


_CLASH_TYPE = {"vless": "vless", "vmess": "vmess", "trojan": "trojan",
               "ss": "shadowsocks", "hysteria2": "hysteria2", "hy2": "hysteria2",
               "tuic": "tuic"}


def _from_clash(px: dict[str, Any]) -> dict[str, Any] | None:
    """One entry of a Clash / Clash.Meta `proxies:` list."""
    _name = str(px.get("name") or px.get("remarks") or "")
    t = _CLASH_TYPE.get(str(px.get("type", "")).lower())
    host, port = px.get("server"), px.get("port")
    if not t or not host or not port:
        return None
    o: dict[str, Any] = {"type": t, "server": host, "server_port": int(port)}
    if t == "vless":
        o.update({"uuid": px.get("uuid", ""), "flow": px.get("flow", ""),
                  "packet_encoding": "xudp"})
    elif t == "vmess":
        o.update({"uuid": px.get("uuid", ""), "alter_id": int(px.get("alterId") or 0),
                  "security": px.get("cipher", "auto")})
    elif t == "trojan":
        o["password"] = px.get("password", "")
    elif t == "shadowsocks":
        o.update({"method": px.get("cipher", ""), "password": px.get("password", "")})
    elif t == "hysteria2":
        o["password"] = px.get("password", "")
        if px.get("obfs"):
            o["obfs"] = {"type": px["obfs"], "password": px.get("obfs-password", "")}
    elif t == "tuic":
        o.update({"uuid": px.get("uuid", ""), "password": px.get("password", "")})
    if px.get("tls") or t in ("hysteria2", "tuic") or px.get("reality-opts"):
        o["tls"] = {"enabled": True,
                    "server_name": px.get("servername") or px.get("sni") or host,
                    "utls": {"enabled": True,
                             "fingerprint": px.get("client-fingerprint") or "chrome"}}
        if px.get("skip-cert-verify"):
            o["tls"]["insecure"] = True
        ro = px.get("reality-opts") or {}
        if ro:
            o["tls"]["reality"] = {"enabled": True,
                                   "public_key": ro.get("public-key", ""),
                                   "short_id": ro.get("short-id", "")}
    net = str(px.get("network", "") or "")
    if net == "ws":
        w = px.get("ws-opts") or {}
        o["transport"] = {"type": "ws", "path": w.get("path", "/"),
                          "headers": w.get("headers") or {}}
    elif net == "grpc":
        g = px.get("grpc-opts") or {}
        o["transport"] = {"type": "grpc",
                          "service_name": g.get("grpc-service-name", "")}
    out = _norm_singbox_outbound(o)
    if out is not None:
        out["_name"] = _name
    return out


def _clash_proxies(text: str) -> list[dict[str, Any]]:
    """Pull the `proxies:` list out of a Clash YAML. Uses PyYAML when the box
    has it; otherwise a deliberately small reader for the two shapes real
    subscriptions use -- block mappings and inline flow mappings. Entware has no
    python3-yaml package, and pulling one in for this would be a poor trade."""
    try:
        import yaml  # type: ignore
        d = yaml.safe_load(text)
        return [x for x in (d or {}).get("proxies", []) if isinstance(x, dict)]
    except ImportError:
        pass
    except Exception:
        return []
    out, cur, in_list, base_indent = [], None, False, None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        if not in_list:
            if line.startswith("proxies:"):
                in_list, base_indent = True, indent
            continue
        if indent <= base_indent and not line.startswith("-"):
            break                                   # next top-level key
        if line.startswith("- "):
            if cur:
                out.append(cur)
            body = line[2:].strip()
            if body.startswith("{"):                # flow style, one line
                cur = _flow_map(body)
                out.append(cur)
                cur = None
                continue
            cur = {}
            line = body
        if cur is None or ":" not in line:
            continue
        k, _, v = line.partition(":")
        v = v.strip()
        if v:
            cur[k.strip()] = _scalar(v)
    if cur:
        out.append(cur)
    return [x for x in out if x]


def _scalar(v: str) -> Any:
    v = v.strip().strip('"').strip("'")
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    if v.isdigit():
        return int(v)
    return v


def _flow_map(body: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for part in body.strip("{}").split(","):
        k, _, v = part.partition(":")
        if k.strip():
            out[k.strip()] = _scalar(v)
    return out


def nodes_from_any(text: str) -> list[dict[str, Any]]:
    """Work out the shape and return normalised outbounds."""
    text = text.strip()
    if not text:
        return []
    # 1. JSON: a sing-box config, an Xray/v2rayN array, Clash-in-JSON, SIP008.
    if text[0] in "[{":
        try:
            d = json.loads(text)
        except Exception:
            d = None
        if isinstance(d, list):
            xs = [x for x in (_from_xray(e) for e in d if isinstance(e, dict)) if x]
            if xs:
                return xs
            # SIP008 lists servers directly
            xs = [x for x in (_from_clash(e) for e in d if isinstance(e, dict)) if x]
            if xs:
                return xs
        elif isinstance(d, dict):
            if isinstance(d.get("outbounds"), list):
                xs = [x for x in (_norm_singbox_outbound(o) for o in d["outbounds"]) if x]
                if xs:
                    return xs
            if isinstance(d.get("proxies"), list):
                xs = [x for x in (_from_clash(o) for o in d["proxies"]) if x]
                if xs:
                    return xs
            if isinstance(d.get("servers"), list):        # SIP008
                xs = []
                for e in d["servers"]:
                    # SIP008 spells the port `server_port`; the Clash mapper
                    # wants `port` and `cipher`.
                    e = dict(e)
                    e.setdefault("type", "ss")
                    e.setdefault("port", e.get("server_port"))
                    e["cipher"] = e.get("method", "")
                    xs.append(_from_clash(e))
                xs = [x for x in xs if x]
                if xs:
                    return xs
    # 2. Clash YAML.
    if "proxies:" in text:
        xs = [x for x in (_from_clash(px) for px in _clash_proxies(text)) if x]
        if xs:
            return xs
    # 3. base64 of any of the above (the common case), then a plain URI list.
    if "://" not in text:
        try:
            return nodes_from_any(b64decode_loose(text))
        except Exception:
            return []
    return _nodes_from_uris(text)


def _nodes_from_uris(text: str) -> list[dict[str, Any]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        scheme = line.split("://", 1)[0].lower()
        fn = PARSERS.get(scheme)
        if not fn:
            print(f"[skip] unsupported scheme: {scheme}", file=sys.stderr)
            continue
        try:
            o = fn(line)
            # The fragment is the provider's own label for the node. It is not
            # cosmetic: a second-provider merge reads it to tell an "LTE" or
            # "auto-select" entry from an ordinary one.
            o.setdefault("_name", urllib.parse.unquote(line.split("#", 1)[1])
                         if "#" in line else "")
            out.append(o)
        except SkipNode as e:
            print(f"[skip] {e}", file=sys.stderr)
        except Exception as e:
            print(f"[err] {scheme}: {e}", file=sys.stderr)
    return out


# ── Top-level subscription parser ───────────────────────────────────────────

def parse_subscription(text: str, country_cache: dict[str, str],
                       resolve_cc: bool = True) -> list[dict[str, Any]]:
    """Parse subscription body, resolve country for each server, attach
    stable tag. Returns list of outbound dicts (with ``_cc`` field added)."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for o in nodes_from_any(text):
        cc = resolve_country(o["_host"], country_cache) if resolve_cc else "xx"
        proto = {"vless": "vless", "vmess": "vmess", "trojan": "trojan",
                 "shadowsocks": "ss", "hysteria2": "hy2", "tuic": "tuic",
                 "shadowtls": "stls", "socks": "socks", "http": "http"}.get(
                     o["type"], o["type"])
        o["_cc"] = cc
        o["tag"] = stable_tag(cc, proto, o["_host"], o["_port"],
                              o["_transport"], o.get("_extra") or "")
        if o["tag"] in seen:
            # Hash a few extra bits to disambiguate truly identical entries.
            h = hashlib.sha1(json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()[:6]
            o["tag"] = f"{o['tag']}-{h}"
        seen.add(o["tag"])
        out.append(o)
    return out


# ── Per-country pool builder ────────────────────────────────────────────────

def build_country_pools(outbounds: list[dict[str, Any]]
                        ) -> dict[str, list[dict[str, Any]]]:
    pools: dict[str, list[dict[str, Any]]] = {}
    for o in outbounds:
        pools.setdefault(o["_cc"], []).append(o)
    return pools


# ── TLS handshake fragmentation (anti-DPI, plan Track A2) ───────────────────

def apply_tls_fragment(ob: dict[str, Any], mode: str = "off",
                       reality: str = "skip") -> dict[str, Any]:
    """Inject sing-box TLS handshake fragmentation into an already-cleaned
    outbound (mutates + returns it). Fragments the OUTER ClientHello sing-box
    sends to the proxy server, to defeat plaintext-SNI matching and — where the
    DPI doesn't reassemble — JA3/JA4 collection. sing-box 1.12.0+; the fields
    are direct siblings of ``enabled`` in the tls object, verified against
    https://sing-box.sagernet.org/configuration/shared/tls/ :

        mode="record" -> record_fragment  (cheaper, recommended first)
        mode="tcp"    -> fragment          (TCP-level, slower)
        mode="off"    -> no change

    ``reality="skip"`` (default) leaves Reality outbounds untouched: the
    fragment+Reality interaction is NOT documented as complementary, and an
    unusual fragmentation of a Chrome-mimicking handshake is itself an anomaly —
    harden non-Reality TLS first, test Reality per-node. ``reality="include"``
    fragments Reality too (experimental).
    """
    if mode == "off":
        return ob
    tls = ob.get("tls")
    if not isinstance(tls, dict) or not tls.get("enabled"):
        return ob  # hysteria2 (QUIC/UDP), shadowsocks, plaintext — N/A
    if tls.get("reality", {}).get("enabled") and reality != "include":
        return ob
    # `clean()` is a shallow copy, so the tls dict is still shared with the
    # caller's outbound — copy it before adding keys so build_config never
    # mutates its input (keeps repeat calls / tests deterministic).
    tls = dict(tls)
    if mode == "record":
        tls["record_fragment"] = True
    elif mode == "tcp":
        tls["fragment"] = True
    ob["tls"] = tls
    return ob


def apply_mux(ob: dict[str, Any], mode: str = "off") -> dict[str, Any]:
    """Add sing-box stream multiplexing + padding to an already-cleaned
    outbound (mutates + returns). Padding normalizes packet sizes/timing —
    the one client-side lever against ТСПУ layer-4 behavioural analysis.
    Requires the SERVER to speak sing-box multiplex (smux/yamux/h2mux); an
    Xray server rejects it, so this is a per-node experiment.

        mode="trojan"     -> only Trojan outbounds (safe test target)
        mode="nonvision"  -> Trojan + VMess + non-vision/non-grpc VLESS
        mode="off"        -> no change

    NEVER applied to xtls-rprx-vision (flow set — mux incompatible) or to gRPC
    (already HTTP/2-multiplexed). Ref:
    https://sing-box.sagernet.org/configuration/shared/multiplex/
    """
    if mode == "off":
        return ob
    transport = (ob.get("transport") or {}).get("type", "tcp")
    if ob.get("flow") or transport == "grpc":
        return ob  # vision / grpc — never mux
    typ = ob.get("type")
    eligible = typ == "trojan" if mode == "trojan" else typ in ("trojan", "vmess", "vless")
    if not eligible:
        return ob
    ob["multiplex"] = {"enabled": True, "protocol": "h2mux",
                       "max_connections": 4, "padding": True}
    return ob


# ── Config builder (per-country TUN inbounds + selectors) ───────────────────

# Single TUN address — `interface OpkgTun0` on the NDM side. Country pools
# are exposed via per-country urltest groups but all share the same inbound.
# Kernel name of the TUN, and the NDM noun that registers it. Both are
# deployment choices: a box already running an Entware tunnel needs
# opkgtun1/OpkgTun1. Overridable so the installer can record what it used.
TUN_NAME = os.environ.get("SINGBOX_TUN_NAME") or "opkgtun0"
NDM_TUN_NOUN = os.environ.get("SINGBOX_NDM_TUN_NOUN") or "OpkgTun0"
TUN_IP = os.environ.get("TUN_ADDR") or "172.19.0.1"
TUN_MTU = int(os.environ.get("TUN_MTU") or 1420)
# TUN network stack. Default gvisor: it is the only stack that works with
# auto_route=false, where NDM owns routing (system/mixed need the kernel plumbing
# auto_route installs — tested 2026-08-12, traffic silently stops forwarding).
# sing-box 1.15 replaced gvisor with its own stack, which is 3-4x faster on this
# box, and it is selected by OMITTING the key entirely — hence "none"/"off"/empty
# meaning "write no stack at all". Keep the default as gvisor so a rollback to
# 1.14.x keeps working unchanged. (env: SINGBOX_TUN_STACK)
TUN_STACK = os.environ.get("SINGBOX_TUN_STACK", "gvisor").strip()


def apply_utls_fingerprint(ob: dict[str, Any], fp: str = "keep") -> dict[str, Any]:
    """Override the client uTLS fingerprint (the JA3/JA4 the ClientHello shows)
    on every TLS outbound. Subs often carry fp=qq (QQ browser) — an anomalous
    fingerprint for a Russian egress that RKN's ML flags more readily than the
    ubiquitous Chrome. uTLS is a CLIENT-side shape; Reality auth is key-based and
    does not depend on it, so normalising to 'chrome' (or 'randomized') is safe
    and improves the DPI blend.
        fp="keep" -> leave whatever the sub set (default, no-op)
        fp=<name> -> force utls.fingerprint = <name> on all TLS outbounds
    """
    if fp == "keep":
        return ob
    tls = ob.get("tls")
    if not isinstance(tls, dict) or not tls.get("enabled"):
        return ob  # non-TLS (hysteria2 QUIC, shadowsocks, plaintext)
    utls = dict(tls.get("utls") or {})
    utls["enabled"] = True
    utls["fingerprint"] = fp
    tls = dict(tls)
    tls["utls"] = utls
    ob["tls"] = tls
    return ob


def apply_connect_timeout(ob: dict[str, Any], ct: str = "5s") -> dict[str, Any]:
    """Cap the dial time on every outbound. Without it a dial to a server whose
    SYN is silently dropped -- exactly what the RU LTE white-list does to a
    non-whitelisted /24 -- hangs in the gvisor netstack effectively forever, so
    every liveness/sweep/rotation probe to a blocked node accumulates and never
    releases. Measured 2026-09-02: under an active white-list sing-box RSS
    climbed 45 -> 203 MB over hours (PAST GOMEMLIMIT -- these are off-heap
    netstack buffers, not Go heap) and load hit 11.55, thrashing the box into a
    reboot. A 5 s cap makes every blocked dial fail fast and free its memory; a
    working node connects in well under 1 s (the white-list survivors measured
    0.05 s), so nothing legitimate is cut.
        ct="keep" -> leave the dial timeout unset (no-op)
        ct=<dur>  -> set connect_timeout=<dur> on all outbounds
    """
    if ct == "keep":
        return ob
    ob["connect_timeout"] = ct
    return ob


def build_config(outbounds: list[dict[str, Any]],
                 clash_secret: str,
                 router_ip: str = "192.168.1.1",
                 exclude_auto_protos: frozenset[str] = frozenset({"shadowsocks", "vmess"}),
                 tls_fragment: str = "off",
                 tls_fragment_reality: str = "skip",
                 mux: str = "off",
                 utls_fingerprint: str = "keep",
                 connect_timeout: str = "5s",
                 country_urltests: bool = True,
                 node_resolver: str = "77.88.8.8",
                 probe_base_port: int = 7900) -> dict[str, Any]:
    """Single-pool config:

    * One TUN inbound (`opkgtun0`).
    * Top-level selector `select` exposes:
        - `urltest-all`     (default, picks fastest across every country)
        - `urltest-<cc>`    (one per country, picks fastest within country)
        - every individual server tag (manual pin for debugging)
      User flips countries from MetaCubeXD by changing `select.now`.
    * `urltest-<cc>` groups stay informational/switchable but route doesn't
      route into them by inbound — everything goes through the single
      `select` and the user's choice decides the country.
    """
    pools = build_country_pools(outbounds)
    all_tags = [o["tag"] for o in outbounds]

    def clean(o: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in o.items() if not k.startswith("_")}

    # DPI-resilience tiering (plan Track A1): detectable legacy transports
    # (Shadowsocks, VMess) stay in `select` for manual pinning but are kept
    # OUT of every urltest auto-pick pool. They often pass the gstatic health
    # check yet get throttled/flagged for *real* traffic, so a latency-only
    # urltest would happily strand us on them.
    def auto_ok(o: dict[str, Any]) -> bool:
        return o["type"] not in exclude_auto_protos

    auto_tags = [o["tag"] for o in outbounds if auto_ok(o)]
    excluded_n = len(all_tags) - len(auto_tags)
    if not auto_tags:
        print("[tier] every server excluded from auto-pick; "
              "urltest-all falls back to the full pool", file=sys.stderr)
        auto_tags = list(all_tags)
    elif excluded_n:
        print(f"[tier] {excluded_n} outbound(s) kept out of urltest auto-pick "
              f"({', '.join(sorted(exclude_auto_protos)) or 'none'})",
              file=sys.stderr)

    urltests: list[dict[str, Any]] = []

    # Global urltest — best server across all countries (auto-pick-eligible).
    urltests.append({
        "type": "urltest", "tag": "urltest-all", "outbounds": auto_tags,
        "url": "https://www.gstatic.com/generate_204",
        "interval": "3m", "tolerance": 50,
        "interrupt_exist_connections": True,
    })

    # Per-country urltests — only for countries with >1 auto-pick-eligible
    # server. Optional (default on): the healthcheck daemon owns select.now,
    # so these are just MetaCubeXD convenience switches. `--country-urltests
    # off` drops them to cut continuous per-country probing (less gvisor
    # connection churn / lower memory) at the cost of the per-country UI button;
    # manual per-node pinning and the daemon still work.
    cc_urltest_tags: list[str] = []
    if country_urltests:
        for cc, servers in sorted(pools.items()):
            tags = [s["tag"] for s in servers if auto_ok(s)]
            if len(tags) <= 1:
                continue
            ut_tag = f"urltest-{cc.lower()}"
            urltests.append({
                "type": "urltest", "tag": ut_tag, "outbounds": tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m", "tolerance": 50,
        "interrupt_exist_connections": True,
            })
            cc_urltest_tags.append(ut_tag)

    # Top-level selector. Order in `outbounds` is the order MetaCubeXD
    # shows: keep urltest-all first (auto), per-country urltests next,
    # then individual servers grouped by country for manual pinning.
    grouped_servers: list[str] = []
    for cc, servers in sorted(pools.items()):
        grouped_servers.extend(s["tag"] for s in servers)
    select = {
        "type": "selector", "tag": "select",
        "outbounds": ["urltest-all", *cc_urltest_tags, *grouped_servers],
        "default": "urltest-all",
        "interrupt_exist_connections": True,
    }

    # ── Per-outbound probe inbounds (isolated, non-disruptive health probing) ─
    # The healthcheck daemon measures each outbound by connecting to a dedicated
    # localhost HTTP-proxy inbound (127.0.0.1:<probe_base_port+N>) whose traffic
    # a route rule pins to that ONE outbound. A full ranking sweep therefore
    # never touches `select.now` and never disrupts live user traffic —
    # replacing the old sweep that tmp-pinned the real selector onto every
    # server (dead ones included) for ~90 s every RANK_INTERVAL. The daemon
    # derives the tag→port map straight from this config (no separate file).
    probe_inbounds = []
    probe_route_rules = []
    for idx, o in enumerate(outbounds):
        itag = f"probe-{idx}"
        probe_inbounds.append({
            "type": "http", "tag": itag,
            "listen": "127.0.0.1", "listen_port": probe_base_port + idx,
        })
        probe_route_rules.append({
            "inbound": [itag], "action": "route", "outbound": o["tag"],
        })

    return {
        # Log writes to tmpfs, level=warn to silence per-connection spam
        # while keeping handshake errors / config issues visible. Keeping
        # logs on UBIFS would hammer NAND with thousands of writes/min on
        # a busy LAN. Survives a reboot's worth — sing-box recreates the
        # file on start.
        "log": {"level": "warn", "timestamp": True,
                "output": "/tmp/sing-box.log"},
        "dns": {
            "servers": [
                # `detour` is a Dial Field on the new-style UDP server (sends
                # the upstream query through `select` so DNS isn't leaked to
                # the ISP). Verified against
                # https://sing-box.sagernet.org/configuration/dns/server/udp/
                # + /configuration/shared/dial/.
                {"type": "udp", "tag": "remote", "server": "1.1.1.1", "detour": "select"},
                {"type": "udp", "tag": "local", "server": router_ip},
                # Resolver for OUTBOUND SERVER ADDRESSES only (22 of 49 nodes
                # are named, and they are mostly the second provider -- i.e.
                # exactly the ones that punch the LTE white-list). It must NOT
                # be the router: on the backup link ndnproxy has no reachable
                # upstream at all (its own servers are bound to PPPoE and their
                # /24 is not white; the DoT shims time out over lte_br0), so a
                # named node would be undialable exactly when it is needed.
                # 77.88.8.8 answers on both links -- measured 0.034 s via ppp0
                # and 0.139 s via lte_br0 with the list active. No `detour`:
                # resolving a node through the tunnel that needs that node is
                # circular. `default_domain_resolver` takes ONE server and
                # skips DNS rule matching entirely (docs: migration.md), so
                # there is no fallback to arrange -- pick the one that works
                # everywhere.
                {"type": "udp", "tag": "nodes", "server": node_resolver},
            ],
            # DNS rule schema in 1.11+: `server` moved to rule actions.
            # https://sing-box.sagernet.org/configuration/dns/rule/
            "rules": [
                {"clash_mode": "direct", "action": "route", "server": "local"},
                {"clash_mode": "global", "action": "route", "server": "remote"},
            ],
            "final": "remote",
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {
                "type": "tun", "tag": "tun-in",
                "interface_name": TUN_NAME,
                "address": [f"{TUN_IP}/30"],
                "mtu": TUN_MTU,
                "auto_route": True, "strict_route": True,
                **({"stack": TUN_STACK} if TUN_STACK not in ("", "none", "off") else {}),
            },
            {
                "type": "http", "tag": "refresh-direct",
                "listen": "127.0.0.1", "listen_port": 7899,
            },
            *probe_inbounds,
        ],
        "outbounds": [
            select,
            *urltests,
            *(apply_connect_timeout(
                apply_utls_fingerprint(
                    apply_mux(
                        apply_tls_fragment(clean(o), tls_fragment, tls_fragment_reality),
                        mux),
                    utls_fingerprint),
                connect_timeout)
              for o in outbounds),
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            # Route rule schema in 1.11+: top-level `outbound` moved to
            # rule actions; `sniff` and `hijack-dns` are non-final actions.
            # https://sing-box.sagernet.org/configuration/route/rule_action/
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "action": "route", "outbound": "direct"},
                # Per-outbound probe ports: pin inbound=probe-N → outbound=<tag>
                # so the daemon health-checks each node without moving select.now.
                {"inbound": ["refresh-direct"], "action": "route", "outbound": "direct"},
                *probe_route_rules,
            ],
            "final": "select",
            "auto_detect_interface": True,
            "default_domain_resolver": "nodes",
        },
        "experimental": {
            "cache_file": {"enabled": True, "path": "/tmp/sing-box-cache.db"},
            "clash_api": {
                "external_controller": os.environ.get("CLASH_ADDR") or f"{router_ip}:9090",
                "secret": clash_secret,
                "default_mode": "rule",
            },
        },
    }


# ── NDM registration helper (emit ndmc commands for current country set) ───

def emit_ndm_setup() -> str:
    """ndmc commands to register the single OpkgTun0 noun in NDM. Idempotent
    — re-running on an already-set-up router just renews the values."""
    lines = [
        "! Run via telnet to NDM (port 23) or `ndmc -c '<line>'`",
        f"interface {NDM_TUN_NOUN}",
        f'interface {NDM_TUN_NOUN} description "sing-box TUN"',
        f"interface {NDM_TUN_NOUN} ip address {TUN_IP} 255.255.255.255",
        f"interface {NDM_TUN_NOUN} ip global auto",
        f"interface {NDM_TUN_NOUN} ip mtu 1420",
        f"interface {NDM_TUN_NOUN} ip tcp adjust-mss pmtu",
        f"interface {NDM_TUN_NOUN} security-level public",
        f"interface {NDM_TUN_NOUN} up",
        f"ip route default {TUN_IP} {NDM_TUN_NOUN}",
        "system configuration save",
    ]
    return "\n".join(lines) + "\n"


# ── CLI entrypoint ──────────────────────────────────────────────────────────

DEFAULT_SECRET = os.environ.get("SINGBOX_HEALTHCHECK_SECRET", "")


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("url", nargs="?", help="subscription URL")
    g.add_argument("--file", help="read raw subscription body from file")
    g.add_argument("--empty-config", action="store_true",
                   help="build an empty single-pool config for independent subscription mergers")
    ap.add_argument("--check-only", action="store_true",
                    help="parse the subscription and exit 0 only if it yields at "
                         "least one usable outbound; write nothing. sub-refresh uses "
                         "this to validate a fetched body -- asking the converter is "
                         "the only check that cannot drift from what it can parse.")
    ap.add_argument("--out", default="-", help="output config path (default stdout)")
    ap.add_argument("--ndm-setup", help="also emit ndmc registration commands to this path")
    ap.add_argument("--secret", default=DEFAULT_SECRET,
                    help="Clash API bearer token (env: SINGBOX_HEALTHCHECK_SECRET)")
    ap.add_argument("--router-ip", default=os.environ.get("ROUTER_HOST", "192.168.1.1"),
                    help="Router LAN IP — baked into the local DNS server tag (env: ROUTER_HOST)")
    ap.add_argument("--exclude-auto-proto",
                    default=os.environ.get("SINGBOX_EXCLUDE_AUTO_PROTO") or "shadowsocks,vmess",
                    help="comma-separated outbound types kept OUT of urltest auto-pick "
                         "(still manually pin-able in `select`). Default drops the "
                         "detectable legacy protos. Empty string disables the filter. "
                         "Aliases: ss=shadowsocks. (env: SINGBOX_EXCLUDE_AUTO_PROTO)")
    ap.add_argument("--tls-fragment", choices=["off", "record", "tcp"],
                    default=os.environ.get("SINGBOX_TLS_FRAGMENT") or "off",
                    help="inject sing-box 1.12+ TLS handshake fragmentation into TLS "
                         "outbounds: 'record' (record_fragment, cheaper — try first) or "
                         "'tcp' (fragment). 'off' = no change. (env: SINGBOX_TLS_FRAGMENT)")
    ap.add_argument("--tls-fragment-reality", choices=["skip", "include"],
                    default=os.environ.get("SINGBOX_TLS_FRAGMENT_REALITY") or "skip",
                    help="whether --tls-fragment also touches Reality outbounds. Default "
                         "'skip' (Reality+fragment is unverified; harden non-Reality TLS "
                         "first). (env: SINGBOX_TLS_FRAGMENT_REALITY)")
    ap.add_argument("--mux", choices=["off", "trojan", "nonvision"],
                    default=os.environ.get("SINGBOX_MUX") or "off",
                    help="add sing-box multiplex+padding (anti-L4-behavioural) to eligible "
                         "outbounds: 'trojan' (safe test) or 'nonvision'. Never vision/grpc. "
                         "Needs a sing-box-compatible server. (env: SINGBOX_MUX)")
    ap.add_argument("--country-urltests", choices=["on", "off"],
                    default=os.environ.get("SINGBOX_COUNTRY_URLTESTS") or "on",
                    help="emit per-country urltest groups (urltest-<cc>). 'off' drops them to "
                         "cut continuous probing / memory; the daemon owns select.now anyway. "
                         "(env: SINGBOX_COUNTRY_URLTESTS)")
    ap.add_argument("--utls-fingerprint",
                    default=os.environ.get("SINGBOX_UTLS_FINGERPRINT") or "keep",
                    help="override the client uTLS fingerprint on every TLS outbound "
                         "(e.g. 'chrome' or 'randomized'); 'keep' leaves the sub's fp. "
                         "Normalises anomalous fp=qq nodes for a better JA3/JA4 blend. "
                         "(env: SINGBOX_UTLS_FINGERPRINT)")
    ap.add_argument("--node-resolver",
                    default=os.environ.get("SINGBOX_NODE_RESOLVER") or "77.88.8.8",
                    help="DNS server sing-box uses to resolve OUTBOUND SERVER "
                         "addresses. Must answer on the backup link too: on LTE "
                         "under the RU white-list the router's own resolver has no "
                         "reachable upstream, and 22 of 49 nodes are named -- they "
                         "would be undialable exactly when needed. Default 77.88.8.8 "
                         "(measured on both links). (env: SINGBOX_NODE_RESOLVER)")
    ap.add_argument("--connect-timeout",
                    default=os.environ.get("SINGBOX_CONNECT_TIMEOUT") or "5s",
                    help="cap the dial time on every outbound (e.g. '5s'); 'keep' leaves "
                         "it unset. Stops dials to white-list-blocked nodes from hanging "
                         "forever in the netstack and ballooning RSS (2026-09-02 OOM/thrash "
                         "root cause). (env: SINGBOX_CONNECT_TIMEOUT)")
    args = ap.parse_args()

    _PROTO_ALIAS = {"ss": "shadowsocks"}
    exclude_protos = frozenset(
        _PROTO_ALIAS.get(p, p)
        for p in (s.strip().lower() for s in args.exclude_auto_proto.split(","))
        if p
    )

    text = "" if args.empty_config else (open(args.file).read() if args.file else fetch(args.url))

    cache = _load_json(COUNTRY_CACHE_PATH, {})

    if args.check_only:
        nodes = parse_subscription(text, cache, resolve_cc=False)
        print("[check] %d usable outbound(s)" % len(nodes), file=sys.stderr)
        return 0 if nodes else 1

    obs = [] if args.empty_config else parse_subscription(text, cache)
    countries = {o["_cc"] for o in obs}
    _save_json(COUNTRY_CACHE_PATH, cache)

    print(f"[+] parsed {len(obs)} outbounds across {len(countries)} countries:",
          file=sys.stderr)
    for cc in sorted(countries):
        n = sum(1 for o in obs if o["_cc"] == cc)
        print(f"      {cc}: {n} outbounds", file=sys.stderr)

    cfg = build_config(obs, args.secret, router_ip=args.router_ip,
                       exclude_auto_protos=exclude_protos,
                       tls_fragment=args.tls_fragment,
                       tls_fragment_reality=args.tls_fragment_reality,
                       mux=args.mux,
                       utls_fingerprint=args.utls_fingerprint,
                       connect_timeout=args.connect_timeout,
                       node_resolver=args.node_resolver,
                       country_urltests=(args.country_urltests == "on"))
    js = json.dumps(cfg, ensure_ascii=False, indent=2)
    if args.out == "-":
        sys.stdout.write(js)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(js)
        print(f"[+] wrote {args.out}", file=sys.stderr)

    if args.ndm_setup:
        with open(args.ndm_setup, "w", encoding="utf-8") as f:
            f.write(emit_ndm_setup())
        print(f"[+] wrote ndmc setup script → {args.ndm_setup}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
