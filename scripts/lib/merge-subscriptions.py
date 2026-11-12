#!/opt/bin/python3
"""Merge EXTRA subscriptions into the generated config.

The main subscription is what sub_to_singbox.py turns into the pool. This adds
any number of others on top -- a second provider bought for one specific job (on
this box: punching the operator's LTE white-list), a friend's server, a spare.
Adding one is a file, never a code change.

It was a single-provider injector with hardcoded VLESS+Reality handling.
Everything it learned the hard way is kept; only the "one provider" part is
gone.

Configure one file per provider in /opt/etc/sing-box/subscriptions.d/*.conf
(KEY=VALUE, 0600 -- they contain subscription URLs):

    URL=https://...            required
    HWID=<uuid>                optional; Remnawave panels gate on x-hwid and
                               return a single dummy 0.0.0.0 node without it
    UA=sing-box                optional; some panels return a DIFFERENT FORMAT
                               per User-Agent -- measured on one provider:
                               base64 URI list to SFI, an Xray JSON array to
                               v2rayNG. Any of them parses; pick what the
                               provider serves most completely (`--probe`
                               tries them all and says which).
    MAX=24                     optional cap on merged nodes
    PREFIX=<tag prefix>        optional; defaults to the file name. Letters and
                               digits only, starting with a letter, 3-16 long:
                               a dash would shift the tag's fields, and a
                               two-letter name is indistinguishable from the
                               main pool's country code.
    MARK=auto                  optional; the tag's SECOND '-' field, which the
                               health daemon reads as the protocol. `auto` (the
                               default) writes the node's real protocol, so ss
                               and vmess from any provider are last-resort
                               exactly like the main pool's. A fixed word
                               (e.g. `wl`) marks the whole provider at once:
                               put it in AUTO_EXCLUDE_PROTO and these nodes are
                               picked only when the main pool is dead.
    WHITE_FIRST=yes            optional; prefer servers on /24s known to punch
                               the LTE white-list, exempt from MAX

Tags are `<prefix>-<mark>-<server>`, probe inbounds `probe-<prefix>-<n>`.

A box that predates subscriptions.d can keep its single-provider file: point
SINGBOX_LEGACY_PROVIDER at it (in .env) and it is read as one more provider,
with the prefix from SINGBOX_LEGACY_PREFIX (MARK=wl, WHITE_FIRST=yes, as the
old injector did). Unset by default, so a fresh install has no hidden second
source. Read from the environment OR straight from .env: the callers source
.env without exporting, and a legacy provider that silently vanished after an
update is exactly the failure that would go unnoticed for days.

Each provider is independent:
    merge-subscriptions.py CFG                 refetch every provider
    merge-subscriptions.py CFG --only a,b      refetch a and b; every other
                                               provider keeps the nodes it has
                                               in the RUNNING config
    merge-subscriptions.py CFG --only none     refetch nothing, carry all
    merge-subscriptions.py CFG --drop c        also strip provider c's nodes
                                               (its .conf is already gone)
    merge-subscriptions.py --list              configured providers, one per
                                               line: prefix, file, host, nodes
    merge-subscriptions.py --probe URL [--hwid H]
                                               try the User-Agents on a URL
                                               and print the best as JSON

A provider whose fetch fails keeps its nodes from the running config (last
known good) instead of disappearing: on a white-listed backup link they may be
the only reachable exits, and one provider's outage must not strip them nor
hold back another provider's update.

Exit: 0 all fine (or nothing configured); 2 at least one provider failed and
its running nodes were carried over; 1 crashed, nothing written -- sub-refresh
then refuses to replace a config that still carries extra nodes.
"""
import argparse
import glob
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys

ACTIVE_CFG = os.environ.get("SINGBOX_ACTIVE_CONFIG") or "/opt/etc/sing-box/config.json"
SUBS_DIR = os.environ.get("SINGBOX_SUBS_DIR") or "/opt/etc/sing-box/subscriptions.d"
ENV_FILE = os.environ.get("SINGBOX_ENV_FILE") or "/opt/etc/sing-box/.env"
WHITE_PREFIXES = "/opt/etc/singbox-lte/lte-white-prefixes"
CONVERTER = os.environ.get("SINGBOX_CONVERTER") or "/opt/share/sing-box/sub_to_singbox.py"

_UTLS_FP = os.environ.get("SINGBOX_UTLS_FINGERPRINT") or "keep"
_CONNECT_TIMEOUT = os.environ.get("SINGBOX_CONNECT_TIMEOUT") or "5s"

# The same short labels the main pool's tags carry, so AUTO_EXCLUDE_PROTO means
# one thing across every provider.
PROTO_LABEL = {"vless": "vless", "vmess": "vmess", "trojan": "trojan",
               "shadowsocks": "ss", "hysteria2": "hy2", "tuic": "tuic",
               "shadowtls": "stls", "socks": "socks", "http": "http"}

# Tags and group names the generator owns; a provider called this would strip
# or shadow them.
RESERVED = {"probe", "select", "urltest", "direct", "main", "none", "all"}

# Offered by --probe, in order. Panels key the response FORMAT and sometimes the
# node SET on this, so the only reliable way to learn what a URL serves is to ask
# as each client in turn.
PROBE_UAS = ("sing-box", "v2rayNG/1.9.14", "ClashforAndroid/2.5.12", "SFI/1.10.0")


def _parser():
    """Reuse the main converter's format sniffing rather than keeping a second,
    weaker parser here. The old code accepted VLESS+Reality URIs and nothing
    else, so a provider serving Clash YAML or an Xray array looked empty."""
    spec = importlib.util.spec_from_file_location("_conv", CONVERTER)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def load_kv(path):
    d = {}
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return d


def env_knob(name, default=""):
    return os.environ.get(name) or load_kv(ENV_FILE).get(name) or default


def clean_prefix(p):
    return re.sub(r"[^a-z0-9]", "", (p or "").lower())[:16]


def prefix_problem(p):
    """None if PREFIX is usable as a tag prefix, else why not."""
    if not re.match(r"^[a-z][a-z0-9]{2,15}$", p or ""):
        return ("must be 3-16 letters/digits starting with a letter (a two-letter "
                "name would look like the main pool's country code)")
    if p in RESERVED:
        return "is reserved (%s)" % ", ".join(sorted(RESERVED))
    return None


def load_providers(quiet=False):
    out, seen = [], set()

    def add(d, path):
        p = clean_prefix(d.get("PREFIX"))
        why = prefix_problem(p)
        if why:
            if not quiet:
                print("[merge] %s: prefix '%s' %s -- skipped"
                      % (os.path.basename(path), p, why), file=sys.stderr)
            return
        if p in seen:
            if not quiet:
                print("[merge] %s: prefix '%s' already used by another provider -- skipped"
                      % (os.path.basename(path), p), file=sys.stderr)
            return
        seen.add(p)
        d["PREFIX"] = p
        d["_file"] = path
        out.append(d)

    for path in sorted(glob.glob(os.path.join(SUBS_DIR, "*.conf"))):
        d = load_kv(path)
        if not d.get("URL"):
            if not quiet:
                print("[merge] %s has no URL -- skipped" % os.path.basename(path),
                      file=sys.stderr)
            continue
        d.setdefault("PREFIX", os.path.basename(path)[:-5])
        add(d, path)
    # A pre-subscriptions.d box points SINGBOX_LEGACY_PROVIDER at its old
    # single-provider file and keeps working with no migration. Empty by
    # default: a fresh install must not read a second source it never
    # configured, and the file name would say which provider it was.
    legacy = env_knob("SINGBOX_LEGACY_PROVIDER")
    if legacy and os.path.exists(legacy):
        d = load_kv(legacy)
        if d.get("URL"):
            d.setdefault("PREFIX", env_knob("SINGBOX_LEGACY_PREFIX", "leg"))
            d.setdefault("MARK", "wl")
            d.setdefault("WHITE_FIRST", "yes")
            add(d, legacy)
    return out


def load_white_nets():
    """/24s observed to survive the RU LTE white-list, as "a.b.c" strings.

    Appended to by the daemon when a failover finds a carrier under an active
    white-list (record_carrier). Missing file -> empty set, which restores plain
    breadth-first curation."""
    nets = set()
    try:
        for line in open(WHITE_PREFIXES, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#"):
                nets.add(line.rsplit("/", 1)[0].rsplit(".", 1)[0])
    except Exception:
        pass
    return nets


def fetch(url, hwid, ua, timeout=25):
    # curl, not python-urllib: Entware's python3 is built without ssl, so it
    # cannot open https URLs. curl is present (sub-refresh fetches with it).
    cmd = ["curl", "-fsS", "-m", str(timeout), "-A", ua]
    proxy = os.environ.get("SINGBOX_REFRESH_PROXY", "")
    if proxy:
        cmd += ["-x", proxy]
    if hwid:
        cmd += ["-H", "x-hwid: " + hwid]
    r = subprocess.run(cmd + [url], capture_output=True, text=True, timeout=timeout + 5)
    if r.returncode != 0:
        raise RuntimeError("curl rc=%d: %s" % (r.returncode, r.stderr.strip()[:200]))
    return (r.stdout or "").strip()


def sanitize(s):
    return re.sub(r"[^A-Za-z0-9]+", "-", s or "").strip("-").lower()


def server_label(host):
    # A hostname's first label identifies it; an IP's first OCTET does not --
    # two servers on the same /24 both reduced to their first octet, collided,
    # and got an order-dependent "-1" suffix, so the tag set changed on every
    # refresh even when the pool did not.
    if re.match(r"^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$", host or ""):
        return host.replace(".", "-")
    return sanitize((host or "").split(".")[0])


def mask_url(url):
    return re.sub(r"^(https?://[^/]+/).*$", r"\1***", url or "")


def priority(name):
    """Providers encode intent in the node's label. Nodes meant for a filtered
    link come first, then their auto-select entries, then ordinary exits."""
    low = (name or "").lower()
    if "lte" in low or "обход" in low:
        return 0
    if "auto" in low or "автовыбор" in low:
        return 1
    return 2


def real(o):
    # The panel answers with a placeholder node ("App not supported",
    # 0.0.0.0:1 / 127.0.0.1) whenever it dislikes the UA or HWID, and it also
    # slips one into an otherwise valid list. It is dead by construction, but it
    # takes a slot, a probe-port and a line in every report.
    h = o.get("server") or ""
    return bool(h) and not h.startswith("127.") and not h.startswith("0.")


def is_ours(tag, prefixes):
    return any(str(tag).startswith(p + "-") for p in prefixes)


def is_our_probe(tag, prefixes):
    # `probe-<prefix>-<n>` now; `probe-<prefix><n>` in configs written before the
    # separator existed -- a running config of that age must still be stripped.
    return any(re.match(r"^probe-%s-?[0-9]+$" % re.escape(p), str(tag)) for p in prefixes)


def add_node(c, ob, prefix, k, port):
    pit = "probe-%s-%d" % (prefix, k)
    c["outbounds"].append(ob)
    # A probe-port per node, so the health daemon RANKS them exactly as it
    # ranks the main pool -- and so a failover can measure which of them
    # actually carries traffic on the link it finds itself on.
    c["inbounds"].append({"type": "http", "tag": pit,
                          "listen": "127.0.0.1", "listen_port": port})
    c["route"]["rules"].append({"inbound": [pit], "action": "route", "outbound": ob["tag"]})


def carry_over(c, prefix, active_obs, used, next_port):
    """Re-add PREFIX's nodes exactly as the running config has them. Tags are
    kept (the ranking, parks and select.now all refer to them); probe-ports are
    renumbered, which the daemon re-reads from the config anyway."""
    tags = []
    for o in active_obs:
        t = str(o.get("tag") or "")
        if not t.startswith(prefix + "-") or not o.get("server") or t in used:
            continue
        used.add(t)
        add_node(c, dict(o), prefix, len(tags), next_port + len(tags))
        tags.append(t)
    return tags, next_port + len(tags)


def merge_one(c, prov, used, next_port, conv):
    prefix = prov["PREFIX"]
    mark = clean_prefix(prov.get("MARK") or "auto") or "auto"
    try:
        max_n = int(prov.get("MAX") or 0)
    except ValueError:
        max_n = 0
    if max_n <= 0:
        max_n = 1000000
    ua = prov.get("UA") or "sing-box"

    urls = [prov["URL"]]
    if "hynet-connect.com" in prov["URL"]:
        urls.append(prov["URL"].replace("hynet-connect.com", "hynet.cloud"))
    elif "hynet.cloud" in prov["URL"]:
        urls.append(prov["URL"].replace("hynet.cloud", "hynet-connect.com"))
    error = None
    for url in urls:
        try:
            body = fetch(url, prov.get("HWID", "").strip(), ua)
            break
        except Exception as e:
            error = e
    else:
        raise error
    nodes = conv.parse_subscription(body, {}, resolve_cc=False)

    cand = [o for o in nodes if real(o)]
    if not cand:
        raise RuntimeError("no usable nodes (HWID/UA gate, or an unknown format)")

    # Sticky, deterministic order. Keyed on the SERVER, never the SNI: measured
    # 2026-09-08, two fetches five seconds apart returned a different subset of
    # 24 servers AND a different SNI front for 13 of them. With the SNI in the
    # sort key that randomness decided which servers won the MAX cap, so every
    # refresh produced a genuinely different pool and a genuinely justified
    # restart -- six or seven a day, each killing every established connection.
    # The sticky flag then keeps the SNI the running config already uses,
    # whenever the provider still offers it.
    active_sni = {}
    try:
        for o in json.load(open(ACTIVE_CFG, encoding="utf-8")).get("outbounds", []):
            if str(o.get("tag", "")).startswith(prefix + "-") and o.get("server"):
                active_sni[o["server"]] = (o.get("tls") or {}).get("server_name", "") or ""
    except Exception:
        pass

    def quality(o):
        # The one-provider version accepted ONLY reality over tcp/grpc/ws and
        # dropped everything else. Widening that is right -- a provider may
        # serve trojan or hysteria2 and there is no reason to refuse it -- but
        # the preference was sound: an encrypted, camouflaged transport should
        # fill the cap before a plaintext one. So rank rather than reject.
        tls = o.get("tls") or {}
        if (tls.get("reality") or {}).get("enabled"):
            return 0
        if tls.get("enabled"):
            return 1
        return 2

    def order(o):
        sni = (o.get("tls") or {}).get("server_name", "") or ""
        return (priority(o.get("_name")), quality(o), o["server"],
                o.get("server_port") or 0,
                0 if active_sni.get(o["server"]) == sni else 1, sni,
                o.get("_name") or "")

    cand.sort(key=order)

    picked = cand[:max_n]
    seen = {o["server"] for o in picked}

    tags = []
    for k, o in enumerate(picked):
        ob = {kk: vv for kk, vv in o.items() if not kk.startswith("_")}
        # `<prefix>-<mark>-<server>`: the SECOND field is what the daemon reads
        # as the protocol. The tag names the SERVER, not the SNI variant -- a tag
        # built from a rotating SNI renames a node that has not moved, and the
        # ranking fills with ghosts.
        m = PROTO_LABEL.get(o.get("type"), clean_prefix(o.get("type")) or "x") \
            if mark == "auto" else mark
        t = ("%s-%s-%s" % (prefix, m, server_label(o["server"])))[:48]
        base_t, i = t, 1
        while t in used:
            t = "%s-%d" % (base_t, i)
            i += 1
        used.add(t)
        ob["tag"] = t
        if _UTLS_FP != "keep" and isinstance(ob.get("tls"), dict) and ob["tls"].get("utls"):
            ob["tls"]["utls"]["fingerprint"] = _UTLS_FP
        if _CONNECT_TIMEOUT != "keep":
            ob["connect_timeout"] = _CONNECT_TIMEOUT
        add_node(c, ob, prefix, k, next_port + k)
        tags.append(t)
    return tags, len(seen), next_port + len(picked)


def split_names(s):
    return [x for x in (clean_prefix(v) for v in (s or "").split(",")) if x]


def cmd_list():
    try:
        active = json.load(open(ACTIVE_CFG, encoding="utf-8")).get("outbounds", [])
    except Exception:
        active = []
    for p in load_providers(quiet=True):
        n = sum(1 for o in active
                if str(o.get("tag") or "").startswith(p["PREFIX"] + "-") and o.get("server"))
        print("%s\t%s\t%s\t%d" % (p["PREFIX"], p["_file"], mask_url(p["URL"]), n))
    return 0


def cmd_probe(url, hwid, only_ua):
    """Find the User-Agent (and whether an HWID is needed) under which URL
    serves the most usable nodes. Asks without the HWID first: sending one
    spends a device slot on the panel, so it is only tried when nothing else
    worked."""
    conv = _parser()
    uas = [only_ua] if only_ua else list(PROBE_UAS)
    tried, best = [], None

    def attempt(ua, hw):
        nonlocal best
        try:
            nodes = [o for o in conv.parse_subscription(
                fetch(url, hw, ua, timeout=15), {}, resolve_cc=False) if real(o)]
        except Exception as e:
            tried.append({"ua": ua, "hwid": bool(hw), "error": str(e)[:120]})
            # rc 6/7/28: resolve/connect/timeout -- the host is unreachable,
            # and asking again under another name will not change that.
            return not re.search(r"curl rc=(6|7|28):", str(e))
        protos = {}
        for o in nodes:
            lab = PROTO_LABEL.get(o.get("type"), o.get("type"))
            protos[lab] = protos.get(lab, 0) + 1
        r = {"ua": ua, "hwid": bool(hw), "nodes": len(nodes),
             "servers": len({o["server"] for o in nodes}), "protos": protos}
        tried.append(r)
        if nodes and (best is None or r["servers"] > best["servers"]):
            best = r
        return True

    for ua in uas:
        if not attempt(ua, ""):
            break
    if best is None and hwid:
        for ua in uas:
            if not attempt(ua, hwid):
                break
    print(json.dumps({"ok": best is not None, "best": best, "tried": tried},
                     ensure_ascii=False))
    return 0 if best else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="merge extra subscriptions into a sing-box config")
    ap.add_argument("cfg", nargs="?", default="/opt/etc/sing-box/config.json")
    ap.add_argument("--only", help="comma list of providers to refetch; 'none' = carry every one")
    ap.add_argument("--drop", help="comma list of prefixes to strip (their .conf was removed)")
    ap.add_argument("--list", action="store_true", help="print the configured providers and exit")
    ap.add_argument("--probe", metavar="URL", help="find the UA/HWID a URL needs and exit")
    ap.add_argument("--hwid", default="", help="with --probe: HWID to try if nothing works without")
    ap.add_argument("--ua", default="", help="with --probe: try only this User-Agent")
    a = ap.parse_args(argv)

    if a.list:
        return cmd_list()
    if a.probe:
        return cmd_probe(a.probe, a.hwid.strip(), a.ua.strip())

    provs = load_providers()
    drop = set(split_names(a.drop))
    only = None
    if a.only is not None:
        only = set() if a.only.strip().lower() == "none" else set(split_names(a.only))
        for name in sorted(only - {p["PREFIX"] for p in provs}):
            print("[merge:%s] --only names a provider that is not configured" % name,
                  file=sys.stderr)
    if not provs and not drop:
        return 0                      # nothing configured -> no-op

    c = json.load(open(a.cfg, encoding="utf-8"))
    prefixes = [p["PREFIX"] for p in provs] + sorted(drop)
    try:
        active_obs = json.load(open(ACTIVE_CFG, encoding="utf-8")).get("outbounds", [])
    except Exception:
        active_obs = []

    # Idempotent: strip every provider's outbounds, probe inbounds and route
    # rules, plus their `select` members, so a re-run rebuilds cleanly. The base
    # may be a fresh converter output (no extras) or a copy of the running config
    # (every extra present) -- both end up the same.
    c["outbounds"] = [o for o in c["outbounds"] if not is_ours(o.get("tag", ""), prefixes)]
    c["inbounds"] = [i for i in c.get("inbounds", [])
                     if not is_our_probe(i.get("tag", ""), prefixes)]
    c.setdefault("route", {}).setdefault("rules", [])

    def stale(r):
        ib = r.get("inbound")
        ib = (ib[0] if ib else None) if isinstance(ib, list) else ib
        return is_ours(r.get("outbound", ""), prefixes) or is_our_probe(ib or "", prefixes)

    c["route"]["rules"] = [r for r in c["route"]["rules"] if not stale(r)]

    port = max([i["listen_port"] for i in c["inbounds"]
                if str(i.get("tag", "")).startswith("probe-") and i.get("listen_port")]
               + [7899]) + 1
    used = {str(o.get("tag") or "") for o in c["outbounds"]}

    conv = None
    all_tags, failed, done = [], [], 0
    for prov in provs:
        name = prov["PREFIX"]
        if only is not None and name not in only:
            tags, port = carry_over(c, name, active_obs, used, port)
            all_tags += tags
            print("[merge:%s] not refetched -- kept %d node(s) from the running config"
                  % (name, len(tags)), file=sys.stderr)
            continue
        try:
            conv = conv or _parser()
            tags, servers, port = merge_one(c, prov, used, port, conv)
        except Exception as e:
            failed.append(name)
            tags, port = carry_over(c, name, active_obs, used, port)
            all_tags += tags
            print("[merge:%s] failed: %s -- kept %d node(s) from the running config"
                  % (name, e, len(tags)), file=sys.stderr)
            continue
        done += 1
        all_tags += tags
        print("[merge:%s] %d node(s) from %d server(s)" % (name, len(tags), servers),
              file=sys.stderr)
    for name in sorted(drop):
        print("[merge:%s] dropped" % name, file=sys.stderr)

    for o in c["outbounds"]:
        if o.get("tag") == "select" and o.get("type") == "selector":
            o["outbounds"] = [x for x in o.get("outbounds", [])
                              if not is_ours(x, prefixes)] + all_tags
            break

    # `urltest-all` is the fallback exit: `select` defaults to it, so it carries
    # the traffic after a restart until the daemon pins a node, and whenever the
    # daemon is down. It used to hold the main pool only -- on 2026-09-23 that
    # was 3-6 live nodes out of 25, while the extra providers' fast nodes sat in
    # `select` alone. Every provider's nodes go in, filtered by the SAME knob
    # the generator applies to the main pool (SINGBOX_EXCLUDE_AUTO_PROTO,
    # default shadowsocks,vmess: detectable transports stay manual-only), so a
    # protocol is either auto-pickable everywhere or nowhere. Stripped and
    # re-added on every run like `select`, so a dropped provider leaves no
    # dangling member.
    conv = conv or _parser()
    cache_path = os.environ.get("SINGBOX_COUNTRY_CACHE") or "/tmp/country_cache.json"
    try:
        country_cache = json.load(open(cache_path, encoding="utf-8"))
    except Exception:
        country_cache = {}
    countries = {}
    for o in c["outbounds"]:
        if o.get("server") and o.get("tag"):
            countries[o["tag"]] = conv.resolve_country(o["server"], country_cache).upper()
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(country_cache, f, ensure_ascii=False, indent=2, sort_keys=True)
    countries_out = os.environ.get("SINGBOX_COUNTRIES_OUT") or "/tmp/probe_countries.json"
    with open(countries_out, "w", encoding="utf-8") as f:
        json.dump(countries, f, ensure_ascii=False, indent=2, sort_keys=True)

    excluded_cc = {s.strip().upper() for s in env_knob("EXCLUDE_AUTO_CC", "RU").split(",") if s.strip()}
    alias = {"ss": "shadowsocks"}
    excl = {alias.get(p, p) for p in (s.strip().lower() for s in
            env_knob("SINGBOX_EXCLUDE_AUTO_PROTO", "shadowsocks,vmess").split(",")) if p}
    types = {o.get("tag"): o.get("type") for o in c["outbounds"]}
    auto_extra = [t for t in all_tags if types.get(t) not in excl
                  and countries.get(t, "") not in excluded_cc]
    for o in c["outbounds"]:
        if o.get("tag") == "urltest-all" and o.get("type") == "urltest":
            o["outbounds"] = [x for x in o.get("outbounds", [])
                              if not is_ours(x, prefixes)] + auto_extra
            print("[merge] urltest-all: %d node(s) from the extra providers (%d kept out as %s)"
                  % (len(auto_extra), len(all_tags) - len(auto_extra),
                     ",".join(sorted(excl)) or "nothing"), file=sys.stderr)
            break

    # indent=2 is REQUIRED, not cosmetic: the healthcheck daemon and sub-refresh
    # extract "secret"/"external_controller" with line-based awk/grep, so the
    # config MUST keep one key per line. A compact dump silently breaks their
    # Clash-API access.
    with open(a.cfg, "w", encoding="utf-8") as f:
        json.dump(c, f, ensure_ascii=False, indent=2)
    shown = ", ".join(all_tags[:4]) + ("..." if len(all_tags) > 4 else "")
    print("[merge] %d node(s) from %d provider(s) into select (%d refetched, %d failed): %s"
          % (len(all_tags), len(provs), done, len(failed), shown))
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
