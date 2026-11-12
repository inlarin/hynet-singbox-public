// Convert v2ray-style base64 subscription (vless/vmess/trojan/ss URIs) into
// a sing-box single-pool config. Behavioural port of monitoring/sub_to_singbox.py;
// drops the multi-pool / OpkgTunN bookkeeping that doesn't apply outside Keenetic.
package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ── flags ────────────────────────────────────────────────────────────────────

var (
	flagURL        = flag.String("url", "", "subscription URL")
	flagFile       = flag.String("file", "", "read subscription body from file")
	flagOut        = flag.String("out", "-", "output config path (- for stdout)")
	flagCache      = flag.String("country-cache", "/tmp/country_cache.json", "country cache file path")
	flagCacheSeed  = flag.String("country-cache-seed", "/etc/hynet/country_cache.json", "fallback read-only cache shipped in image")
	flagSecret     = flag.String("clash-secret", "", "Clash API bearer token")
	flagClashAddr  = flag.String("clash-addr", "0.0.0.0:9090", "Clash API external_controller address")
	flagTunName    = flag.String("tun-name", "tun0", "TUN interface name inside container netns")
	flagTunAddr    = flag.String("tun-addr", "172.19.0.1", "TUN address (without /32)")
	flagTunMTU     = flag.Int("tun-mtu", 1420, "TUN MTU")
	flagLogPath    = flag.String("log-path", "/tmp/sing-box.log", "sing-box log path")
	flagCachePath  = flag.String("cache-db", "/tmp/sing-box-cache.db", "sing-box cache.db path")
	flagSkipGeoIP  = flag.Bool("skip-geoip", false, "skip ip-api.com lookups; fall back to ZZ for unknown hosts")
	flagExcludeCC  = flag.String("exclude-auto-cc", "RU", "comma-separated country codes excluded from urltest-all auto-pick (still selectable manually). Empty disables filter.")
	flagProbeBasePort = flag.Int("probe-base-port", 7900, "first TCP port for the per-outbound probe HTTP inbounds (sequentially allocated)")
	flagProbePortsOut = flag.String("probe-ports-out", "/tmp/probe_ports.json", "path to write tag→probe-port JSON map (used by healthcheck daemon)")
	flagTunStack      = flag.String("tun-stack", "system", "sing-box tun.stack — system (kernel, fastest, ~half the CPU of mixed), mixed (TCP=kernel,UDP=gvisor — old default), or gvisor (pure userspace, OOM-prone)")
)

// ── helpers ──────────────────────────────────────────────────────────────────

var ipRE = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
var tagSanRE = regexp.MustCompile(`[^a-z0-9._-]+`)

func b64decodeLoose(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	pad := (-len(s)) % 4
	for i := 0; i < pad; i++ {
		s += "="
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func loadJSON(path string, dst interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func saveJSON(path string, src interface{}) error {
	b, err := json.MarshalIndent(src, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(parentDir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func parentDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return "."
}

// ── subscription fetch ──────────────────────────────────────────────────────

func fetchURL(u string) (string, error) {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "ClashforAndroid/2.5.12")
	cli := &http.Client{Timeout: 30 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// ── country resolver (cached) ───────────────────────────────────────────────

type countryCache struct {
	m       map[string]string
	dirty   bool
	path    string
	skipNet bool
}

func newCountryCache(path, seed string, skipNet bool) *countryCache {
	c := &countryCache{m: map[string]string{}, path: path, skipNet: skipNet}
	if err := loadJSON(path, &c.m); err != nil {
		// If primary cache is missing, try seed (shipped with image).
		_ = loadJSON(seed, &c.m)
	}
	return c
}

func (c *countryCache) save() {
	if !c.dirty {
		return
	}
	if err := saveJSON(c.path, c.m); err != nil {
		fmt.Fprintf(os.Stderr, "[cache] save %s failed: %v\n", c.path, err)
	}
}

func (c *countryCache) lookup(host string) string {
	if cc, ok := c.m[host]; ok {
		return cc
	}
	ip := host
	if !ipRE.MatchString(host) {
		ips, err := net.LookupHost(host)
		if err == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}
	if cc, ok := c.m[ip]; ok {
		c.m[host] = cc
		c.dirty = true
		return cc
	}
	cc := "ZZ"
	if !c.skipNet {
		cc = ipAPILookup(ip)
	}
	c.m[host] = cc
	c.m[ip] = cc
	c.dirty = true
	return cc
}

func ipAPILookup(ip string) string {
	cli := &http.Client{Timeout: 10 * time.Second}
	resp, err := cli.Get("http://ip-api.com/json/" + url.PathEscape(ip) + "?fields=countryCode")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[geoip] %s: %v\n", ip, err)
		return "ZZ"
	}
	defer resp.Body.Close()
	var d struct {
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return "ZZ"
	}
	cc := strings.ToUpper(strings.TrimSpace(d.CountryCode))
	if cc == "" {
		return "ZZ"
	}
	return cc
}

// ── stable tag ──────────────────────────────────────────────────────────────

func stableTag(cc, proto, host string, port int, transport, extra string) string {
	parts := []string{strings.ToLower(cc), proto, strings.ReplaceAll(host, ":", ""), strconv.Itoa(port), transport}
	if extra != "" {
		parts = append(parts, extra)
	}
	raw := strings.ToLower(strings.Join(parts, "-"))
	raw = tagSanRE.ReplaceAllString(raw, "-")
	return strings.Trim(raw, "-")
}

func shortHash(o map[string]interface{}) string {
	b, _ := json.Marshal(o)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	if len(enc) > 6 {
		enc = enc[:6]
	}
	return strings.ToLower(enc)
}

// ── per-protocol parsers ────────────────────────────────────────────────────

type rawOutbound struct {
	body      map[string]interface{}
	host      string
	port      int
	transport string
	extra     string
	proto     string // vless / vmess / trojan / ss
}

func qsGet(q url.Values, k string, def string) string {
	if v := q.Get(k); v != "" {
		return v
	}
	return def
}

func parseVless(uri string) (*rawOutbound, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	ttype := qsGet(q, "type", "tcp")
	flow := q.Get("flow")
	extra := ""
	if strings.Contains(flow, "vision") {
		extra = "vision"
	}
	port, _ := strconv.Atoi(u.Port())
	o := map[string]interface{}{
		"type":            "vless",
		"server":          u.Hostname(),
		"server_port":     port,
		"uuid":            u.User.Username(),
		"flow":            flow,
		"packet_encoding": "xudp",
	}
	switch q.Get("security") {
	case "reality":
		o["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": q.Get("sni"),
			"utls":        map[string]interface{}{"enabled": true, "fingerprint": qsGet(q, "fp", "chrome")},
			"reality": map[string]interface{}{
				"enabled":    true,
				"public_key": q.Get("pbk"),
				"short_id":   q.Get("sid"),
			},
		}
	case "tls":
		o["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": qsGet(q, "sni", u.Hostname()),
			"utls":        map[string]interface{}{"enabled": true, "fingerprint": qsGet(q, "fp", "chrome")},
		}
	}
	switch ttype {
	case "grpc":
		o["transport"] = map[string]interface{}{"type": "grpc", "service_name": q.Get("serviceName")}
	case "ws":
		t := map[string]interface{}{"type": "ws", "path": qsGet(q, "path", "/")}
		if h := q.Get("host"); h != "" {
			t["headers"] = map[string]interface{}{"Host": h}
		}
		o["transport"] = t
	case "http":
		t := map[string]interface{}{"type": "http", "path": qsGet(q, "path", "/")}
		if h := q.Get("host"); h != "" {
			t["host"] = []string{h}
		}
		o["transport"] = t
	}
	return &rawOutbound{body: o, host: u.Hostname(), port: port, transport: ttype, extra: extra, proto: "vless"}, nil
}

func parseVmess(uri string) (*rawOutbound, error) {
	body := strings.TrimPrefix(uri, "vmess://")
	dec, err := b64decodeLoose(body)
	if err != nil {
		return nil, err
	}
	var j map[string]interface{}
	if err := json.Unmarshal(dec, &j); err != nil {
		return nil, err
	}
	getStr := func(k string) string {
		if v, ok := j[k].(string); ok {
			return v
		}
		return ""
	}
	getInt := func(k string) int {
		switch v := j[k].(type) {
		case float64:
			return int(v)
		case string:
			n, _ := strconv.Atoi(v)
			return n
		}
		return 0
	}
	net := getStr("net")
	if net == "" {
		net = "tcp"
	}
	extra := ""
	if net == "tcp" && getStr("type") == "http" {
		extra = "http"
	}
	port := getInt("port")
	host := getStr("add")
	o := map[string]interface{}{
		"type":            "vmess",
		"server":          host,
		"server_port":     port,
		"uuid":            getStr("id"),
		"alter_id":        getInt("aid"),
		"security":        firstNonEmpty(getStr("scy"), "auto"),
		"packet_encoding": "xudp",
	}
	if getStr("tls") == "tls" {
		sni := firstNonEmpty(getStr("sni"), getStr("host"), host)
		o["tls"] = map[string]interface{}{"enabled": true, "server_name": sni}
	}
	switch net {
	case "ws":
		t := map[string]interface{}{"type": "ws", "path": firstNonEmpty(getStr("path"), "/")}
		if h := getStr("host"); h != "" {
			t["headers"] = map[string]interface{}{"Host": h}
		}
		o["transport"] = t
	case "grpc":
		o["transport"] = map[string]interface{}{"type": "grpc", "service_name": getStr("path")}
	case "tcp":
		if getStr("type") == "http" {
			t := map[string]interface{}{"type": "http", "path": firstNonEmpty(getStr("path"), "/")}
			if h := getStr("host"); h != "" {
				t["host"] = []string{h}
			}
			o["transport"] = t
		}
	}
	return &rawOutbound{body: o, host: host, port: port, transport: net, extra: extra, proto: "vmess"}, nil
}

func parseTrojan(uri string) (*rawOutbound, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	ttype := qsGet(q, "type", "tcp")
	port, _ := strconv.Atoi(u.Port())
	pw, _ := url.QueryUnescape(u.User.Username())
	o := map[string]interface{}{
		"type":        "trojan",
		"server":      u.Hostname(),
		"server_port": port,
		"password":    pw,
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": qsGet(q, "sni", u.Hostname()),
			"utls":        map[string]interface{}{"enabled": true, "fingerprint": qsGet(q, "fp", "chrome")},
		},
	}
	switch ttype {
	case "ws":
		t := map[string]interface{}{"type": "ws", "path": qsGet(q, "path", "/")}
		if h := q.Get("host"); h != "" {
			t["headers"] = map[string]interface{}{"Host": h}
		}
		o["transport"] = t
	case "grpc":
		o["transport"] = map[string]interface{}{"type": "grpc", "service_name": q.Get("serviceName")}
	}
	return &rawOutbound{body: o, host: u.Hostname(), port: port, transport: ttype, proto: "trojan"}, nil
}

var ssLegacyRE = regexp.MustCompile(`^([^:]+):([^@]+)@([^:]+):(\d+)`)

func parseSS(uri string) (*rawOutbound, error) {
	u, err := url.Parse(uri)
	if err == nil && u.User != nil && u.Host != "" && u.Port() != "" {
		var method, password string
		if pw, has := u.User.Password(); has {
			method = u.User.Username()
			password = pw
		} else {
			creds, err := b64decodeLoose(u.User.Username())
			if err != nil {
				return nil, err
			}
			parts := strings.SplitN(string(creds), ":", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("ss creds malformed")
			}
			method, password = parts[0], parts[1]
		}
		port, _ := strconv.Atoi(u.Port())
		return &rawOutbound{
			body: map[string]interface{}{
				"type": "shadowsocks", "server": u.Hostname(), "server_port": port,
				"method": method, "password": password,
			},
			host: u.Hostname(), port: port, transport: "tcp", proto: "ss",
		}, nil
	}
	body := strings.TrimPrefix(uri, "ss://")
	body = strings.SplitN(body, "#", 2)[0]
	dec, err := b64decodeLoose(body)
	if err != nil {
		return nil, err
	}
	m := ssLegacyRE.FindStringSubmatch(string(dec))
	if m == nil {
		return nil, fmt.Errorf("unparsable ss URI")
	}
	port, _ := strconv.Atoi(m[4])
	return &rawOutbound{
		body: map[string]interface{}{
			"type": "shadowsocks", "server": m[3], "server_port": port,
			"method": m[1], "password": m[2],
		},
		host: m[3], port: port, transport: "tcp", proto: "ss",
	}, nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// ── subscription parser ─────────────────────────────────────────────────────

type taggedOutbound struct {
	body map[string]interface{}
	cc   string
	tag  string
}

func parseSubscription(text string, cache *countryCache) []*taggedOutbound {
	if dec, err := b64decodeLoose(text); err == nil && len(dec) > 0 && strings.Contains(string(dec), "://") {
		text = string(dec)
	}
	var out []*taggedOutbound
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "://") {
			continue
		}
		scheme := strings.ToLower(strings.SplitN(line, "://", 2)[0])
		var ro *rawOutbound
		var err error
		switch scheme {
		case "vless":
			ro, err = parseVless(line)
		case "vmess":
			ro, err = parseVmess(line)
		case "trojan":
			ro, err = parseTrojan(line)
		case "ss":
			ro, err = parseSS(line)
		default:
			fmt.Fprintf(os.Stderr, "[skip] unsupported scheme: %s\n", scheme)
			continue
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[err] %s: %v\n", scheme, err)
			continue
		}
		cc := cache.lookup(ro.host)
		tag := stableTag(cc, ro.proto, ro.host, ro.port, ro.transport, ro.extra)
		if seen[tag] {
			tag = tag + "-" + shortHash(ro.body)
		}
		seen[tag] = true
		ro.body["tag"] = tag
		out = append(out, &taggedOutbound{body: ro.body, cc: cc, tag: tag})
	}
	return out
}

// ── config builder ──────────────────────────────────────────────────────────

func buildConfig(obs []*taggedOutbound) map[string]interface{} {
	pools := map[string][]*taggedOutbound{}
	for _, o := range obs {
		pools[o.cc] = append(pools[o.cc], o)
	}

	excluded := map[string]bool{}
	for _, cc := range strings.Split(*flagExcludeCC, ",") {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if cc != "" {
			excluded[cc] = true
		}
	}
	autoTags := []string{}
	for _, o := range obs {
		if excluded[strings.ToUpper(o.cc)] {
			continue
		}
		autoTags = append(autoTags, o.tag)
	}
	if len(autoTags) == 0 {
		fmt.Fprintf(os.Stderr, "[warn] every server matched exclude-auto-cc=%q; urltest-all falls back to full pool\n", *flagExcludeCC)
		for _, o := range obs {
			autoTags = append(autoTags, o.tag)
		}
	} else {
		excludedCount := len(obs) - len(autoTags)
		if excludedCount > 0 {
			fmt.Fprintf(os.Stderr, "[+] urltest-all excludes %d outbound(s) matching cc=%q\n", excludedCount, *flagExcludeCC)
		}
	}

	// Per-outbound probe inbounds — daemon connects to 127.0.0.1:<port> as an
	// HTTP proxy and the route.rule for inbound=probe-N pins the request to
	// outbound o.tag, so we can measure each outbound without touching
	// select.now and disrupting user traffic.
	probeInbounds := []map[string]interface{}{}
	probeRouteRules := []map[string]interface{}{}
	probeInboundTags := []string{}
	portMap := map[string]int{}
	probeIdx := 0
	for _, o := range obs {
		if excluded[strings.ToUpper(o.cc)] {
			continue
		}
		port := *flagProbeBasePort + probeIdx
		inboundTag := fmt.Sprintf("probe-%d", probeIdx)
		probeInbounds = append(probeInbounds, map[string]interface{}{
			"type":        "http",
			"tag":         inboundTag,
			"listen":      "127.0.0.1",
			"listen_port": port,
		})
		probeRouteRules = append(probeRouteRules, map[string]interface{}{
			"inbound":  inboundTag,
			"outbound": o.tag,
		})
		probeInboundTags = append(probeInboundTags, inboundTag)
		portMap[o.tag] = port
		probeIdx++
	}
	if probeIdx > 0 {
		fmt.Fprintf(os.Stderr, "[+] probe inbounds: %d ports starting at %d (one per non-excluded outbound)\n",
			probeIdx, *flagProbeBasePort)
	}
	if *flagProbePortsOut != "" {
		if err := saveJSON(*flagProbePortsOut, portMap); err != nil {
			fmt.Fprintf(os.Stderr, "[warn] write probe ports map %s: %v\n", *flagProbePortsOut, err)
		}
	}

	urltests := []map[string]interface{}{
		{
			"type": "urltest", "tag": "urltest-all", "outbounds": autoTags,
			"url":      "https://www.gstatic.com/generate_204",
			"interval": "3m", "tolerance": 50,
		},
	}

	ccs := []string{}
	for cc := range pools {
		ccs = append(ccs, cc)
	}
	sort.Strings(ccs)
	ccUrlTests := []string{}
	for _, cc := range ccs {
		if len(pools[cc]) <= 1 {
			continue
		}
		tags := []string{}
		for _, s := range pools[cc] {
			tags = append(tags, s.tag)
		}
		ut := "urltest-" + strings.ToLower(cc)
		urltests = append(urltests, map[string]interface{}{
			"type": "urltest", "tag": ut, "outbounds": tags,
			"url":      "https://www.gstatic.com/generate_204",
			"interval": "3m", "tolerance": 50,
		})
		ccUrlTests = append(ccUrlTests, ut)
	}

	grouped := []string{}
	for _, cc := range ccs {
		for _, s := range pools[cc] {
			grouped = append(grouped, s.tag)
		}
	}
	selectOutbounds := append([]string{"urltest-all"}, ccUrlTests...)
	selectOutbounds = append(selectOutbounds, grouped...)
	selector := map[string]interface{}{
		"type": "selector", "tag": "select",
		"outbounds": selectOutbounds, "default": "urltest-all",
	}

	outbounds := []map[string]interface{}{selector}
	for _, ut := range urltests {
		outbounds = append(outbounds, ut)
	}
	for _, o := range obs {
		outbounds = append(outbounds, o.body)
	}
	outbounds = append(outbounds, map[string]interface{}{"type": "direct", "tag": "direct"})

	allInbounds := []map[string]interface{}{
		{
			"type": "tun", "tag": "tun-in",
			"interface_name": *flagTunName,
			// /30 instead of /32: sing-box's system+mixed stacks require
			// the TUN prefix to contain at least one *other* address
			// besides the local one (it uses peer addresses for kernel
			// socket binding). /32 errors out with "need one more IPv4
			// address in first prefix for system stack". /30 is the
			// minimum that passes (4 addresses: net, .1, .2, broadcast).
			"address":        []string{*flagTunAddr + "/30"},
			"mtu":            *flagTunMTU,
			// auto_route=true installs an ip rule inside the container netns
			// that redirects ALL outbound traffic into this TUN — required so
			// that packets coming in from RouterOS via veth-hynet (after the
			// LAN mangle mark routes them to the container) are actually
			// captured by sing-box instead of bouncing right back out the
			// veth via the netns default route. With auto_route=false the
			// container would proxy nothing — packets just U-turn at the
			// kernel, hit the host's mangle again as br-hynet egress, and
			// land on WAN unproxied (the failure mode we hit in production).
			//
			// strict_route stays false: container netns is already isolated,
			// we don't want sing-box's iptables MASQUERADE/conntrack-ip-rules
			// fighting with our healthcheck probe-port routing.
			"auto_route":     true, "strict_route": false,
			// stack=system: pure kernel TCP/IP stack inside the container
			// netns, no userspace per-connection buffers. On L009 (2-core
			// 800 MHz armv7) this drops total CPU from ~97% busy to ~71%
			// busy (sirq 43% → 25%) under the same LAN load — about
			// half what `mixed` and `gvisor` cost. RB4011 / RB5009 with
			// 4-core CPUs see less dramatic but still real savings.
			//
			// Pure `gvisor` was eating the router alive — RB4011/1GB RAM
			// ran out and rebooted under real LAN load, because gvisor
			// allocates per-connection user-space buffers that stack up
			// fast once auto_route catches everything.
			//
			// `mixed` (TCP=kernel, UDP=gvisor) was the previous default,
			// kept as escape hatch for hosts where system-stack UDP misbehaves
			// inside a netns. Override with -tun-stack=mixed if needed.
			"stack": *flagTunStack,
		},
	}
	allInbounds = append(allInbounds, probeInbounds...)

	allRouteRules := []map[string]interface{}{
		{"action": "sniff"},
		{"protocol": "dns", "action": "hijack-dns"},
		{"ip_is_private": true, "outbound": "direct"},
	}
	allRouteRules = append(allRouteRules, probeRouteRules...)

	// 'local' DNS server resolves via container's /etc/resolv.conf (independent
	// of select.now). Required for probe traffic so a dead select.now doesn't
	// prevent the daemon from even resolving the upstream URL. Also used as
	// route.default_domain_resolver (sing-box 1.12+ requirement).
	dnsServers := []map[string]interface{}{
		{"type": "udp", "tag": "remote", "server": "1.1.1.1", "detour": "select"},
		{"type": "local", "tag": "local"},
	}
	dnsRules := []map[string]interface{}{}
	if len(probeInboundTags) > 0 {
		dnsRules = append(dnsRules, map[string]interface{}{
			"inbound": probeInboundTags,
			"server":  "local",
		})
	}

	return map[string]interface{}{
		"log": map[string]interface{}{"level": "warn", "timestamp": true, "output": *flagLogPath},
		"dns": map[string]interface{}{
			"servers":  dnsServers,
			"rules":    dnsRules,
			"final":    "remote",
			"strategy": "ipv4_only",
		},
		"inbounds":  allInbounds,
		"outbounds": outbounds,
		"route": map[string]interface{}{
			"rules": allRouteRules,
			"final": "select",
			// auto_detect_interface=true is REQUIRED whenever the TUN
			// inbound has auto_route=true. Without it (or default_interface,
			// or bind_interface on every outbound) sing-box's own outbound
			// connections to the remote proxy server get caught by the
			// auto_route ip rule, looped back into the TUN, and processed
			// again — infinite loop, per-packet state allocation grows
			// without bound, container OOMs and takes the router with it.
			// On the live RB4011 this loop ate 1GB of RAM in ~30 seconds
			// of real LAN traffic and rebooted the box. With detection on,
			// sing-box auto-picks veth-hynet (the only non-TUN interface
			// in the container netns) and outbounds escape cleanly to
			// the host, where they reach WAN via main routing.
			"auto_detect_interface":   true,
			"default_domain_resolver": "local",
		},
		"experimental": map[string]interface{}{
			"cache_file": map[string]interface{}{"enabled": true, "path": *flagCachePath},
			"clash_api": map[string]interface{}{
				"external_controller": *flagClashAddr,
				"secret":              *flagSecret,
				"default_mode":        "rule",
			},
		},
	}
}

// ── main ────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()
	if (*flagURL == "" && *flagFile == "") || (*flagURL != "" && *flagFile != "") {
		fmt.Fprintln(os.Stderr, "usage: sub2singbox -url <URL> | -file <path> [-out config.json]")
		os.Exit(2)
	}

	var text string
	if *flagFile != "" {
		b, err := os.ReadFile(*flagFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read file:", err)
			os.Exit(1)
		}
		text = string(b)
	} else {
		t, err := fetchURL(*flagURL)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fetch:", err)
			os.Exit(1)
		}
		text = t
	}

	cache := newCountryCache(*flagCache, *flagCacheSeed, *flagSkipGeoIP)
	obs := parseSubscription(text, cache)
	cache.save()

	countries := map[string]int{}
	for _, o := range obs {
		countries[o.cc]++
	}
	fmt.Fprintf(os.Stderr, "[+] parsed %d outbounds across %d countries\n", len(obs), len(countries))
	ccs := []string{}
	for cc := range countries {
		ccs = append(ccs, cc)
	}
	sort.Strings(ccs)
	for _, cc := range ccs {
		fmt.Fprintf(os.Stderr, "      %s: %d\n", cc, countries[cc])
	}

	if len(obs) == 0 {
		fmt.Fprintln(os.Stderr, "no outbounds parsed; aborting")
		os.Exit(1)
	}

	cfg := buildConfig(obs)
	js, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal:", err)
		os.Exit(1)
	}
	if *flagOut == "-" {
		os.Stdout.Write(js)
		os.Stdout.Write([]byte("\n"))
	} else {
		if err := os.MkdirAll(parentDir(*flagOut), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "mkdir:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*flagOut, js, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[+] wrote %s\n", *flagOut)
	}
}
