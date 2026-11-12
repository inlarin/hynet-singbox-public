package main

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type subscriptionProvider struct {
	Prefix string
	URL    string
	HWID   string
	UA     string
	Mark   string
	Max    int
	File   string
}

type renderResult struct {
	Tags        []string
	NextPort    int
	ServerCount int
}

func shortSHA1(data []byte) string {
	sum := sha1.Sum(data)
	return fmt.Sprintf("%x", sum)[:6]
}

func cleanPrefix(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if len(result) > 16 {
		result = result[:16]
	}
	return result
}

func sanitizeLabel(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func serverLabel(host string) string {
	if ip := netParseIPv4(host); ip != "" {
		return strings.ReplaceAll(ip, ".", "-")
	}
	return sanitizeLabel(strings.Split(host, ".")[0])
}

func netParseIPv4(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return ""
	}
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return ""
		}
	}
	return host
}

func loadKeyValues(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			value = strings.TrimSpace(value)
			value = strings.Trim(value, "\"'")
			out[strings.TrimSpace(key)] = value
		}
	}
	return out
}

func validProviderPrefix(prefix string) error {
	if len(prefix) < 3 || len(prefix) > 16 || prefix[0] < 'a' || prefix[0] > 'z' {
		return fmt.Errorf("must be 3-16 letters/digits starting with a letter")
	}
	for _, r := range prefix {
		if r < 'a' || r > 'z' {
			if r < '0' || r > '9' {
				return fmt.Errorf("must contain only letters and digits")
			}
		}
	}
	switch prefix {
	case "probe", "select", "urltest", "direct", "main", "none", "all":
		return fmt.Errorf("is reserved")
	}
	return nil
}

func loadProviders(directory string) []subscriptionProvider {
	paths, _ := filepath.Glob(filepath.Join(directory, "*.conf"))
	sort.Strings(paths)
	var providers []subscriptionProvider
	seen := map[string]bool{}
	for _, path := range paths {
		values := loadKeyValues(path)
		if values["URL"] == "" {
			fmt.Fprintf(os.Stderr, "[merge] %s has no URL -- skipped\n", filepath.Base(path))
			continue
		}
		prefix := cleanPrefix(values["PREFIX"])
		if prefix == "" {
			prefix = cleanPrefix(strings.TrimSuffix(filepath.Base(path), ".conf"))
		}
		if err := validProviderPrefix(prefix); err != nil || seen[prefix] {
			fmt.Fprintf(os.Stderr, "[merge] %s: invalid or duplicate prefix %q -- skipped\n", filepath.Base(path), prefix)
			continue
		}
		seen[prefix] = true
		maxNodes, _ := strconv.Atoi(values["MAX"])
		if maxNodes <= 0 {
			maxNodes = 1000000
		}
		ua := values["UA"]
		if ua == "" {
			ua = "sing-box"
		}
		mark := cleanPrefix(values["MARK"])
		if mark == "" {
			mark = "auto"
		}
		providers = append(providers, subscriptionProvider{
			Prefix: prefix, URL: values["URL"], HWID: strings.TrimSpace(values["HWID"]),
			UA: ua, Mark: mark, Max: maxNodes, File: path,
		})
	}
	return providers
}

func fetchSubscription(ctx context.Context, rawURL, hwid, ua string) (string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if proxy := os.Getenv("SINGBOX_REFRESH_PROXY"); proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return "", err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", ua)
	if hwid != "" {
		req.Header.Set("x-hwid", hwid)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func fetchProvider(ctx context.Context, provider subscriptionProvider) (string, error) {
	urls := []string{provider.URL}
	if strings.Contains(provider.URL, "hynet-connect.com") {
		urls = append(urls, strings.ReplaceAll(provider.URL, "hynet-connect.com", "hynet.cloud"))
	} else if strings.Contains(provider.URL, "hynet.cloud") {
		urls = append(urls, strings.ReplaceAll(provider.URL, "hynet.cloud", "hynet-connect.com"))
	}
	var lastErr error
	for _, rawURL := range urls {
		body, err := fetchSubscription(ctx, rawURL, provider.HWID, provider.UA)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func realNode(node jsonObject) bool {
	host := textValue(node["server"])
	return host != "" && !strings.HasPrefix(host, "127.") && !strings.HasPrefix(host, "0.")
}

func nodePriority(node jsonObject) int {
	name := strings.ToLower(textValue(node["_name"]))
	if strings.Contains(name, "lte") || strings.Contains(name, "обход") {
		return 0
	}
	if strings.Contains(name, "auto") || strings.Contains(name, "автовыбор") {
		return 1
	}
	return 2
}

func nodeQuality(node jsonObject) int {
	tls := objectValue(node["tls"])
	if boolValue(objectValue(tls["reality"])["enabled"]) {
		return 0
	}
	if boolValue(tls["enabled"]) {
		return 1
	}
	return 2
}

func nodeSNI(node jsonObject) string {
	return textValue(objectValue(node["tls"])["server_name"])
}

func activeOutbounds(path string) []jsonObject {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var config jsonObject
	if json.Unmarshal(data, &config) != nil {
		return nil
	}
	var out []jsonObject
	for _, item := range arrayValue(config["outbounds"]) {
		out = append(out, objectValue(item))
	}
	return out
}

func cleanNode(node jsonObject) jsonObject {
	out := jsonObject{}
	for key, value := range node {
		if !strings.HasPrefix(key, "_") {
			out[key] = value
		}
	}
	return out
}

func appendProbeNode(config jsonObject, node jsonObject, providerTag string, index, port int) {
	probeTag := fmt.Sprintf("probe-%s-%d", providerTag, index)
	config["outbounds"] = append(arrayValue(config["outbounds"]), node)
	config["inbounds"] = append(arrayValue(config["inbounds"]), jsonObject{
		"type": "http", "tag": probeTag, "listen": "127.0.0.1", "listen_port": port,
	})
	route := objectValue(config["route"])
	route["rules"] = append(arrayValue(route["rules"]), jsonObject{
		"inbound": []any{probeTag}, "action": "route", "outbound": node["tag"],
	})
}

func mergeProvider(ctx context.Context, config jsonObject, provider subscriptionProvider, active []jsonObject, used map[string]bool, nextPort int) (renderResult, error) {
	body, err := fetchProvider(ctx, provider)
	if err != nil {
		return renderResult{}, err
	}
	nodes := parseSubscription(body, map[string]string{}, false)
	var candidates []jsonObject
	for _, node := range nodes {
		if realNode(node) {
			candidates = append(candidates, node)
		}
	}
	if len(candidates) == 0 {
		return renderResult{}, fmt.Errorf("no usable nodes (HWID/UA gate, or an unknown format)")
	}
	activeSNI := map[string]string{}
	for _, node := range active {
		if strings.HasPrefix(textValue(node["tag"]), provider.Prefix+"-") && textValue(node["server"]) != "" {
			activeSNI[textValue(node["server"])] = nodeSNI(node)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if nodePriority(a) != nodePriority(b) {
			return nodePriority(a) < nodePriority(b)
		}
		if nodeQuality(a) != nodeQuality(b) {
			return nodeQuality(a) < nodeQuality(b)
		}
		if textValue(a["server"]) != textValue(b["server"]) {
			return textValue(a["server"]) < textValue(b["server"])
		}
		if intValue(a["server_port"]) != intValue(b["server_port"]) {
			return intValue(a["server_port"]) < intValue(b["server_port"])
		}
		aSticky := activeSNI[textValue(a["server"])] == nodeSNI(a)
		bSticky := activeSNI[textValue(b["server"])] == nodeSNI(b)
		if aSticky != bSticky {
			return aSticky
		}
		if nodeSNI(a) != nodeSNI(b) {
			return nodeSNI(a) < nodeSNI(b)
		}
		return textValue(a["_name"]) < textValue(b["_name"])
	})
	if len(candidates) > provider.Max {
		candidates = candidates[:provider.Max]
	}
	servers := map[string]bool{}
	result := renderResult{NextPort: nextPort}
	utlsFingerprint := envOr("SINGBOX_UTLS_FINGERPRINT", "keep")
	connectTimeout := envOr("SINGBOX_CONNECT_TIMEOUT", "5s")
	for index, candidate := range candidates {
		servers[textValue(candidate["server"])] = true
		node := cleanNode(candidate)
		mark := provider.Mark
		if mark == "auto" {
			mark = protocolLabels[textValue(candidate["type"])]
			if mark == "" {
				mark = cleanPrefix(textValue(candidate["type"]))
			}
		}
		tag := fmt.Sprintf("%s-%s-%s", provider.Prefix, mark, serverLabel(textValue(candidate["server"])))
		if len(tag) > 48 {
			tag = tag[:48]
		}
		baseTag := tag
		for suffix := 1; used[tag]; suffix++ {
			tag = fmt.Sprintf("%s-%d", baseTag, suffix)
		}
		used[tag] = true
		node["tag"] = tag
		if utlsFingerprint != "keep" {
			tls := objectValue(node["tls"])
			if utls, ok := tls["utls"].(map[string]any); ok {
				utls["fingerprint"] = utlsFingerprint
			}
		}
		if connectTimeout != "keep" {
			node["connect_timeout"] = connectTimeout
		}
		appendProbeNode(config, node, provider.Prefix, index, result.NextPort)
		result.NextPort++
		result.Tags = append(result.Tags, tag)
	}
	result.ServerCount = len(servers)
	return result, nil
}

func carryProvider(config jsonObject, provider subscriptionProvider, active []jsonObject, used map[string]bool, nextPort int) renderResult {
	result := renderResult{NextPort: nextPort}
	for _, node := range active {
		tag := textValue(node["tag"])
		if !strings.HasPrefix(tag, provider.Prefix+"-") || textValue(node["server"]) == "" || used[tag] {
			continue
		}
		used[tag] = true
		copyNode := jsonObject{}
		for key, value := range node {
			copyNode[key] = value
		}
		appendProbeNode(config, copyNode, provider.Prefix, len(result.Tags), result.NextPort)
		result.NextPort++
		result.Tags = append(result.Tags, tag)
	}
	return result
}

func splitProviderNames(value string) map[string]bool {
	out := map[string]bool{}
	for _, item := range strings.Split(value, ",") {
		if name := cleanPrefix(item); name != "" {
			out[name] = true
		}
	}
	return out
}

func excludedProtocolSet() map[string]bool {
	out := map[string]bool{}
	for _, item := range strings.Split(envOr("SINGBOX_EXCLUDE_AUTO_PROTO", "shadowsocks,vmess"), ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "ss" {
			item = "shadowsocks"
		}
		if item != "" {
			out[item] = true
		}
	}
	return out
}

func excludedCountrySet() map[string]bool {
	out := map[string]bool{}
	for _, item := range strings.Split(envOr("EXCLUDE_AUTO_CC", "RU"), ",") {
		if item = strings.ToUpper(strings.TrimSpace(item)); item != "" {
			out[item] = true
		}
	}
	return out
}

func buildEmptyConfig(secret, routerIP string) jsonObject {
	tunName := envOr("SINGBOX_TUN_NAME", "opkgtun0")
	tunAddress := envOr("TUN_ADDR", "172.19.0.1") + "/30"
	tunMTU := envInt("TUN_MTU", 1420)
	tun := jsonObject{
		"type": "tun", "tag": "tun-in", "interface_name": tunName,
		"address": []any{tunAddress}, "mtu": tunMTU,
		"auto_route": true, "strict_route": true,
	}
	if stack := strings.TrimSpace(os.Getenv("SINGBOX_TUN_STACK")); stack != "" && stack != "none" && stack != "off" {
		tun["stack"] = stack
	} else if _, present := os.LookupEnv("SINGBOX_TUN_STACK"); !present {
		tun["stack"] = "gvisor"
	}
	clashAddress := os.Getenv("CLASH_ADDR")
	if clashAddress == "" {
		clashAddress = routerIP + ":9090"
	}
	return jsonObject{
		"log": jsonObject{"level": "warn", "timestamp": true, "output": "/tmp/sing-box.log"},
		"dns": jsonObject{
			"servers": []any{
				jsonObject{"type": "udp", "tag": "remote", "server": "1.1.1.1", "detour": "select"},
				jsonObject{"type": "udp", "tag": "local", "server": routerIP},
				jsonObject{"type": "udp", "tag": "nodes", "server": envOr("SINGBOX_NODE_RESOLVER", "77.88.8.8")},
			},
			"rules": []any{
				jsonObject{"clash_mode": "direct", "action": "route", "server": "local"},
				jsonObject{"clash_mode": "global", "action": "route", "server": "remote"},
			},
			"final": "remote", "strategy": "ipv4_only",
		},
		"inbounds": []any{
			tun,
			jsonObject{"type": "http", "tag": "refresh-direct", "listen": "127.0.0.1", "listen_port": 7899},
		},
		"outbounds": []any{
			jsonObject{
				"type": "selector", "tag": "select", "outbounds": []any{"urltest-all"},
				"default": "urltest-all", "interrupt_exist_connections": true,
			},
			jsonObject{
				"type": "urltest", "tag": "urltest-all", "outbounds": []any{},
				"url": "https://www.gstatic.com/generate_204", "interval": "3m", "tolerance": 50,
				"interrupt_exist_connections": true,
			},
			jsonObject{"type": "direct", "tag": "direct"},
		},
		"route": jsonObject{
			"rules": []any{
				jsonObject{"action": "sniff"},
				jsonObject{"protocol": "dns", "action": "hijack-dns"},
				jsonObject{"ip_is_private": true, "action": "route", "outbound": "direct"},
				jsonObject{"inbound": []any{"refresh-direct"}, "action": "route", "outbound": "direct"},
			},
			"final": "select", "auto_detect_interface": true, "default_domain_resolver": "nodes",
		},
		"experimental": jsonObject{
			"cache_file": jsonObject{"enabled": true, "path": "/tmp/sing-box-cache.db"},
			"clash_api": jsonObject{
				"external_controller": clashAddress, "secret": secret, "default_mode": "rule",
			},
		},
	}
}

func readCountryCache(path string) map[string]string {
	cache := map[string]string{}
	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &cache)
	}
	return cache
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func updateSelector(config jsonObject, tags []string, countries map[string]string) {
	for _, item := range arrayValue(config["outbounds"]) {
		outbound := objectValue(item)
		switch textValue(outbound["tag"]) {
		case "select":
			members := []any{"urltest-all"}
			for _, tag := range tags {
				members = append(members, tag)
			}
			outbound["outbounds"] = members
		case "urltest-all":
			excludedProtocols := excludedProtocolSet()
			excludedCountries := excludedCountrySet()
			members := []any{}
			for _, tag := range tags {
				if !excludedProtocols[textValue(outboundType(config, tag))] && !excludedCountries[countries[tag]] {
					members = append(members, tag)
				}
			}
			outbound["outbounds"] = members
		}
	}
}

func outboundType(config jsonObject, tag string) string {
	for _, item := range arrayValue(config["outbounds"]) {
		outbound := objectValue(item)
		if textValue(outbound["tag"]) == tag {
			return textValue(outbound["type"])
		}
	}
	return ""
}

func probePortMap(config jsonObject) map[string]int {
	ports := map[string]int{}
	inbounds := map[string]int{}
	for _, item := range arrayValue(config["inbounds"]) {
		inbound := objectValue(item)
		inbounds[textValue(inbound["tag"])] = intValue(inbound["listen_port"])
	}
	for _, item := range arrayValue(objectValue(config["route"])["rules"]) {
		rule := objectValue(item)
		inbound := arrayValue(rule["inbound"])
		if len(inbound) == 0 {
			continue
		}
		tag := textValue(inbound[0])
		if strings.HasPrefix(tag, "probe-") && textValue(rule["outbound"]) != "" {
			ports[textValue(rule["outbound"])] = inbounds[tag]
		}
	}
	return ports
}

func runRender(args []string) int {
	flags := flag.NewFlagSet("render", flag.ContinueOnError)
	subscriptionsDir := flags.String("subscriptions-dir", envOr("SINGBOX_SUBS_DIR", "/tmp/sing-box/subscriptions.d"), "directory containing provider .conf files")
	activeConfig := flags.String("active-config", envOr("SINGBOX_ACTIVE_CONFIG", "/tmp/config.json"), "running config used for keep-last-known-good")
	output := flags.String("out", "", "write generated sing-box config here")
	countryCachePath := flags.String("country-cache", envOr("SINGBOX_COUNTRY_CACHE", "/tmp/country_cache.json"), "persistent country cache")
	countriesOut := flags.String("countries-out", envOr("SINGBOX_COUNTRIES_OUT", "/tmp/probe_countries.json"), "write tag-to-country map")
	probePortsOut := flags.String("probe-ports-out", envOr("PROBE_PORTS", "/tmp/probe_ports.json"), "write tag-to-probe-port map")
	secret := flags.String("secret", envOr("CLASH_SECRET", os.Getenv("SINGBOX_HEALTHCHECK_SECRET")), "Clash API secret")
	routerIP := flags.String("router-ip", envOr("ROUTER_HOST", "192.168.1.1"), "router DNS address")
	onlyValue := flags.String("only", "", "comma-separated providers to refresh; 'none' carries all")
	dropValue := flags.String("drop", "", "comma-separated providers to drop")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *output == "" {
		fmt.Fprintln(os.Stderr, "render: --out is required")
		return 2
	}
	providers := loadProviders(*subscriptionsDir)
	if len(providers) == 0 {
		fmt.Fprintln(os.Stderr, "render: no valid subscriptions configured")
		return 1
	}
	only := splitProviderNames(*onlyValue)
	drop := splitProviderNames(*dropValue)
	active := activeOutbounds(*activeConfig)
	config := buildEmptyConfig(*secret, *routerIP)
	used := map[string]bool{"select": true, "urltest-all": true, "direct": true}
	nextPort := 7900
	var allTags []string
	var failed []string
	refreshed := 0
	for _, provider := range providers {
		if drop[provider.Prefix] {
			continue
		}
		var result renderResult
		var err error
		if *onlyValue != "" && !only[provider.Prefix] {
			result = carryProvider(config, provider, active, used, nextPort)
			fmt.Fprintf(os.Stderr, "[merge:%s] not refetched -- kept %d node(s)\n", provider.Prefix, len(result.Tags))
		} else {
			result, err = mergeProvider(context.Background(), config, provider, active, used, nextPort)
			if err != nil {
				failed = append(failed, provider.Prefix)
				result = carryProvider(config, provider, active, used, nextPort)
				fmt.Fprintf(os.Stderr, "[merge:%s] failed: %v -- kept %d node(s)\n", provider.Prefix, err, len(result.Tags))
			} else {
				refreshed++
				fmt.Fprintf(os.Stderr, "[merge:%s] %d node(s) from %d server(s)\n", provider.Prefix, len(result.Tags), result.ServerCount)
			}
		}
		nextPort = result.NextPort
		allTags = append(allTags, result.Tags...)
	}
	if len(allTags) == 0 {
		fmt.Fprintln(os.Stderr, "render: no usable outbounds from any subscription")
		return 1
	}
	countryCache := readCountryCache(*countryCachePath)
	countries := map[string]string{}
	for _, tag := range allTags {
		for _, item := range arrayValue(config["outbounds"]) {
			outbound := objectValue(item)
			if textValue(outbound["tag"]) == tag && textValue(outbound["server"]) != "" {
				countries[tag] = strings.ToUpper(resolveCountry(textValue(outbound["server"]), countryCache))
				break
			}
		}
	}
	updateSelector(config, allTags, countries)
	if err := writeJSONAtomic(*countryCachePath, countryCache, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "render:", err)
		return 1
	}
	if err := writeJSONAtomic(*countriesOut, countries, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "render:", err)
		return 1
	}
	if err := writeJSONAtomic(*probePortsOut, probePortMap(config), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "render:", err)
		return 1
	}
	if err := writeJSONAtomic(*output, config, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "render:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "[merge] %d node(s) from %d provider(s) into select (%d refetched, %d failed)\n",
		len(allTags), len(providers), refreshed, len(failed))
	if len(failed) > 0 {
		return 2
	}
	return 0
}
