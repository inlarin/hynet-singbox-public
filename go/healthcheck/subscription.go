package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type jsonObject map[string]any

func textValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func intValue(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	default:
		return 0
	}
}

func boolValue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		b, _ := strconv.ParseBool(x)
		return b
	default:
		return false
	}
}

func objectValue(v any) jsonObject {
	switch m := v.(type) {
	case jsonObject:
		return m
	case map[string]any:
		return m
	default:
		return jsonObject{}
	}
}

func arrayValue(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	return nil
}

func firstObject(v any) jsonObject {
	for _, item := range arrayValue(v) {
		if m, ok := item.(map[string]any); ok {
			return m
		}
	}
	return jsonObject{}
}

func decodeLoose(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\r", "", "\n", "", "\t", "", " ", "").Replace(s)
	s += strings.Repeat("=", (4-len(s)%4)%4)
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(s)
	}
	return string(b), err
}

func privateNode(o jsonObject, host string, port int, transport, extra string) jsonObject {
	o["_host"] = host
	o["_port"] = port
	o["_transport"] = transport
	o["_extra"] = extra
	return o
}

func uriPort(u *url.URL, fallback int) (int, error) {
	if u.Port() == "" {
		if fallback > 0 {
			return fallback, nil
		}
		return 0, fmt.Errorf("missing port")
	}
	return strconv.Atoi(u.Port())
}

func queryValues(u *url.URL) jsonObject {
	out := jsonObject{}
	for k, values := range u.Query() {
		if len(values) > 0 {
			out[k] = values[0]
		}
	}
	return out
}

func queryOr(q jsonObject, key, fallback string) string {
	if v := textValue(q[key]); v != "" {
		return v
	}
	return fallback
}

func refuseXrayOnly(transport string) error {
	if transport == "xhttp" || transport == "splithttp" {
		return fmt.Errorf("transport %q is Xray-only, sing-box cannot use it", transport)
	}
	return nil
}

func parseVLESS(raw string) (jsonObject, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := queryValues(u)
	transport := queryOr(q, "type", "tcp")
	if err := refuseXrayOnly(transport); err != nil {
		return nil, err
	}
	port, err := uriPort(u, 0)
	if err != nil {
		return nil, err
	}
	flow := textValue(q["flow"])
	extra := ""
	if strings.Contains(flow, "vision") {
		extra = "vision"
	}
	o := jsonObject{
		"type": "vless", "server": u.Hostname(), "server_port": port,
		"uuid": u.User.Username(), "flow": flow, "packet_encoding": "xudp",
	}
	switch q["security"] {
	case "reality":
		o["tls"] = jsonObject{
			"enabled": true, "server_name": q["sni"],
			"utls":    jsonObject{"enabled": true, "fingerprint": queryOr(q, "fp", "chrome")},
			"reality": jsonObject{"enabled": true, "public_key": q["pbk"], "short_id": q["sid"]},
		}
	case "tls":
		o["tls"] = jsonObject{
			"enabled": true, "server_name": queryOr(q, "sni", u.Hostname()),
			"utls": jsonObject{"enabled": true, "fingerprint": queryOr(q, "fp", "chrome")},
		}
	}
	switch transport {
	case "grpc":
		o["transport"] = jsonObject{"type": "grpc", "service_name": q["serviceName"]}
	case "ws":
		headers := jsonObject{}
		if textValue(q["host"]) != "" {
			headers["Host"] = q["host"]
		}
		o["transport"] = jsonObject{"type": "ws", "path": queryOr(q, "path", "/"), "headers": headers}
	case "http":
		hosts := []any{}
		if textValue(q["host"]) != "" {
			hosts = append(hosts, q["host"])
		}
		o["transport"] = jsonObject{"type": "http", "path": queryOr(q, "path", "/"), "host": hosts}
	}
	return privateNode(o, u.Hostname(), port, transport, extra), nil
}

func parseVMess(raw string) (jsonObject, error) {
	decoded, err := decodeLoose(strings.TrimPrefix(raw, "vmess://"))
	if err != nil {
		return nil, err
	}
	var j jsonObject
	if err := json.Unmarshal([]byte(decoded), &j); err != nil {
		return nil, err
	}
	host := textValue(j["add"])
	port := intValue(j["port"])
	transport := queryOr(j, "net", "tcp")
	extra := ""
	if transport == "tcp" && textValue(j["type"]) == "http" {
		extra = "http"
	}
	o := jsonObject{
		"type": "vmess", "server": host, "server_port": port,
		"uuid": j["id"], "alter_id": intValue(j["aid"]),
		"security": queryOr(j, "scy", "auto"), "packet_encoding": "xudp",
	}
	if textValue(j["tls"]) == "tls" {
		serverName := textValue(j["sni"])
		if serverName == "" {
			serverName = textValue(j["host"])
		}
		if serverName == "" {
			serverName = host
		}
		o["tls"] = jsonObject{"enabled": true, "server_name": serverName}
	}
	switch transport {
	case "ws":
		headers := jsonObject{}
		if textValue(j["host"]) != "" {
			headers["Host"] = j["host"]
		}
		o["transport"] = jsonObject{"type": "ws", "path": queryOr(j, "path", "/"), "headers": headers}
	case "grpc":
		o["transport"] = jsonObject{"type": "grpc", "service_name": queryOr(j, "path", "")}
	case "tcp":
		if textValue(j["type"]) == "http" {
			hosts := []any{}
			if textValue(j["host"]) != "" {
				hosts = append(hosts, j["host"])
			}
			o["transport"] = jsonObject{"type": "http", "path": queryOr(j, "path", "/"), "host": hosts}
		}
	}
	return privateNode(o, host, port, transport, extra), nil
}

func parseTrojan(raw string) (jsonObject, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := queryValues(u)
	transport := queryOr(q, "type", "tcp")
	if err := refuseXrayOnly(transport); err != nil {
		return nil, err
	}
	port, err := uriPort(u, 0)
	if err != nil {
		return nil, err
	}
	o := jsonObject{
		"type": "trojan", "server": u.Hostname(), "server_port": port,
		"password": u.User.Username(),
		"tls": jsonObject{
			"enabled": true, "server_name": queryOr(q, "sni", u.Hostname()),
			"utls": jsonObject{"enabled": true, "fingerprint": queryOr(q, "fp", "chrome")},
		},
	}
	switch transport {
	case "ws":
		headers := jsonObject{}
		if textValue(q["host"]) != "" {
			headers["Host"] = q["host"]
		}
		o["transport"] = jsonObject{"type": "ws", "path": queryOr(q, "path", "/"), "headers": headers}
	case "grpc":
		o["transport"] = jsonObject{"type": "grpc", "service_name": q["serviceName"]}
	}
	return privateNode(o, u.Hostname(), port, transport, ""), nil
}

func parseSS(raw string) (jsonObject, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	var method, password, host string
	var port int
	if u.User != nil && u.Hostname() != "" && u.Port() != "" {
		username := u.User.Username()
		if passwordPart, ok := u.User.Password(); ok {
			method, password = username, passwordPart
		} else {
			creds, err := decodeLoose(username)
			if err != nil {
				return nil, err
			}
			method, password, _ = strings.Cut(creds, ":")
		}
		host = u.Hostname()
		port, err = uriPort(u, 0)
		if err != nil {
			return nil, err
		}
	} else {
		body := strings.SplitN(strings.TrimPrefix(raw, "ss://"), "#", 2)[0]
		decoded, err := decodeLoose(body)
		if err != nil {
			return nil, err
		}
		credentials, endpoint, ok := strings.Cut(decoded, "@")
		if !ok {
			return nil, fmt.Errorf("unparsable ss URI")
		}
		method, password, _ = strings.Cut(credentials, ":")
		var portText string
		host, portText, err = net.SplitHostPort(endpoint)
		if err != nil {
			return nil, err
		}
		port, err = strconv.Atoi(portText)
		if err != nil {
			return nil, err
		}
	}
	o := jsonObject{
		"type": "shadowsocks", "server": host, "server_port": port,
		"method": method, "password": password,
	}
	return privateNode(o, host, port, "tcp", ""), nil
}

func parseHysteria2(raw string) (jsonObject, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := queryValues(u)
	port, err := uriPort(u, 443)
	if err != nil {
		return nil, err
	}
	insecureValue := textValue(q["insecure"])
	insecure := insecureValue == "1" || strings.EqualFold(insecureValue, "true")
	password := u.User.Username()
	if password == "" {
		password = textValue(q["password"])
	}
	tls := jsonObject{
		"enabled": true, "server_name": queryOr(q, "sni", queryOr(q, "peer", u.Hostname())),
		"insecure": insecure,
	}
	if textValue(q["alpn"]) != "" {
		tls["alpn"] = strings.Split(textValue(q["alpn"]), ",")
	}
	o := jsonObject{
		"type": "hysteria2", "server": u.Hostname(), "server_port": port,
		"password": password, "tls": tls,
	}
	if obfs := textValue(q["obfs"]); obfs != "" && !strings.EqualFold(obfs, "none") {
		o["obfs"] = jsonObject{"type": obfs, "password": q["obfs-password"]}
	}
	for uriKey, outputKey := range map[string]string{"upmbps": "up_mbps", "downmbps": "down_mbps"} {
		if n, err := strconv.Atoi(textValue(q[uriKey])); err == nil && textValue(q[uriKey]) != "" {
			o[outputKey] = n
		}
	}
	return privateNode(o, u.Hostname(), port, "quic", ""), nil
}

func parseTUIC(raw string) (jsonObject, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	q := queryValues(u)
	port, err := uriPort(u, 443)
	if err != nil {
		return nil, err
	}
	password, _ := u.User.Password()
	allowInsecure := textValue(q["allow_insecure"])
	tls := jsonObject{
		"enabled": true, "server_name": queryOr(q, "sni", u.Hostname()),
		"insecure": allowInsecure == "1" || strings.EqualFold(allowInsecure, "true"),
	}
	if textValue(q["alpn"]) != "" {
		tls["alpn"] = strings.Split(textValue(q["alpn"]), ",")
	}
	o := jsonObject{
		"type": "tuic", "server": u.Hostname(), "server_port": port,
		"uuid": u.User.Username(), "password": password, "tls": tls,
	}
	if textValue(q["congestion_control"]) != "" {
		o["congestion_control"] = q["congestion_control"]
	}
	if textValue(q["udp_relay_mode"]) != "" {
		o["udp_relay_mode"] = q["udp_relay_mode"]
	}
	return privateNode(o, u.Hostname(), port, "quic", ""), nil
}

func parseURI(raw string) (jsonObject, error) {
	scheme := strings.ToLower(strings.SplitN(raw, "://", 2)[0])
	var o jsonObject
	var err error
	switch scheme {
	case "vless":
		o, err = parseVLESS(raw)
	case "vmess":
		o, err = parseVMess(raw)
	case "trojan":
		o, err = parseTrojan(raw)
	case "ss":
		o, err = parseSS(raw)
	case "hysteria2", "hy2":
		o, err = parseHysteria2(raw)
	case "tuic":
		o, err = parseTUIC(raw)
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", scheme)
	}
	if err != nil {
		return nil, err
	}
	if u, parseErr := url.Parse(raw); parseErr == nil {
		o["_name"] = u.Fragment
	}
	return o, nil
}

var supportedOutbounds = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true,
	"hysteria2": true, "tuic": true, "shadowtls": true, "socks": true, "http": true,
}

func normalizeSingbox(o jsonObject) jsonObject {
	if !supportedOutbounds[textValue(o["type"])] || textValue(o["server"]) == "" || intValue(o["server_port"]) == 0 {
		return nil
	}
	out := jsonObject{}
	for k, v := range o {
		if k != "tag" {
			out[k] = v
		}
	}
	out["_name"] = textValue(o["tag"])
	host := textValue(o["server"])
	port := intValue(o["server_port"])
	transport := textValue(objectValue(o["transport"])["type"])
	if transport == "" {
		transport = "tcp"
		if o["type"] == "hysteria2" || o["type"] == "tuic" {
			transport = "quic"
		}
	}
	extra := ""
	if strings.Contains(textValue(o["flow"]), "vision") {
		extra = "vision"
	}
	return privateNode(out, host, port, transport, extra)
}

func fromXray(element jsonObject) jsonObject {
	var proxy jsonObject
	for _, item := range arrayValue(element["outbounds"]) {
		candidate := objectValue(item)
		if textValue(candidate["tag"]) == "proxy" {
			proxy = candidate
			break
		}
	}
	if proxy == nil {
		return nil
	}
	settings := objectValue(proxy["settings"])
	vnext := firstObject(settings["vnext"])
	if len(vnext) == 0 {
		vnext = firstObject(settings["servers"])
	}
	host := textValue(vnext["address"])
	port := intValue(vnext["port"])
	if host == "" || port == 0 {
		return nil
	}
	stream := objectValue(proxy["streamSettings"])
	protocol := textValue(proxy["protocol"])
	user := firstObject(vnext["users"])
	o := jsonObject{"server": host, "server_port": port}
	switch protocol {
	case "vless":
		o["type"] = "vless"
		o["uuid"] = textValue(user["id"])
		o["flow"] = textValue(user["flow"])
		o["packet_encoding"] = "xudp"
	case "vmess":
		o["type"] = "vmess"
		o["uuid"] = textValue(user["id"])
		o["security"] = queryOr(user, "security", "auto")
		o["alter_id"] = intValue(user["alterId"])
	case "trojan":
		o["type"] = "trojan"
		o["password"] = textValue(vnext["password"])
	case "shadowsocks":
		o["type"] = "shadowsocks"
		o["method"] = textValue(vnext["method"])
		o["password"] = textValue(vnext["password"])
	default:
		return nil
	}
	security := textValue(stream["security"])
	tlsSettings := objectValue(stream["tlsSettings"])
	if len(tlsSettings) == 0 {
		tlsSettings = objectValue(stream["realitySettings"])
	}
	if security == "tls" || security == "reality" {
		tls := jsonObject{
			"enabled": true, "server_name": queryOr(tlsSettings, "serverName", host),
			"utls": jsonObject{"enabled": true, "fingerprint": queryOr(tlsSettings, "fingerprint", "chrome")},
		}
		if security == "reality" {
			tls["reality"] = jsonObject{
				"enabled": true, "public_key": tlsSettings["publicKey"], "short_id": tlsSettings["shortId"],
			}
		}
		o["tls"] = tls
	}
	transport := queryOr(stream, "network", "tcp")
	switch transport {
	case "ws":
		ws := objectValue(stream["wsSettings"])
		o["transport"] = jsonObject{
			"type": "ws", "path": queryOr(ws, "path", "/"), "headers": objectValue(ws["headers"]),
		}
	case "grpc":
		grpc := objectValue(stream["grpcSettings"])
		o["transport"] = jsonObject{"type": "grpc", "service_name": grpc["serviceName"]}
	case "xhttp", "splithttp":
		fmt.Fprintf(os.Stderr, "[skip] %s:%d: transport %q is Xray-only\n", host, port, transport)
		return nil
	}
	out := normalizeSingbox(o)
	if out != nil {
		out["_name"] = textValue(element["remarks"])
	}
	return out
}

var clashTypes = map[string]string{
	"vless": "vless", "vmess": "vmess", "trojan": "trojan", "ss": "shadowsocks",
	"hysteria2": "hysteria2", "hy2": "hysteria2", "tuic": "tuic",
}

func fromClash(px jsonObject) jsonObject {
	typeName := clashTypes[strings.ToLower(textValue(px["type"]))]
	host := textValue(px["server"])
	port := intValue(px["port"])
	if typeName == "" || host == "" || port == 0 {
		return nil
	}
	o := jsonObject{"type": typeName, "server": host, "server_port": port}
	switch typeName {
	case "vless":
		o["uuid"] = textValue(px["uuid"])
		o["flow"] = textValue(px["flow"])
		o["packet_encoding"] = "xudp"
	case "vmess":
		o["uuid"] = textValue(px["uuid"])
		o["alter_id"] = intValue(px["alterId"])
		o["security"] = queryOr(px, "cipher", "auto")
	case "trojan":
		o["password"] = textValue(px["password"])
	case "shadowsocks":
		o["method"] = textValue(px["cipher"])
		o["password"] = textValue(px["password"])
	case "hysteria2":
		o["password"] = textValue(px["password"])
		if textValue(px["obfs"]) != "" {
			o["obfs"] = jsonObject{"type": px["obfs"], "password": px["obfs-password"]}
		}
	case "tuic":
		o["uuid"] = textValue(px["uuid"])
		o["password"] = textValue(px["password"])
	}
	if boolValue(px["tls"]) || typeName == "hysteria2" || typeName == "tuic" || len(objectValue(px["reality-opts"])) > 0 {
		tls := jsonObject{
			"enabled": true, "server_name": queryOr(px, "servername", queryOr(px, "sni", host)),
			"utls": jsonObject{"enabled": true, "fingerprint": queryOr(px, "client-fingerprint", "chrome")},
		}
		if boolValue(px["skip-cert-verify"]) {
			tls["insecure"] = true
		}
		if reality := objectValue(px["reality-opts"]); len(reality) > 0 {
			tls["reality"] = jsonObject{
				"enabled": true, "public_key": reality["public-key"], "short_id": reality["short-id"],
			}
		}
		o["tls"] = tls
	}
	switch textValue(px["network"]) {
	case "ws":
		ws := objectValue(px["ws-opts"])
		o["transport"] = jsonObject{"type": "ws", "path": queryOr(ws, "path", "/"), "headers": objectValue(ws["headers"])}
	case "grpc":
		grpc := objectValue(px["grpc-opts"])
		o["transport"] = jsonObject{"type": "grpc", "service_name": grpc["grpc-service-name"]}
	}
	out := normalizeSingbox(o)
	if out != nil {
		out["_name"] = queryOr(px, "name", textValue(px["remarks"]))
	}
	return out
}

func nodesFromJSON(text string) []jsonObject {
	var decoded any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		return nil
	}
	var out []jsonObject
	switch d := decoded.(type) {
	case []any:
		for _, item := range d {
			if node := fromXray(objectValue(item)); node != nil {
				out = append(out, node)
			}
		}
		if len(out) > 0 {
			return out
		}
		for _, item := range d {
			if node := fromClash(objectValue(item)); node != nil {
				out = append(out, node)
			}
		}
	case map[string]any:
		for _, item := range arrayValue(d["outbounds"]) {
			if node := normalizeSingbox(objectValue(item)); node != nil {
				out = append(out, node)
			}
		}
		if len(out) > 0 {
			return out
		}
		for _, item := range arrayValue(d["proxies"]) {
			if node := fromClash(objectValue(item)); node != nil {
				out = append(out, node)
			}
		}
		if len(out) > 0 {
			return out
		}
		for _, item := range arrayValue(d["servers"]) {
			px := objectValue(item)
			if textValue(px["type"]) == "" {
				px["type"] = "ss"
			}
			if intValue(px["port"]) == 0 {
				px["port"] = px["server_port"]
			}
			px["cipher"] = textValue(px["method"])
			if node := fromClash(px); node != nil {
				out = append(out, node)
			}
		}
	}
	return out
}

func nodesFromAny(text string) []jsonObject {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if text[0] == '[' || text[0] == '{' {
		if nodes := nodesFromJSON(text); len(nodes) > 0 {
			return nodes
		}
	}
	if strings.Contains(text, "proxies:") {
		var document struct {
			Proxies []jsonObject `yaml:"proxies"`
		}
		if err := yaml.Unmarshal([]byte(text), &document); err == nil {
			var out []jsonObject
			for _, px := range document.Proxies {
				if node := fromClash(px); node != nil {
					out = append(out, node)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	if !strings.Contains(text, "://") {
		decoded, err := decodeLoose(text)
		if err != nil {
			return nil
		}
		return nodesFromAny(decoded)
	}
	var out []jsonObject
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "://") {
			continue
		}
		node, err := parseURI(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[skip] %v\n", err)
			continue
		}
		out = append(out, node)
	}
	return out
}

var protocolLabels = map[string]string{
	"vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "ss",
	"hysteria2": "hy2", "tuic": "tuic", "shadowtls": "stls", "socks": "socks", "http": "http",
}

func stableTag(cc, protocol, host string, port int, transport, extra string) string {
	raw := strings.Join([]string{strings.ToLower(cc), protocol, strings.ReplaceAll(host, ":", ""), strconv.Itoa(port), transport}, "-")
	if extra != "" {
		raw += "-" + extra
	}
	var b strings.Builder
	for _, r := range strings.ToLower(raw) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func resolveCountry(host string, cache map[string]string) string {
	if cc := cache[host]; cc != "" {
		return cc
	}
	ip := host
	if net.ParseIP(host) == nil {
		if resolved, err := net.ResolveIPAddr("ip", host); err == nil {
			ip = resolved.IP.String()
		}
	}
	if cc := cache[ip]; cc != "" {
		cache[host] = cc
		return cc
	}
	cc := "ZZ"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip + "?fields=countryCode")
	if err == nil {
		defer resp.Body.Close()
		var result struct {
			CountryCode string `json:"countryCode"`
		}
		if json.NewDecoder(resp.Body).Decode(&result) == nil && result.CountryCode != "" {
			cc = strings.ToUpper(result.CountryCode)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[geoip] %s failed: %v\n", host, err)
	}
	cache[host] = cc
	cache[ip] = cc
	return cc
}

func parseSubscription(text string, cache map[string]string, resolveCC bool) []jsonObject {
	var out []jsonObject
	seen := map[string]bool{}
	for _, node := range nodesFromAny(text) {
		cc := "xx"
		if resolveCC {
			cc = resolveCountry(textValue(node["_host"]), cache)
		}
		protocol := protocolLabels[textValue(node["type"])]
		if protocol == "" {
			protocol = textValue(node["type"])
		}
		node["_cc"] = cc
		tag := stableTag(cc, protocol, textValue(node["_host"]), intValue(node["_port"]), textValue(node["_transport"]), textValue(node["_extra"]))
		if seen[tag] {
			encoded, _ := json.Marshal(node)
			tag += "-" + shortSHA1(encoded)
		}
		seen[tag] = true
		node["tag"] = tag
		out = append(out, node)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
