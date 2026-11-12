// Sidecar healthcheck daemon for sing-box. Real-data probes catch servers
// that pass TLS handshake then reset on data — sing-box's own urltest probes
// HEAD /generate_204 and is fooled by them.
//
// Probes go through DEDICATED HTTP-proxy inbounds (one per outbound, on
// 127.0.0.1:7900+N inside the container, set up by sub2singbox). Each probe
// inbound is statically routed to its corresponding outbound, so we measure
// any specific outbound by hitting its proxy port — without ever touching
// select.now and without disrupting user traffic. select.now only changes
// when (a) liveness on the current pin actually fails, or (b) pinBest finds
// a materially-faster candidate.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ── flags / env ─────────────────────────────────────────────────────────────

var (
	flagClashAPI           = flag.String("clash-api", envOr("CLASH_API", "http://127.0.0.1:9090"), "Clash API endpoint")
	flagClashSecret        = flag.String("clash-secret", envOr("CLASH_SECRET", ""), "Clash API bearer token")
	flagSelectTag          = flag.String("select-tag", envOr("SELECT_TAG", "select"), "name of the top-level selector group")
	flagLivenessURL        = flag.String("liveness-url", envOr("LIVENESS_URL", "https://speed.cloudflare.com/__down?bytes=100000"), "real-data probe URL")
	flagLivenessBytes      = flag.Int64("liveness-bytes", envInt64("LIVENESS_BYTES", 100000), "expected response size; partial = fail")
	flagLivenessInterval   = flag.Duration("liveness-interval", envDur("LIVENESS_INTERVAL", 30*time.Second), "interval between liveness probes")
	flagRankInterval       = flag.Duration("rank-interval", envDur("RANK_INTERVAL", 10*time.Minute), "interval between full ranking sweeps")
	flagRankStale          = flag.Duration("rank-stale-after", envDur("RANK_STALE_AFTER", 25*time.Minute), "discard ranking entries older than this interval")
	flagProbeTimeout       = flag.Duration("probe-timeout", envDur("PROBE_TIMEOUT", 12*time.Second), "per-probe timeout")
	flagProbeConcurrency   = flag.Int("probe-concurrency", envInt("PROBE_CONCURRENCY", 4), "maximum simultaneous outbound probes")
	flagFailThreshold      = flag.Int("fail-threshold", envInt("FAIL_THRESHOLD", 2), "consecutive failures before rotating select.now")
	flagRotsBeforeForce    = flag.Int("rotations-before-force-sweep", envInt("ROTATIONS_BEFORE_FORCE_SWEEP", 3), "consecutive rotations w/o success → force sweep")
	flagHysteresisPct      = flag.Int("hysteresis-pct", envInt("HYSTERESIS_PCT", 15), "%% better required before pinBest switches host")
	flagSevereImprovePct   = flag.Int("severe-improve-pct", envInt("SEVERE_IMPROVE_PCT", 50), "%% improvement that bypasses dwell and repeated confirmation")
	flagFailoverCandidates = flag.Int("failover-candidates", envInt("FAILOVER_CANDIDATES", 5), "ranked candidates freshly probed during failure rotation")
	flagMinSwitch          = flag.Duration("min-switch-interval", envDur("MIN_SWITCH_INTERVAL", 15*time.Minute), "minimum dwell time before switching for lower latency")
	flagImproveConfirm     = flag.Int("improve-confirmations", envInt("IMPROVE_CONFIRMATIONS", 2), "consecutive sweeps required before switching for lower latency")
	flagAutoPin            = flag.Bool("auto-pin", envBool("AUTO_PIN", true), "allow daemon to change select.now")
	flagExcludeCC          = flag.String("exclude-probe-cc", envOr("EXCLUDE_AUTO_CC", "RU"), "comma-separated country codes excluded from probe pool (still pickable manually)")
	flagExcludeProto       = flag.String("exclude-auto-proto", envOr("SINGBOX_EXCLUDE_AUTO_PROTO", "shadowsocks,vmess"), "comma-separated protocols excluded from automatic selection")
	flagStateDir           = flag.String("state-dir", envOr("STATE_DIR", "/tmp/healthcheck"), "tmpfs state dir for ranking + counters")
	flagProbePortsPath     = flag.String("probe-ports", envOr("PROBE_PORTS", "/tmp/probe_ports.json"), "tag→probe-port JSON map written by sub2singbox")
	flagProbeCountries     = flag.String("probe-countries", envOr("PROBE_COUNTRIES", "/tmp/probe_countries.json"), "tag→country-code JSON map written by sub-refresh")

	// Telegram selector (tg-select) management — kept entirely separate from
	// the main `select` pool. No-op when tg-select is absent (HY2_URI unset).
	flagTGSelectTag  = flag.String("tg-select-tag", envOr("TG_SELECT_TAG", "tg-select"), "Telegram-only selector group managed independently of the main pool")
	flagTGHysteria   = flag.String("tg-hysteria", envOr("TG_HYSTERIA", "yes"), "yes: prefer the injected hy2 member for Telegram; no: manager owns the pick, hy2 never chosen")
	flagTGInterval   = flag.Duration("tg-manage-interval", envDur("TG_MANAGE_INTERVAL", 30*time.Second), "interval for the Telegram selector manager")
	flagTGFailThresh = flag.Int("tg-hy2-fail-threshold", envInt("TG_HY2_FAIL_THRESHOLD", 2), "consecutive active-path liveness failures before the Telegram manager re-pins")
	flagTGLiveURL    = flag.String("tg-liveness-url", envOr("TG_LIVENESS_URL", "https://www.gstatic.com/generate_204"), "URL for the Clash-delay liveness probes used by the Telegram manager")
	flagTGFailover   = flag.String("tg-failover-tag", envOr("TG_FAILOVER_TAG", "tg-failover"), "urltest group tag: cold-start default and last-resort fallback for tg-select (built by inject-hy2.sh from the non-RU pool)")
)

func tgHysteriaOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "no", "0", "false", "off":
		return false
	}
	return true
}

func envOr(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

// ── daemon ──────────────────────────────────────────────────────────────────

type RankEntry struct {
	LatencyMs int64 `json:"latency_ms"`
	Failed    bool  `json:"failed,omitempty"`
	UpdatedAt int64 `json:"ts"`
}

type Daemon struct {
	api                string
	secret             string
	selectTag          string
	excluded           map[string]bool
	livenessURL        string
	livenessBytes      int64
	probeTimeout       time.Duration
	failThreshold      int
	rotsBeforeForce    int
	hysteresisPct      int
	severeImprovePct   int
	failoverCandidates int
	minSwitch          time.Duration
	improveConfirm     int
	autoPin            bool
	stateDir           string
	probePortsPath     string
	probeCountries     string
	lastSwitch         time.Time
	candidate          string
	candidateN         int
	firstSweep         bool

	tgSelectTag   string
	tgHysteria    bool
	tgInterval    time.Duration
	tgFailThresh  int
	tgLiveURL     string
	tgFailoverTag string
	tgFail        int // touched only by the single tgManage goroutine

	mu         sync.Mutex
	rankings   map[string]RankEntry
	portMap    map[string]int
	countryMap map[string]string
	failCnt    int
	rotCnt     int

	cli *http.Client
}

func newDaemon() *Daemon {
	excl := map[string]bool{}
	for _, cc := range strings.Split(*flagExcludeCC, ",") {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if cc != "" {
			excl[cc] = true
		}
	}
	return &Daemon{
		api:                strings.TrimRight(*flagClashAPI, "/"),
		secret:             *flagClashSecret,
		selectTag:          *flagSelectTag,
		excluded:           excl,
		livenessURL:        *flagLivenessURL,
		livenessBytes:      *flagLivenessBytes,
		probeTimeout:       *flagProbeTimeout,
		failThreshold:      *flagFailThreshold,
		rotsBeforeForce:    *flagRotsBeforeForce,
		hysteresisPct:      *flagHysteresisPct,
		severeImprovePct:   *flagSevereImprovePct,
		failoverCandidates: *flagFailoverCandidates,
		minSwitch:          *flagMinSwitch,
		improveConfirm:     *flagImproveConfirm,
		autoPin:            *flagAutoPin,
		stateDir:           *flagStateDir,
		probePortsPath:     *flagProbePortsPath,
		probeCountries:     *flagProbeCountries,
		firstSweep:         true,
		tgSelectTag:        *flagTGSelectTag,
		tgHysteria:         tgHysteriaOn(*flagTGHysteria),
		tgInterval:         *flagTGInterval,
		tgFailThresh:       *flagTGFailThresh,
		tgLiveURL:          *flagTGLiveURL,
		tgFailoverTag:      *flagTGFailover,
		rankings:           map[string]RankEntry{},
		portMap:            map[string]int{},
		countryMap:         map[string]string{},
		cli:                &http.Client{Timeout: 0}, // per-call timeouts via context
	}
}

// ── Clash API ───────────────────────────────────────────────────────────────

type clashProxy struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

func (d *Daemon) clashGET(path string, out interface{}) error {
	req, _ := http.NewRequest("GET", d.api+path, nil)
	req.Header.Set("Authorization", "Bearer "+d.secret)
	resp, err := d.cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("clash GET %s: HTTP %d %s", path, resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (d *Daemon) clashPUT(path string, body interface{}) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", d.api+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+d.secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("clash PUT %s: HTTP %d %s", path, resp.StatusCode, string(body))
	}
	return nil
}

func excludedProtocol(tag string) bool {
	parts := strings.Split(tag, "-")
	if len(parts) < 2 {
		return false
	}
	proto := parts[1]
	for _, p := range strings.Split(*flagExcludeProto, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "shadowsocks" {
			p = "ss"
		}
		if p != "" && proto == p {
			return true
		}
	}
	return false
}

func (d *Daemon) listPool() ([]string, error) {
	var p clashProxy
	if err := d.clashGET("/proxies/"+d.selectTag, &p); err != nil {
		return nil, err
	}
	out := []string{}
	for _, t := range p.All {
		if t == "direct" || strings.HasPrefix(t, "urltest-") || strings.HasPrefix(t, "select-") {
			continue
		}
		if d.excludedCountry(t) || excludedProtocol(t) {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func (d *Daemon) nowPick() (string, error) {
	var p clashProxy
	if err := d.clashGET("/proxies/"+d.selectTag, &p); err != nil {
		return "", err
	}
	return p.Now, nil
}

func (d *Daemon) setPick(tag string) error {
	return d.clashPUT("/proxies/"+d.selectTag, map[string]string{"name": tag})
}

// ── probe via dedicated HTTP-proxy inbound ─────────────────────────────────

// probeViaPort dials sing-box's per-outbound HTTP proxy on 127.0.0.1:port.
// Sing-box's route.rule pins inbound=probe-N → outbound=<tag>, so the request
// goes through that specific outbound regardless of select.now. Real-data
// (must download exactly LIVENESS_BYTES) catches handshake-OK / data-reset
// servers that fool sing-box's HEAD probe.
func (d *Daemon) probeViaPort(ctx context.Context, port int) (time.Duration, error) {
	proxyURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)}
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: d.probeTimeout,
	}
	cli := &http.Client{Transport: transport}

	pCtx, cancel := context.WithTimeout(ctx, d.probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(pCtx, "GET", d.livenessURL, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := cli.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return 0, err
	}
	if n != d.livenessBytes {
		return 0, fmt.Errorf("partial: got %d, want %d", n, d.livenessBytes)
	}
	if err := d.probeTelegram(ctx, proxyURL); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// loadPortMap re-reads /tmp/probe_ports.json. Called before each sweep
// and before liveness if the cached map is empty (e.g., daemon just started
// before sub2singbox finished writing).
func (d *Daemon) loadPortMap() error {
	b, err := os.ReadFile(d.probePortsPath)
	if err != nil {
		return err
	}
	var m map[string]int
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	countries := map[string]string{}
	if cb, readErr := os.ReadFile(d.probeCountries); readErr == nil {
		_ = json.Unmarshal(cb, &countries)
	}
	d.mu.Lock()
	d.portMap = m
	d.countryMap = countries
	d.mu.Unlock()
	return nil
}

func (d *Daemon) excludedCountry(tag string) bool {
	d.mu.Lock()
	cc := strings.ToUpper(d.countryMap[tag])
	d.mu.Unlock()
	return d.excluded[cc]
}

func (d *Daemon) snapshotPortMap() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	cp := make(map[string]int, len(d.portMap))
	for k, v := range d.portMap {
		cp[k] = v
	}
	return cp
}

// resolveNow follows nested groups (urltest-all → tr-vless-...) until it
// reaches a tag that has a probe port assigned. Returns "" if select.now
// resolves to something we don't have a port for (typically RU exit when
// user manually picked it).
func (d *Daemon) resolveNow() (string, error) {
	cur := d.selectTag
	for i := 0; i < 5; i++ {
		var p clashProxy
		if err := d.clashGET("/proxies/"+cur, &p); err != nil {
			return "", err
		}
		if p.Now == "" {
			return cur, nil
		}
		d.mu.Lock()
		_, hasPort := d.portMap[p.Now]
		d.mu.Unlock()
		if hasPort {
			if d.excludedCountry(p.Now) {
				return "", nil
			}
			return p.Now, nil
		}
		// Recurse: now points at another group (urltest-tr etc.)
		cur = p.Now
	}
	return "", fmt.Errorf("recursion limit resolving %s.now", d.selectTag)
}

// ── state persistence ──────────────────────────────────────────────────────

func (d *Daemon) persistRankings() {
	if err := os.MkdirAll(d.stateDir, 0o755); err != nil {
		log.Printf("mkdir %s: %v", d.stateDir, err)
		return
	}
	d.mu.Lock()
	cp := make(map[string]RankEntry, len(d.rankings))
	for k, v := range d.rankings {
		cp[k] = v
	}
	d.mu.Unlock()
	b, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return
	}
	tmp := filepath.Join(d.stateDir, "ranking.json.tmp")
	final := filepath.Join(d.stateDir, "ranking.json")
	_ = os.WriteFile(tmp, b, 0o644)
	_ = os.Rename(tmp, final)
}

// ── core logic ──────────────────────────────────────────────────────────────

// sweep: probe each outbound through its dedicated probe-port — select.now
// is NOT touched during measurement. A small worker pool bounds WAN load,
// while persisting every result makes the first useful ranking available early.
func (d *Daemon) sweep(ctx context.Context) {
	if err := d.loadPortMap(); err != nil {
		log.Printf("sweep: load probe ports %s: %v", d.probePortsPath, err)
		return
	}
	pm := d.snapshotPortMap()
	if len(pm) == 0 {
		log.Printf("sweep: probe-ports map empty, skipping")
		return
	}

	tags := make([]string, 0, len(pm))
	for tag := range pm {
		if !excludedProtocol(tag) && !d.excludedCountry(tag) {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	current, _ := d.resolveNow()
	sort.SliceStable(tags, func(i, j int) bool {
		return tags[i] == current && tags[j] != current
	})
	log.Printf("=== sweep start (%d outbounds, concurrency %d) ===", len(tags), *flagProbeConcurrency)

	type result struct {
		tag string
		rtt time.Duration
		err error
	}
	jobs := make(chan string)
	results := make(chan result)
	workers := *flagProbeConcurrency
	if workers < 1 {
		workers = 1
	}
	if workers > len(tags) {
		workers = len(tags)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tag := range jobs {
				rtt, err := d.probeViaPort(ctx, pm[tag])
				select {
				case results <- result{tag, rtt, err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, tag := range tags {
			select {
			case jobs <- tag:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	completed := 0
	for r := range results {
		now := time.Now().Unix()
		d.mu.Lock()
		if r.err != nil {
			d.rankings[r.tag] = RankEntry{Failed: true, UpdatedAt: now}
		} else {
			d.rankings[r.tag] = RankEntry{LatencyMs: int64(r.rtt / time.Millisecond), UpdatedAt: now}
		}
		d.mu.Unlock()
		if r.err != nil {
			log.Printf("sweep: %-50s -> fail (%v)", r.tag, r.err)
		} else {
			log.Printf("sweep: %-50s -> %dms", r.tag, r.rtt/time.Millisecond)
		}
		d.persistRankings()
		completed++
		if d.firstSweep && completed == workers {
			d.pinBest()
		}
	}

	d.mu.Lock()
	for tag := range d.rankings {
		if _, ok := pm[tag]; !ok {
			delete(d.rankings, tag)
		}
	}
	d.firstSweep = false
	d.mu.Unlock()
	d.persistRankings()
	log.Printf("=== sweep done ===")
}

// pinBest switches immediately when there is no healthy current choice or the
// best fresh measurement is severely better. Ordinary improvements retain
// hysteresis, repeated confirmation and dwell time to prevent flapping.
func (d *Daemon) pinBest() {
	if !d.autoPin {
		return
	}
	type entry struct {
		tag string
		ms  int64
	}
	d.mu.Lock()
	sorted := []entry{}
	for tag, r := range d.rankings {
		if excludedProtocol(tag) || d.excluded[strings.ToUpper(d.countryMap[tag])] {
			continue
		}
		if r.Failed || r.LatencyMs <= 0 || time.Now().Unix()-r.UpdatedAt > int64(flagRankStale.Seconds()) {
			continue
		}
		sorted = append(sorted, entry{tag, r.LatencyMs})
	}
	d.mu.Unlock()
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ms < sorted[j].ms })
	if len(sorted) == 0 {
		log.Printf("pinBest: no live outbounds in ranking")
		return
	}
	best := sorted[0]

	cur, _ := d.nowPick()
	if cur == best.tag {
		d.candidate = ""
		d.candidateN = 0
		return
	}
	actual := cur
	if strings.HasPrefix(cur, "urltest-") {
		if resolved, err := d.resolveNow(); err == nil {
			actual = resolved
		}
	}
	if actual == best.tag {
		return
	}

	d.mu.Lock()
	curRank, hasCur := d.rankings[actual]
	d.mu.Unlock()
	if hasCur && !curRank.Failed && curRank.LatencyMs > 0 {
		impPct := 100 * (curRank.LatencyMs - best.ms) / curRank.LatencyMs
		if impPct < int64(d.hysteresisPct) {
			d.candidate = ""
			d.candidateN = 0
			log.Printf("pinBest: keep %s (%dms) vs %s (%dms) [hysteresis %d%%]",
				actual, curRank.LatencyMs, best.tag, best.ms, d.hysteresisPct)
			return
		}
		severe := impPct >= int64(d.severeImprovePct)
		if severe {
			log.Printf("pinBest: %s is %d%% faster than %s; bypassing dwell and confirmation",
				best.tag, impPct, actual)
		} else {
			if time.Since(d.lastSwitch) < d.minSwitch {
				log.Printf("pinBest: keep %s during dwell (%s remaining)", actual, d.minSwitch-time.Since(d.lastSwitch))
				return
			}
			if d.candidate == best.tag {
				d.candidateN++
			} else {
				d.candidate = best.tag
				d.candidateN = 1
			}
			if d.candidateN < d.improveConfirm {
				log.Printf("pinBest: candidate %s needs confirmation %d/%d", best.tag, d.candidateN, d.improveConfirm)
				return
			}
		}
	} else {
		d.candidateN = 0
	}

	log.Printf("pinBest: %s -> %s (%dms, was %s)", cur, best.tag, best.ms, cur)
	if err := d.setPick(best.tag); err != nil {
		log.Printf("pinBest: setPick: %v", err)
		return
	}
	d.lastSwitch = time.Now()
	d.candidate = ""
	d.candidateN = 0
}

// liveness refreshes the current outbound's rank on every successful probe.
// On consecutive failures it rotates to the fastest freshly verified candidate.
// After ROTATIONS_BEFORE_FORCE_SWEEP rotations without success, force a sweep.
func (d *Daemon) liveness(ctx context.Context) {
	tag, err := d.resolveNow()
	if err != nil {
		log.Printf("liveness: resolveNow: %v", err)
		return
	}
	if tag == "" {
		// select.now resolves to something we don't probe (e.g., manually
		// pinned RU exit). Don't claim failure — user's choice.
		return
	}
	d.mu.Lock()
	port, ok := d.portMap[tag]
	d.mu.Unlock()
	if !ok {
		_ = d.loadPortMap()
		d.mu.Lock()
		port, ok = d.portMap[tag]
		d.mu.Unlock()
		if !ok {
			return
		}
	}

	rtt, err := d.probeViaPort(ctx, port)
	if err == nil {
		d.mu.Lock()
		d.rankings[tag] = RankEntry{LatencyMs: int64(rtt / time.Millisecond), UpdatedAt: time.Now().Unix()}
		d.mu.Unlock()
		d.failCnt = 0
		d.rotCnt = 0
		return
	}
	d.failCnt++
	log.Printf("liveness probe failed (%d/%d) on %s: %v", d.failCnt, d.failThreshold, tag, err)
	if d.failCnt < d.failThreshold {
		return
	}
	if !d.autoPin {
		log.Printf("liveness: AUTO_PIN=0, keeping manually selected %s", tag)
		return
	}

	next := d.nextAlive(ctx, tag)
	if next == "" || next == tag {
		log.Printf("liveness: no alternative outbound, sticking with %s", tag)
		return
	}
	log.Printf("liveness: rotating select.now: %s -> %s", tag, next)
	if err := d.setPick(next); err != nil {
		log.Printf("liveness: setPick: %v", err)
		return
	}
	d.lastSwitch = time.Now()
	d.candidate = ""
	d.candidateN = 0
	d.failCnt = 0
	d.rotCnt++
	if d.rotCnt >= d.rotsBeforeForce {
		log.Printf("liveness: %d rotations w/o success, forcing sweep", d.rotCnt)
		d.sweep(ctx)
		d.pinBest()
		d.rotCnt = 0
	}
}

// nextAlive freshly measures the best-ranked candidates and returns the
// fastest live one. Cached latency only determines which candidates are worth
// probing; it must not by itself decide a failure-driven switch.
func (d *Daemon) nextAlive(ctx context.Context, current string) string {
	type entry struct {
		tag string
		ms  int64
	}
	d.mu.Lock()
	sorted := []entry{}
	dead := map[string]bool{}
	for tag, r := range d.rankings {
		if excludedProtocol(tag) || d.excluded[strings.ToUpper(d.countryMap[tag])] {
			continue
		}
		if r.Failed {
			dead[tag] = true
			continue
		}
		if r.LatencyMs <= 0 || time.Now().Unix()-r.UpdatedAt > int64(flagRankStale.Seconds()) {
			continue
		}
		sorted = append(sorted, entry{tag, r.LatencyMs})
	}
	d.mu.Unlock()
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ms < sorted[j].ms })

	candidates := []string{}
	for _, e := range sorted {
		if e.tag != current {
			candidates = append(candidates, e.tag)
		}
	}
	if len(candidates) == 0 {
		pool, err := d.listPool()
		if err != nil {
			return ""
		}
		for _, tag := range pool {
			if tag != current && !dead[tag] {
				candidates = append(candidates, tag)
			}
		}
	}
	limit := d.failoverCandidates
	if limit < 1 {
		limit = 1
	}
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}

	bestTag := ""
	bestRTT := time.Duration(1<<63 - 1)
	probed := 0
	for _, tag := range candidates {
		d.mu.Lock()
		port, ok := d.portMap[tag]
		d.mu.Unlock()
		if !ok {
			continue
		}
		rtt, err := d.probeViaPort(ctx, port)
		probed++
		now := time.Now().Unix()
		d.mu.Lock()
		if err != nil {
			d.rankings[tag] = RankEntry{Failed: true, UpdatedAt: now}
		} else {
			d.rankings[tag] = RankEntry{LatencyMs: int64(rtt / time.Millisecond), UpdatedAt: now}
		}
		d.mu.Unlock()
		if err != nil {
			log.Printf("liveness: failover candidate %s -> fail (%v)", tag, err)
			continue
		}
		log.Printf("liveness: failover candidate %s -> %dms", tag, rtt/time.Millisecond)
		if rtt < bestRTT {
			bestTag, bestRTT = tag, rtt
		}
	}
	if probed > 0 {
		d.persistRankings()
	}
	return bestTag
}

// ── Telegram selector (tg-select) management ────────────────────────────────

// setTG points the Telegram-only selector at tag via the Clash API.
func (d *Daemon) setTG(tag string) error {
	return d.clashPUT("/proxies/"+d.tgSelectTag, map[string]string{"name": tag})
}

// tgDelayOK probes a tag's liveness via the Clash delay API (a HEAD through
// the tag to a tiny 204 URL). Works for real nodes AND for groups (hy2,
// tg-failover), where it tests through the group's current Select() path —
// i.e. exactly what Telegram traffic rides. Non-disruptive; needs no probe
// port, so hy2/groups stay out of the general pool's probe/rank machinery.
func (d *Daemon) tgDelayOK(ctx context.Context, tag string) bool {
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := url.Values{}
	q.Set("timeout", "8000")
	q.Set("url", d.tgLiveURL)
	path := "/proxies/" + url.PathEscape(tag) + "/delay?" + q.Encode()
	req, _ := http.NewRequestWithContext(pctx, "GET", d.api+path, nil)
	req.Header.Set("Authorization", "Bearer "+d.secret)
	resp, err := d.cli.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false // Clash returns non-200 (e.g. 408/503) when the delay test fails
	}
	var r struct {
		Delay int `json:"delay"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) != nil {
		return false
	}
	return r.Delay > 0
}

// hasMember reports whether tag is one of the selector's current members.
func hasMember(all []string, tag string) bool {
	for _, m := range all {
		if m == tag {
			return true
		}
	}
	return false
}

// tgAliveNow live-checks a DIRECT pin candidate: a real-data fetch through
// the node's dedicated probe-port (the same source of truth as the ranking
// sweep, independent of sing-box's wedge-prone urltest plumbing). Falls back
// to the Clash delay probe for tags without a probe port.
func (d *Daemon) tgAliveNow(ctx context.Context, tag string) bool {
	d.mu.Lock()
	port, ok := d.portMap[tag]
	d.mu.Unlock()
	if !ok {
		_ = d.loadPortMap()
		d.mu.Lock()
		port, ok = d.portMap[tag]
		d.mu.Unlock()
	}
	if ok {
		_, err := d.probeViaPort(ctx, port)
		return err == nil
	}
	return d.tgDelayOK(ctx, tag)
}

// tgActiveAlive answers "is the CURRENT tg-select pick working?". Groups
// (tg-failover) and hy2 have no probe port → Clash delay probe through them;
// direct nodes get the real-data probe-port check.
func (d *Daemon) tgActiveAlive(ctx context.Context, cur string) bool {
	if cur == d.tgFailoverTag || strings.HasPrefix(cur, "hy2-") {
		return d.tgDelayOK(ctx, cur)
	}
	return d.tgAliveNow(ctx, cur)
}

// tgCandidates returns tg-select's DIRECT members (skip groups/hy2/RU),
// ordered: ranking-alive by latency first, then unranked (post-rotation nodes
// the sweep hasn't seen yet), ranking-dead last (still better than nothing
// when everything else is stale).
func (d *Daemon) tgCandidates(members []string) []string {
	type cand struct {
		grp int
		ms  int64
		tag string
	}
	d.mu.Lock()
	out := []cand{}
	for _, t := range members {
		if t == d.tgFailoverTag || t == "direct" ||
			strings.HasPrefix(t, "hy2-") || strings.HasPrefix(t, "urltest-") ||
			strings.HasPrefix(t, "select") || strings.HasPrefix(t, "ru-") {
			continue
		}
		r, ranked := d.rankings[t]
		switch {
		case ranked && !r.Failed && r.LatencyMs > 0:
			out = append(out, cand{0, r.LatencyMs, t})
		case !ranked:
			out = append(out, cand{1, 0, t})
		default:
			out = append(out, cand{2, 0, t})
		}
	}
	d.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].grp != out[j].grp {
			return out[i].grp < out[j].grp
		}
		if out[i].ms != out[j].ms {
			return out[i].ms < out[j].ms
		}
		return out[i].tag < out[j].tag
	})
	tags := make([]string, 0, len(out))
	for _, c := range out {
		tags = append(tags, c.tag)
	}
	return tags
}

// tgBestDirect returns the best verified-live direct member; tries the top
// few so one freshly-dead entry in a stale ranking can't strand Telegram.
func (d *Daemon) tgBestDirect(ctx context.Context, members []string) string {
	for i, c := range d.tgCandidates(members) {
		if i >= 5 {
			break
		}
		if d.tgAliveNow(ctx, c) {
			return c
		}
	}
	return ""
}

// tgManage owns the Telegram-only tg-select selector the way the daemon owns
// the main `select` (ported 1:1 from keenetic-singbox tg-select-manager
// 6f73a95, the "wedged urltest" incident fix: sing-box's urltest checker can
// wedge forever on one hung dial, so it must not be the only health authority
// for the TG path).
//
// TG_HYSTERIA=yes + hy2 member present (legacy hy2-primary): Telegram returns
// to hy2 whenever hy2 answers its delay probe; when hy2 is down >= threshold
// runs, fall back to a verified-live direct member (tg-failover only if none
// verifies).
//
// Otherwise (TG_HYSTERIA=no, or no hy2 member — the manager-owned mode): keep
// the current pick while a LIVE probe answers (zero churn); after threshold
// consecutive fails re-pin to the best ranking-ordered direct member,
// live-verified through its probe-port right before the PUT. tg-failover
// stays as cold-start default / last resort. While tg-failover itself answers
// probes it is deliberately NOT vacated (healthy urltest = fine reactive
// failover). RU is never chosen. Only ever PUTs current members, so a config
// without hy2 can no longer cause "Selector update error: not found" spam.
//
// No-op when tg-select is absent (HY2_URI unset). Touches ONLY tg-select,
// never `select`, so general traffic is unaffected.
func (d *Daemon) tgManage(ctx context.Context) {
	var tg clashProxy
	if err := d.clashGET("/proxies/"+d.tgSelectTag, &tg); err != nil {
		return // tg-select absent → nothing to manage
	}
	if tg.Now == "" {
		return
	}
	hy2Tag := ""
	for _, m := range tg.All {
		if strings.HasPrefix(m, "hy2-") {
			hy2Tag = m
			break
		}
	}

	// ── hy2-primary mode ────────────────────────────────────────────────
	if d.tgHysteria && hy2Tag != "" {
		if d.tgDelayOK(ctx, hy2Tag) {
			d.tgFail = 0
			if tg.Now != hy2Tag {
				if err := d.setTG(hy2Tag); err != nil {
					log.Printf("tg-select: setTG %s: %v", hy2Tag, err)
					return
				}
				log.Printf("tg-select: %s -> %s (hy2 primary, recovered)", tg.Now, hy2Tag)
			}
			return
		}
		d.tgFail++
		if d.tgFail < d.tgFailThresh {
			return // tolerate transient hy2 blips
		}
		if tg.Now != hy2Tag && d.tgActiveAlive(ctx, tg.Now) {
			return // already on a live fallback — no churn
		}
		target := d.tgBestDirect(ctx, tg.All)
		if target == "" {
			if !hasMember(tg.All, d.tgFailoverTag) {
				if d.tgFail == d.tgFailThresh {
					log.Printf("tg-select: hy2 down, no candidate and no %s group, staying on %s", d.tgFailoverTag, tg.Now)
				}
				return
			}
			target = d.tgFailoverTag
		}
		if tg.Now != target {
			if err := d.setTG(target); err != nil {
				log.Printf("tg-select: setTG %s: %v", target, err)
				return
			}
			d.tgFail = 0
			log.Printf("tg-select: %s -> %s (hy2 DOWN -> verified-live non-RU fallback)", tg.Now, target)
		}
		return
	}

	// ── manager-owned mode (TG_HYSTERIA=no, or no hy2 member) ───────────
	// Leftover hy2 pick from a mode flip: move off unconditionally —
	// TG_HYSTERIA=no means Telegram must not ride Hysteria2.
	if hy2Tag != "" && tg.Now == hy2Tag {
		target := d.tgBestDirect(ctx, tg.All)
		if target == "" && hasMember(tg.All, d.tgFailoverTag) {
			target = d.tgFailoverTag
		}
		if target != "" {
			if err := d.setTG(target); err != nil {
				log.Printf("tg-select: setTG %s: %v", target, err)
				return
			}
			d.tgFail = 0
			log.Printf("tg-select: %s -> %s (TG_HYSTERIA=no: moving off hy2)", tg.Now, target)
		}
		return
	}

	if d.tgActiveAlive(ctx, tg.Now) {
		d.tgFail = 0
		return
	}
	d.tgFail++
	if d.tgFail < d.tgFailThresh {
		log.Printf("tg-select: active TG path '%s' probe failed (%d/%d)", tg.Now, d.tgFail, d.tgFailThresh)
		return
	}

	target := d.tgBestDirect(ctx, tg.All)
	if target == "" {
		if tg.Now != d.tgFailoverTag && hasMember(tg.All, d.tgFailoverTag) {
			// Nothing verifies right now — hand back to the urltest group as
			// a last resort (it may still route via frozen-but-alive history).
			target = d.tgFailoverTag
		} else {
			log.Printf("tg-select: active TG path '%s' dead and no live candidate — keeping (will retry)", tg.Now)
			return
		}
	}
	if target != tg.Now {
		if err := d.setTG(target); err != nil {
			log.Printf("tg-select: setTG %s: %v", target, err)
			return
		}
		log.Printf("tg-select: %s -> %s (active path dead %d/%d, verified-live re-pin)", tg.Now, target, d.tgFail, d.tgFailThresh)
		d.tgFail = 0
	} else {
		log.Printf("tg-select: active TG path '%s' dead; no better candidate verified — keeping (will retry)", tg.Now)
	}
}

// Run blocks until ctx is canceled. Initial wait for Clash API, initial
// sweep + pin, then liveness loop with periodic full sweeps.
func (d *Daemon) Run(ctx context.Context) {
	for {
		if _, err := d.nowPick(); err == nil {
			break
		}
		log.Printf("waiting for Clash API at %s ...", d.api)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}
	}
	log.Printf("Clash API ready, daemon starting")

	d.sweep(ctx)
	d.pinBest()
	d.tgManage(ctx) // pin Telegram promptly after the first sweep (no-op if tg-select absent)

	livTicker := time.NewTicker(*flagLivenessInterval)
	defer livTicker.Stop()
	rankTicker := time.NewTicker(*flagRankInterval)
	defer rankTicker.Stop()
	tgTicker := time.NewTicker(d.tgInterval)
	defer tgTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("daemon: ctx done, exit")
			return
		case <-livTicker.C:
			d.liveness(ctx)
		case <-rankTicker.C:
			d.sweep(ctx)
			d.pinBest()
			d.rotCnt = 0
		case <-tgTicker.C:
			d.tgManage(ctx)
		}
	}
}

// ── main ────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("hynet-hc ")

	if *flagLivenessBytes <= 0 {
		fmt.Fprintln(os.Stderr, "liveness-bytes must be > 0")
		os.Exit(2)
	}
	if !strings.HasPrefix(*flagLivenessURL, "http://") && !strings.HasPrefix(*flagLivenessURL, "https://") {
		fmt.Fprintln(os.Stderr, "liveness-url must be http(s)")
		os.Exit(2)
	}

	d := newDaemon()
	log.Printf("config: liveness=%s every %s, rank every %s, exclude=%v",
		d.livenessURL, *flagLivenessInterval, *flagRankInterval, d.excluded)
	mode := "manager-owned (TG_HYSTERIA=no)"
	if d.tgHysteria {
		mode = "hy2-primary if hy2 member present"
	}
	log.Printf("tg-config: select=%s mode=%s failover=%s every %s (fail-threshold %d, liveness %s)",
		d.tgSelectTag, mode, d.tgFailoverTag, d.tgInterval, d.tgFailThresh, d.tgLiveURL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		log.Printf("shutdown signal received")
		cancel()
	}()
	d.Run(ctx)

	// Graceful: restore best pin (if any) before exit so user keeps a working
	// outbound after daemon dies. Best-effort.
	d.pinBest()
	if err := errors.Unwrap(ctx.Err()); err != nil {
		log.Printf("ctx err: %v", err)
	}
}
