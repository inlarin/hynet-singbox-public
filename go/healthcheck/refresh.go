package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"
)

func singBoxPIDs() string {
	output, err := exec.Command("pidof", "sing-box").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func terminateSingBox() {
	for _, pid := range strings.Fields(singBoxPIDs()) {
		_ = exec.Command("kill", "-TERM", pid).Run()
	}
}

func copyFileAtomic(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	temporary := destination + ".new"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, destination)
}

func configsEqual(first, second string) bool {
	firstData, err := os.ReadFile(first)
	if err != nil {
		return false
	}
	secondData, err := os.ReadFile(second)
	if err != nil {
		return false
	}
	var firstConfig, secondConfig any
	if json.Unmarshal(firstData, &firstConfig) != nil || json.Unmarshal(secondData, &secondConfig) != nil {
		return false
	}
	return reflect.DeepEqual(firstConfig, secondConfig)
}

func clashBaseURL() string {
	if value := os.Getenv("CLASH_API"); value != "" {
		return strings.TrimRight(value, "/")
	}
	return "http://" + envOr("CLASH_ADDR", "172.20.0.2:9090")
}

func clashRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, clashBaseURL()+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("CLASH_SECRET"))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	return client.Do(req)
}

func currentSelection() string {
	resp, err := clashRequest(http.MethodGet, "/proxies/select", nil)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var selection struct {
		Now string `json:"now"`
	}
	if json.NewDecoder(resp.Body).Decode(&selection) != nil {
		return ""
	}
	return selection.Now
}

func restoreSelection(tag string) error {
	if tag == "" {
		return nil
	}
	payload, _ := json.Marshal(map[string]string{"name": tag})
	resp, err := clashRequest(http.MethodPut, "/proxies/select", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Clash API returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func waitForClash(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := clashRequest(http.MethodGet, "/version", nil)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(time.Second)
	}
	return false
}

func runRefresh(args []string) int {
	flags := flag.NewFlagSet("refresh", flag.ContinueOnError)
	subscriptionsDir := flags.String("subscriptions-dir", envOr("SINGBOX_SUBS_DIR", "/tmp/sing-box/subscriptions.d"), "directory containing provider .conf files")
	activeConfig := flags.String("active-config", envOr("SINGBOX_ACTIVE_CONFIG", "/tmp/config.json"), "active sing-box config")
	countryCache := flags.String("country-cache", envOr("SINGBOX_COUNTRY_CACHE", "/tmp/country_cache.json"), "country cache path")
	countriesOut := flags.String("countries-out", envOr("SINGBOX_COUNTRIES_OUT", "/tmp/probe_countries.json"), "tag-to-country output")
	probePortsOut := flags.String("probe-ports-out", envOr("PROBE_PORTS", "/tmp/probe_ports.json"), "tag-to-probe-port output")
	secret := flags.String("secret", envOr("CLASH_SECRET", os.Getenv("SINGBOX_HEALTHCHECK_SECRET")), "Clash API secret")
	routerIP := flags.String("router-ip", envOr("ROUTER_HOST", "172.20.0.1"), "router DNS address")
	only := flags.String("only", "", "comma-separated providers to refresh")
	drop := flags.String("drop", "", "comma-separated providers to drop")
	singBoxBinary := flags.String("sing-box", "/usr/local/bin/sing-box", "sing-box binary used for config validation")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *secret == "" {
		fmt.Fprintln(os.Stderr, "refresh: CLASH_SECRET is required")
		return 2
	}
	candidate := *activeConfig + ".candidate"
	_ = os.Remove(candidate)
	defer os.Remove(candidate)

	running := singBoxPIDs() != ""
	if running {
		_ = os.Setenv("SINGBOX_REFRESH_PROXY", "http://127.0.0.1:7899")
	}
	renderArgs := []string{
		"--subscriptions-dir", *subscriptionsDir,
		"--active-config", *activeConfig,
		"--out", candidate,
		"--country-cache", *countryCache,
		"--countries-out", *countriesOut,
		"--probe-ports-out", *probePortsOut,
		"--secret", *secret,
		"--router-ip", *routerIP,
	}
	if *only != "" {
		renderArgs = append(renderArgs, "--only", *only)
	}
	if *drop != "" {
		renderArgs = append(renderArgs, "--drop", *drop)
	}
	renderRC := runRender(renderArgs)
	if renderRC == 1 {
		fmt.Fprintln(os.Stderr, "refresh: candidate generation failed; keeping current config")
		return 1
	}
	if renderRC == 2 {
		fmt.Fprintln(os.Stderr, "refresh: at least one subscription failed; its running nodes were kept")
	}
	check := exec.Command(*singBoxBinary, "check", "-c", candidate)
	if output, err := check.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "refresh: sing-box check rejected candidate: %v\n%s\n", err, output)
		return 2
	}
	if configsEqual(*activeConfig, candidate) {
		fmt.Fprintln(os.Stderr, "refresh: pool identical; keeping running config, no restart")
		return 0
	}

	selection := currentSelection()
	previous := *activeConfig + ".prev"
	_ = os.Remove(previous)
	if _, err := os.Stat(*activeConfig); err == nil {
		if err := copyFileAtomic(*activeConfig, previous); err != nil {
			fmt.Fprintln(os.Stderr, "refresh: could not back up current config:", err)
			return 1
		}
	}
	if err := os.Chmod(candidate, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "refresh:", err)
		return 1
	}
	if err := os.Rename(candidate, *activeConfig); err != nil {
		fmt.Fprintln(os.Stderr, "refresh: could not replace active config:", err)
		return 1
	}
	if !running {
		fmt.Fprintln(os.Stderr, "refresh: config replaced; sing-box is not running, no restart needed")
		return 0
	}

	fmt.Fprintln(os.Stderr, "refresh: config replaced; restarting sing-box")
	terminateSingBox()
	time.Sleep(time.Second)
	if !waitForClash(30 * time.Second) {
		fmt.Fprintln(os.Stderr, "refresh: new config did not start; restoring previous config")
		if _, err := os.Stat(previous); err == nil {
			restore := *activeConfig + ".restore"
			_ = os.Remove(restore)
			if copyFileAtomic(previous, restore) == nil && os.Rename(restore, *activeConfig) == nil {
				terminateSingBox()
				waitForClash(15 * time.Second)
			}
		}
		return 2
	}
	if err := restoreSelection(selection); err != nil {
		fmt.Fprintln(os.Stderr, "refresh: previous select.now is no longer available:", err)
	} else if selection != "" {
		fmt.Fprintln(os.Stderr, "refresh: restored select.now")
	}
	fmt.Fprintln(os.Stderr, "refresh: done")
	return 0
}
