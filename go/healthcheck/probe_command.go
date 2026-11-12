package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

func runProbe(args []string) int {
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	api := flags.String("api", envOr("CLASH_API", "http://127.0.0.1:9090"), "Clash API endpoint")
	secret := flags.String("secret", os.Getenv("CLASH_SECRET"), "Clash API bearer token")
	timeout := flags.Duration("timeout", 5*time.Second, "probe timeout")
	realData := flags.Bool("real-data", envBool("PROBE_REAL_DATA", false), "also test the current outbound with a real download")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	client := &http.Client{Timeout: *timeout}
	req, err := http.NewRequest(http.MethodGet, *api+"/version", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+*secret)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: Clash API:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "probe: Clash API HTTP", resp.StatusCode)
		return 1
	}
	if !*realData {
		fmt.Println("probe: Clash API OK")
		return 0
	}

	d := newDaemon()
	d.api = *api
	d.secret = *secret
	d.probeTimeout = *timeout
	if err := d.loadPortMap(); err != nil {
		fmt.Fprintln(os.Stderr, "probe: load probe ports:", err)
		return 1
	}
	tag, err := d.resolveNow()
	if err != nil || tag == "" {
		fmt.Fprintln(os.Stderr, "probe: cannot resolve current outbound:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	rtt, err := d.probeViaPort(ctx, d.portMap[tag])
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: current outbound failed:", err)
		return 1
	}
	fmt.Printf("probe: current outbound %s OK in %s\n", tag, rtt)
	return 0
}
