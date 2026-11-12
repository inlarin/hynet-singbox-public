package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	flagTelegramHealth = flag.Bool("telegram-healthcheck", envBool("TELEGRAM_HEALTHCHECK", true), "require Telegram API and MTProto connectivity for every automatic candidate")
	flagTelegramAPI    = flag.String("telegram-api-url", envOr("TELEGRAM_API_URL", "https://api.telegram.org"), "Telegram API URL used for general outbound health checks")
	flagMTProtoAddr    = flag.String("mtproto-address", envOr("MTPROTO_ADDRESS", "149.154.167.50:80"), "Telegram MTProto TCP address used for CONNECT health checks")
)

func (d *Daemon) probeTelegram(ctx context.Context, proxyURL *url.URL) error {
	if !*flagTelegramHealth {
		return nil
	}
	if err := d.probeTelegramAPI(ctx, proxyURL); err != nil {
		return fmt.Errorf("telegram API: %w", err)
	}
	if err := d.probeMTProto(ctx, proxyURL); err != nil {
		return fmt.Errorf("mtproto CONNECT: %w", err)
	}
	return nil
}

func (d *Daemon) probeTelegramAPI(ctx context.Context, proxyURL *url.URL) error {
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: d.probeTimeout,
	}
	cli := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	pCtx, cancel := context.WithTimeout(ctx, d.probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(pCtx, "GET", *flagTelegramAPI, nil)
	if err != nil {
		return err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (d *Daemon) probeMTProto(ctx context.Context, proxyURL *url.URL) error {
	pCtx, cancel := context.WithTimeout(ctx, d.probeTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(pCtx, "tcp", proxyURL.Host)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d.probeTimeout))
	if _, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", *flagMTProtoAddr, *flagMTProtoAddr); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "HTTP/") || !strings.Contains(line, " 200 ") {
		return fmt.Errorf("proxy response %q", strings.TrimSpace(line))
	}
	return nil
}
