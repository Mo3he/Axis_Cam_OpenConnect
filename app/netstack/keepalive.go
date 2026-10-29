// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"time"
)

// startKeepAlive sends a small DNS query through the tunnel every
// GP_KEEPALIVE_MINUTES minutes (0 or unset: off), so a gateway idle timeout
// does not end the session of a camera nobody is currently viewing. The query
// is for GP_KEEPALIVE_HOST (the portal's own name) and goes to the DNS servers
// the gateway pushed, so it never leaves the VPN.
func (t *tunnel) startKeepAlive(dnsServers []netip.Addr) {
	minutes, _ := strconv.Atoi(os.Getenv("GP_KEEPALIVE_MINUTES"))
	if minutes <= 0 {
		return
	}
	if len(dnsServers) == 0 {
		slog.Warn("keep-alive is on, but the gateway pushed no DNS server to send it to; it stays off")
		return
	}
	// An address would be answered locally without a query; any name works,
	// since a "no such name" answer is tunnel traffic too.
	host := os.Getenv("GP_KEEPALIVE_HOST")
	if _, err := netip.ParseAddr(host); err == nil || host == "" {
		host = "keepalive.invalid"
	}
	interval := time.Duration(minutes) * time.Minute
	slog.Info("keep-alive on", "every", interval.String(), "dns", dnsServers[0].String(), "query", host)

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-t.stopCh:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, err := t.tnet.LookupContextHost(ctx, host)
				cancel()
				if err != nil {
					slog.Debug("keep-alive query", "err", err)
				}
			}
		}
	}()
}
