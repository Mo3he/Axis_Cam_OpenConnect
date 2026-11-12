// SPDX-License-Identifier: BSD-3-Clause

// Userspace netstack + proxy sidecar for the OpenConnect ACAP. OpenConnect's
// --script-tun mode hands us a SOCK_DGRAM socketpair fd in $VPNFD (one datagram
// == one decrypted IP packet); a gVisor netstack on it (wireguard's helper, used
// only for stack setup) runs the same forwarders and proxies as the WireGuard
// and OpenVPN ACAPs. No kernel TUN, no root.
//
// Args: netstack_proxy <tun_fd> <client_cidr> <mtu> <http_port> <socks_port> [forward_ports] [dns_servers]

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// defaultForwardPorts are forwarded directly: VPN-IP:port -> camera port.
var defaultForwardPorts = []int{80, 443, 554}

// maxForwardPorts caps how many listeners a config can ask for.
const maxForwardPorts = 16

// parseForwardPorts returns up to maxForwardPorts unique valid ports, or the defaults if none.
func parseForwardPorts(value string) []int {
	ports := make([]int, 0, maxForwardPorts)
	seen := make(map[int]bool, maxForwardPorts)
	for _, field := range strings.Split(value, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
		if len(ports) == maxForwardPorts {
			break
		}
	}
	if len(ports) == 0 {
		return defaultForwardPorts
	}
	return ports
}

// inboundSOCKS5Port is the SOCKS5 port on the VPN interface (netstack side).
const inboundSOCKS5Port = 1080

const pumpOffset = 0

type tunnel struct {
	tnet   *netstack.Net
	vpnDNS bool
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// parseDNSServers accepts the space- or comma-separated IPv4 list OpenConnect
// exports as INTERNAL_IP4_DNS.
func parseDNSServers(value string) []netip.Addr {
	var servers []netip.Addr
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' }) {
		if addr, err := netip.ParseAddr(field); err == nil && addr.Is4() {
			servers = append(servers, addr)
		}
	}
	return servers
}

func parsePort(s string, def int) int {
	if p, err := strconv.Atoi(s); err == nil && p > 0 && p < 65536 {
		return p
	}
	return def
}

// reportPortUnavailable tells the app bridge, which reads our stderr through
// OpenConnect, that an outbound proxy could not start (usually another app on
// the camera already uses the port).
func reportPortUnavailable(kind string, port int, err error) {
	reason := err.Error()
	if strings.Contains(reason, "address already in use") {
		reason = "already in use by another app"
	}
	fmt.Fprintf(os.Stderr, "netstack: outbound %s proxy port %d unavailable: %s\n", kind, port, reason)
}

// pump copies IP packets both ways between the OpenConnect socketpair fd and the netstack device.
func (t *tunnel) pump(dev tun.Device, fd *os.File, mtu int) {
	// inbound: fd -> netstack
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		buf := make([]byte, mtu+256)
		for {
			n, err := fd.Read(buf)
			if err != nil {
				select {
				case <-t.stopCh:
				default:
					slog.Error("tun fd read", "err", err)
				}
				return
			}
			if n <= 0 {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			if _, err := dev.Write([][]byte{pkt}, pumpOffset); err != nil {
				slog.Warn("netstack write", "err", err)
			}
		}
	}()

	// outbound: netstack -> fd
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		bufs := [][]byte{make([]byte, mtu+256)}
		sizes := make([]int, 1)
		for {
			k, err := dev.Read(bufs, sizes, pumpOffset)
			if err != nil {
				select {
				case <-t.stopCh:
				default:
					slog.Error("netstack read", "err", err)
				}
				return
			}
			for i := 0; i < k; i++ {
				if _, err := fd.Write(bufs[i][pumpOffset : pumpOffset+sizes[i]]); err != nil {
					slog.Warn("tun fd write", "err", err)
				}
			}
		}
	}()
}

// runTCPProxy listens on localAddr:port inside the netstack and forwards each
// accepted connection to the same camera port.
func (t *tunnel) runTCPProxy(localAddr netip.Addr, port int) {
	defer t.wg.Done()
	listenAddr := net.TCPAddrFromAddrPort(netip.AddrPortFrom(localAddr, uint16(port)))
	ln, err := t.tnet.ListenTCP(listenAddr)
	if err != nil {
		slog.Error("proxy listen", "port", port, "err", err)
		return
	}
	go func() { <-t.stopCh; _ = ln.Close() }()
	slog.Info("transparent forwarder ready", "listen", listenAddr, "dst", net.JoinHostPort(cameraHost, strconv.Itoa(port)))
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-t.stopCh:
				return
			default:
				time.Sleep(time.Second)
				continue
			}
		}
		go relay(c, port)
	}
}

func relay(src net.Conn, port int) {
	defer src.Close()
	dstConn, err := dialCamera(port)
	if err != nil {
		return
	}
	defer dstConn.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dstConn, src); done <- struct{}{} }()
	go func() { _, _ = io.Copy(src, dstConn); done <- struct{}{} }()
	<-done
}

// runInboundSOCKS5 listens on the VPN IP and forwards SOCKS5 CONNECT to the
// requested camera port (VPN peer -> any camera port).
func (t *tunnel) runInboundSOCKS5(localAddr netip.Addr, port int) {
	defer t.wg.Done()
	listenAddr := net.TCPAddrFromAddrPort(netip.AddrPortFrom(localAddr, uint16(port)))
	ln, err := t.tnet.ListenTCP(listenAddr)
	if err != nil {
		slog.Error("inbound socks5 listen", "err", err)
		return
	}
	go func() { <-t.stopCh; _ = ln.Close() }()
	slog.Info("inbound SOCKS5 ready", "addr", listenAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-t.stopCh:
				return
			default:
				time.Sleep(time.Second)
				continue
			}
		}
		go handleInboundSOCKS5(c)
	}
}

// handleInboundSOCKS5 implements SOCKS5 CONNECT (RFC 1928); the destination host
// is always replaced with the camera so it can only reach local camera services.
func handleInboundSOCKS5(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 257)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(c, buf[:nmethods]); err != nil {
		return
	}
	_, _ = c.Write([]byte{0x05, 0x00})
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var port uint16
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(c, buf[:6]); err != nil {
			return
		}
		port = binary.BigEndian.Uint16(buf[4:6])
	case 0x03:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		nameLen := int(buf[0])
		if _, err := io.ReadFull(c, buf[:nameLen+2]); err != nil {
			return
		}
		port = binary.BigEndian.Uint16(buf[nameLen : nameLen+2])
	case 0x04:
		if _, err := io.ReadFull(c, buf[:18]); err != nil {
			return
		}
		port = binary.BigEndian.Uint16(buf[16:18])
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = c.SetDeadline(time.Time{})
	dstConn, err := dialCamera(int(port))
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer dstConn.Close()
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(port >> 8), byte(port)})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(dstConn, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, dstConn); done <- struct{}{} }()
	<-done
}

// resolve tries the DNS servers pushed by the gateway (through the tunnel) so
// internal names work, then falls back to the camera's own resolver.
func (t *tunnel) resolve(ctx context.Context, host string) (string, error) {
	if t.vpnDNS {
		vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := t.tnet.LookupContextHost(vctx, host)
		cancel()
		if err == nil && len(addrs) > 0 {
			return addrs[0], nil
		}
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("resolve %s: %w", host, err)
	}
	return addrs[0], nil
}

// dialViaVPN resolves the host (VPN DNS first) and dials through the tunnel.
func (t *tunnel) dialViaVPN(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip == nil {
		host, err = t.resolve(ctx, host)
		if err != nil {
			return nil, err
		}
	}
	return t.tnet.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
}

// runHTTPProxy listens on 127.0.0.1:port (host) and handles HTTP CONNECT (and
// plain HTTP) by tunnelling through the netstack (camera -> VPN/internet).
func (t *tunnel) runHTTPProxy(port int) {
	defer t.wg.Done()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		slog.Error("http proxy listen failed", "port", port, "err", err)
		reportPortUnavailable("HTTP", port, err)
		return
	}
	go func() { <-t.stopCh; _ = ln.Close() }()
	slog.Info("HTTP CONNECT proxy ready", "addr", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-t.stopCh:
				return
			default:
				time.Sleep(time.Second)
				continue
			}
		}
		go t.handleHTTPProxy(c)
	}
}

func (t *tunnel) handleHTTPProxy(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	rd := bufio.NewReader(c)
	requestLine, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(requestLine), " ", 3)
	if len(parts) != 3 {
		return
	}
	method, target, httpVer := parts[0], parts[1], parts[2]
	if strings.ToUpper(method) == "CONNECT" {
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			if strings.TrimSpace(line) == "" {
				break
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		upstream, err := t.dialViaVPN(ctx, target)
		cancel()
		if err != nil {
			_, _ = fmt.Fprintf(c, "%s 502 Bad Gateway\r\n\r\n", httpVer)
			return
		}
		defer upstream.Close()
		_ = c.SetDeadline(time.Time{})
		_, _ = fmt.Fprintf(c, "%s 200 Connection established\r\n\r\n", httpVer)
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(upstream, rd); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
		<-done
		return
	}
	u, err := url.Parse(target)
	if err != nil {
		_, _ = fmt.Fprintf(c, "%s 400 Bad Request\r\n\r\n", httpVer)
		return
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	var headerLines []string
	for {
		line, readErr := rd.ReadString('\n')
		if readErr != nil {
			return
		}
		headerLines = append(headerLines, line)
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	upstream, err := t.dialViaVPN(ctx, host)
	cancel()
	if err != nil {
		_, _ = fmt.Fprintf(c, "%s 502 Bad Gateway\r\n\r\n", httpVer)
		return
	}
	defer upstream.Close()
	_ = c.SetDeadline(time.Time{})
	_, _ = fmt.Fprintf(upstream, "%s %s %s\r\n", method, u.RequestURI(), httpVer)
	for _, h := range headerLines {
		_, _ = upstream.Write([]byte(h))
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, rd); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

// runOutboundSOCKS5 listens on 127.0.0.1:port (host) and forwards SOCKS5 CONNECT
// through the netstack (camera services -> VPN/internet).
func (t *tunnel) runOutboundSOCKS5(port int) {
	defer t.wg.Done()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		slog.Error("outbound socks5 listen failed", "port", port, "err", err)
		reportPortUnavailable("SOCKS5", port, err)
		return
	}
	go func() { <-t.stopCh; _ = ln.Close() }()
	slog.Info("outbound SOCKS5 ready", "addr", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-t.stopCh:
				return
			default:
				time.Sleep(time.Second)
				continue
			}
		}
		go t.handleOutboundSOCKS5(c)
	}
}

func (t *tunnel) handleOutboundSOCKS5(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 257)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(c, buf[:nmethods]); err != nil {
		return
	}
	_, _ = c.Write([]byte{0x05, 0x00})
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	if buf[0] != 0x05 || buf[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	var hostport string
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(c, buf[:6]); err != nil {
			return
		}
		ip := net.IP(buf[:4]).String()
		port := binary.BigEndian.Uint16(buf[4:6])
		hostport = net.JoinHostPort(ip, strconv.Itoa(int(port)))
	case 0x03:
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		nameLen := int(buf[0])
		if _, err := io.ReadFull(c, buf[:nameLen+2]); err != nil {
			return
		}
		name := string(buf[:nameLen])
		port := binary.BigEndian.Uint16(buf[nameLen : nameLen+2])
		hostport = net.JoinHostPort(name, strconv.Itoa(int(port)))
	case 0x04:
		if _, err := io.ReadFull(c, buf[:18]); err != nil {
			return
		}
		ip := net.IP(buf[:16]).String()
		port := binary.BigEndian.Uint16(buf[16:18])
		hostport = net.JoinHostPort(ip, strconv.Itoa(int(port)))
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = c.SetDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	upstream, err := t.dialViaVPN(ctx, hostport)
	cancel()
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, upstream); done <- struct{}{} }()
	<-done
}

func main() {
	if w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, "OpenConnect_VPN"); err == nil {
		slog.SetDefault(slog.New(slog.NewTextHandler(w, nil)))
	}

	// A peer-closed SOCK_DGRAM socketpair never reads EOF, so without this an
	// orphaned sidecar would keep the proxy ports bound after OpenConnect dies.
	exitWithParent()

	if len(os.Args) < 6 {
		slog.Error("usage: netstack_proxy <tun_fd> <client_cidr> <mtu> <http_port> <socks_port> [forward_ports] [dns_servers]")
		os.Exit(2)
	}
	fdNum, _ := strconv.Atoi(os.Args[1])
	clientCIDR := os.Args[2]
	mtu := parsePort(os.Args[3], 1500)
	httpPort := parsePort(os.Args[4], 28080)
	socksOutPort := parsePort(os.Args[5], 21080)
	forwardPorts := defaultForwardPorts
	if len(os.Args) > 6 {
		forwardPorts = parseForwardPorts(os.Args[6])
	}
	var dnsServers []netip.Addr
	if len(os.Args) > 7 {
		dnsServers = parseDNSServers(os.Args[7])
	}

	prefix, err := netip.ParsePrefix(clientCIDR)
	if err != nil {
		slog.Error("invalid client CIDR", "cidr", clientCIDR, "err", err)
		os.Exit(1)
	}
	localAddr := prefix.Addr()

	fd := os.NewFile(uintptr(fdNum), "tun")
	if fd == nil {
		slog.Error("invalid tun fd", "fd", fdNum)
		os.Exit(1)
	}

	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{localAddr}, dnsServers, mtu)
	if err != nil {
		slog.Error("create netstack", "err", err)
		os.Exit(1)
	}

	t := &tunnel{tnet: tnet, vpnDNS: len(dnsServers) > 0, stopCh: make(chan struct{})}
	t.pump(dev, fd, mtu)

	for _, port := range forwardPorts {
		t.wg.Add(1)
		go t.runTCPProxy(localAddr, port)
	}
	t.wg.Add(1)
	go t.runInboundSOCKS5(localAddr, inboundSOCKS5Port)
	t.wg.Add(1)
	go t.runHTTPProxy(httpPort)
	t.wg.Add(1)
	go t.runOutboundSOCKS5(socksOutPort)

	slog.Info("netstack proxy up", "vpn_ip", localAddr.String(), "mtu", mtu, "vpn_dns", len(dnsServers))
	t.startKeepAlive(dnsServers)
	t.wg.Wait()
}
