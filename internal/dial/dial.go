// Package dial connects stdin/stdout to a target, directly over the VPN when
// possible and through an portash gateway on 443 otherwise.
package dial

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"portash/internal/gateway"
	"portash/internal/pin"
	"portash/internal/resume"
	"portash/internal/wsconn"
)

type Options struct {
	Gateway       string             // host:port of the gateway, or https://host[/path] behind a tunnel
	Pins          []string           // sha256:... of accepted gateway keys; empty = verify with system CAs
	Token         string             // psh_...
	Device        ed25519.PrivateKey // signs each gateway request
	Network       netip.Prefix       // VPN CIDR; the direct path is only tried inside it
	DirectTimeout time.Duration      // 0 disables the direct attempt
	Verbose       io.Writer          // diagnostics (stderr), may be nil
	// Resume makes gateway streams survive network changes and sleep: the
	// stream reconnects and carries on for up to ResumeWindow (default 10m).
	Resume       bool
	ResumeWindow time.Duration
	Ticket       string // from Unlock, when the gateway requires one
	// TunnelCAs verifies the HTTPS of a tunnel or reverse proxy; nil uses the
	// system CAs.
	TunnelCAs *x509.CertPool
}

// ErrUnlockRequired means the gateway wants a fresh ticket.
var ErrUnlockRequired = errors.New("unlock required: run `portash unlock` (ticket missing or expired)")

// ErrSessionGone means the gateway no longer has the session to resume
// (it restarted, or the session was closed while we were away).
var ErrSessionGone = errors.New("the gateway no longer has this session")

func (o *Options) logf(format string, args ...any) {
	if o.Verbose != nil {
		fmt.Fprintf(o.Verbose, "portash: "+format+"\n", args...)
	}
}

// Connect returns a stream to target (IP:port).
func Connect(ctx context.Context, o Options, target string) (net.Conn, error) {
	if o.DirectTimeout > 0 && viaVPN(o.Network, target) {
		d := net.Dialer{Timeout: o.DirectTimeout, KeepAlive: 15 * time.Second}
		c, err := d.DialContext(ctx, "tcp", target)
		if err == nil {
			o.logf("direct to %s", target)
			return c, nil
		}
		o.logf("direct to %s failed (%v)", target, err)
	} else if o.DirectTimeout > 0 {
		o.logf("not trying %s directly: no route through the VPN", target)
	}
	if o.Gateway == "" {
		return nil, errors.New("direct connection failed and no gateway configured (portash login)")
	}
	if o.Resume {
		return resumable(ctx, o, target)
	}
	c, _, err := GatewayStream(ctx, o, target, "")
	if err != nil {
		return nil, fmt.Errorf("gateway %s: %w", o.Gateway, err)
	}
	o.logf("via gateway %s to %s", o.Gateway, target)
	return c, nil
}

// resumable opens a gateway stream that reconnects by itself.
func resumable(ctx context.Context, o Options, target string) (net.Conn, error) {
	t, sid, err := GatewayStream(ctx, o, target, "new")
	if err != nil {
		return nil, fmt.Errorf("gateway %s: %w", o.Gateway, err)
	}
	if sid == "" {
		o.logf("via gateway %s to %s (gateway can't resume streams)", o.Gateway, target)
		return t, nil
	}
	lost := make(chan error, 1)
	rc := resume.New(resume.Config{OnDetach: func(err error) {
		select {
		case lost <- err:
		default:
		}
	}})
	if err := rc.Attach(t); err != nil {
		return nil, fmt.Errorf("gateway %s: %w", o.Gateway, err)
	}
	o.logf("via gateway %s to %s, resumable", o.Gateway, target)
	go keepAttached(o, target, sid, rc, lost)
	return rc, nil
}

// keepAttached reconnects to the gateway whenever the transport fails, with
// backoff, until the session ends or the resume window runs out.
func keepAttached(o Options, target, sid string, rc *resume.Conn, lost <-chan error) {
	window := o.ResumeWindow
	if window <= 0 {
		window = 10 * time.Minute
	}
	for {
		var why error
		select {
		case <-rc.Done():
			return
		case why = <-lost:
		}
		o.logf("connection to gateway lost (%v), reconnecting", why)
		start, delay := time.Now(), 250*time.Millisecond
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			t, _, err := GatewayStream(ctx, o, target, sid)
			cancel()
			if err == nil {
				if err = rc.Attach(t); err == nil {
					o.logf("reconnected after %s", time.Since(start).Round(100*time.Millisecond))
					break
				}
			}
			if rc.Err() != nil {
				return
			}
			if errors.Is(err, ErrSessionGone) || errors.Is(err, ErrUnlockRequired) {
				rc.Abort(err)
				return
			}
			if time.Since(start) > window {
				rc.Abort(fmt.Errorf("could not reconnect within %s: %w", window, err))
				return
			}
			o.logf("reconnect failed: %v", err)
			select {
			case <-rc.Done():
				return
			case <-time.After(delay):
			}
			delay = min(delay*2, 5*time.Second)
		}
	}
}

// viaVPN reports whether the OS would send packets for target from an
// address inside the VPN network, i.e. through the Vabbit interface. When
// the VPN is down, the same IP may belong to a stranger on a hotel network
// (100.64.0.0/10 is carrier-grade NAT space), so the direct path is skipped.
func viaVPN(network netip.Prefix, target string) bool {
	if !network.IsValid() {
		return false
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil || !network.Contains(ap.Addr().Unmap()) {
		return false
	}
	// A UDP "connect" sends nothing; it just asks the kernel for the route.
	c, err := net.Dial("udp", target)
	if err != nil {
		return false
	}
	defer c.Close()
	local, ok := netip.AddrFromSlice(c.LocalAddr().(*net.UDPAddr).IP)
	return ok && network.Contains(local.Unmap()) && local.Unmap() != ap.Addr().Unmap()
}

// handshake opens a TLS connection to the gateway, checks its pin, and
// returns the exported keying material the device key signs.
func handshake(ctx context.Context, o Options) (*tls.Conn, []byte, error) {
	host, _, err := net.SplitHostPort(o.hostPort())
	if err != nil {
		return nil, nil, err
	}
	if len(o.Device) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("no device key (portash device)")
	}
	var raw net.Conn
	if strings.HasPrefix(o.Gateway, "https://") {
		raw, err = dialTunnel(ctx, o.Gateway, o.TunnelCAs)
	} else {
		raw, err = dialTCP(ctx, o.Gateway)
	}
	if err != nil {
		return nil, nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host, NextProtos: []string{"http/1.1"}}
	if len(o.Pins) > 0 {
		// The pin replaces CA verification entirely; VerifyConnection still
		// runs and rejects any other key.
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = pin.Verifier(o.Pins)
	}
	tc := tls.Client(raw, cfg)
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, nil, err
	}
	cs := tc.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(gateway.ExporterLabel, nil, 32)
	if err != nil {
		tc.Close()
		return nil, nil, err
	}
	return tc, ekm, nil
}

// GatewayStream opens one upgraded stream. resumeReq is "" (plain stream),
// "new" or a session id; the new session's id is returned.
func GatewayStream(ctx context.Context, o Options, target, resumeReq string) (net.Conn, string, error) {
	tc, ekm, err := handshake(ctx, o)
	if err != nil {
		return nil, "", err
	}
	sig := ed25519.Sign(o.Device, gateway.SignedMessage(ekm, target))
	req := "GET " + gateway.Path + "?target=" + url.QueryEscape(target) + " HTTP/1.1\r\n" +
		"Host: " + o.hostPort() + "\r\n" +
		"Authorization: Bearer " + o.Token + "\r\n" +
		gateway.SigHeader + ": " + base64.RawURLEncoding.EncodeToString(sig) + "\r\n" +
		"Connection: Upgrade\r\nUpgrade: " + gateway.UpgradeProto + "\r\n"
	if o.Ticket != "" {
		req += gateway.TicketHeader + ": " + o.Ticket + "\r\n"
	}
	if resumeReq != "" {
		req += gateway.ResumeHeader + ": " + resumeReq + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		tc.Close()
		return nil, "", err
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		tc.Close()
		return nil, "", err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		tc.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, "", errors.New("rejected (bad or expired token, wrong device, or not an portash gateway)")
		}
		if resp.StatusCode == http.StatusGone {
			return nil, "", ErrSessionGone
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, "", ErrUnlockRequired
		}
		return nil, "", fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	tc.SetDeadline(time.Time{})
	return &readerConn{Conn: tc, r: br}, resp.Header.Get(gateway.SessionHeader), nil
}

// dialTCP honours HTTPS_PROXY with an HTTP CONNECT, for networks that force a proxy.
func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}
	req, _ := http.NewRequest(http.MethodConnect, "https://"+addr, nil)
	proxy, err := http.ProxyFromEnvironment(req)
	if err != nil || proxy == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	pa := proxy.Host
	if proxy.Port() == "" {
		pa = net.JoinHostPort(proxy.Hostname(), "80")
	}
	c, err := d.DialContext(ctx, "tcp", pa)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	hdr := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if u := proxy.User; u != nil {
		p, _ := u.Password()
		hdr += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+p)) + "\r\n"
	}
	if _, err := io.WriteString(c, hdr+"\r\n"); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("proxy CONNECT: %s", resp.Status)
	}
	c.SetDeadline(time.Time{})
	return &readerConn{Conn: c, r: br}, nil
}

type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *readerConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Stdio pipes stdin/stdout through c. It returns when the remote side
// finishes sending, or when sending to it fails.
func Stdio(c net.Conn) error {
	upErr := make(chan error, 1)
	downErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(c, os.Stdin)
		if err == nil {
			if cw, ok := c.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
		}
		upErr <- err
	}()
	go func() {
		_, err := io.Copy(os.Stdout, c)
		downErr <- err
	}()
	var err error
	select {
	case err = <-downErr:
	case err = <-upErr:
		if err == nil {
			err = <-downErr // stdin closed cleanly; drain the rest of the reply
		}
	}
	c.Close()
	return err
}

// Unlock trades a TOTP code for a ticket (see gateway.Unlock).
func Unlock(ctx context.Context, o Options, code string) (string, time.Time, error) {
	tc, ekm, err := handshake(ctx, o)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tc.Close()
	sig := ed25519.Sign(o.Device, gateway.SignedMessage(ekm, gateway.UnlockTarget))
	req := "POST " + gateway.UnlockPath + " HTTP/1.1\r\n" +
		"Host: " + o.hostPort() + "\r\n" +
		"Authorization: Bearer " + o.Token + "\r\n" +
		gateway.SigHeader + ": " + base64.RawURLEncoding.EncodeToString(sig) + "\r\n" +
		gateway.TOTPHeader + ": " + code + "\r\n" +
		"Content-Length: 0\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		return "", time.Time{}, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		return "", time.Time{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", time.Time{}, errors.New("rejected (bad or expired token, wrong device, or the gateway doesn't require unlock)")
	default:
		return "", time.Time{}, errors.New(strings.TrimSpace(string(body)))
	}
	lines := strings.Fields(string(body))
	if len(lines) != 2 {
		return "", time.Time{}, errors.New("unexpected unlock response")
	}
	exp, err := time.Parse(time.RFC3339, lines[1])
	if err != nil {
		return "", time.Time{}, err
	}
	return lines[0], exp, nil
}

// hostPort is the gateway's host:port, also for a tunnel URL.
func (o *Options) hostPort() string {
	u, err := url.Parse(o.Gateway)
	if err != nil || u.Scheme != "https" {
		return o.Gateway
	}
	if u.Port() == "" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return u.Host
}

// dialTunnel reaches a gateway behind Cloudflare Tunnel or a reverse proxy:
// ordinary HTTPS to the proxy (checked against the system CAs), then a
// WebSocket to the gateway. The caller runs the pinned TLS handshake inside
// it, so the proxy can't read or alter the stream.
func dialTunnel(ctx context.Context, gw string, roots *x509.CertPool) (net.Conn, error) {
	u, err := url.Parse(gw)
	if err != nil {
		return nil, err
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		path = gateway.TunnelPath
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	raw, err := dialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: roots, NextProtos: []string{"http/1.1"}})
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	ws, err := wsconn.Client(tc, u.Host, path)
	if err != nil {
		tc.Close()
		return nil, err
	}
	tc.SetDeadline(time.Time{})
	return ws, nil
}
