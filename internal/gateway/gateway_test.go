package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"portash/internal/dial"
	"portash/internal/gateway"
	"portash/internal/pin"
	"portash/internal/resume"
	"portash/internal/tokens"
	"portash/internal/totp"
)

type env struct {
	g       *gateway.Gateway
	device  ed25519.PrivateKey
	gwAddr  string
	pin     string
	token   string
	tokPath string
	echo    string // echo server address, inside the allowed network
	cert    tls.Certificate
}

func setup(t *testing.T) env { return setupWith(t, nil) }

func setupWith(t *testing.T, tweak func(*gateway.Config)) env {
	t.Helper()
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "tokens")
	pub, device, _ := ed25519.GenerateKey(rand.Reader)
	tok, err := tokens.Add(tokPath, "laptop", pub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store, err := tokens.NewStore(tokPath)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.(*net.TCPConn).CloseWrite() }()
		}
	}()
	_, echoPort, _ := net.SplitHostPort(ln.Addr().String())
	ports, _ := gateway.ParsePorts(echoPort)
	cfg := gateway.Config{
		Network:     netip.MustParsePrefix("127.0.0.0/8"),
		Ports:       ports,
		Tokens:      store,
		MaxStreams:  2,
		FailLimit:   3,
		IdleTimeout: 300 * time.Millisecond,
		SweepEvery:  50 * time.Millisecond,
		Log:         log.New(io.Discard, "", 0),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	g, err := gateway.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pin.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(g)
	srv.TLS = g.Server("", cert).TLSConfig
	srv.StartTLS()
	t.Cleanup(srv.Close)
	leaf, _ := pin.Leaf(cert)
	return env{g: g, device: device, gwAddr: srv.Listener.Addr().String(), pin: pin.Of(leaf), token: tok, tokPath: tokPath, echo: ln.Addr().String(), cert: cert}
}

func (e env) opts() dial.Options {
	return dial.Options{Gateway: e.gwAddr, Pins: []string{e.pin}, Token: e.token, Device: e.device}
}

func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	msg := strings.Repeat("hello through 443 ", 10000)
	go func() {
		io.WriteString(c, msg)
		c.(interface{ CloseWrite() error }).CloseWrite()
	}()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Fatalf("echo mismatch: %d bytes", len(got))
	}
}

func TestStreamThroughGateway(t *testing.T) {
	e := setup(t)
	c, err := dial.Connect(context.Background(), e.opts(), e.echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip(t, c)
}

func TestRejectsBadToken(t *testing.T) {
	e := setup(t)
	o := e.opts()
	o.Token = "psh_" + strings.Repeat("A", 43)
	if _, err := dial.Connect(context.Background(), o, e.echo); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("want rejection, got %v", err)
	}
}

func TestRevocationIsImmediate(t *testing.T) {
	e := setup(t)
	if err := tokens.Remove(e.tokPath, "laptop"); err != nil {
		t.Fatal(err)
	}
	if _, err := dial.Connect(context.Background(), e.opts(), e.echo); err == nil {
		t.Fatal("revoked token still accepted")
	}
}

func TestRejectsWrongPin(t *testing.T) {
	e := setup(t)
	o := e.opts()
	o.Pins = []string{"sha256:" + strings.Repeat("A", 43)}
	_, err := dial.Connect(context.Background(), o, e.echo)
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("want pin mismatch, got %v", err)
	}
}

func TestTargetRestrictions(t *testing.T) {
	e := setup(t)
	_, port, _ := net.SplitHostPort(e.echo)
	for _, target := range []string{
		"10.0.0.1:" + port,          // outside network
		"169.254.169.254:" + port,   // cloud metadata
		"127.0.0.1:1",               // port not allowed
		"localhost:" + port,         // names are not accepted
		"[::ffff:10.0.0.1]:" + port, // mapped IPv6 outside network
	} {
		if _, err := dial.Connect(context.Background(), e.opts(), target); err == nil || !strings.Contains(err.Error(), "403") {
			t.Errorf("%s: want 403, got %v", target, err)
		}
	}
}

func TestStreamLimit(t *testing.T) {
	e := setup(t)
	var open []net.Conn
	for i := 0; i < 2; i++ {
		c, err := dial.Connect(context.Background(), e.opts(), e.echo)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
	}
	if _, err := dial.Connect(context.Background(), e.opts(), e.echo); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("want 429, got %v", err)
	}
	for _, c := range open {
		c.Close()
	}
}

func TestPlainProbeLooksLike404(t *testing.T) {
	e := setup(t)
	c, err := tls.Dial("tcp", e.gwAddr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /v1/tcp?target="+e.echo+" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(b), "HTTP/1.1 404") {
		t.Fatalf("got %q", strings.SplitN(string(b), "\r\n", 2)[0])
	}
}

func TestTokenFileMustBePrivate(t *testing.T) {
	e := setup(t)
	os.Chmod(e.tokPath, 0o644)
	if _, err := tokens.NewStore(e.tokPath); err == nil {
		t.Fatal("world-readable token file accepted")
	}
}

func TestRejectsOtherDevice(t *testing.T) {
	e := setup(t)
	o := e.opts()
	_, o.Device, _ = ed25519.GenerateKey(rand.Reader) // the token copied to another machine
	if _, err := dial.Connect(context.Background(), o, e.echo); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("token worked from another device: %v", err)
	}
}

func TestAcceptsSecondPin(t *testing.T) {
	e := setup(t)
	o := e.opts()
	o.Pins = []string{"sha256:" + strings.Repeat("A", 43), e.pin} // rotation: next key pinned first
	c, err := dial.Connect(context.Background(), o, e.echo)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestExpiredTokenRejected(t *testing.T) {
	e := setup(t)
	entries, _ := tokens.Load(e.tokPath)
	entries[0].Expires = time.Now().Add(-time.Minute)
	if err := tokens.Save(e.tokPath, entries); err != nil {
		t.Fatal(err)
	}
	if _, err := dial.Connect(context.Background(), e.opts(), e.echo); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestRevocationKillsOpenStream(t *testing.T) {
	e := setup(t)
	c, err := dial.Connect(context.Background(), e.opts(), e.echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := tokens.Remove(e.tokPath, "laptop"); err != nil {
		t.Fatal(err)
	}
	keepBusy(c)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("stream not closed after revocation: %v", err)
	}
}

func TestIdleStreamClosed(t *testing.T) {
	e := setup(t)
	c, err := dial.Connect(context.Background(), e.opts(), e.echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("idle stream not closed: %v", err)
	}
}

// keepBusy writes now and then so the idle timeout doesn't explain a close.
func keepBusy(c net.Conn) {
	go func() {
		for i := 0; i < 40; i++ {
			if _, err := c.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
}

func TestRepeatedFailuresAreIgnored(t *testing.T) {
	e := setup(t)
	bad := e.opts()
	bad.Token = "psh_" + strings.Repeat("A", 43)
	for i := 0; i < 3; i++ {
		dial.Connect(context.Background(), bad, e.echo)
	}
	// Now even the right token from this IP gets the bare 404 until the window passes.
	if _, err := dial.Connect(context.Background(), e.opts(), e.echo); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("want lockout, got %v", err)
	}
}

func TestDirectPathNeedsVPNRoute(t *testing.T) {
	e := setup(t)
	o := e.opts()
	o.DirectTimeout = time.Second
	var log strings.Builder
	o.Verbose = &log
	// The echo server is on 127.0.0.1; a "VPN" of 10.99.0.0/16 doesn't contain it,
	// so portash must not dial it directly and must use the gateway.
	o.Network = netip.MustParsePrefix("10.99.0.0/16")
	c, err := dial.Connect(context.Background(), o, e.echo)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if !strings.Contains(log.String(), "via gateway") || strings.Contains(log.String(), "direct to") {
		t.Fatalf("expected gateway path, got: %s", log.String())
	}
	// No network configured: never direct.
	o.Network = netip.Prefix{}
	log.Reset()
	c, err = dial.Connect(context.Background(), o, e.echo)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if strings.Contains(log.String(), "direct to") {
		t.Fatalf("direct attempted without a VPN network: %s", log.String())
	}
}

func (e env) resumeOpts() dial.Options {
	o := e.opts()
	o.Resume = true
	return o
}

// The client's connection drops twice mid-stream; the stream carries on and
// nothing is lost or repeated.
func TestStreamResumesAfterDrop(t *testing.T) {
	e := setup(t)
	c, err := dial.Connect(context.Background(), e.resumeOpts(), e.echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rc, ok := c.(*resume.Conn)
	if !ok {
		t.Fatalf("got %T, want a resumable stream", c)
	}
	msg := strings.Repeat("survives a dropped connection ", 20000)
	go func() {
		third := len(msg) / 3
		io.WriteString(c, msg[:third])
		rc.Detach()
		io.WriteString(c, msg[third:2*third])
		time.Sleep(100 * time.Millisecond)
		rc.Detach()
		io.WriteString(c, msg[2*third:])
		rc.CloseWrite()
	}()
	done := make(chan []byte)
	go func() { got, _ := io.ReadAll(c); done <- got }()
	select {
	case got := <-done:
		if string(got) != msg {
			t.Fatalf("got %d bytes, want %d", len(got), len(msg))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not resume")
	}
}

// A session id alone is useless: resuming needs the same token and device,
// for the same target.
func TestResumeNeedsSameToken(t *testing.T) {
	e := setup(t)
	o := e.opts()
	tr, sid, err := dial.GatewayStream(context.Background(), o, e.echo, "new")
	if err != nil || sid == "" {
		t.Fatalf("new session: sid=%q err=%v", sid, err)
	}
	defer tr.Close()

	pub, dev2, _ := ed25519.GenerateKey(rand.Reader)
	tok2, err := tokens.Add(e.tokPath, "other", pub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other := o
	other.Token, other.Device = tok2, dev2
	if _, _, err := dial.GatewayStream(context.Background(), other, e.echo, sid); !errors.Is(err, dial.ErrSessionGone) {
		t.Fatalf("other token resumed someone else's session: %v", err)
	}
	if _, _, err := dial.GatewayStream(context.Background(), o, e.echo, "not-a-session"); !errors.Is(err, dial.ErrSessionGone) {
		t.Fatalf("unknown session: %v", err)
	}
}

// If the client doesn't come back within the resume window, the gateway
// closes the session and a later resume is refused.
func TestUnresumedSessionExpires(t *testing.T) {
	e := setupWith(t, func(c *gateway.Config) { c.ResumeWindow = 200 * time.Millisecond })
	o := e.opts()
	tr, sid, err := dial.GatewayStream(context.Background(), o, e.echo, "new")
	if err != nil {
		t.Fatal(err)
	}
	rc := resume.New(resume.Config{})
	if err := rc.Attach(tr); err != nil {
		t.Fatal(err)
	}
	rc.Detach() // and never come back
	time.Sleep(600 * time.Millisecond)
	if _, _, err := dial.GatewayStream(context.Background(), o, e.echo, sid); !errors.Is(err, dial.ErrSessionGone) {
		t.Fatalf("expired session resumed: %v", err)
	}
}

func TestRevocationKillsResumableStream(t *testing.T) {
	e := setup(t)
	c, err := dial.Connect(context.Background(), e.resumeOpts(), e.echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := tokens.Remove(e.tokPath, "laptop"); err != nil {
		t.Fatal(err)
	}
	keepBusy(c)
	done := make(chan struct{})
	go func() { io.Copy(io.Discard, c); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("resumable stream not closed after revocation")
	}
}

const testSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

func code(t *testing.T, offset int64) string {
	t.Helper()
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(testSecret)
	return totp.Code(raw, totp.Step(time.Now())+offset)
}

func setupUnlock(t *testing.T, ttl time.Duration) env {
	dir := t.TempDir()
	st := totp.Store{Dir: filepath.Join(dir, "unlock"), ValidName: tokens.ValidName}
	if err := st.Import("laptop", testSecret); err != nil {
		t.Fatal(err)
	}
	return setupWith(t, func(c *gateway.Config) {
		c.Unlock = &gateway.Unlock{TOTP: st, TicketTTL: ttl, File: filepath.Join(dir, "tickets")}
	})
}

// Without a ticket nothing connects; one TOTP code buys a ticket that then
// works for every connection, with no further prompts.
func TestUnlockGatesStreams(t *testing.T) {
	e := setupUnlock(t, time.Hour)
	o := e.opts()
	if _, err := dial.Connect(context.Background(), o, e.echo); !errors.Is(err, dial.ErrUnlockRequired) {
		t.Fatalf("connected without unlocking: %v", err)
	}
	if _, _, err := dial.Unlock(context.Background(), o, "000000"); err == nil {
		t.Fatal("wrong code unlocked")
	}
	c := code(t, 0)
	ticket, exp, err := dial.Unlock(context.Background(), o, c)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 59*time.Minute || d > time.Hour {
		t.Fatalf("ticket expires in %s, want 1h", d)
	}
	if _, _, err := dial.Unlock(context.Background(), o, c); err == nil {
		t.Fatal("reused code unlocked again")
	}
	o.Ticket = ticket
	for i := 0; i < 3; i++ {
		s, err := dial.Connect(context.Background(), o, e.echo)
		if err != nil {
			t.Fatalf("connection %d with ticket: %v", i, err)
		}
		roundTrip(t, s)
		s.Close()
	}
	o.Ticket = "psht_" + strings.Repeat("A", 43)
	if _, err := dial.Connect(context.Background(), o, e.echo); !errors.Is(err, dial.ErrUnlockRequired) {
		t.Fatalf("made-up ticket accepted: %v", err)
	}
}

// A ticket belongs to the token that unlocked it.
func TestTicketBoundToToken(t *testing.T) {
	e := setupUnlock(t, time.Hour)
	o := e.opts()
	ticket, _, err := dial.Unlock(context.Background(), o, code(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	pub, dev2, _ := ed25519.GenerateKey(rand.Reader)
	tok2, err := tokens.Add(e.tokPath, "other", pub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other := o
	other.Token, other.Device, other.Ticket = tok2, dev2, ticket
	if _, err := dial.Connect(context.Background(), other, e.echo); !errors.Is(err, dial.ErrUnlockRequired) {
		t.Fatalf("another token used this ticket: %v", err)
	}
}

// When the ticket runs out, open streams close too.
func TestTicketExpiryClosesStream(t *testing.T) {
	e := setupUnlock(t, 1500*time.Millisecond)
	o := e.opts()
	var err error
	if o.Ticket, _, err = dial.Unlock(context.Background(), o, code(t, 0)); err != nil {
		t.Fatal(err)
	}
	c, err := dial.Connect(context.Background(), o, e.echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	keepBusy(c)
	c.SetReadDeadline(time.Now().Add(4 * time.Second))
	start := time.Now()
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("stream not closed when the ticket expired: %v", err)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Fatal("stream closed before the ticket expired")
	}
}

// No unlock configured: the endpoint looks like any other 404.
func TestUnlockEndpointHiddenWhenOff(t *testing.T) {
	e := setup(t)
	if _, _, err := dial.Unlock(context.Background(), e.opts(), code(t, 0)); err == nil {
		t.Fatal("unlock succeeded on a gateway without --require-unlock")
	}
}

// tunnel puts the gateway behind a reverse proxy that terminates HTTPS, the
// way Cloudflare Tunnel, Caddy or Traefik would, and returns options that
// reach it through the proxy.
func (e env) tunnel(t *testing.T) dial.Options {
	o, _ := e.tunnelProxy(t)
	return o
}

func (e env) tunnelProxy(t *testing.T) (dial.Options, *httptest.Server) {
	t.Helper()
	o := e.opts()
	tl := gateway.NewTunnelListener("X-Real-IP")
	inner := e.g.Server("", e.cert)
	go inner.ServeTLS(tl, "", "")
	t.Cleanup(func() { inner.Close() })
	plain := httptest.NewServer(tl)
	t.Cleanup(plain.Close)
	backend, _ := url.Parse(plain.URL)
	rp := httputil.NewSingleHostReverseProxy(backend)
	director := rp.Director
	rp.Director = func(r *http.Request) { director(r); r.Header.Set("X-Real-IP", "203.0.113.7") }
	proxy := httptest.NewTLSServer(rp)
	t.Cleanup(proxy.Close)
	pool := x509.NewCertPool()
	pool.AddCert(proxy.Certificate())
	o.Gateway = proxy.URL
	o.TunnelCAs = pool
	return o, proxy
}

func TestStreamThroughTunnel(t *testing.T) {
	e := setup(t)
	c, err := dial.Connect(context.Background(), e.tunnel(t), e.echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	roundTrip(t, c)
}

func TestTunnelKeepsPinning(t *testing.T) {
	e := setup(t)
	o := e.tunnel(t)
	o.Pins = []string{"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	if _, err := dial.Connect(context.Background(), o, e.echo); err == nil {
		t.Fatal("wrong pin accepted through the tunnel")
	}
}

func TestTunnelNeedsTrustedProxyCert(t *testing.T) {
	e := setup(t)
	o := e.tunnel(t)
	o.TunnelCAs = x509.NewCertPool()
	if _, err := dial.Connect(context.Background(), o, e.echo); err == nil {
		t.Fatal("untrusted proxy certificate accepted")
	}
}

func TestResumeThroughTunnel(t *testing.T) {
	e := setupWith(t, func(c *gateway.Config) { c.IdleTimeout = time.Minute })
	o, proxy := e.tunnelProxy(t)
	o.Resume = true
	c, err := dial.Connect(context.Background(), o, e.echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 5)
	for i := 0; i < 3; i++ {
		io.WriteString(c, "hello")
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
			t.Fatalf("round %d: %q %v", i, buf, err)
		}
		proxy.CloseClientConnections() // the tunnel drops; dial reconnects through it
	}
	roundTrip(t, c)
}
