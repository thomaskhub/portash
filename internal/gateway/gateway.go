// Package gateway accepts authenticated TLS streams on 443 and splices them
// to allowed host:port targets inside the VPN.
package gateway

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"portash/internal/resume"
	"portash/internal/tokens"
)

const (
	SigHeader     = "Portash-Device-Signature"
	ExporterLabel = "EXPORTER-portash-device-auth"
	Path          = "/v1/tcp"
	UpgradeProto  = "portash"
	// ResumeHeader is "new" for a resumable stream, or a session id to
	// reattach to; SessionHeader carries a new session's id back.
	ResumeHeader  = "Portash-Resume"
	SessionHeader = "Portash-Session"
	dialTimeout   = 5 * time.Second
	headerTimeout = 10 * time.Second
)

type Config struct {
	Network       netip.Prefix  // targets must be inside this prefix
	Ports         map[int]bool  // and use one of these ports
	Tokens        *tokens.Store // who may connect
	MaxStreams    int           // concurrent streams per token (default 16)
	MaxConns      int           // concurrent TCP connections in total (default 512)
	IdleTimeout   time.Duration // close a stream with no traffic either way (default 10m)
	MaxSession    time.Duration // close any stream after this long (default 24h)
	FailLimit     int           // failed attempts per IP per 10 minutes before it is ignored (default 10)
	MaxConnsPerIP int           // concurrent connections from one IP (an IPv6 /64) (default 32)
	SweepEvery    time.Duration // how often open streams are re-checked (default 5s)
	// ResumeWindow is how long a resumable stream waits for its client to
	// reconnect before the connection to the target is closed (default 10m).
	ResumeWindow time.Duration
	// Unlock, when set, makes every stream need a ticket from a TOTP unlock.
	Unlock *Unlock
	Log    *log.Logger
	// Dial is overridable for tests.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

type stream struct {
	name   string
	hash   [32]byte
	start  time.Time
	last   atomic.Int64 // unix nanos of the last byte either way
	ticket [32]byte     // with Unlock: the ticket the stream was opened with
	kill   func(why string)
	// detached is set for resumable streams: when the client's connection
	// dropped, or zero while connected.
	detached func() time.Time
}

// session is a resumable stream the client can reattach to.
type session struct {
	hash   [32]byte
	target netip.AddrPort
	rc     *resume.Conn
	s      *stream
}

type Gateway struct {
	cfg     Config
	mu      sync.Mutex
	active  map[string]int
	streams map[*stream]struct{}
	resumes map[string]*session
	tickets *ticketStore
	fails   *failLimiter
}

func New(cfg Config) (*Gateway, error) {
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = 16
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 512
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}
	if cfg.MaxSession <= 0 {
		cfg.MaxSession = 24 * time.Hour
	}
	if cfg.MaxConnsPerIP <= 0 {
		cfg.MaxConnsPerIP = 32
	}
	if cfg.FailLimit <= 0 {
		cfg.FailLimit = 10
	}
	if cfg.ResumeWindow <= 0 {
		cfg.ResumeWindow = 10 * time.Minute
	}
	if cfg.SweepEvery <= 0 {
		cfg.SweepEvery = 5 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = log.Default()
	}
	if cfg.Dial == nil {
		d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
		cfg.Dial = d.DialContext
	}
	tickets := &ticketStore{m: map[[32]byte]ticket{}}
	if cfg.Unlock != nil {
		if cfg.Unlock.TicketTTL <= 0 {
			cfg.Unlock.TicketTTL = 12 * time.Hour
		}
		var err error
		if tickets, err = newTicketStore(cfg.Unlock.File); err != nil {
			return nil, err
		}
	}
	g := &Gateway{tickets: tickets, cfg: cfg, active: map[string]int{}, streams: map[*stream]struct{}{}, resumes: map[string]*session{},
		fails: newFailLimiter(cfg.FailLimit, 10*time.Minute)}
	go g.sweepLoop()
	return g, nil
}

// Server returns an http.Server that only speaks TLS 1.3. Serve it with
// ServeTLS on Listener(...) so the connection cap applies.
func (g *Gateway) Server(addr string, cert tls.Certificate) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           g,
		ReadHeaderTimeout: headerTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"http/1.1"}, // upgrades need HTTP/1.1
		},
		ErrorLog: log.New(io.Discard, "", 0), // TLS scanner noise
	}
}

// Listener caps concurrent connections at MaxConns, and at MaxConnsPerIP from
// one address; extra ones wait in the kernel backlog (or, over the per-IP
// cap, are closed) instead of costing a goroutine and a TLS handshake.
func (g *Gateway) Listener(ln net.Listener) net.Listener {
	return &limitListener{Listener: ln, sem: make(chan struct{}, g.cfg.MaxConns),
		perIP: g.cfg.MaxConnsPerIP, byIP: map[string]int{}}
}

// LimitListener caps concurrent connections without a per-IP limit, for a
// listener whose peers are all one proxy (the tunnel's plain-HTTP side).
func LimitListener(ln net.Listener, n int) net.Listener {
	return &limitListener{Listener: ln, sem: make(chan struct{}, n)}
}

type limitListener struct {
	net.Listener
	sem   chan struct{}
	perIP int
	mu    sync.Mutex
	byIP  map[string]int
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		l.sem <- struct{}{}
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			return nil, err
		}
		if l.perIP == 0 {
			return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
		}
		key := ipKey(hostOf(c.RemoteAddr().String()))
		l.mu.Lock()
		over := l.byIP[key] >= l.perIP
		if !over {
			l.byIP[key]++
		}
		l.mu.Unlock()
		if over {
			c.Close()
			<-l.sem
			continue
		}
		return &limitConn{Conn: c, release: func() {
			l.mu.Lock()
			if l.byIP[key]--; l.byIP[key] <= 0 {
				delete(l.byIP, key)
			}
			l.mu.Unlock()
			<-l.sem
		}}, nil
	}
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (c *limitConn) CloseWrite() error { return closeWrite(c.Conn) }

// failLimiter ignores an IP after too many failed attempts in a window.
type failLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	m      map[string]*failBucket
}

const maxFailEntries = 10000

type failBucket struct {
	n     int
	reset time.Time
}

func newFailLimiter(limit int, window time.Duration) *failLimiter {
	return &failLimiter{limit: limit, window: window, m: map[string]*failBucket{}}
}

// hostOf strips the port from host:port.
func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// ipKey groups IPv6 addresses by /64, which one client usually owns whole,
// so rotating through its addresses doesn't escape the limits.
func ipKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

func (f *failLimiter) blocked(ip string) bool {
	ip = ipKey(ip)
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.m[ip]
	return b != nil && time.Now().Before(b.reset) && b.n >= f.limit
}

func (f *failLimiter) fail(ip string) {
	ip = ipKey(ip)
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if len(f.m) >= maxFailEntries { // bound memory under a spray of source IPs
		for k, b := range f.m {
			if now.After(b.reset) {
				delete(f.m, k)
			}
		}
		// Still full: forget arbitrary entries (map order is random).
		for k := range f.m {
			if len(f.m) < maxFailEntries*9/10 {
				break
			}
			delete(f.m, k)
		}
	}
	b := f.m[ip]
	if b == nil || now.After(b.reset) {
		b = &failBucket{reset: now.Add(f.window)}
		f.m[ip] = b
	}
	b.n++
}

// ParseTarget accepts only a literal IP:port, so there is no DNS to rebind.
func (g *Gateway) ParseTarget(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return ap, errors.New("target must be IP:port")
	}
	addr := ap.Addr().Unmap()
	if addr.Zone() != "" || !g.cfg.Network.Contains(addr) {
		return ap, errors.New("target outside network")
	}
	if !g.cfg.Ports[int(ap.Port())] {
		return ap, errors.New("port not allowed")
	}
	return netip.AddrPortFrom(addr, ap.Port()), nil
}

func (g *Gateway) acquire(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active[name] >= g.cfg.MaxStreams {
		return false
	}
	g.active[name]++
	return true
}

func (g *Gateway) release(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active[name]--; g.active[name] <= 0 {
		delete(g.active, name)
	}
}

func (g *Gateway) track(s *stream, on bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if on {
		g.streams[s] = struct{}{}
	} else {
		delete(g.streams, s)
	}
}

func (g *Gateway) sweepLoop() {
	for range time.Tick(g.cfg.SweepEvery) {
		g.Sweep()
	}
}

// Sweep closes streams whose token was revoked or expired, that have been
// idle too long, or that exceeded the maximum session length.
func (g *Gateway) Sweep() {
	g.mu.Lock()
	open := make([]*stream, 0, len(g.streams))
	for s := range g.streams {
		open = append(open, s)
	}
	g.mu.Unlock()
	now := time.Now()
	for _, s := range open {
		why := ""
		var detached time.Time
		if s.detached != nil {
			detached = s.detached()
		}
		switch {
		case !g.tokenLive(s.hash):
			why = "token revoked or expired"
		case g.cfg.Unlock != nil && !g.tickets.valid(s.ticket, s.hash):
			why = "unlock ticket expired"
		case !detached.IsZero():
			if now.Sub(detached) > g.cfg.ResumeWindow {
				why = "client did not reconnect"
			}
		case now.Sub(time.Unix(0, s.last.Load())) > g.cfg.IdleTimeout:
			why = "idle"
		case now.Sub(s.start) > g.cfg.MaxSession:
			why = "max session length"
		}
		if why != "" {
			g.cfg.Log.Printf("kill token=%s: %s", s.name, why)
			s.kill(why)
		}
	}
}

func (g *Gateway) tokenLive(h [32]byte) bool {
	_, ok := g.cfg.Tokens.LookupHash(h)
	return ok
}

// authenticate checks the bearer token and that the request is signed by the
// token's device key over this TLS session's exported keying material, so a
// copied token alone is useless and a captured request can't be replayed.
func (g *Gateway) authenticate(r *http.Request, target string) (tokens.Entry, [32]byte, bool) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var h [32]byte
	if r.TLS == nil || !tokens.ValidFormat(tok) {
		return tokens.Entry{}, h, false
	}
	h = sha256.Sum256([]byte(tok))
	e, ok := g.cfg.Tokens.LookupHash(h)
	sig, err := base64.RawURLEncoding.DecodeString(r.Header.Get(SigHeader))
	if !ok || err != nil || len(sig) != ed25519.SignatureSize {
		return tokens.Entry{}, h, false
	}
	ekm, err := r.TLS.ExportKeyingMaterial(ExporterLabel, nil, 32)
	if err != nil || !ed25519.Verify(e.Device, SignedMessage(ekm, target), sig) {
		return tokens.Entry{}, h, false
	}
	return e, h, true
}

// SignedMessage is what the device key signs: the TLS exporter value and the
// requested target.
func SignedMessage(ekm []byte, target string) []byte {
	return append(append([]byte("portash-v1\x00"), ekm...), target...)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	remote, ip := r.RemoteAddr, clientIP(r)

	if r.URL.Path == UnlockPath && r.Method == http.MethodPost {
		if g.fails.blocked(ip) {
			http.NotFound(w, r)
			return
		}
		g.serveUnlock(w, r, ip)
		return
	}
	// Anything that isn't a well-formed, authenticated upgrade looks like a
	// plain 404, so scanners learn nothing. IPs that keep failing are ignored
	// before any token work is done.
	if r.URL.Path != Path || r.Method != http.MethodGet || r.ProtoMajor != 1 ||
		!strings.EqualFold(r.Header.Get("Upgrade"), UpgradeProto) ||
		!headerHasToken(r.Header, "Connection", "upgrade") {
		http.NotFound(w, r)
		return
	}
	if g.fails.blocked(ip) {
		http.NotFound(w, r)
		return
	}
	rawTarget := r.URL.Query().Get("target")
	entry, hash, ok := g.authenticate(r, rawTarget)
	if !ok {
		g.fails.fail(ip)
		g.cfg.Log.Printf("deny %s: bad token or device signature", remote)
		http.NotFound(w, r)
		return
	}
	name := entry.Name
	var th [32]byte
	if g.cfg.Unlock != nil {
		var ok bool
		th, ok = ticketHash(r)
		if !ok || !g.tickets.valid(th, hash) {
			g.cfg.Log.Printf("deny %s token=%s: no valid unlock ticket", remote, name)
			http.Error(w, "unlock required: run portash unlock", http.StatusUnauthorized)
			return
		}
	}
	target, err := g.ParseTarget(rawTarget)
	if err != nil {
		g.cfg.Log.Printf("deny %s token=%s target=%q: %v", remote, name, rawTarget, err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	resumeReq := r.Header.Get(ResumeHeader)
	if resumeReq != "" && resumeReq != "new" {
		g.reattach(w, r, resumeReq, hash, target, name)
		return
	}
	if !g.acquire(name) {
		g.cfg.Log.Printf("deny %s token=%s target=%s: too many streams", remote, name, target)
		http.Error(w, "too many streams", http.StatusTooManyRequests)
		return
	}
	defer g.release(name)

	ctx, cancel := context.WithTimeout(r.Context(), dialTimeout)
	backend, err := g.cfg.Dial(ctx, "tcp", target.String())
	cancel()
	if err != nil {
		g.cfg.Log.Printf("fail %s token=%s target=%s: %v", remote, name, target, err)
		http.Error(w, "target unreachable", http.StatusBadGateway)
		return
	}
	defer backend.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unsupported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	client.SetDeadline(time.Time{})
	s := &stream{name: name, hash: hash, ticket: th, start: time.Now()}
	s.last.Store(s.start.UnixNano())
	front := net.Conn(&bufferedConn{Conn: client, r: rw.Reader})
	extra, sid := "", ""
	if resumeReq == "new" {
		sid = newSessionID()
		extra = SessionHeader + ": " + sid + "\r\n"
	}
	if _, err := io.WriteString(client, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+UpgradeProto+"\r\n"+extra+"\r\n"); err != nil {
		return
	}
	if sid != "" {
		rc := resume.New(resume.Config{Timeout: 30 * time.Second})
		if err := rc.Attach(front); err != nil {
			g.cfg.Log.Printf("fail %s token=%s target=%s: resume hello: %v", remote, name, target, err)
			return
		}
		front = rc
		s.detached = rc.DetachedSince
		s.kill = func(why string) { rc.Abort(errors.New(why)); backend.Close() }
		g.mu.Lock()
		g.resumes[sid] = &session{hash: hash, target: target, rc: rc, s: s}
		g.mu.Unlock()
		defer func() {
			g.mu.Lock()
			delete(g.resumes, sid)
			g.mu.Unlock()
			rc.Close()
		}()
	} else {
		s.kill = func(string) { client.Close(); backend.Close() }
	}
	g.track(s, true)
	defer g.track(s, false)
	g.cfg.Log.Printf("open %s token=%s target=%s resumable=%t", remote, name, target, sid != "")
	up, down := Splice(&activeConn{Conn: front, s: s}, &activeConn{Conn: backend, s: s})
	g.cfg.Log.Printf("close %s token=%s target=%s up=%d down=%d dur=%s", remote, name, target, up, down, time.Since(s.start).Round(time.Second))
}

func newSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// reattach hands a new client connection to a waiting resumable stream. The
// request was authenticated like any other, and must come from the same
// token for the same target, so a leaked session id is useless on its own.
func (g *Gateway) reattach(w http.ResponseWriter, r *http.Request, sid string, hash [32]byte, target netip.AddrPort, name string) {
	g.mu.Lock()
	sess := g.resumes[sid]
	g.mu.Unlock()
	if sess == nil || sess.hash != hash || sess.target != target {
		g.cfg.Log.Printf("deny %s token=%s target=%s: no such session to resume", r.RemoteAddr, name, target)
		http.Error(w, "session gone", http.StatusGone)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unsupported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	client.SetDeadline(time.Time{})
	if _, err := io.WriteString(client, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+UpgradeProto+"\r\n\r\n"); err != nil {
		client.Close()
		return
	}
	if err := sess.rc.Attach(&bufferedConn{Conn: client, r: rw.Reader}); err != nil {
		g.cfg.Log.Printf("fail %s token=%s target=%s: resume: %v", r.RemoteAddr, name, target, err)
		return
	}
	sess.s.last.Store(time.Now().UnixNano())
	g.cfg.Log.Printf("resume %s token=%s target=%s", r.RemoteAddr, name, target)
}

// activeConn records traffic for the idle timeout.
type activeConn struct {
	net.Conn
	s *stream
}

func (c *activeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.s.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *activeConn) CloseWrite() error { return closeWrite(c.Conn) }

func headerHasToken(h http.Header, key, tok string) bool {
	for _, v := range h.Values(key) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), tok) {
				return true
			}
		}
	}
	return false
}

// bufferedConn returns bytes the HTTP server already buffered before the
// hijack, then reads from the connection.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufferedConn) CloseWrite() error { return closeWrite(c.Conn) }

type closeWriter interface{ CloseWrite() error }

func closeWrite(c net.Conn) error {
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// Splice copies both ways, propagating half-closes, and returns the byte
// counts a->b and b->a.
func Splice(a, b net.Conn) (ab, ba int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var err error
		ab, err = io.Copy(b, a)
		finish(a, b, err)
	}()
	go func() {
		defer wg.Done()
		var err error
		ba, err = io.Copy(a, b)
		finish(b, a, err)
	}()
	wg.Wait()
	return
}

// finish half-closes dst after a clean EOF from src, or tears both down on
// an error so the other direction doesn't hang.
func finish(src, dst net.Conn, err error) {
	if err != nil {
		src.Close()
		dst.Close()
		return
	}
	closeWrite(dst)
}

// ParsePorts parses "22,2222".
func ParsePorts(s string) (map[int]bool, error) {
	out := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("bad port " + strconv.Quote(p))
		}
		out[n] = true
	}
	return out, nil
}
