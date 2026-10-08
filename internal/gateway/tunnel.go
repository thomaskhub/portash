package gateway

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"portash/internal/wsconn"
)

// TunnelPath is where the plain-HTTP tunnel listener accepts WebSockets.
const TunnelPath = "/v1/tunnel"

// TunnelListener lets the gateway sit behind Cloudflare Tunnel or a reverse
// proxy (Caddy, Traefik, nginx) that terminates HTTPS. The proxy forwards a
// WebSocket to it over plain HTTP; the laptop runs the gateway's usual pinned
// TLS 1.3 inside that WebSocket, so pinning and the device signature work
// exactly as on the direct port and the proxy only sees ciphertext.
//
// It is an http.Handler for the plain-HTTP side and a net.Listener for the
// gateway's TLS server: serve it with g.Server(...).ServeTLS(g.Listener(tl)).
type TunnelListener struct {
	// IPHeader names the header the proxy puts the client's address in
	// (CF-Connecting-IP for Cloudflare, X-Real-IP for most proxies). Logs
	// and the failed-attempt limit use it. Only set it when the listener
	// can be reached by the proxy alone.
	IPHeader string

	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func NewTunnelListener(ipHeader string) *TunnelListener {
	return &TunnelListener{IPHeader: ipHeader, conns: make(chan net.Conn), done: make(chan struct{})}
}

func (t *TunnelListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != TunnelPath || !wsconn.IsUpgrade(r) {
		http.NotFound(w, r)
		return
	}
	var remote net.Addr
	if t.IPHeader != "" {
		// A proxy may append to a list; its own entry is the last one.
		v := r.Header.Get(t.IPHeader)
		if i := strings.LastIndexByte(v, ','); i >= 0 {
			v = v[i+1:]
		}
		if ip, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			remote = net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), 0))
		}
	}
	c, err := wsconn.Accept(w, r, remote)
	if err != nil {
		return
	}
	select {
	case t.conns <- c:
	case <-t.done:
		c.Close()
	}
}

func (t *TunnelListener) Accept() (net.Conn, error) {
	select {
	case c := <-t.conns:
		return c, nil
	case <-t.done:
		return nil, net.ErrClosed
	}
}

func (t *TunnelListener) Close() error {
	t.once.Do(func() { close(t.done) })
	return nil
}

func (t *TunnelListener) Addr() net.Addr { return tunnelAddr{} }

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "websocket" }
func (tunnelAddr) String() string  { return TunnelPath }
