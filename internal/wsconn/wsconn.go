// Package wsconn carries a byte stream over a WebSocket (RFC 6455), so the
// gateway can sit behind Cloudflare Tunnel or a reverse proxy that terminates
// HTTPS. portash runs its own pinned TLS inside the stream, so the proxy only
// ever sees ciphertext.
package wsconn

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	opCont   = 0x0
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA

	maxFrame = 1 << 20 // incoming frames larger than this end the connection
	guid     = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// Conn is a net.Conn whose bytes travel as binary WebSocket frames.
type Conn struct {
	c      net.Conn
	br     *bufio.Reader
	client bool // clients mask what they send
	remote net.Addr

	rmu  sync.Mutex
	left int64 // payload bytes left in the current data frame
	mask [4]byte
	mpos int
	rerr error

	wmu    sync.Mutex
	closed bool
}

func accept(key string) string {
	h := sha1.Sum([]byte(key + guid))
	return base64.StdEncoding.EncodeToString(h[:])
}

// IsUpgrade reports whether r asks for a WebSocket.
func IsUpgrade(r *http.Request) bool {
	return headerHas(r.Header, "Connection", "upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func headerHas(h http.Header, key, tok string) bool {
	for _, v := range h.Values(key) {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), tok) {
				return true
			}
		}
	}
	return false
}

// Accept completes the server side of the handshake. remote, if non-nil,
// replaces the connection's RemoteAddr (the client's address as reported by
// a trusted proxy).
func Accept(w http.ResponseWriter, r *http.Request, remote net.Addr) (*Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !IsUpgrade(r) || r.Method != http.MethodGet || key == "" || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "websocket required", http.StatusBadRequest)
		return nil, errors.New("not a websocket request")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("connection can't be hijacked")
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Time{})
	if _, err := io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: "+accept(key)+"\r\n\r\n"); err != nil {
		c.Close()
		return nil, err
	}
	if remote == nil {
		remote = c.RemoteAddr()
	}
	return &Conn{c: c, br: rw.Reader, remote: remote}, nil
}

// Client performs the client side of the handshake on an established
// connection (normally TLS to the proxy) and returns the stream.
func Client(c net.Conn, host, path string) (*Conn, error) {
	k := make([]byte, 16)
	rand.Read(k)
	key := base64.StdEncoding.EncodeToString(k)
	req := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\nUser-Agent: portash\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("tunnel: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != accept(key) {
		return nil, errors.New("tunnel: bad websocket handshake")
	}
	return &Conn{c: c, br: br, client: true, remote: c.RemoteAddr()}, nil
}

// Read returns payload bytes of data frames, answering pings on the way.
func (w *Conn) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for w.left == 0 {
		if w.rerr != nil {
			return 0, w.rerr
		}
		if err := w.nextFrame(); err != nil {
			if sticky(err) {
				w.rerr = err
			}
			return 0, err
		}
	}
	if int64(len(p)) > w.left {
		p = p[:w.left]
	}
	n, err := w.br.Read(p)
	w.unmask(p[:n])
	w.left -= int64(n)
	if err != nil && sticky(err) {
		w.rerr = err
	}
	return n, err
}

func (w *Conn) unmask(p []byte) {
	if w.client { // servers don't mask
		return
	}
	for i := range p {
		p[i] ^= w.mask[w.mpos&3]
		w.mpos++
	}
}

// nextFrame reads frame headers until a data frame starts. Each frame
// header (and control frame) is peeked whole before anything is consumed, so
// a read deadline firing midway (net/http uses one to abort its background
// read when a handler hijacks) never leaves the stream out of step.
func (w *Conn) nextFrame() error {
	for {
		h, err := w.br.Peek(2)
		if err != nil {
			return err
		}
		op, masked := h[0]&0x0F, h[1]&0x80 != 0
		if masked == w.client {
			return errors.New("websocket: wrong masking")
		}
		hlen := 2
		switch h[1] & 0x7F {
		case 126:
			hlen += 2
		case 127:
			hlen += 8
		}
		if masked {
			hlen += 4
		}
		if h, err = w.br.Peek(hlen); err != nil {
			return err
		}
		n := int64(h[1] & 0x7F)
		switch n {
		case 126:
			n = int64(binary.BigEndian.Uint16(h[2:]))
		case 127:
			n = int64(binary.BigEndian.Uint64(h[2:]))
		}
		if n < 0 || n > maxFrame {
			return errors.New("websocket: frame too large")
		}
		var mask [4]byte
		if masked {
			copy(mask[:], h[hlen-4:])
		}
		switch op {
		case opBinary, opCont:
			w.br.Discard(hlen)
			w.mask, w.mpos = mask, 0
			if n > 0 {
				w.left = n
				return nil
			}
		case opPing, opPong, opClose:
			if n > 125 {
				return errors.New("websocket: control frame too large")
			}
			f, err := w.br.Peek(hlen + int(n))
			if err != nil {
				return err
			}
			b := append([]byte(nil), f[hlen:]...)
			w.br.Discard(hlen + int(n))
			w.mask, w.mpos = mask, 0
			w.unmask(b)
			switch op {
			case opPing:
				w.writeFrame(opPong, b)
			case opClose:
				w.writeFrame(opClose, nil)
				return io.EOF
			}
		default:
			return fmt.Errorf("websocket: unexpected opcode %d", op)
		}
	}
}

// sticky reports whether err ends the stream; deadline timeouts don't.
func sticky(err error) bool {
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func (w *Conn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := min(len(p), 64<<10)
		if err := w.writeFrame(opBinary, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (w *Conn) writeFrame(op byte, p []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	hdr := make([]byte, 0, 14+len(p))
	hdr = append(hdr, 0x80|op)
	var mbit byte
	if w.client {
		mbit = 0x80
	}
	switch n := len(p); {
	case n < 126:
		hdr = append(hdr, mbit|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, mbit|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, mbit|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	if w.client {
		var m [4]byte
		rand.Read(m[:])
		hdr = append(hdr, m[:]...)
		start := len(hdr)
		hdr = append(hdr, p...)
		for i := range p {
			hdr[start+i] ^= m[i&3]
		}
	} else {
		hdr = append(hdr, p...)
	}
	if op == opClose {
		w.closed = true
	}
	_, err := w.c.Write(hdr)
	return err
}

// Close sends a close frame and closes the connection.
func (w *Conn) Close() error {
	w.c.SetWriteDeadline(time.Now().Add(time.Second))
	w.writeFrame(opClose, nil)
	return w.c.Close()
}

func (w *Conn) LocalAddr() net.Addr                { return w.c.LocalAddr() }
func (w *Conn) RemoteAddr() net.Addr               { return w.remote }
func (w *Conn) SetDeadline(t time.Time) error      { return w.c.SetDeadline(t) }
func (w *Conn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *Conn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }
