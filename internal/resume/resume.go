// Package resume keeps one byte stream alive across many transport
// connections, so a laptop can sleep or change networks without ssh noticing.
//
// Each side keeps the bytes it sent until the peer acknowledges them. After a
// reconnect both sides say how many bytes they have received, and each resends
// whatever the other is missing. On the wire, after a hello, the stream is a
// sequence of frames:
//
//	'D' len:uint32 data   stream bytes, in order
//	'A' n:uint64          I have received n bytes in total
//	'P'                   keepalive
//	'F'                   no more data from me (half-close)
//	'X'                   session over; don't reconnect
package resume

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	magic    = "portash-resume-1\n"
	maxFrame = 32 << 10
	ackEvery = 64 << 10
)

// ErrSessionGone means the peer ended the session or it was aborted.
var ErrSessionGone = errors.New("session ended")

type Config struct {
	SendBuffer int           // unacknowledged bytes kept for resending (default 4 MiB); Write blocks when full
	RecvBuffer int           // received bytes not yet read (default 1 MiB)
	Ping       time.Duration // keepalive interval (default 5s)
	Timeout    time.Duration // a transport with no frames for this long is dead (default 15s)
	// OnDetach is called (in its own goroutine) when a transport fails.
	OnDetach func(err error)
}

// Conn is a net.Conn whose Read and Write survive transport failures. They
// only fail once the session is over (Close, Abort, or the peer's 'X').
type Conn struct {
	cfg  Config
	mu   sync.Mutex
	cond *sync.Cond

	// sending
	buf      []byte // bytes from sentBase not yet acknowledged
	sentBase uint64 // stream offset of buf[0]
	sendPos  uint64 // next offset to put on the current transport
	eof      bool   // CloseWrite called
	eofSent  bool   // 'F' sent on the current transport
	ackDue   bool
	pingDue  bool
	byeDue   bool // send 'X'
	byeSent  chan struct{}

	// receiving
	rbuf     []byte
	rxOff    uint64 // bytes received in total
	unacked  int    // received since the last ack we sent
	peerEOF  bool
	peerGone bool

	// transport
	t           net.Conn
	gen         uint64
	detachedAt  time.Time
	dead        error // set once the session is over
	done        chan struct{}
	lastWallRun time.Time
}

func New(cfg Config) *Conn {
	if cfg.SendBuffer <= 0 {
		cfg.SendBuffer = 4 << 20
	}
	if cfg.RecvBuffer <= 0 {
		cfg.RecvBuffer = 1 << 20
	}
	if cfg.Ping <= 0 {
		cfg.Ping = 5 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	c := &Conn{cfg: cfg, done: make(chan struct{}), byeSent: make(chan struct{}), detachedAt: time.Now()}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// Attach makes t the transport, after exchanging received-byte counts with
// the peer. Any previous transport is closed. On error t is closed and the
// session stays detached (or dead, if the peer's state can't be reconciled).
func (c *Conn) Attach(t net.Conn) error {
	c.mu.Lock()
	if c.dead != nil {
		c.mu.Unlock()
		t.Close()
		return c.dead
	}
	c.gen++
	gen := c.gen
	c.dropTransport()
	rx := c.rxOff
	c.mu.Unlock()

	t.SetDeadline(time.Now().Add(c.cfg.Timeout))
	hello := make([]byte, len(magic)+8)
	copy(hello, magic)
	binary.BigEndian.PutUint64(hello[len(magic):], rx)
	if _, err := t.Write(hello); err != nil {
		t.Close()
		return err
	}
	br := bufio.NewReaderSize(t, maxFrame+16)
	peer := make([]byte, len(hello))
	if _, err := io.ReadFull(br, peer); err != nil {
		t.Close()
		return err
	}
	if string(peer[:len(magic)]) != magic {
		t.Close()
		return errors.New("resume: bad hello")
	}
	peerRx := binary.BigEndian.Uint64(peer[len(magic):])
	t.SetDeadline(time.Time{})

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen || c.dead != nil {
		t.Close()
		return errors.New("resume: superseded")
	}
	writeOff := c.sentBase + uint64(len(c.buf))
	if peerRx < c.sentBase || peerRx > writeOff {
		// The peer lost bytes we already dropped, or claims bytes we never
		// sent: the stream can't be repaired.
		t.Close()
		c.kill(fmt.Errorf("resume: peer has %d bytes, we can resend %d..%d", peerRx, c.sentBase, writeOff))
		return c.dead
	}
	c.trim(peerRx)
	c.sendPos = peerRx
	c.eofSent = false
	c.ackDue = c.rxOff > 0
	c.t = t
	c.detachedAt = time.Time{}
	c.cond.Broadcast()
	go c.reader(t, br, gen)
	go c.writer(t, gen)
	go c.pinger(gen)
	return nil
}

// DetachedSince is when the last transport failed, or zero while attached.
func (c *Conn) DetachedSince() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.detachedAt
}

// Done is closed when the session is over.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err is why the session ended (nil while it is alive).
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dead
}

// PeerClosed reports whether the peer ended the session with 'X'.
func (c *Conn) PeerClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerGone
}

// Detach drops the current transport, as if it had failed.
func (c *Conn) Detach() {
	c.mu.Lock()
	gen := c.gen
	c.mu.Unlock()
	c.detach(gen, errors.New("detached"))
}

func (c *Conn) detach(gen uint64, err error) {
	c.mu.Lock()
	if c.gen != gen || c.t == nil {
		c.mu.Unlock()
		return
	}
	c.gen++
	c.dropTransport()
	dead := c.dead != nil
	c.mu.Unlock()
	if !dead && c.cfg.OnDetach != nil {
		go c.cfg.OnDetach(err)
	}
}

// dropTransport closes the current transport. c.mu must be held.
func (c *Conn) dropTransport() {
	if c.t != nil {
		c.t.Close()
		c.t = nil
		c.detachedAt = time.Now()
	}
	c.cond.Broadcast()
}

func (c *Conn) kill(err error) {
	if c.dead == nil {
		c.dead = err
		close(c.done)
	}
	c.gen++
	c.dropTransport()
}

// trim drops acknowledged bytes up to offset n. c.mu must be held.
func (c *Conn) trim(n uint64) {
	if n <= c.sentBase {
		return
	}
	c.buf = c.buf[n-c.sentBase:]
	if len(c.buf) == 0 {
		c.buf = nil // let a large backing array go
	}
	c.sentBase = n
	c.cond.Broadcast()
}

func (c *Conn) reader(t net.Conn, br *bufio.Reader, gen uint64) {
	var hdr [8]byte
	for {
		t.SetReadDeadline(time.Now().Add(c.cfg.Timeout))
		typ, err := br.ReadByte()
		if err != nil {
			c.detach(gen, err)
			return
		}
		switch typ {
		case 'D':
			if _, err := io.ReadFull(br, hdr[:4]); err != nil {
				c.detach(gen, err)
				return
			}
			n := binary.BigEndian.Uint32(hdr[:4])
			if n == 0 || n > maxFrame {
				c.detach(gen, errors.New("resume: bad frame"))
				return
			}
			data := make([]byte, n)
			if _, err := io.ReadFull(br, data); err != nil {
				c.detach(gen, err)
				return
			}
			c.mu.Lock()
			for c.gen == gen && c.dead == nil && len(c.rbuf)+len(data) > c.cfg.RecvBuffer && len(c.rbuf) > 0 {
				c.cond.Wait()
			}
			if c.gen != gen || c.dead != nil {
				c.mu.Unlock()
				return
			}
			c.rbuf = append(c.rbuf, data...)
			c.rxOff += uint64(n)
			c.unacked += int(n)
			// Ack every 64 KiB, and whenever the peer has paused, so a closing
			// peer isn't left waiting for the next keepalive.
			if c.unacked >= ackEvery || br.Buffered() == 0 {
				c.ackDue = true
			}
			c.cond.Broadcast()
			c.mu.Unlock()
		case 'A':
			if _, err := io.ReadFull(br, hdr[:]); err != nil {
				c.detach(gen, err)
				return
			}
			n := binary.BigEndian.Uint64(hdr[:])
			c.mu.Lock()
			if c.gen == gen {
				if n > c.sendPos {
					c.mu.Unlock()
					c.detach(gen, errors.New("resume: ack beyond sent data"))
					return
				}
				c.trim(n)
			}
			c.mu.Unlock()
		case 'P':
			c.mu.Lock()
			if c.unacked > 0 {
				c.ackDue = true
				c.cond.Broadcast()
			}
			c.mu.Unlock()
		case 'F':
			c.mu.Lock()
			if c.gen == gen {
				c.peerEOF = true
				c.ackDue = true
				c.cond.Broadcast()
			}
			c.mu.Unlock()
		case 'X':
			c.mu.Lock()
			if c.gen == gen {
				c.peerGone = true
				c.kill(ErrSessionGone)
			}
			c.mu.Unlock()
			return
		default:
			c.detach(gen, fmt.Errorf("resume: unknown frame %q", typ))
			return
		}
	}
}

func (c *Conn) writer(t net.Conn, gen uint64) {
	out := make([]byte, 0, maxFrame+64)
	for {
		c.mu.Lock()
		for c.gen == gen && !c.byeDue && !c.ackDue && !c.pingDue &&
			c.sendPos == c.sentBase+uint64(len(c.buf)) && (!c.eof || c.eofSent) {
			c.cond.Wait()
		}
		if c.gen != gen {
			c.mu.Unlock()
			return
		}
		out = out[:0]
		if c.ackDue {
			out = append(out, 'A')
			out = binary.BigEndian.AppendUint64(out, c.rxOff)
			c.ackDue, c.unacked = false, 0
		}
		if c.pingDue {
			out = append(out, 'P')
			c.pingDue = false
		}
		if end := c.sentBase + uint64(len(c.buf)); c.sendPos < end {
			n := min(end-c.sendPos, maxFrame)
			out = append(out, 'D')
			out = binary.BigEndian.AppendUint32(out, uint32(n))
			start := c.sendPos - c.sentBase
			out = append(out, c.buf[start:start+n]...)
			c.sendPos += n
		}
		if c.eof && !c.eofSent && c.sendPos == c.sentBase+uint64(len(c.buf)) {
			out = append(out, 'F')
			c.eofSent = true
		}
		bye := c.byeDue && c.sendPos == c.sentBase+uint64(len(c.buf))
		if bye {
			out = append(out, 'X')
			c.byeDue = false
		}
		c.mu.Unlock()

		t.SetWriteDeadline(time.Now().Add(c.cfg.Timeout))
		if _, err := t.Write(out); err != nil {
			c.detach(gen, err)
			return
		}
		if bye {
			close(c.byeSent)
			return
		}
	}
}

// pinger sends keepalives, and drops the transport straight away after the
// machine slept (the wall clock jumped), instead of waiting for a timeout.
func (c *Conn) pinger(gen uint64) {
	tick := time.NewTicker(c.cfg.Ping)
	defer tick.Stop()
	last := time.Now().Round(0) // wall clock only
	for range tick.C {
		now := time.Now().Round(0)
		slept := now.Sub(last) > 3*c.cfg.Ping
		last = now
		c.mu.Lock()
		if c.gen != gen {
			c.mu.Unlock()
			return
		}
		c.pingDue = true
		c.cond.Broadcast()
		c.mu.Unlock()
		if slept {
			c.detach(gen, errors.New("woke from sleep"))
			return
		}
	}
}

// Read blocks while detached; it fails only when the session is over.
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.rbuf) == 0 && !c.peerEOF && c.dead == nil {
		c.cond.Wait()
	}
	if len(c.rbuf) == 0 {
		if c.peerEOF || c.peerGone {
			return 0, io.EOF
		}
		return 0, c.dead
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	if len(c.rbuf) == 0 {
		c.rbuf = nil
	}
	c.cond.Broadcast() // room for the reader goroutine
	return n, nil
}

// Write buffers p for (re)sending. It blocks while the send buffer is full.
func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for len(p) > 0 {
		for c.dead == nil && !c.eof && len(c.buf) >= c.cfg.SendBuffer {
			c.cond.Wait()
		}
		if c.dead != nil {
			return written, c.dead
		}
		if c.eof {
			return written, errors.New("resume: write after CloseWrite")
		}
		n := min(len(p), c.cfg.SendBuffer-len(c.buf))
		c.buf = append(c.buf, p[:n]...)
		p = p[n:]
		written += n
		c.cond.Broadcast()
	}
	return written, nil
}

// CloseWrite sends 'F' after the buffered data.
func (c *Conn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.eof = true
	c.cond.Broadcast()
	return nil
}

// Close ends the session: it waits up to wait for the peer to acknowledge
// everything sent, tells the peer with 'X', and closes the transport.
func (c *Conn) Close() error { return c.Shutdown(3 * time.Second) }

// Abort ends the session without waiting for data to be acknowledged.
func (c *Conn) Abort(err error) {
	c.Shutdown(0)
	c.mu.Lock()
	if c.dead == ErrSessionGone && err != nil {
		c.dead = err
	}
	c.mu.Unlock()
}

func (c *Conn) Shutdown(wait time.Duration) error {
	deadline := time.Now().Add(wait)
	timer := time.AfterFunc(wait, func() { c.mu.Lock(); c.cond.Broadcast(); c.mu.Unlock() })
	defer timer.Stop()
	c.mu.Lock()
	for c.dead == nil && c.t != nil && len(c.buf) > 0 && time.Now().Before(deadline) {
		c.cond.Wait()
	}
	if c.dead != nil {
		c.mu.Unlock()
		return nil
	}
	if c.t != nil {
		c.byeDue = true
		c.cond.Broadcast()
		c.mu.Unlock()
		select {
		case <-c.byeSent:
		case <-time.After(time.Second):
		}
		c.mu.Lock()
	}
	c.kill(ErrSessionGone)
	c.mu.Unlock()
	return nil
}

type addr struct{}

func (addr) Network() string { return "portash-resume" }
func (addr) String() string  { return "portash-resume" }

func (c *Conn) LocalAddr() net.Addr              { return addr{} }
func (c *Conn) RemoteAddr() net.Addr             { return addr{} }
func (c *Conn) SetDeadline(time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(time.Time) error { return nil }
