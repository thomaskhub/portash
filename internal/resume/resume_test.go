package resume

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		ch <- c
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a, <-ch
}

// attach connects a and b over a fresh TCP connection.
func attach(t *testing.T, a, b *Conn) error {
	t.Helper()
	x, y := tcpPair(t)
	errc := make(chan error, 1)
	go func() { errc <- b.Attach(y) }()
	err := a.Attach(x)
	if err2 := <-errc; err == nil {
		err = err2
	}
	return err
}

func fastCfg() Config { return Config{Ping: 50 * time.Millisecond, Timeout: 500 * time.Millisecond} }

func TestEchoAndClose(t *testing.T) {
	a, b := New(fastCfg()), New(fastCfg())
	if err := attach(t, a, b); err != nil {
		t.Fatal(err)
	}
	a.Write([]byte("hello"))
	a.CloseWrite()
	got, err := io.ReadAll(b)
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}
	b.Write([]byte("bye"))
	b.Close() // waits for the ack, then sends 'X'
	got, err = io.ReadAll(a)
	if err != nil || string(got) != "bye" {
		t.Fatalf("got %q, %v", got, err)
	}
	select {
	case <-a.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("peer's Close didn't end the session")
	}
	if !a.PeerClosed() {
		t.Fatal("PeerClosed false")
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("write after the session ended")
	}
}

// Both directions move 8 MiB while the transport is cut every few
// milliseconds; every byte must arrive once, in order.
func TestSurvivesRepeatedDrops(t *testing.T) {
	a, b := New(fastCfg()), New(fastCfg())
	if err := attach(t, a, b); err != nil {
		t.Fatal(err)
	}
	const size = 8 << 20
	send := func(c *Conn) [32]byte {
		data := make([]byte, size)
		rand.Read(data)
		go func() {
			// Paced, so the transfer outlasts at least five forced drops
			// however fast the machine is.
			for i, p := 0, data; len(p) > 0; i++ {
				n := min(len(p), 7777)
				c.Write(p[:n])
				p = p[n:]
				if i%4 == 3 {
					time.Sleep(time.Millisecond)
				}
			}
			c.CloseWrite()
		}()
		return sha256.Sum256(data)
	}
	recv := func(c *Conn, out *[32]byte, wg *sync.WaitGroup) {
		defer wg.Done()
		h := sha256.New()
		if _, err := io.Copy(h, c); err != nil {
			t.Error(err)
		}
		copy(out[:], h.Sum(nil))
	}
	wantAB, wantBA := send(a), send(b)
	var gotAB, gotBA [32]byte
	var wg sync.WaitGroup
	wg.Add(2)
	go recv(b, &gotAB, &wg)
	go recv(a, &gotBA, &wg)
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()

	drops := 0
	for {
		select {
		case <-finished:
			if gotAB != wantAB || gotBA != wantBA {
				t.Fatal("data corrupted across reconnects")
			}
			if drops < 5 {
				t.Fatalf("only %d drops; test didn't exercise resume", drops)
			}
			t.Logf("%d reconnects", drops)
			return
		case <-time.After(15 * time.Millisecond):
			if drops%2 == 0 {
				a.Detach()
			} else {
				b.Detach()
			}
			drops++
			if err := attach(t, a, b); err != nil {
				t.Fatalf("reattach %d: %v", drops, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("timed out")
		}
	}
}

// A transport that silently stops delivering (laptop lid closed, Wi-Fi gone)
// is noticed by the keepalive timeout.
func TestDeadTransportDetected(t *testing.T) {
	detached := make(chan error, 2)
	cfg := fastCfg()
	cfg.OnDetach = func(err error) { detached <- err }
	a := New(cfg)
	b := New(fastCfg())

	// Relay through a proxy we can freeze.
	x, y := tcpPair(t)
	p, q := tcpPair(t)
	var frozen atomic.Bool
	pump := func(dst, src net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			for frozen.Load() {
				time.Sleep(time.Millisecond)
			}
			dst.Write(buf[:n])
		}
	}
	go pump(p, y)
	go pump(y, p)
	errc := make(chan error, 1)
	go func() { errc <- b.Attach(q) }()
	if err := a.Attach(x); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	frozen.Store(true)
	defer frozen.Store(false)
	select {
	case <-detached:
	case <-time.After(3 * time.Second):
		t.Fatal("frozen transport not detected")
	}
	if a.DetachedSince().IsZero() {
		t.Fatal("DetachedSince zero after detach")
	}
	if a.Err() != nil {
		t.Fatal("session died instead of waiting for a resume")
	}
}

// A peer that lost its state (e.g. a restarted gateway) can't be resumed.
func TestStateMismatchEndsSession(t *testing.T) {
	a, b := New(fastCfg()), New(fastCfg())
	if err := attach(t, a, b); err != nil {
		t.Fatal(err)
	}
	b.Write(bytes.Repeat([]byte("x"), 1000))
	buf := make([]byte, 1000)
	io.ReadFull(a, buf)
	a.Detach()
	fresh := New(fastCfg()) // has received nothing; a has 1000 bytes from b
	if err := attach(t, a, fresh); err == nil {
		t.Fatal("resumed against a peer with the wrong state")
	}
	// fresh is asked for bytes it never had, so it gives up.
	if fresh.Err() == nil {
		t.Fatal("fresh should be dead")
	}
}

func TestAbortReason(t *testing.T) {
	a := New(fastCfg())
	want := errors.New("revoked")
	a.Abort(want)
	if _, err := a.Read(make([]byte, 1)); err != want {
		t.Fatalf("Read error %v, want %v", err, want)
	}
}
