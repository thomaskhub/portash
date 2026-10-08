package wsconn

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func pair(t *testing.T) (client, server *Conn) {
	t.Helper()
	ch := make(chan *Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		ch <- c
	}))
	t.Cleanup(srv.Close)
	raw, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Client(raw, "x", "/")
	if err != nil {
		t.Fatal(err)
	}
	s := <-ch
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func TestBothWays(t *testing.T) {
	c, s := pair(t)
	data := make([]byte, 3<<20) // several frames
	rand.Read(data)
	go func() { c.Write(data); s.Write(data) }()
	for _, r := range []*Conn{s, c} {
		got := make([]byte, len(data))
		r.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, data) {
			t.Fatalf("mismatch: %v", err)
		}
	}
}

// Fragments and pings from a proxy are handled; pings get pongs.
func TestFragmentsAndPings(t *testing.T) {
	c, s := pair(t)
	s.writeFrame(opPing, []byte("hi"))
	s.wmu.Lock()
	s.c.Write([]byte{0x02, 3, 'a', 'b', 'c'}) // binary, not final
	s.c.Write([]byte{0x80, 2, 'd', 'e'})      // final continuation
	s.wmu.Unlock()
	got := make([]byte, 5)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "abcde" {
		t.Fatalf("got %q %v", got, err)
	}
	// The pong is consumed by the server's reader; it must not show up as data.
	c.Write([]byte("z"))
	b := make([]byte, 1)
	s.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(s, b); err != nil || b[0] != 'z' {
		t.Fatalf("got %q %v", b, err)
	}
}

// A read deadline that fires does not break the stream.
func TestTimeoutIsNotFatal(t *testing.T) {
	c, s := pair(t)
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected a timeout")
	}
	c.SetReadDeadline(time.Time{})
	s.Write([]byte("ok"))
	got := make([]byte, 2)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "ok" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestCloseIsEOF(t *testing.T) {
	c, s := pair(t)
	s.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("got %v, want EOF", err)
	}
}

func TestRejectsUnmaskedClientFrames(t *testing.T) {
	c, s := pair(t)
	c.client = false // send like a server would
	c.writeFrame(opBinary, []byte("x"))
	s.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("unmasked client frame accepted")
	}
}
