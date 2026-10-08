package tokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tok, err := Add(path, "alice", pub, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Add(path, "alice", pub, time.Hour); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if _, err := Add(path, "bob", nil, time.Hour); err == nil {
		t.Fatal("token without device accepted")
	}
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := s.Lookup(tok)
	if !ok || e.Name != "alice" || !e.Device.Equal(pub) {
		t.Fatalf("lookup failed: %+v %v", e, ok)
	}
	other, _ := New()
	if _, ok := s.Lookup(other); ok {
		t.Fatal("wrong token accepted")
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("expired token accepted")
	}
	s.now = time.Now
	// Same-size rewrite within the same second is still noticed (content hash).
	if err := Remove(path, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("removed token still accepted")
	}
}

func TestStoreFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tok, _ := Add(path, "alice", pub, 0)
	s, _ := NewStore(path)
	os.WriteFile(path, []byte("garbage line\n"), 0o600)
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("corrupt file should reject everything")
	}
	os.Chmod(path, 0o644)
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("world-readable file should reject everything")
	}
}
