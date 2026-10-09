package tokens

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Save wrote this line format before FormatEntry was extracted from it;
// gateways in the field read it.
func TestSaveKeepsItsLineFormat(t *testing.T) {
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	dev := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "tokens")
	if err := Save(path, entries(Entry{Name: "a", Hash: hash, Device: dev, Expires: exp}, Entry{Name: "b", Hash: hash, Device: dev})); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	d := FormatDevice(dev)
	want := "# portash gateway tokens: name sha256(token) device=<key> [expires=<time>]\n" +
		"a 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f device=" + d + " expires=2030-01-02T03:04:05Z\n" +
		"b 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f device=" + d + "\n"
	if string(got) != want {
		t.Fatalf("file:\n%s\nwant:\n%s", got, want)
	}
}

func entries(e ...Entry) []Entry { return e }

func TestNewEntry(t *testing.T) {
	dev := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	tok, e, err := NewEntry("alice", dev, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidFormat(tok) || e.Name != "alice" || e.Expires.IsZero() {
		t.Fatalf("token %q entry %+v", tok, e)
	}
	if strings.Contains(FormatEntry(e), tok) {
		t.Fatal("the entry line holds the token")
	}
	if _, _, err := NewEntry("a b", dev, time.Hour); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, _, err := NewEntry("alice", nil, time.Hour); err == nil {
		t.Fatal("missing device accepted")
	}
	if _, e0, _ := NewEntry("alice", dev, 0); !e0.Expires.IsZero() {
		t.Fatal("ttl 0 must never expire")
	}
}
