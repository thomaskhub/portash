package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"portash/internal/tokens"
)

func newDevice(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return tokens.FormatDevice(pub)
}

func TestTokenNewLineVerifiesTheToken(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "alice.token")
	dev := newDevice(t)
	line, err := capture(t, func() error { return tokenNew("alice-laptop", dev, time.Hour, out, false) })
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(string(raw))
	if !tokens.ValidFormat(tok) {
		t.Fatalf("file holds %q, not a token", raw)
	}
	// The line is what a VM keeps: put it in a tokens file and look the token up.
	path := filepath.Join(dir, "tokens")
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := tokens.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := st.Lookup(tok)
	if !ok || e.Name != "alice-laptop" || tokens.FormatDevice(e.Device) != dev {
		t.Fatalf("lookup = %+v, %v", e, ok)
	}
	if e.Expires.IsZero() {
		t.Fatal("the ttl was lost")
	}
}

func TestTokenNewNeverPrintsTheToken(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		out := filepath.Join(t.TempDir(), "t")
		printed, err := capture(t, func() error { return tokenNew("bob", newDevice(t), 0, out, asJSON) })
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(out)
		tok := strings.TrimSpace(string(raw))
		if tok == "" || strings.Contains(printed, tok) || strings.Contains(printed, "psh_") {
			t.Fatalf("json=%v: output %q contains the token", asJSON, printed)
		}
		if asJSON {
			var res struct {
				Name    string  `json:"name"`
				Line    string  `json:"line"`
				Expires *string `json:"expires"`
			}
			if err := json.Unmarshal([]byte(printed), &res); err != nil {
				t.Fatalf("not JSON: %q: %v", printed, err)
			}
			if res.Name != "bob" || !strings.HasPrefix(res.Line, "bob ") || res.Expires != nil {
				t.Fatalf("json = %+v (ttl 0 must give expires null)", res)
			}
		}
	}
}

func TestTokenNewNeedsAFileAndNeverReplacesOne(t *testing.T) {
	dev := newDevice(t)
	if _, err := capture(t, func() error { return tokenNew("a", dev, time.Hour, "", false) }); err == nil {
		t.Fatal("token new without --out worked: the token would be lost or printed")
	}
	out := filepath.Join(t.TempDir(), "t")
	if err := os.WriteFile(out, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	printed, err := capture(t, func() error { return tokenNew("a", dev, time.Hour, out, false) })
	if err == nil {
		t.Fatal("token new replaced an existing file")
	}
	if printed != "" {
		t.Fatalf("a failed run printed %q", printed)
	}
	if got, _ := os.ReadFile(out); string(got) != "keep me" {
		t.Fatalf("file changed: %q", got)
	}
}

func TestTokenNewRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	good := newDevice(t)
	for name, c := range map[string]struct{ name, dev string }{
		"bad name":   {"a b", good},
		"bad device": {"alice", "pshd_nope"},
		"no device":  {"alice", ""},
	} {
		out := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		if _, err := capture(t, func() error { return tokenNew(c.name, c.dev, time.Hour, out, false) }); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Lstat(out); err == nil {
			t.Errorf("%s: a token file was left behind", name)
		}
	}
}
