package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"portash/internal/tokens"
)

func TestTokenLsShowsDropinsAndWhatWasIgnored(t *testing.T) {
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tok, err := tokens.New()
	if err != nil {
		t.Fatal(err)
	}
	drop := filepath.Join(dir, tokens.DropinName)
	if err := os.Mkdir(drop, 0o700); err != nil {
		t.Fatal(err)
	}
	line := fmt.Sprintf("ci %x device=%s\n", sha256.Sum256([]byte(tok)), tokens.FormatDevice(pub))
	if err := os.WriteFile(filepath.Join(drop, "ci"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, func() error { return cmdToken([]string{"ls", "--dir", dir}) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "FROM") || !strings.Contains(out, "ci") || !strings.Contains(out, tokens.DropinName+"/ci") {
		t.Fatalf("token ls did not show the source:\n%s", out)
	}
	if err := cmdToken([]string{"rm", "ci", "--dir", dir}); err == nil || !strings.Contains(err.Error(), tokens.DropinName+"/ci") {
		t.Fatalf("rm = %v, want an error naming the file", err)
	}
}
