//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	secretA = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	secretB = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
)

// importAs runs `portash totp import alice <flags>` with secret on stdin.
func importAs(t *testing.T, dir, secret string, flags ...string) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(secret + "\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	oldIn := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldIn; r.Close() }()
	args := append([]string{"import", "alice", "--totp-dir", dir}, flags...)
	return capture(t, func() error { return cmdTOTP(args) })
}

func TestTotpImportIfMissingLeavesWhatIsThere(t *testing.T) {
	dir := t.TempDir()
	if _, err := importAs(t, dir, secretA); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(dir, "alice.secret")
	stateFile := filepath.Join(dir, "alice.state")
	if err := os.WriteFile(stateFile, []byte(`{"lastStep":42}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(secretFile)

	out, err := importAs(t, dir, secretB, "--if-missing", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var res struct{ Name, Status string }
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Name != "alice" || res.Status != "unchanged" {
		t.Fatalf("output %q (%v)", out, err)
	}
	if strings.Contains(out, secretA) || strings.Contains(out, secretB) {
		t.Fatal("the output holds a secret")
	}
	after, _ := os.ReadFile(secretFile)
	state, _ := os.ReadFile(stateFile)
	if string(before) != string(after) || string(state) != `{"lastStep":42}` {
		t.Fatal("the secret or its replay state changed")
	}
}

func TestTotpImportIfMissingCreatesAndReportsIt(t *testing.T) {
	dir := t.TempDir()
	out, err := importAs(t, dir, secretA, "--if-missing", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var res struct{ Name, Status string }
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Status != "created" {
		t.Fatalf("output %q (%v)", out, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "alice.secret")); err != nil {
		t.Fatal("no secret was written")
	}
}

// A secret whose file has the wrong mode is unusable, but it is still there:
// --if-missing must not replace it.
func TestTotpImportIfMissingKeepsAFileWithABadMode(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "alice.secret")
	if err := os.WriteFile(secretFile, []byte(secretA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := importAs(t, dir, secretB, "--if-missing"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(secretFile); !strings.Contains(string(got), secretA) {
		t.Fatalf("the secret was replaced: %q", got)
	}
}

func TestTotpImportWithoutIfMissingStillReplaces(t *testing.T) {
	dir := t.TempDir()
	if _, err := importAs(t, dir, secretA); err != nil {
		t.Fatal(err)
	}
	if _, err := importAs(t, dir, secretB); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "alice.secret")); !strings.Contains(string(got), secretB) {
		t.Fatalf("plain import no longer replaces: %q", got)
	}
}
