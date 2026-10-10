package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"portash/internal/invite"
	"portash/internal/pin"
	"portash/internal/tokens"
	"portash/internal/totp"
)

// statusDir builds a gateway state folder with every kind of thing in it and
// returns the folder and every secret or private value that was put in, so a
// test can check that none of them shows up in the output.
func statusDir(t *testing.T) (dir string, secrets []string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, c := range []struct {
		name string
		ttl  time.Duration
	}{{"alice", time.Hour}, {"old", -time.Hour}} {
		tok, err := tokens.New()
		if err != nil {
			t.Fatal(err)
		}
		dev := newDevice(t)
		pub, _ := tokens.ParseDevice(dev)
		h := sha256.Sum256([]byte(tok))
		line := fmt.Sprintf("%s %x device=%s", c.name, h, dev)
		if c.ttl != 0 {
			line += " expires=" + time.Now().Add(c.ttl).UTC().Format(time.RFC3339)
		}
		_ = pub
		lines = append(lines, line)
		secrets = append(secrets, tok, hex.EncodeToString(h[:]), dev)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokens"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// tokens.d: one good file, one that does not parse
	drop := filepath.Join(dir, tokens.DropinName)
	if err := os.Mkdir(drop, 0o700); err != nil {
		t.Fatal(err)
	}
	tok, _ := tokens.New()
	h := sha256.Sum256([]byte(tok))
	dev := newDevice(t)
	if err := os.WriteFile(filepath.Join(drop, "ci"), []byte(fmt.Sprintf("ci %x device=%s\n", h, dev)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(drop, "broken"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secrets = append(secrets, tok, hex.EncodeToString(h[:]), dev)
	// gateway key (the pin is public, the key is not)
	if _, err := pin.LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	if k, err := os.ReadFile(filepath.Join(dir, "gateway.key")); err == nil {
		for _, l := range strings.Split(string(k), "\n") {
			if len(l) > 20 && !strings.HasPrefix(l, "-----") {
				secrets = append(secrets, l)
			}
		}
	}
	// TOTP secret for the daily unlock, ticket file, invites
	st := totp.Store{Dir: filepath.Join(dir, "unlock"), ValidName: tokens.ValidName}
	if err := os.MkdirAll(st.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if err := st.Import("alice", totpSecret); err != nil {
		t.Fatal(err)
	}
	ticket := strings.Repeat("deadbeef", 8)
	if err := os.WriteFile(filepath.Join(dir, "tickets"), []byte(ticket+" "+ticket+" 2099-01-01T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	invDir := filepath.Join(dir, "invites")
	secret, err := invite.Create(invDir, invite.Invite{Name: "bob", Host: "vm1", Expires: time.Now().Add(time.Hour), TokenTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	secrets = append(secrets, totpSecret, ticket, secret)
	return dir, secrets
}

func TestGatewayStatusFieldsAndValues(t *testing.T) {
	dir, _ := statusDir(t)
	out, err := capture(t, func() error { return cmdGatewayStatus([]string{"--dir", dir, "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var st gatewayStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	cert, err := pin.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pin.Leaf(cert)
	if st.Pin != pin.Of(leaf) || st.Dir != dir || st.Version == "" {
		t.Fatalf("identity fields wrong: %+v", st)
	}
	// alice + old from the file, ci from tokens.d; "old" is expired; "broken" is ignored
	if st.Tokens != 3 || st.TokensExpired != 1 || st.DropinTokens != 1 || st.DropinRefused != 1 {
		t.Fatalf("token counts wrong: %+v", st)
	}
	if st.OpenInvites != 1 || st.PendingLaptops != 0 || st.UnlockSecrets != 1 {
		t.Fatalf("invite or unlock counts wrong: %+v", st)
	}
	byName := map[string]statusCheck{}
	for _, c := range st.Checks {
		byName[c.Name] = c
	}
	if c := byName["tokens.d"]; c.OK || !strings.Contains(c.Detail, "broken") {
		t.Fatalf("tokens.d check = %+v, want a failure naming the broken file", c)
	}
	if runtime.GOOS != "windows" {
		for _, n := range []string{"state folder", "tokens file", "gateway key", "tickets file", "unlock folder"} {
			if !byName[n].OK {
				t.Errorf("check %q failed on a correct folder: %+v", n, byName[n])
			}
		}
	}
}

// The JSON names are an API for scripts: a change must be deliberate.
func TestGatewayStatusJSONFieldNames(t *testing.T) {
	dir, _ := statusDir(t)
	out, _ := capture(t, func() error { return cmdGatewayStatus([]string{"--dir", dir, "--json"}) })
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"checks", "dir", "dropinRefused", "dropinTokens", "openInvites", "pendingLaptops", "pin", "tokens", "tokensExpired", "unlockSecrets", "version"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("fields = %v, want %v", got, want)
	}
}

func TestGatewayStatusNeverShowsASecret(t *testing.T) {
	dir, secrets := statusDir(t)
	if len(secrets) < 12 {
		t.Fatalf("the fixture has only %d secrets to look for", len(secrets))
	}
	for _, args := range [][]string{{"--dir", dir, "--json"}, {"--dir", dir}} {
		out, err := capture(t, func() error { return cmdGatewayStatus(args) })
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if len(s) >= 16 && strings.Contains(out, s) {
				t.Fatalf("args %v: the output contains a secret or private value (%s...)", args, s[:8])
			}
		}
	}
}

func TestGatewayStatusOnlyReads(t *testing.T) {
	dir, _ := statusDir(t)
	// an invite that expired: List would delete it, status must not
	invDir := filepath.Join(dir, "invites")
	if _, err := invite.Create(invDir, invite.Invite{Name: "late", Host: "vm1", Expires: time.Now().Add(-time.Hour), TokenTTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		var b strings.Builder
		filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
			if err == nil {
				fmt.Fprintf(&b, "%s %d %v\n", p, fi.Size(), fi.ModTime().UnixNano())
			}
			return nil
		})
		return b.String()
	}
	before := snapshot()
	if _, err := capture(t, func() error { return cmdGatewayStatus([]string{"--dir", dir, "--json"}) }); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(); after != before {
		t.Fatalf("gateway-status changed the folder:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestGatewayStatusExitCodes(t *testing.T) {
	if _, err := capture(t, func() error { return cmdGatewayStatus([]string{"--dir", filepath.Join(t.TempDir(), "nope")}) }); err == nil {
		t.Fatal("a folder that does not exist must be an error (exit 1)")
	}
	if runtime.GOOS == "windows" {
		return
	}
	dir, _ := statusDir(t)
	if err := os.Chmod(filepath.Join(dir, "tokens"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, func() error { return cmdGatewayStatus([]string{"--dir", dir}) })
	if err != nil {
		t.Fatalf("a failed check must not make the command fail: %v", err)
	}
	if !strings.Contains(out, "FAIL") {
		t.Fatalf("the failed check is not shown:\n%s", out)
	}
}

func TestGatewayStatusEmptyFolder(t *testing.T) {
	dir := t.TempDir()
	out, err := capture(t, func() error { return cmdGatewayStatus([]string{"--dir", dir, "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var st gatewayStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Tokens != 0 || st.Pin != "" || st.Checks == nil {
		t.Fatalf("empty folder: %+v, %v", st, err)
	}
}

func TestInviteApproveQuietStillShowsErrors(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInvite([]string{"approve", "nobody", "ABCD-EFGH", "--dir", dir, "--quiet"}); err == nil {
		t.Fatal("--quiet hid the error of an approval that cannot happen")
	}
}
