package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"portash/internal/provision"
	"portash/internal/tokens"
)

// captureBoth runs f and returns what it printed on stdout and on stderr.
func captureBoth(t *testing.T, f func() error) (stdout, stderr string, err error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	os.Stdout, os.Stderr = wo, we
	err = f()
	wo.Close()
	we.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	o, _ := io.ReadAll(ro)
	e, _ := io.ReadAll(re)
	return string(o), string(e), err
}

func create(t *testing.T, dir string, extra ...string) (stdout, stderr string) {
	t.Helper()
	args := append([]string{"vm1", "--dir", dir, "--ttl", "1h", "--days", "30"}, extra...)
	o, e, err := captureBoth(t, func() error { return provisionCreate(args) })
	if err != nil {
		t.Fatal(err)
	}
	return o, e
}

func TestProvisionCreateThenApplyGivesAWorkingTokenStore(t *testing.T) {
	laptop(t)
	dir := filepath.Join(t.TempDir(), "p")
	out, errOut := create(t, dir)
	bundle := strings.TrimSpace(out)
	if bundle != filepath.Join(dir, "provision.bundle") {
		t.Fatalf("stdout = %q, want only the bundle path", out)
	}
	tok := strings.TrimSpace(readFile(t, filepath.Join(dir, "admin.token")))
	if strings.Contains(out, tok) || strings.Contains(errOut, tok) {
		t.Fatal("create printed the token")
	}
	if !strings.Contains(errOut, "otpauth://") {
		t.Fatal("the unlock link is not shown on first creation")
	}

	state := filepath.Join(t.TempDir(), "state")
	so, se, err := captureBoth(t, func() error { return provisionApply([]string{bundle, "--dir", state}) })
	if err != nil {
		t.Fatal(err)
	}
	b, _ := provision.Parse(readFile(t, bundle))
	for _, secret := range []string{tok, b.TOTP, "PRIVATE KEY"} {
		if strings.Contains(so+se, secret) {
			t.Fatalf("apply printed a secret (%.6s...)", secret)
		}
	}
	if !strings.Contains(so, "created") || !strings.Contains(so, b.Pin) {
		t.Fatalf("apply output:\n%s", so)
	}
	st, err := tokens.NewStore(filepath.Join(state, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := st.Lookup(tok); !ok || e.Name != "admin" {
		t.Fatalf("the token does not work on the applied state: %+v %v", e, ok)
	}
}

func TestProvisionCreateTwiceReusesAndOnlyShowsTheUnlockOnce(t *testing.T) {
	laptop(t)
	dir := filepath.Join(t.TempDir(), "p")
	_, e1 := create(t, dir)
	b1 := readFile(t, filepath.Join(dir, "provision.bundle"))
	_, e2 := create(t, dir)
	if readFile(t, filepath.Join(dir, "provision.bundle")) != b1 {
		t.Fatal("a repeat changed the bundle")
	}
	if !strings.Contains(e1, "otpauth://") || strings.Contains(e2, "otpauth://") {
		t.Fatal("the unlock link must be shown on the first run only")
	}
	if !strings.Contains(e2, "reused") {
		t.Fatalf("second run did not say it reused things:\n%s", e2)
	}
	_, e3 := create(t, dir, "--show-totp")
	if !strings.Contains(e3, "otpauth://") {
		t.Fatal("--show-totp did not show the link")
	}
}

func TestProvisionCreateWithGatewayMakesAGrantThatJoins(t *testing.T) {
	laptop(t)
	dir := filepath.Join(t.TempDir(), "p")
	create(t, dir, "--gateway", "https://vm1.example.com", "--ssh-user", "alice")
	grant := filepath.Join(dir, "admin.grant")
	if err := cmdJoin(context.Background(), []string{grant}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := loadConfig()
	p := cfg.Gateways["vm1.example.com"]
	b, _ := provision.Parse(readFile(t, filepath.Join(dir, "provision.bundle")))
	if p == nil || p.Gateway != "https://vm1.example.com" || p.Pins[0] != b.Pin || p.User != "alice" ||
		p.Token != strings.TrimSpace(readFile(t, filepath.Join(dir, "admin.token"))) {
		t.Fatalf("profile = %+v", p)
	}
}

func TestProvisionApplyReadsStdinAndEnvAndDryRun(t *testing.T) {
	laptop(t)
	dir := filepath.Join(t.TempDir(), "p")
	create(t, dir)
	text := readFile(t, filepath.Join(dir, "provision.bundle"))

	// stdin, with a comment line before the bundle
	r, w, _ := os.Pipe()
	w.WriteString("# from the secrets store\n" + text)
	w.Close()
	oldIn := os.Stdin
	os.Stdin = r
	state := filepath.Join(t.TempDir(), "state")
	out, _, err := captureBoth(t, func() error { return provisionApply([]string{"-", "--dir", state, "--dry-run", "--json"}) })
	os.Stdin = oldIn
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		DryRun bool
		Pin    string
		Items  []provision.Result
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || !res.DryRun || len(res.Items) != 4 {
		t.Fatalf("json = %q, %v", out, err)
	}
	if _, err := os.Stat(state); err == nil {
		t.Fatal("a dry run wrote the state folder")
	}

	// environment variable
	t.Setenv("PORTASH_PROVISION", strings.TrimSpace(text))
	if _, _, err := captureBoth(t, func() error { return provisionApply([]string{"--dir", state}) }); err != nil {
		t.Fatal(err)
	}
	// second run: everything unchanged
	out, _, err = captureBoth(t, func() error { return provisionApply([]string{"--dir", state, "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal([]byte(out), &res)
	for _, it := range res.Items {
		if it.Status != provision.Unchanged {
			t.Errorf("%s: %s on the second run", it.Item, it.Status)
		}
	}
}

func TestProvisionApplyRejectsBadInput(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	t.Setenv("PORTASH_PROVISION", "")
	for name, args := range map[string][]string{
		"no source":    {"--dir", state},
		"no such file": {filepath.Join(t.TempDir(), "none"), "--dir", state},
		"two sources":  {"a", "b", "--dir", state},
	} {
		if _, _, err := captureBoth(t, func() error { return provisionApply(args) }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	junk := filepath.Join(t.TempDir(), "junk")
	os.WriteFile(junk, []byte("pshp1.AAAA\n"), 0o600)
	if _, _, err := captureBoth(t, func() error { return provisionApply([]string{junk, "--dir", state}) }); err == nil {
		t.Error("a damaged bundle was accepted")
	}
	if _, err := os.Stat(state); err == nil {
		t.Error("a rejected bundle left a folder behind")
	}
}

func TestProvisionCreateRejectsBadNames(t *testing.T) {
	laptop(t)
	for _, args := range [][]string{{"bad name"}, {"vm1", "--user", "a/b"}, {}} {
		full := append(append([]string{}, args...), "--dir", filepath.Join(t.TempDir(), "p"))
		if _, _, err := captureBoth(t, func() error { return provisionCreate(full) }); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
