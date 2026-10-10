package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"portash/internal/tokens"
)

const testHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

var testPin = "sha256:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))

// laptop gives the test its own HOME and config folder and a device key, and
// returns that key as the admin would see it (portash device).
func laptop(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("APPDATA", filepath.Join(home, ".config"))
	priv, err := deviceKey(true)
	if err != nil {
		t.Fatal(err)
	}
	return tokens.FormatDevice(priv.Public().(ed25519.PublicKey))
}

// makeGrant runs token new and grant like an admin would, and returns the
// grant file and the token.
func makeGrant(t *testing.T, device string, extra ...string) (grantFile, token string) {
	t.Helper()
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "alice.token")
	if _, err := capture(t, func() error { return tokenNew("alice-laptop", device, time.Hour, tokFile, false) }); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(tokFile)
	grantFile = filepath.Join(dir, "alice.grant")
	args := append([]string{"--device", device, "--token-file", tokFile, "--gateway", "https://vm1.example.com",
		"--pin", testPin, "--out", grantFile}, extra...)
	if err := cmdGrant(args); err != nil {
		t.Fatal(err)
	}
	return grantFile, strings.TrimSpace(string(raw))
}

func TestGrantThenJoinSetsTheLaptopUpWithoutANetwork(t *testing.T) {
	dev := laptop(t)
	hostKeyFile := filepath.Join(t.TempDir(), "host.pub")
	if err := os.WriteFile(hostKeyFile, []byte(testHostKey+" root@vm1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	grant, token := makeGrant(t, dev, "--ssh-user", "alice", "--host-key", hostKeyFile)

	// no listener anywhere: a join that tried to connect would fail or hang
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cmdJoin(ctx, []string{grant}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Gateways["vm1.example.com"]
	if p == nil || p.Gateway != "https://vm1.example.com" || len(p.Pins) != 1 || p.Pins[0] != testPin || p.Token != token || p.User != "alice" {
		t.Fatalf("profile = %+v", p)
	}
	home, _ := os.UserHomeDir()
	known, _ := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts"))
	if !strings.Contains(string(known), "vm1.example.com "+testHostKey) {
		t.Fatalf("host key not trusted: %q", known)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "portash.conf")); err != nil {
		t.Fatalf("ssh config not written: %v", err)
	}
	// the same grant again is not an error and changes nothing
	if err := cmdJoin(ctx, []string{grant}); err != nil {
		t.Fatal(err)
	}
}

func TestGrantTokenIsNeverAnArgument(t *testing.T) {
	dev := laptop(t)
	args := []string{"--device", dev, "--token", "psh_" + strings.Repeat("A", 43), "--gateway", "vm1.example.com", "--pin", testPin}
	if err := cmdGrant(args); err == nil {
		t.Fatal("grant took the token as an argument")
	}
	if err := cmdGrant([]string{"--device", dev, "--gateway", "vm1.example.com", "--pin", testPin}); err == nil {
		t.Fatal("grant without --token-file worked")
	}
}

func TestGrantOutFileIsPrivateAndNeverReplaced(t *testing.T) {
	dev := laptop(t)
	grant, _ := makeGrant(t, dev)
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(grant)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("grant file mode %v, %v", fi.Mode(), err)
		}
	}
	tokFile := filepath.Join(filepath.Dir(grant), "alice.token")
	err := cmdGrant([]string{"--device", dev, "--token-file", tokFile, "--gateway", "https://vm1.example.com", "--pin", testPin, "--out", grant})
	if err == nil {
		t.Fatal("grant replaced an existing file")
	}
}

func TestGrantWithoutOutPrintsIt(t *testing.T) {
	dev := laptop(t)
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "t")
	if _, err := capture(t, func() error { return tokenNew("a", dev, time.Hour, tokFile, false) }); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, func() error {
		return cmdGrant([]string{"--device", dev, "--token-file", tokFile, "--gateway", "vm1.example.com", "--pin", testPin})
	})
	if err != nil || !strings.HasPrefix(out, "pshg1.") || strings.Count(out, "\n") != 1 {
		t.Fatalf("output %q, %v", out, err)
	}
}

func TestJoinRefusesAGrantForAnotherLaptop(t *testing.T) {
	_ = laptop(t) // this laptop's key
	other := newDevice(t)
	grant, _ := makeGrant(t, other)
	err := cmdJoin(context.Background(), []string{grant})
	if err == nil || !strings.Contains(err.Error(), "another laptop") {
		t.Fatalf("join = %v, want the 'another laptop' error", err)
	}
	cfg, _ := loadConfig()
	if len(cfg.Gateways) != 0 {
		t.Fatalf("a refused grant changed the config: %+v", cfg.Gateways)
	}
}

// A laptop without a device key must not get one made behind its back: the
// token would be bound to a key the admin never saw.
func TestJoinDoesNotMakeADeviceKeyForAGrant(t *testing.T) {
	dev := newDevice(t)
	grant, _ := makeGrant(t, dev)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("APPDATA", filepath.Join(home, ".config"))
	err := cmdJoin(context.Background(), []string{grant})
	if err == nil || !strings.Contains(err.Error(), "portash device") {
		t.Fatalf("join = %v, want a hint about portash device", err)
	}
	if _, statErr := deviceKey(false); statErr == nil {
		t.Fatal("join made a device key")
	}
}

func TestJoinNeverSilentlyReplacesAGatewayYouHave(t *testing.T) {
	dev := laptop(t)
	grant, token := makeGrant(t, dev)
	if err := saveProfile("vm1.example.com", &profile{Gateway: "vm1.example.com:443", Pins: []string{testPin}, Token: "psh_old"}, ""); err != nil {
		t.Fatal(err)
	}
	if err := cmdJoin(context.Background(), []string{grant}); err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("join over another gateway = %v, want a --replace hint", err)
	}
	if cfg, _ := loadConfig(); cfg.Gateways["vm1.example.com"].Token != "psh_old" {
		t.Fatal("the existing profile was replaced")
	}
	if err := cmdJoin(context.Background(), []string{grant, "--replace"}); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := loadConfig(); cfg.Gateways["vm1.example.com"].Token != token {
		t.Fatal("--replace did not replace")
	}
}

func TestJoinRejectsDamagedGrantsAndChangesNothing(t *testing.T) {
	dev := laptop(t)
	grant, _ := makeGrant(t, dev)
	raw, _ := os.ReadFile(grant)
	s := strings.TrimSpace(string(raw))
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte(s[:len(s)-8]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, arg := range map[string]string{"truncated file": bad, "truncated string": s[:len(s)-8], "empty file": filepath.Join(t.TempDir(), "none")} {
		if err := cmdJoin(context.Background(), []string{arg}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if cfg, _ := loadConfig(); len(cfg.Gateways) != 0 {
		t.Fatalf("a damaged grant changed the config: %+v", cfg.Gateways)
	}
}

func TestSaveProfileTrustsAHostKeyOnce(t *testing.T) {
	laptop(t)
	for range 2 {
		if err := saveProfile("vm9", &profile{Gateway: "vm9:443", Pins: []string{testPin}, Token: "psh_x"}, testHostKey); err != nil {
			t.Fatal(err)
		}
	}
	home, _ := os.UserHomeDir()
	known, _ := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts"))
	if strings.Count(string(known), "vm9 ") != 1 {
		t.Fatalf("known_hosts = %q", known)
	}
}
