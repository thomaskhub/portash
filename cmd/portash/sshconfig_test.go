package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestQuoteExe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("checks the Unix shell")
	}
	for _, exe := range []string{
		"/usr/local/bin/portash",
		"/tmp/with space/portash",
		`/tmp/dollar$HOME/portash`,
		"/tmp/back`tick`/portash",
		`/tmp/quo"te/portash`,
		"/tmp/it's/portash",
		`/tmp/back\slash/portash`,
	} {
		line := quoteExe(exe) + " dial --gateway vm1 %h %p"
		// What ssh does with ProxyCommand: run it with sh -c. printf shows argv[0].
		out, err := exec.Command("sh", "-c", `printf %s\\n `+line).Output()
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		want := exe + "\ndial\n--gateway\nvm1\n%h\n%p\n"
		if string(out) != want {
			t.Errorf("exe %q: sh saw %q, want %q", exe, out, want)
		}
	}
}

func TestQuoteExePlainPathUntouched(t *testing.T) {
	if got := quoteExe("/usr/bin/portash"); got != "/usr/bin/portash" {
		t.Fatalf("got %q", got)
	}
}

func TestWriteSSHConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	os.MkdirAll(sshDir, 0o700)
	mine := "Host vm1\n    User ubuntu\n"
	os.WriteFile(filepath.Join(sshDir, "config"), []byte(mine), 0o644)

	c := clientConfig{Gateways: map[string]*profile{"vm1": {}, "vm2": {}}}
	for i := 0; i < 3; i++ { // running it again changes nothing
		if err := writeSSHConfig(c); err != nil {
			t.Fatal(err)
		}
	}
	cfg, _ := os.ReadFile(filepath.Join(sshDir, "config"))
	if !strings.HasPrefix(string(cfg), "# Host blocks") || strings.Count(string(cfg), "Include portash.conf") != 1 ||
		!strings.HasSuffix(string(cfg), mine) {
		t.Errorf("config:\n%s", cfg)
	}
	if fi, _ := os.Stat(filepath.Join(sshDir, "config")); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Errorf("config mode %v, want the old 0644", fi.Mode().Perm())
	}
	inc, _ := os.ReadFile(filepath.Join(sshDir, "portash.conf"))
	if strings.Count(string(inc), "Host vm1\n") != 1 || strings.Count(string(inc), "Host vm2\n") != 1 {
		t.Errorf("portash.conf:\n%s", inc)
	}

	// A removed gateway disappears from portash.conf on the next run.
	delete(c.Gateways, "vm2")
	writeSSHConfig(c)
	inc, _ = os.ReadFile(filepath.Join(sshDir, "portash.conf"))
	if strings.Contains(string(inc), "vm2") {
		t.Errorf("vm2 still there:\n%s", inc)
	}

	// An Include the user wrote themselves counts.
	if !includesPortash("include ~/.ssh/portash.conf\n") || includesPortash("Host x\n  # portash.conf\n") {
		t.Error("includesPortash")
	}
}

func TestWriteSSHConfigWithRealSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil || runtime.GOOS == "windows" {
		t.Skip("needs OpenSSH")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host vm1\n    User ubuntu\n"), 0o600)
	if err := writeSSHConfig(clientConfig{Gateways: map[string]*profile{"vm1": {}}}); err != nil {
		t.Fatal(err)
	}
	// ssh -G prints the settings ssh would use: both files must apply.
	out, err := exec.Command("ssh", "-G", "-F", filepath.Join(home, ".ssh", "config"), "vm1").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"user ubuntu", "hostname 127.0.0.1", "hostkeyalias vm1", "dial --gateway vm1"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("ssh -G misses %q", want)
		}
	}
}
