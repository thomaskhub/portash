package main

import (
	"os/exec"
	"runtime"
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
