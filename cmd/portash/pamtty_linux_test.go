//go:build linux

package main

import "testing"

func TestPAMTTYOnlyOpensTerminals(t *testing.T) {
	for _, name := range []string{"", "/dev/null", "/dev/sda", "../etc/shadow", "/dev/pts/../../etc/shadow",
		"pts/1x", "/etc/shadow", "/dev/pts/999999"} {
		if f, err := openPAMTTY(name, "root"); err == nil {
			f.Close()
			t.Errorf("%q opened", name)
		}
	}
}
