//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The sandbox can't be undone, so it is applied in a child process.
func TestMain(m *testing.M) {
	if dir := os.Getenv("PORTASH_SANDBOX_CHILD"); dir != "" {
		allowed, denied := filepath.Join(dir, "allowed"), filepath.Join(dir, "denied")
		if err := Restrict([]string{allowed}); err != nil {
			os.Stdout.WriteString("restrict: " + err.Error())
			os.Exit(2)
		}
		var out []string
		try := func(name string, err error) {
			if err == nil {
				out = append(out, name+"=ok")
			} else {
				out = append(out, name+"=denied")
			}
		}
		try("write-allowed", os.WriteFile(filepath.Join(allowed, "f"), []byte("x"), 0o600))
		try("write-denied", os.WriteFile(filepath.Join(denied, "f"), []byte("x"), 0o600))
		try("delete-denied", os.Remove(filepath.Join(denied, "keep")))
		try("rename-out", os.Rename(filepath.Join(denied, "keep"), filepath.Join(allowed, "stolen")))
		try("truncate-denied", os.Truncate(filepath.Join(denied, "keep"), 0))
		_, err := os.ReadFile(filepath.Join(denied, "keep"))
		try("read-denied-dir", err)
		// Children inherit the sandbox: a shell can't escape it.
		try("child-shell", exec.Command("/bin/sh", "-c", "echo x > "+filepath.Join(denied, "g")).Run())
		os.Stdout.WriteString(strings.Join(out, " "))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRestrict(t *testing.T) {
	if ABI() < 1 {
		t.Skip("no Landlock in this kernel")
	}
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "allowed"), 0o755)
	os.Mkdir(filepath.Join(dir, "denied"), 0o755)
	os.WriteFile(filepath.Join(dir, "denied", "keep"), []byte("data"), 0o644)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "PORTASH_SANDBOX_CHILD="+dir)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child: %v %s", err, out)
	}
	want := "write-allowed=ok write-denied=denied delete-denied=denied rename-out=denied truncate-denied=denied read-denied-dir=ok child-shell=denied"
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "denied", "keep")); string(b) != "data" {
		t.Fatal("protected file was changed")
	}
}
