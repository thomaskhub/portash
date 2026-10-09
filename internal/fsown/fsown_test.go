//go:build unix

package fsown

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRootWritesTakeTheFolderOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	dir := t.TempDir()
	os.Chown(dir, 4242, 4242)
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)
	p := filepath.Join(dir, "secret")
	os.Symlink(victim, p) // planted by the folder's owner
	if err := WriteFile(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("write followed a symlink the folder's owner planted")
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("not a regular file: %v %v", fi, err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 4242 || st.Gid != 4242 {
		t.Fatalf("owner %d:%d, want 4242:4242", st.Uid, st.Gid)
	}
}
