package secretfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := WriteNew(path, []byte("secret\n")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "secret\n" {
		t.Fatalf("content %q, %v", got, err)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
}

func TestWriteNewNeverReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := WriteNew(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(path, []byte("second")); !errors.Is(err, ErrExists) {
		t.Fatalf("second write = %v, want ErrExists", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "first" {
		t.Fatalf("file now holds %q", got)
	}
}

func TestWriteNewRefusesASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	link := filepath.Join(dir, "token")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(link, []byte("secret")); !errors.Is(err, ErrExists) {
		t.Fatalf("write through a symlink = %v, want ErrExists", err)
	}
	if _, err := os.Lstat(victim); err == nil {
		t.Fatal("the secret was written through the symlink")
	}
}
