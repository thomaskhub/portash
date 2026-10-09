package pin

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func load(t *testing.T, dir string) tls.Certificate {
	t.Helper()
	c, err := tls.LoadX509KeyPair(filepath.Join(dir, "gateway.crt"), filepath.Join(dir, "gateway.key"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGenerateReturnsThePinOfWhatItWrote(t *testing.T) {
	dir := t.TempDir()
	got, err := Generate(dir, "vm1", 30)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := Leaf(load(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if want := Of(leaf); got != want {
		t.Fatalf("Generate returned %s, the certificate on disk has %s", got, want)
	}
	if !Valid(got) {
		t.Fatalf("%q is not a valid pin", got)
	}
	// The gateway's own start-up path finds the key and does not make another one.
	c, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := Leaf(c); Of(l) != got {
		t.Fatal("LoadOrCreate changed the key")
	}
}

func TestGenerateNeverReplacesAnything(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir, "vm1", 30); err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(filepath.Join(dir, "gateway.key"))
	crt, _ := os.ReadFile(filepath.Join(dir, "gateway.crt"))
	if _, err := Generate(dir, "vm1", 30); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("second Generate = %v, want ErrKeyExists", err)
	}
	key2, _ := os.ReadFile(filepath.Join(dir, "gateway.key"))
	crt2, _ := os.ReadFile(filepath.Join(dir, "gateway.crt"))
	if string(key) != string(key2) || string(crt) != string(crt2) {
		t.Fatal("the files changed")
	}
}

// A certificate that is missing next to an existing key used to make the
// gateway write a new key over the old one.
func TestLoadOrCreateKeepsAKeyWhoseCertificateIsMissing(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir, "vm1", 30); err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(filepath.Join(dir, "gateway.key"))
	if err := os.Remove(filepath.Join(dir, "gateway.crt")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("LoadOrCreate = %v, want ErrKeyExists", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "gateway.key"))
	if string(key) != string(after) {
		t.Fatal("the key was replaced")
	}
}

func TestOnlyACertificateAlsoBlocks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gateway.crt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(dir, "vm1", 30); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("Generate = %v, want ErrKeyExists", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "gateway.key")); err == nil {
		t.Fatal("a key was written next to a foreign certificate")
	}
}

func TestKeyModeAndSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes and symlinks differ on Windows")
	}
	dir := t.TempDir()
	if _, err := Generate(dir, "vm1", 30); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "gateway.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v, want 0600", fi.Mode().Perm())
	}

	dir2, victim := t.TempDir(), filepath.Join(t.TempDir(), "victim")
	if err := os.Symlink(victim, filepath.Join(dir2, "gateway.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(dir2, "vm1", 30); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("Generate over a symlink = %v, want ErrKeyExists", err)
	}
	if _, err := os.Lstat(victim); err == nil {
		t.Fatal("the key was written through the symlink")
	}
}

func TestNameAndDays(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir, "vm1.example.com", 90); err != nil {
		t.Fatal(err)
	}
	leaf, _ := Leaf(load(t, dir))
	if !strings.Contains(leaf.Subject.CommonName, "vm1.example.com") {
		t.Fatalf("subject %q does not name the VM", leaf.Subject.CommonName)
	}
	if got := time.Until(leaf.NotAfter); got < 89*24*time.Hour || got > 91*24*time.Hour {
		t.Fatalf("valid for %v, want about 90 days", got)
	}
	for _, bad := range []string{"a b", "a/b", "../x", "a\nb", strings.Repeat("a", 65)} {
		if _, err := Generate(t.TempDir(), bad, 30); err == nil {
			t.Errorf("name %q was accepted", bad)
		}
	}
	for _, days := range []int{0, -1, 3651} {
		if _, err := Generate(t.TempDir(), "vm1", days); err == nil {
			t.Errorf("days %d was accepted", days)
		}
	}
}

func TestParallelGenerateHasOneWinner(t *testing.T) {
	dir := t.TempDir()
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Generate(dir, "vm1", 30); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d calls succeeded, want exactly 1", wins.Load())
	}
	// Whatever the losers did, what is on disk is one consistent pair.
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "gateway.crt"), filepath.Join(dir, "gateway.key")); err != nil {
		t.Fatalf("key and certificate do not belong together: %v", err)
	}
}
