package provision

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"portash/internal/tokens"
	"portash/internal/totp"
)

func device(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func prepare(t *testing.T, dir string, dev ed25519.PublicKey) Prepared {
	t.Helper()
	p, err := Prepare(Options{Dir: dir, VM: "vm1", User: "admin", Device: dev, TTL: time.Hour, Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// snapshot lists every file under dir with its size, mode and content hash.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		c := ""
		if fi.Mode().IsRegular() {
			c = fmt.Sprint(len(read(t, p)), read(t, p))
		}
		lines = append(lines, fmt.Sprintf("%s %v %s", p, fi.Mode(), c))
		return nil
	})
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestPrepareTwiceMakesNothingTwice(t *testing.T) {
	dir, dev := filepath.Join(t.TempDir(), "p"), device(t)
	a := prepare(t, dir, dev)
	if !a.NewKey || !a.NewToken || !a.NewTOTP {
		t.Fatalf("first run must make everything: %+v", a)
	}
	bundle1, tok1 := read(t, a.BundleOut), read(t, a.TokenFile)
	b := prepare(t, dir, dev)
	if b.NewKey || b.NewToken || b.NewTOTP {
		t.Fatalf("second run made something again: %+v", b)
	}
	if read(t, b.BundleOut) != bundle1 || read(t, b.TokenFile) != tok1 || a.Pin != b.Pin {
		t.Fatal("a repeat changed the bundle, the token or the pin")
	}
	if got := strings.TrimSpace(read(t, filepath.Join(dir, "pin"))); got != a.Pin {
		t.Fatalf("pin file = %q, want %q", got, a.Pin)
	}
}

// The pin file once ended up empty; it is rewritten from the certificate.
func TestPrepareRewritesAnEmptyPinFile(t *testing.T) {
	dir, dev := filepath.Join(t.TempDir(), "p"), device(t)
	a := prepare(t, dir, dev)
	if err := os.WriteFile(filepath.Join(dir, "pin"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prepare(t, dir, dev)
	if got := strings.TrimSpace(read(t, filepath.Join(dir, "pin"))); got != a.Pin {
		t.Fatalf("pin file = %q after a repeat, want %q", got, a.Pin)
	}
}

func TestPrepareRefusesAFolderOfAnotherDevice(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	prepare(t, dir, device(t))
	before := snapshot(t, dir)
	if _, err := Prepare(Options{Dir: dir, VM: "vm1", User: "admin", Device: device(t), TTL: time.Hour}); err == nil || !strings.Contains(err.Error(), "another device key") {
		t.Fatalf("Prepare = %v, want the 'another device key' error", err)
	}
	if snapshot(t, dir) != before {
		t.Fatal("a refused run changed the folder")
	}
}

func TestPrepareNotesHalfMadeTokens(t *testing.T) {
	dir, dev := filepath.Join(t.TempDir(), "p"), device(t)
	a := prepare(t, dir, dev)
	if err := os.Remove(a.LineFile); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(Options{Dir: dir, VM: "vm1", User: "admin", Device: dev, TTL: time.Hour}); err == nil {
		t.Fatal("a token without its line was silently replaced")
	}
}

func TestPrepareChecksTheTokenBelongsToTheLine(t *testing.T) {
	dir, dev := filepath.Join(t.TempDir(), "p"), device(t)
	a := prepare(t, dir, dev)
	other, _, _ := tokens.NewEntry("x", dev, time.Hour)
	if err := os.WriteFile(a.TokenFile, []byte(other+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(Options{Dir: dir, VM: "vm1", User: "admin", Device: dev, TTL: time.Hour}); err == nil {
		t.Fatal("a token that does not match its line was accepted")
	}
}

func TestPrepareFilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are advisory on Windows")
	}
	dir := filepath.Join(t.TempDir(), "p")
	a := prepare(t, dir, device(t))
	for path, want := range map[string]os.FileMode{dir: 0o700, a.TokenFile: 0o600, a.TOTPFile: 0o600, a.BundleOut: 0o600,
		filepath.Join(dir, "gw", "gateway.key"): 0o600} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, %v; want %v", path, fi.Mode().Perm(), err, want)
		}
	}
}

// The line names the device's public key (the VM needs it to check the token's signature);
// the token itself and the private key are never in the bundle.
func TestBundleHoldsNoTokenAndNoPrivateDeviceKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := prepare(t, filepath.Join(t.TempDir(), "p"), pub)
	tok := strings.TrimSpace(read(t, a.TokenFile))
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(read(t, a.BundleOut)), Prefix))
	if strings.Contains(string(raw), tok) {
		t.Fatal("the bundle contains the token")
	}
	if strings.Contains(string(raw), base64.RawURLEncoding.EncodeToString(priv.Seed())) {
		t.Fatal("the bundle contains the device's private key")
	}
}

func TestParseRoundTripAndRejections(t *testing.T) {
	a := prepare(t, filepath.Join(t.TempDir(), "p"), device(t))
	got, err := Parse(read(t, a.BundleOut))
	if err != nil || got != a.Bundle {
		t.Fatalf("round trip: %v", err)
	}
	other := prepare(t, filepath.Join(t.TempDir(), "q"), device(t)).Bundle
	_, expired, _ := tokens.NewEntry("admin", device(t), time.Hour)
	expired.Expires = time.Now().Add(-time.Hour)
	mut := map[string]func(*Bundle){
		"version":        func(b *Bundle) { b.Version = 2 },
		"vm name":        func(b *Bundle) { b.VM = "a b" },
		"token name":     func(b *Bundle) { b.Name = "../x" },
		"pin":            func(b *Bundle) { b.Pin = other.Pin },
		"bad pin":        func(b *Bundle) { b.Pin = "sha256:x" },
		"key of another": func(b *Bundle) { b.Key = other.Key },
		"cert of another": func(b *Bundle) {
			b.Cert = other.Cert
		},
		"key not pem":     func(b *Bundle) { b.Key = "nope" },
		"cert not pem":    func(b *Bundle) { b.Cert = "nope" },
		"line for other":  func(b *Bundle) { b.Name = "other" },
		"two lines":       func(b *Bundle) { b.Line += "\n" + b.Line },
		"garbage line":    func(b *Bundle) { b.Line = "garbage" },
		"expired token":   func(b *Bundle) { b.Line = tokens.FormatEntry(expired) },
		"short totp":      func(b *Bundle) { b.TOTP = "ABCD" },
		"non-base32 totp": func(b *Bundle) { b.TOTP = strings.Repeat("1", 32) },
	}
	for name, f := range mut {
		b := a.Bundle
		f(&b)
		if _, err := Parse(b.String()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s := a.Bundle.String()
	for name, bad := range map[string]string{
		"no prefix": strings.TrimPrefix(s, Prefix), "truncated": s[:len(s)-9], "empty": "",
		"not base64": Prefix + "!!!", "too long": Prefix + strings.Repeat("A", MaxSize+1),
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// an unknown field, and two values in a row
	var m map[string]any
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, Prefix))
	json.Unmarshal(raw, &m)
	m["extra"] = 1
	j, _ := json.Marshal(m)
	if _, err := Parse(Prefix + base64.RawURLEncoding.EncodeToString(j)); err == nil {
		t.Error("an unknown field was accepted")
	}
	if _, err := Parse(Prefix + base64.RawURLEncoding.EncodeToString(append(raw, raw...))); err == nil {
		t.Error("trailing data was accepted")
	}
}

func applyTo(t *testing.T, dir string, b Bundle, dry bool) map[string]string {
	t.Helper()
	res, err := Apply(dir, b, dry)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, r := range res {
		m[r.Item] = r.Status
	}
	return m
}

func TestApplyCreatesThenIsUnchanged(t *testing.T) {
	b := prepare(t, filepath.Join(t.TempDir(), "p"), device(t)).Bundle
	state := filepath.Join(t.TempDir(), "state")
	first := applyTo(t, state, b, false)
	for item, st := range first {
		if st != Created {
			t.Errorf("first apply: %s is %s", item, st)
		}
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{state: 0o700, filepath.Join(state, "gateway.key"): 0o600,
			filepath.Join(state, "gateway.crt"): 0o644, filepath.Join(state, "tokens.d", "admin"): 0o600,
			filepath.Join(state, "tokens.d"): 0o700, filepath.Join(state, "unlock", "admin.secret"): 0o600} {
			fi, err := os.Stat(path)
			if err != nil || fi.Mode().Perm() != want {
				t.Errorf("%s: %v, %v; want %v", path, fi.Mode().Perm(), err, want)
			}
		}
	}
	before := snapshot(t, state)
	for item, st := range applyTo(t, state, b, false) {
		if st != Unchanged {
			t.Errorf("second apply: %s is %s", item, st)
		}
	}
	if snapshot(t, state) != before {
		t.Fatal("a repeat changed the folder")
	}
}

// What apply writes works: a Store on that folder accepts the token.
func TestAppliedTokenWorksInAStore(t *testing.T) {
	a := prepare(t, filepath.Join(t.TempDir(), "p"), device(t))
	state := filepath.Join(t.TempDir(), "state")
	applyTo(t, state, a.Bundle, false)
	st, err := tokens.NewStore(filepath.Join(state, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := st.Lookup(strings.TrimSpace(read(t, a.TokenFile))); !ok || e.Name != "admin" {
		t.Fatalf("lookup = %+v, %v", e, ok)
	}
	if !(totp.Store{Dir: filepath.Join(state, "unlock"), ValidName: tokens.ValidName}).Has("admin") {
		t.Fatal("the unlock secret is not usable")
	}
}

func TestApplyNeverReplacesADifferentKey(t *testing.T) {
	a := prepare(t, filepath.Join(t.TempDir(), "p"), device(t)).Bundle
	b := prepare(t, filepath.Join(t.TempDir(), "q"), device(t)).Bundle
	state := filepath.Join(t.TempDir(), "state")
	applyTo(t, state, a, false)
	before := snapshot(t, state)
	if _, err := Apply(state, b, false); err == nil || !strings.Contains(err.Error(), "different gateway key") {
		t.Fatalf("Apply = %v, want the different-key error", err)
	}
	if snapshot(t, state) != before {
		t.Fatal("a refused apply changed the folder")
	}
}

func TestApplyUpdatesTheTokenLineAndKeepsTheUnlockState(t *testing.T) {
	dir, dev := filepath.Join(t.TempDir(), "p"), device(t)
	a := prepare(t, dir, dev)
	state := filepath.Join(t.TempDir(), "state")
	applyTo(t, state, a.Bundle, false)
	stateFile := filepath.Join(state, "unlock", "admin.state")
	if err := os.WriteFile(stateFile, []byte(`{"lastStep":42}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// a new bundle with another line for the same name (a renewed expiry)
	_, e, _ := tokens.NewEntry("admin", dev, 48*time.Hour)
	b := a.Bundle
	b.Line = tokens.FormatEntry(e)
	b.TOTP = strings.Repeat("A", 32) // a bundle with another secret must not overwrite the existing one
	got := applyTo(t, state, b, false)
	if got["token admin"] != Updated || got["unlock secret admin"] != Unchanged || got["gateway key"] != Unchanged {
		t.Fatalf("results = %v", got)
	}
	if read(t, stateFile) != `{"lastStep":42}` {
		t.Fatal("the unlock state was reset")
	}
	if !strings.Contains(read(t, filepath.Join(state, "tokens.d", "admin")), "expires=") {
		t.Fatal("the new line is not in place")
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	b := prepare(t, filepath.Join(t.TempDir(), "p"), device(t)).Bundle
	state := filepath.Join(t.TempDir(), "state")
	if got := applyTo(t, state, b, true); got["gateway key"] != Created {
		t.Fatalf("dry run results = %v", got)
	}
	if _, err := os.Stat(state); err == nil {
		t.Fatal("a dry run created the folder")
	}
	applyTo(t, state, b, false)
	before := snapshot(t, state)
	applyTo(t, state, b, true)
	if snapshot(t, state) != before {
		t.Fatal("a dry run changed the folder")
	}
}

func TestApplyValidatesBeforeWriting(t *testing.T) {
	b := prepare(t, filepath.Join(t.TempDir(), "p"), device(t)).Bundle
	b.TOTP = "ABCD"
	state := filepath.Join(t.TempDir(), "state")
	if _, err := Apply(state, b, false); err == nil {
		t.Fatal("a bad bundle was applied")
	}
	if _, err := os.Stat(state); err == nil {
		t.Fatal("a bad bundle left a folder behind")
	}
}

func TestApplyKeyWithoutCertificateAndCertificateWithoutKey(t *testing.T) {
	b := prepare(t, filepath.Join(t.TempDir(), "p"), device(t)).Bundle
	state := filepath.Join(t.TempDir(), "state")
	applyTo(t, state, b, false)
	// certificate lost: it is put back
	if err := os.Remove(filepath.Join(state, "gateway.crt")); err != nil {
		t.Fatal(err)
	}
	if got := applyTo(t, state, b, false); got["gateway certificate"] != Created || got["gateway key"] != Unchanged {
		t.Fatalf("results = %v", got)
	}
	// key lost, certificate there: refused, nothing guessed
	if err := os.Remove(filepath.Join(state, "gateway.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(state, b, false); err == nil {
		t.Fatal("a certificate without its key was papered over")
	}
}
