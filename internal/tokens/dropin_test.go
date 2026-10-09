package tokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture is a tokens file and its tokens.d folder in a temp dir.
type fixture struct {
	t    *testing.T
	main string
	dir  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{t: t, main: filepath.Join(root, "tokens"), dir: filepath.Join(root, DropinName)}
	if err := os.Mkdir(f.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

// token makes a token for name and returns it with its tokens-file line.
func token(t *testing.T, name string, ttl time.Duration) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tok, e, err := newEntry(name, pub, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tok, formatLine(e)
}

func (f *fixture) drop(name, content string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(content+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) store() *Store {
	f.t.Helper()
	s, err := NewStore(f.main)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) logs(s *Store) *[]string {
	var mu sync.Mutex
	var lines []string
	s.SetLog(func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	return &lines
}

func TestDropinTokenConnectsAndUnlistedDoesNot(t *testing.T) {
	f := newFixture(t)
	tok, line := token(t, "ci", time.Hour)
	f.drop("ci", line)
	other, _ := token(t, "other", time.Hour)
	s := f.store()
	if e, ok := s.Lookup(tok); !ok || e.Name != "ci" || e.Source != DropinName+"/ci" {
		t.Fatalf("lookup = %+v, %v", e, ok)
	}
	if _, ok := s.Lookup(other); ok {
		t.Fatal("a token that is in no file was accepted")
	}
}

func TestDropinsAndMainFileWorkTogether(t *testing.T) {
	f := newFixture(t)
	tokA, lineA := token(t, "a", time.Hour)
	tokB, lineB := token(t, "b", time.Hour)
	if err := os.WriteFile(f.main, []byte(lineA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.drop("b", lineB)
	s := f.store()
	for _, tok := range []string{tokA, tokB} {
		if _, ok := s.Lookup(tok); !ok {
			t.Fatalf("token %s refused", tok[:8])
		}
	}
}

func TestChangesAndRemovalTakeEffectAtOnce(t *testing.T) {
	f := newFixture(t)
	s := f.store()
	tok, line := token(t, "ci", time.Hour)
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("accepted before the file exists")
	}
	f.drop("ci", line)
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("a new file is not seen")
	}
	f.drop("ci", "# access withdrawn")
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("an emptied file still grants access")
	}
	f.drop("ci", line)
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("restored file is not seen")
	}
	if err := os.Remove(filepath.Join(f.dir, "ci")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("a removed file still grants access")
	}
}

func TestDropinCannotRelaxExpiry(t *testing.T) {
	f := newFixture(t)
	tok, line := token(t, "ci", time.Hour)
	f.drop("ci", line)
	s := f.store()
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("an expired drop-in token was accepted")
	}
}

// A broken file takes away only itself.
func TestOneBadFileDoesNotStopTheOthers(t *testing.T) {
	f := newFixture(t)
	good, goodLine := token(t, "good", time.Hour)
	f.drop("good", goodLine)
	bad, badLine := token(t, "bad", time.Hour)
	f.drop("bad-parse", badLine+" frobnicate=1") // unknown field
	f.drop("bad-trunc", badLine[:len(badLine)/2])
	f.drop("bad-line", "garbage")
	s := f.store()
	lines := f.logs(s)
	if _, ok := s.Lookup(good); !ok {
		t.Fatal("a broken neighbour took the good file down")
	}
	if _, ok := s.Lookup(bad); ok {
		t.Fatal("a file that does not parse granted access")
	}
	if len(*lines) != 3 {
		t.Fatalf("logged %d lines, want 3: %q", len(*lines), *lines)
	}
}

func TestBadModeSymlinkAndFolderAreRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes and symlinks are Unix things")
	}
	f := newFixture(t)
	tok, line := token(t, "ci", time.Hour)

	f.drop("loose", line)
	if err := os.Chmod(filepath.Join(f.dir, "loose"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := f.store()
	lines := f.logs(s)
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("a file that others can read was accepted")
	}
	if !strings.Contains(strings.Join(*lines, "\n"), "loose") {
		t.Fatalf("not logged: %q", *lines)
	}

	// a symlink to a good file elsewhere
	elsewhere := filepath.Join(t.TempDir(), "real")
	if err := os.WriteFile(elsewhere, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(f.dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("a symlink was followed")
	}

	// a folder that others can write to: nothing in it counts
	f.drop("good", line)
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("setup: the good file is not accepted")
	}
	if err := os.Chmod(f.dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("a folder writable by others was trusted")
	}
}

func TestDuplicatesAreRefusedAndNothingIsShadowed(t *testing.T) {
	f := newFixture(t)
	tokMain, lineMain := token(t, "same", time.Hour)
	tokDrop, lineDrop := token(t, "same", time.Hour) // same name, other token
	if err := os.WriteFile(f.main, []byte(lineMain+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.drop("x", lineDrop)
	// the same token (hash) under another name, in a later file
	tokOne, lineOne := token(t, "one", time.Hour)
	f.drop("y", lineOne)
	f.drop("z", strings.Replace(lineOne, "one ", "two ", 1))
	s := f.store()
	lines := f.logs(s)
	if _, ok := s.Lookup(tokMain); !ok {
		t.Fatal("the main file's token was shadowed")
	}
	if _, ok := s.Lookup(tokDrop); ok {
		t.Fatal("a drop-in took over a name")
	}
	if e, ok := s.Lookup(tokOne); !ok || e.Name != "one" {
		t.Fatalf("first file must win: %+v %v", e, ok)
	}
	if len(*lines) != 2 {
		t.Fatalf("logged %d lines, want 2: %q", len(*lines), *lines)
	}
}

func TestEachProblemIsLoggedOnceUntilTheFileChanges(t *testing.T) {
	f := newFixture(t)
	f.drop("bad", "garbage")
	s := f.store()
	lines := f.logs(s)
	for range 5 {
		s.Lookup("psh_" + strings.Repeat("A", 43))
	}
	if len(*lines) != 1 {
		t.Fatalf("logged %d times, want once: %q", len(*lines), *lines)
	}
	f.drop("bad", "still garbage")
	s.Lookup("psh_" + strings.Repeat("A", 43))
	if len(*lines) != 2 {
		t.Fatalf("a changed file must be logged again: %q", *lines)
	}
}

func TestEditorFilesAndDotFilesAreSkipped(t *testing.T) {
	f := newFixture(t)
	tok, line := token(t, "ci", time.Hour)
	f.drop(".hidden", line)
	f.drop("ci~", line)
	s := f.store()
	lines := f.logs(s)
	if _, ok := s.Lookup(tok); ok {
		t.Fatal("a temp file granted access")
	}
	if len(*lines) != 0 {
		t.Fatalf("temp files are not worth a log line: %q", *lines)
	}
}

func TestLoadAllShowsTheSourceAndWhatWasIgnored(t *testing.T) {
	f := newFixture(t)
	_, lineMain := token(t, "m", time.Hour)
	if err := os.WriteFile(f.main, []byte(lineMain+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, lineD := token(t, "d", time.Hour)
	f.drop("d", lineD)
	f.drop("broken", "garbage")
	entries, refused, err := LoadAll(f.main)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Source
	}
	if got["m"] != "" || got["d"] != DropinName+"/d" || len(got) != 2 {
		t.Fatalf("entries = %v", got)
	}
	if len(refused) != 1 || refused[0].File != "broken" {
		t.Fatalf("refused = %v", refused)
	}
}

func TestManagedTokensCannotBeRemovedOrReplacedByTheCommands(t *testing.T) {
	f := newFixture(t)
	_, line := token(t, "ci", time.Hour)
	f.drop("ci", line)
	if err := Remove(f.main, "ci"); err == nil || !strings.Contains(err.Error(), DropinName+"/ci") {
		t.Fatalf("Remove = %v, want an error naming the file", err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Add(f.main, "ci", pub, time.Hour); err == nil {
		t.Fatal("Add made a second token with a drop-in's name")
	}
	if !Exists(f.main, "ci") {
		t.Fatal("Exists does not see the drop-in token")
	}
	if Exists(f.main, "nobody") {
		t.Fatal("Exists invented a token")
	}
}

func TestBrokenMainFileStillStopsEverybody(t *testing.T) {
	f := newFixture(t)
	tok, line := token(t, "ci", time.Hour)
	f.drop("ci", line)
	if err := os.WriteFile(f.main, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(f.main); err == nil {
		t.Fatal("a main file that does not parse was accepted")
	}
	_ = tok
}

// newEntry and formatLine build a token and its line without depending on
// other helpers: the same bytes `portash token new` writes.
func newEntry(name string, device ed25519.PublicKey, ttl time.Duration) (string, Entry, error) {
	tok, err := New()
	if err != nil {
		return "", Entry{}, err
	}
	e := Entry{Name: name, Hash: sha256.Sum256([]byte(tok)), Device: device}
	if ttl > 0 {
		e.Expires = time.Now().Add(ttl).UTC().Truncate(time.Second)
	}
	return tok, e, nil
}

func formatLine(e Entry) string {
	line := fmt.Sprintf("%s %s device=%s", e.Name, hex.EncodeToString(e.Hash[:]), FormatDevice(e.Device))
	if !e.Expires.IsZero() {
		line += " expires=" + e.Expires.UTC().Format(time.RFC3339)
	}
	return line
}

// Nobody has to connect for a broken file to be reported: Refresh (the
// gateway calls it with every sweep) does it.
func TestRefreshReportsABrokenFileWithoutAConnection(t *testing.T) {
	f := newFixture(t)
	s := f.store()
	lines := f.logs(s)
	f.drop("broken", "garbage")
	s.Refresh()
	if len(*lines) != 1 || !strings.Contains((*lines)[0], "broken") {
		t.Fatalf("logged %q", *lines)
	}
	s.Refresh()
	if len(*lines) != 1 {
		t.Fatalf("logged again without a change: %q", *lines)
	}
}
