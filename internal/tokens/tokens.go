// Package tokens manages gateway access tokens. Only SHA-256 hashes are
// stored. Every token is bound to one device's Ed25519 key and expires.
package tokens

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"portash/internal/fsown"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	Prefix       = "psh_"
	DevicePrefix = "pshd_"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
var tokenRe = regexp.MustCompile(`^psh_[A-Za-z0-9_-]{43}$`)

type Entry struct {
	Name    string
	Hash    [32]byte
	Device  ed25519.PublicKey
	Expires time.Time // zero = never
	Source  string    // "" = the tokens file, else the drop-in file (tokens.d/NAME)
}

func (e Entry) Expired(now time.Time) bool { return !e.Expires.IsZero() && !now.Before(e.Expires) }

// New returns a fresh 256-bit token.
func New() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func ValidFormat(tok string) bool { return tokenRe.MatchString(tok) }

func ValidName(name string) bool { return nameRe.MatchString(name) }

// FormatDevice / ParseDevice convert a device public key to and from "pshd_…".
func FormatDevice(pub ed25519.PublicKey) string {
	return DevicePrefix + base64.RawURLEncoding.EncodeToString(pub)
}

func ParseDevice(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, DevicePrefix))
	if !strings.HasPrefix(s, DevicePrefix) || err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("device key must look like pshd_<43 chars> (run `portash device` on the laptop)")
	}
	return ed25519.PublicKey(b), nil
}

// Parse reads lines of "name sha256hex device=pshd_… [expires=RFC3339]".
func Parse(data []byte, path string) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || !ValidName(f[0]) {
			return nil, fmt.Errorf("%s:%d: malformed line", path, n)
		}
		h, err := hex.DecodeString(f[1])
		if err != nil || len(h) != 32 {
			return nil, fmt.Errorf("%s:%d: bad hash", path, n)
		}
		e := Entry{Name: f[0]}
		copy(e.Hash[:], h)
		for _, kv := range f[2:] {
			k, v, _ := strings.Cut(kv, "=")
			switch k {
			case "device":
				if e.Device, err = ParseDevice(v); err != nil {
					return nil, fmt.Errorf("%s:%d: %v", path, n, err)
				}
			case "expires":
				if e.Expires, err = time.Parse(time.RFC3339, v); err != nil {
					return nil, fmt.Errorf("%s:%d: bad expires", path, n)
				}
			default:
				return nil, fmt.Errorf("%s:%d: unknown field %q", path, n, k)
			}
		}
		if e.Device == nil {
			return nil, fmt.Errorf("%s:%d: token has no device key", path, n)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func Load(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, path)
}

// FormatEntry is the tokens-file line of one entry (without the newline).
// It holds the token's hash, never the token.
func FormatEntry(e Entry) string {
	line := fmt.Sprintf("%s %s device=%s", e.Name, hex.EncodeToString(e.Hash[:]), FormatDevice(e.Device))
	if !e.Expires.IsZero() {
		line += " expires=" + e.Expires.UTC().Format(time.RFC3339)
	}
	return line
}

// NewEntry makes a token for name, bound to device, valid for ttl (0 = never
// expires), without touching any file. It returns the token and the entry (the
// hash and the rules); only the entry belongs on a VM.
func NewEntry(name string, device ed25519.PublicKey, ttl time.Duration) (string, Entry, error) {
	if !ValidName(name) {
		return "", Entry{}, errors.New("name must be 1-64 chars of letters, digits, . _ @ -")
	}
	if len(device) != ed25519.PublicKeySize {
		return "", Entry{}, errors.New("a device key is required")
	}
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

// Save writes the file atomically with mode 0600.
func Save(path string, entries []Entry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# portash gateway tokens: name sha256(token) device=<key> [expires=<time>]\n")
	for _, e := range entries {
		b.WriteString(FormatEntry(e))
		b.WriteByte('\n')
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tokens-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := fsown.LikeParent(tmp.Name()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Add creates a token for name, bound to device, valid for ttl (0 = never
// expires). Returns the plaintext token.
func Add(path, name string, device ed25519.PublicKey, ttl time.Duration) (string, error) {
	if !ValidName(name) {
		return "", errors.New("name must be 1-64 chars of letters, digits, . _ @ -")
	}
	if len(device) != ed25519.PublicKeySize {
		return "", errors.New("a device key is required")
	}
	entries, err := Load(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	for _, e := range entries {
		if e.Name == name {
			return "", fmt.Errorf("token %q already exists; remove it first", name)
		}
	}
	if src, ok := dropinSource(path, name); ok {
		return "", fmt.Errorf("token %q already exists in %s", name, src)
	}
	tok, err := New()
	if err != nil {
		return "", err
	}
	return tok, addEntry(path, entries, name, sha256.Sum256([]byte(tok)), device, ttl)
}

// AddHash is Add for a token made elsewhere, of which only the hash is
// known (an approved `portash join`).
func AddHash(path, name string, hash [32]byte, device ed25519.PublicKey, ttl time.Duration) error {
	if !ValidName(name) {
		return errors.New("name must be 1-64 chars of letters, digits, . _ @ -")
	}
	if len(device) != ed25519.PublicKeySize {
		return errors.New("a device key is required")
	}
	entries, err := Load(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range entries {
		if e.Name == name {
			return fmt.Errorf("token %q already exists; remove it first", name)
		}
	}
	if src, ok := dropinSource(path, name); ok {
		return fmt.Errorf("token %q already exists in %s", name, src)
	}
	return addEntry(path, entries, name, hash, device, ttl)
}

func addEntry(path string, entries []Entry, name string, hash [32]byte, device ed25519.PublicKey, ttl time.Duration) error {
	e := Entry{Name: name, Hash: hash, Device: device}
	if ttl > 0 {
		e.Expires = time.Now().Add(ttl).UTC().Truncate(time.Second)
	}
	return Save(path, append(entries, e))
}

// Exists reports whether a token named name is in the file at path.
func Exists(path, name string) bool {
	entries, _, _ := LoadAll(path)
	for _, e := range entries {
		if e.Name == name {
			return true
		}
	}
	return false
}

func Remove(path, name string) error {
	entries, err := Load(path)
	if err != nil && !isNotExist(err) {
		return err
	}
	kept := entries[:0]
	for _, e := range entries {
		if e.Name != name {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(entries) {
		if src, ok := dropinSource(path, name); ok {
			return fmt.Errorf("token %q comes from %s: remove that line or file", name, src)
		}
		return fmt.Errorf("no token named %q", name)
	}
	return Save(path, kept)
}

// Store checks presented tokens against the tokens file and the drop-in
// folder next to it (tokens.d). Both are re-read on every check (they are
// tiny) and re-parsed whenever their contents change, so revocation takes
// effect on the next connection.
type Store struct {
	path string
	now  func() time.Time
	log  func(format string, args ...any) // see SetLog

	mu          sync.Mutex
	refused     []Refused // what the last load ignored
	sum         [32]byte  // of everything read last time
	entries     []Entry
	mainSum     [32]byte
	mainEntries []Entry
	logged      map[string]bool
}

// Path is the token file the store reads.
func (s *Store) Path() string { return s.path }

func NewStore(path string) (*Store, error) {
	s := &Store{path: path, now: time.Now, logged: map[string]bool{}}
	if _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// SetLog makes the store tell f about every drop-in file or line it ignores:
// once, and again only if that file changes. What was ignored at start-up is
// reported at once.
func (s *Store) SetLog(f func(format string, args ...any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = f
	s.report(s.refused)
}

// Refresh looks at the tokens file and tokens.d now, so that a broken file is
// reported soon after it was written and not only when somebody connects.
func (s *Store) Refresh() { s.load() }

// readMain reads the tokens file. A missing file means no tokens; a file
// others can read, or one that does not parse, is an error and nobody gets in
// (the drop-ins included): that is how it has always been.
func (s *Store) readMain() ([]Entry, [32]byte, error) {
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, [32]byte{}, nil
	}
	if err != nil {
		return nil, [32]byte{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, [32]byte{}, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, [32]byte{}, fmt.Errorf("%s must not be readable by group/other (chmod 600)", s.path)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, [32]byte{}, err
	}
	sum := sha256.Sum256(buf.Bytes())
	if sum == s.mainSum && s.mainEntries != nil {
		return s.mainEntries, sum, nil
	}
	entries, err := Parse(buf.Bytes(), s.path)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if entries == nil {
		entries = []Entry{}
	}
	return entries, sum, nil
}

func (s *Store) load() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	main, mainSum, err := s.readMain()
	if err != nil {
		return nil, err
	}
	files, refused := readDropins(DropinDir(s.path))
	h := sha256.New()
	h.Write(mainSum[:])
	for _, f := range files {
		h.Write([]byte(f.name))
		h.Write(f.sum[:])
	}
	for _, r := range refused {
		h.Write([]byte(r.File + "\x00" + r.Reason))
		h.Write(r.sum[:])
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	if sum == s.sum && s.entries != nil {
		return s.entries, nil
	}
	entries, dup := merge(main, files)
	s.refused = append(refused, dup...)
	s.report(s.refused)
	s.mainEntries, s.mainSum = main, mainSum
	s.entries, s.sum = entries, sum
	return entries, nil
}

// report tells Log about each refusal that was not reported yet.
func (s *Store) report(rs []Refused) {
	if s.log == nil {
		return
	}
	for _, r := range rs {
		key := fmt.Sprintf("%s|%s|%x", r.File, r.Reason, r.sum)
		if !s.logged[key] {
			s.logged[key] = true
			s.log("%s", r.String())
		}
	}
}

// Lookup returns the live entry for a token, or false. Every entry is
// compared so timing doesn't reveal which one matched.
func (s *Store) Lookup(tok string) (Entry, bool) {
	if !ValidFormat(tok) {
		return Entry{}, false
	}
	return s.LookupHash(sha256.Sum256([]byte(tok)))
}

// LookupHash is Lookup for an already-hashed token; the gateway uses it to
// re-check open streams.
func (s *Store) LookupHash(h [32]byte) (Entry, bool) {
	entries, err := s.load()
	if err != nil {
		return Entry{}, false // fail closed
	}
	var found Entry
	ok := false
	for _, e := range entries {
		if subtle.ConstantTimeCompare(h[:], e.Hash[:]) == 1 {
			found, ok = e, true
		}
	}
	if !ok || found.Expired(s.now()) {
		return Entry{}, false
	}
	return found, true
}
