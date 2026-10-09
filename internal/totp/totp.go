// Package totp implements RFC 6238 time-based one-time codes (SHA-1, 6
// digits, 30 s) and a per-user secret store with replay protection and
// lockout. Secrets live in a root-only directory; only root processes (the
// portash authd daemon and the PAM helper) ever read them.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"portash/internal/fsown"
	"regexp"
	"strings"
	"time"
)

const (
	Period   = 30
	Digits   = 6
	Skew     = 1 // accept one step either side for clock drift
	MaxFails = 5
	Lockout  = 15 * time.Minute
)

var (
	ErrNoSecret = errors.New("no TOTP enrolled for this user")
	ErrLocked   = errors.New("too many wrong codes; locked for 15 minutes")
	ErrInvalid  = errors.New("wrong or reused code")
	userRe      = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	codeRe      = regexp.MustCompile(`^[0-9]{6}$`)
	b32         = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// Code returns the code for secret at time step.
func Code(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

func Step(t time.Time) int64 { return t.Unix() / Period }

// Match returns the step a code is valid for, checking every step in the
// window (constant work regardless of which one matches).
func Match(secret []byte, code string, now time.Time) (int64, bool) {
	if !codeRe.MatchString(code) {
		return 0, false
	}
	cur := Step(now)
	var found int64
	ok := false
	for s := cur - Skew; s <= cur+Skew; s++ {
		if subtle.ConstantTimeCompare([]byte(Code(secret, s)), []byte(code)) == 1 {
			found, ok = s, true
		}
	}
	return found, ok
}

func ValidUser(u string) bool { return userRe.MatchString(u) }

// Store keeps one secret and one state file per user in Dir (mode 0700).
type Store struct {
	Dir string
	Now func() time.Time
	// ValidName checks names used as file names (default ValidUser).
	ValidName func(string) bool
}

type state struct {
	LastStep    int64     `json:"lastStep"`
	Fails       int       `json:"fails"`
	LockedUntil time.Time `json:"lockedUntil"`
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s Store) path(user, ext string) (string, error) {
	valid := s.ValidName
	if valid == nil {
		valid = ValidUser
	}
	if !valid(user) || strings.ContainsAny(user, "/\\") || strings.Trim(user, ".") == "" {
		return "", fmt.Errorf("invalid user name %q", user)
	}
	return filepath.Join(s.Dir, user+ext), nil
}

// Enroll creates (or replaces) a user's secret and returns an otpauth:// URI
// for authenticator apps.
func (s Store) Enroll(user, issuer string) (string, error) {
	p, err := s.path(user, ".secret")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return "", err
	}
	if err := fsown.LikeParent(s.Dir); err != nil {
		return "", err
	}
	enc, err := NewSecret()
	if err != nil {
		return "", err
	}
	if err := s.write(p, user, enc); err != nil {
		return "", err
	}
	return URI(enc, user, issuer), nil
}

// NewSecret returns a random 160-bit secret, base32 without padding.
func NewSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return b32.EncodeToString(secret), nil
}

// URI is the otpauth:// link authenticator apps import (as text or QR code).
func URI(secret, user, issuer string) string {
	label := url.PathEscape(issuer + ":" + user)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Has reports whether user has a secret.
func (s Store) Has(user string) bool {
	_, err := s.secret(user)
	return err == nil
}

// Import stores an existing secret (base32, or an otpauth:// URI), so one
// authenticator entry can unlock several machines.
func (s Store) Import(user, secret string) error {
	secret = strings.TrimSpace(secret)
	if u, err := url.Parse(secret); err == nil && u.Scheme == "otpauth" {
		secret = u.Query().Get("secret")
	}
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if raw, err := b32.DecodeString(strings.TrimRight(secret, "=")); err != nil || len(raw) < 16 {
		return errors.New("not a base32 TOTP secret of at least 128 bits")
	}
	p, err := s.path(user, ".secret")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	if err := fsown.LikeParent(s.Dir); err != nil {
		return err
	}
	return s.write(p, user, strings.TrimRight(secret, "="))
}

func (s Store) write(p, user, enc string) error {
	if err := fsown.WriteFile(p, []byte(enc+"\n"), 0o600); err != nil {
		return err
	}
	sp, _ := s.path(user, ".state")
	os.Remove(sp)
	return nil
}

func (s Store) Remove(user string) error {
	p, err := s.path(user, ".secret")
	if err != nil {
		return err
	}
	sp, _ := s.path(user, ".state")
	os.Remove(sp)
	return os.Remove(p)
}

func (s Store) secret(user string) ([]byte, error) {
	p, err := s.path(user, ".secret")
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoSecret
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be mode 0600", p)
	}
	var buf [128]byte
	n, _ := f.Read(buf[:])
	return b32.DecodeString(strings.ToUpper(strings.TrimSpace(string(buf[:n]))))
}

// Check verifies a code for user. It refuses codes from a step that was
// already used (replay) and locks the user after MaxFails wrong codes. A
// separate lock file serializes concurrent checks (authd and PAM); the state
// file itself is replaced atomically, so a crash can't leave it half written.
func (s Store) Check(user, code string) error {
	secret, err := s.secret(user)
	if err != nil {
		return err
	}
	sp, _ := s.path(user, ".state")
	lp, _ := s.path(user, ".lock")
	lf, err := os.OpenFile(lp, os.O_RDWR|os.O_CREATE|noFollow, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	fsown.LikeParent(lp)
	unlock, err := lockFile(lf)
	if err != nil {
		return err
	}
	defer unlock()
	now := s.now()
	var st state
	if b, err := os.ReadFile(sp); err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &st); err != nil {
			// Unreadable state (the file was damaged by something other
			// than us): don't let that open or permanently close the door.
			// Lock for one lockout period; the next write replaces the file.
			st = state{LockedUntil: now.Add(Lockout)}
			if err := writeState(sp, st); err != nil {
				return err
			}
		}
	}
	if now.Before(st.LockedUntil) {
		return ErrLocked
	}
	step, ok := Match(secret, code, now)
	if ok && step > st.LastStep {
		st.LastStep, st.Fails = step, 0
		return writeState(sp, st)
	}
	st.Fails++
	if st.Fails >= MaxFails {
		st.Fails, st.LockedUntil = 0, now.Add(Lockout)
	}
	if err := writeState(sp, st); err != nil {
		return err
	}
	return ErrInvalid
}

// writeState replaces the state file atomically (temp file, fsync, rename).
func writeState(path string, st state) error {
	b, _ := json.Marshal(st)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
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
