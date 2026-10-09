// Package invite lets a laptop set itself up from one code instead of a
// device key, a token, a pin and a TOTP link passed back and forth.
//
// The admin makes an invite on the VM (portash invite NAME). The laptop
// redeems it over the pinned gateway connection (portash join), which
// registers its device key as pending and hands it its token and TOTP link.
// Nothing works until the admin approves the pending laptop with the
// confirmation code the laptop shows (portash invite approve NAME CODE):
// a stolen invite gets someone a pending entry with the wrong code, never
// access.
//
// Invites and pending laptops are files in one directory, so the root CLI
// and the gateway (its own user) share them without talking to each other.
// Taking one is removing its file, so each is used at most once.
package invite

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"portash/internal/fsown"
)

const (
	SecretPrefix = "pshi_"
	CodePrefix   = "pshi1."
)

var (
	ErrNotFound = errors.New("no such invite (wrong, already used, or expired)")
	ErrExpired  = errors.New("invite expired")
	secretRe    = regexp.MustCompile(`^pshi_[A-Za-z0-9_-]{43}$`)
)

// Invite is what the VM keeps for an invite it handed out.
type Invite struct {
	Name     string        `json:"name"`     // the token name the laptop will get
	Host     string        `json:"host"`     // shown in the authenticator app
	Expires  time.Time     `json:"expires"`  // redeem before this
	TokenTTL time.Duration `json:"tokenTTL"` // lifetime of the token once approved
}

// Pending is a laptop that redeemed an invite and waits for approval.
type Pending struct {
	Name      string        `json:"name"`
	Device    []byte        `json:"device"`    // ed25519 public key
	TokenHash string        `json:"tokenHash"` // hex sha256 of the token the laptop holds
	TOTP      string        `json:"totp"`      // base32 unlock secret to install, or ""
	TokenTTL  time.Duration `json:"tokenTTL"`
	Joined    time.Time     `json:"joined"`
	Expires   time.Time     `json:"expires"` // approve before this
}

// PendingTTL is how long an unapproved laptop is kept.
const PendingTTL = 24 * time.Hour

// Create stores a new invite in dir and returns its secret.
func Create(dir string, inv Invite) (string, error) {
	if err := ensureDir(dir); err != nil {
		return "", err
	}
	Cleanup(dir, time.Now())
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := SecretPrefix + base64.RawURLEncoding.EncodeToString(raw)
	b, _ := json.Marshal(inv)
	return secret, fsown.WriteFile(invitePath(dir, secret), b, 0o600)
}

// Redeem takes the invite for secret out of dir. It works once.
func Redeem(dir, secret string, now time.Time) (Invite, error) {
	if !secretRe.MatchString(secret) {
		return Invite{}, ErrNotFound
	}
	p := invitePath(dir, secret)
	b, err := os.ReadFile(p)
	if err != nil {
		return Invite{}, ErrNotFound
	}
	if err := os.Remove(p); err != nil {
		return Invite{}, ErrNotFound // someone else took it first
	}
	var inv Invite
	if err := json.Unmarshal(b, &inv); err != nil {
		return Invite{}, err
	}
	if !now.Before(inv.Expires) {
		return Invite{}, ErrExpired
	}
	return inv, nil
}

// AddPending records a laptop waiting for approval, replacing an earlier
// one with the same name.
func AddPending(dir string, p Pending) error {
	if err := ensureDir(dir); err != nil {
		return err
	}
	b, _ := json.Marshal(p)
	return fsown.WriteFile(pendingPath(dir, p.Name), b, 0o600)
}

// TakePending removes and returns the pending laptop called name.
func TakePending(dir, name string, now time.Time) (Pending, error) {
	p := pendingPath(dir, name)
	b, err := os.ReadFile(p)
	if err != nil {
		return Pending{}, fmt.Errorf("no laptop is waiting for approval as %q", name)
	}
	var pd Pending
	if err := json.Unmarshal(b, &pd); err != nil {
		return Pending{}, err
	}
	if !now.Before(pd.Expires) {
		os.Remove(p)
		return Pending{}, fmt.Errorf("the pending laptop %q expired; make a new invite", name)
	}
	if err := os.Remove(p); err != nil {
		return Pending{}, err
	}
	return pd, nil
}

// List returns open invites and pending laptops, oldest first, dropping
// expired ones.
func List(dir string, now time.Time) ([]Invite, []Pending) {
	Cleanup(dir, now)
	var invs []Invite
	var pend []Pending
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if strings.HasPrefix(filepath.Base(f), "pending-") {
			var p Pending
			if json.Unmarshal(b, &p) == nil {
				pend = append(pend, p)
			}
		} else {
			var i Invite
			if json.Unmarshal(b, &i) == nil {
				invs = append(invs, i)
			}
		}
	}
	sort.Slice(invs, func(a, b int) bool { return invs[a].Expires.Before(invs[b].Expires) })
	sort.Slice(pend, func(a, b int) bool { return pend[a].Joined.Before(pend[b].Joined) })
	return invs, pend
}

// Remove deletes open invites and the pending laptop for name.
func Remove(dir, name string) int {
	n := 0
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var v struct{ Name string }
		if json.Unmarshal(b, &v) == nil && v.Name == name && os.Remove(f) == nil {
			n++
		}
	}
	return n
}

// Cleanup removes expired invites and pending laptops.
func Cleanup(dir string, now time.Time) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var v struct{ Expires time.Time }
		if json.Unmarshal(b, &v) == nil && !now.Before(v.Expires) {
			os.Remove(f)
		}
	}
}

// ConfirmCode is the short code a laptop shows for its device key, and the
// admin types to approve it: 40 bits of the key's hash, as XXXX-XXXX.
func ConfirmCode(device ed25519.PublicKey) string {
	h := sha256.Sum256(append([]byte("portash-confirm\x00"), device...))
	s := base32.StdEncoding.EncodeToString(h[:5])
	return s[:4] + "-" + s[4:8]
}

// SameCode compares codes ignoring case, spaces and dashes.
func SameCode(a, b string) bool {
	norm := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r == '-' || r == ' ' {
				return -1
			}
			return r
		}, strings.ToUpper(s))
	}
	return norm(a) != "" && norm(a) == norm(b)
}

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	return fsown.LikeParent(dir)
}

func invitePath(dir, secret string) string {
	h := sha256.Sum256([]byte(secret))
	return filepath.Join(dir, "invite-"+hex.EncodeToString(h[:])+".json")
}

func pendingPath(dir, name string) string {
	return filepath.Join(dir, "pending-"+name+".json")
}

// Code is everything a laptop needs, in one string: where the gateway is,
// its pin, the invite secret, and optionally the VM's SSH host key and the
// login name to use.
type Code struct {
	Gateway string `json:"g"`           // host:port or https://host
	Name    string `json:"n"`           // what the laptop calls the VM (ssh Host)
	Pin     string `json:"p"`           // sha256:...
	Secret  string `json:"s"`           // pshi_...
	HostKey string `json:"k,omitempty"` // "ssh-ed25519 AAAA..."
	User    string `json:"u,omitempty"` // ssh login name
}

func (c Code) String() string {
	b, _ := json.Marshal(c)
	return CodePrefix + base64.RawURLEncoding.EncodeToString(b)
}

// ParseCode reads a code made by Code.String.
func ParseCode(s string) (Code, error) {
	var c Code
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), CodePrefix)
	if !ok {
		return c, errors.New("not a portash invite code (they start with " + CodePrefix + ")")
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || json.Unmarshal(b, &c) != nil {
		return c, errors.New("the invite code is damaged; copy it again in full")
	}
	if c.Gateway == "" || c.Name == "" || !secretRe.MatchString(c.Secret) {
		return c, errors.New("the invite code is incomplete")
	}
	return c, nil
}
