package gateway

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"portash/internal/totp"
)

const (
	UnlockPath   = "/v1/unlock"
	UnlockTarget = "portash-unlock" // what the device key signs for an unlock
	TOTPHeader   = "Portash-TOTP"
	TicketHeader = "Portash-Ticket"
	ticketPrefix = "psht_"
)

// Unlock makes every stream need a ticket, which a laptop gets once a day by
// sending a TOTP code with its token (portash unlock). ssh, scp and Ansible then
// work without prompts until the ticket expires.
type Unlock struct {
	TOTP      totp.Store    // secrets named after tokens
	TicketTTL time.Duration // default 12h
	File      string        // where ticket hashes are kept across restarts
}

type ticket struct {
	token   [32]byte // hash of the token it belongs to
	expires time.Time
}

type ticketStore struct {
	mu   sync.Mutex
	file string
	m    map[[32]byte]ticket // by ticket hash
}

func newTicketStore(file string) (*ticketStore, error) {
	ts := &ticketStore{file: file, m: map[[32]byte]ticket{}}
	if file == "" {
		return ts, nil
	}
	b, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return ts, nil
	}
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(file); err == nil && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be mode 0600", file)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	now := time.Now()
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			continue
		}
		var th, tok [32]byte
		a, err1 := hex.DecodeString(f[0])
		c, err2 := hex.DecodeString(f[1])
		exp, err3 := time.Parse(time.RFC3339, f[2])
		if err1 != nil || err2 != nil || err3 != nil || len(a) != 32 || len(c) != 32 || !exp.After(now) {
			continue
		}
		copy(th[:], a)
		copy(tok[:], c)
		ts.m[th] = ticket{token: tok, expires: exp}
	}
	return ts, nil
}

// issue returns a new ticket for a token. Only its hash is kept.
func (ts *ticketStore) issue(token [32]byte, ttl time.Duration) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	t := ticketPrefix + base64.RawURLEncoding.EncodeToString(raw)
	exp := time.Now().Add(ttl).Truncate(time.Second)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.m[sha256.Sum256([]byte(t))] = ticket{token: token, expires: exp}
	return t, exp, ts.saveLocked()
}

// valid reports whether the ticket hash is live and belongs to token.
func (ts *ticketStore) valid(th, token [32]byte) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	t, ok := ts.m[th]
	return ok && t.token == token && time.Now().Before(t.expires)
}

func (ts *ticketStore) saveLocked() error {
	now := time.Now()
	var b strings.Builder
	for th, t := range ts.m {
		if !now.Before(t.expires) {
			delete(ts.m, th)
			continue
		}
		fmt.Fprintf(&b, "%x %x %s\n", th, t.token, t.expires.UTC().Format(time.RFC3339))
	}
	if ts.file == "" {
		return nil
	}
	tmp := filepath.Join(filepath.Dir(ts.file), ".tickets.tmp")
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ts.file)
}

// ticketHash parses the Portash-Ticket header.
func ticketHash(r *http.Request) ([32]byte, bool) {
	t := r.Header.Get(TicketHeader)
	if !strings.HasPrefix(t, ticketPrefix) || len(t) != len(ticketPrefix)+43 {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(t)), true
}

// serveUnlock handles POST /v1/unlock: a token, signed by its device, plus a
// TOTP code, buys a ticket.
func (g *Gateway) serveUnlock(w http.ResponseWriter, r *http.Request, ip string) {
	if g.cfg.Unlock == nil {
		http.NotFound(w, r)
		return
	}
	entry, hash, ok := g.authenticate(r, UnlockTarget)
	if !ok {
		g.fails.fail(ip)
		g.cfg.Log.Printf("deny %s: unlock with bad token or device signature", r.RemoteAddr)
		http.NotFound(w, r)
		return
	}
	err := g.cfg.Unlock.TOTP.Check(entry.Name, r.Header.Get(TOTPHeader))
	switch {
	case errors.Is(err, totp.ErrLocked):
		g.cfg.Log.Printf("deny %s token=%s: unlock locked out", r.RemoteAddr, entry.Name)
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	case errors.Is(err, totp.ErrNoSecret):
		g.cfg.Log.Printf("deny %s token=%s: no TOTP enrolled", r.RemoteAddr, entry.Name)
		http.Error(w, "no TOTP enrolled for this token on this gateway (portash totp enroll --unlock)", http.StatusForbidden)
		return
	case err != nil:
		g.fails.fail(ip)
		g.cfg.Log.Printf("deny %s token=%s: unlock: %v", r.RemoteAddr, entry.Name, err)
		http.Error(w, "wrong or reused code", http.StatusForbidden)
		return
	}
	t, exp, err := g.tickets.issue(hash, g.cfg.Unlock.TicketTTL)
	if err != nil {
		g.cfg.Log.Printf("fail token=%s: saving ticket: %v", entry.Name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	g.cfg.Log.Printf("unlock %s token=%s until %s", r.RemoteAddr, entry.Name, exp.UTC().Format(time.RFC3339))
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s\n%s\n", t, exp.UTC().Format(time.RFC3339))
}
