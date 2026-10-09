package gateway

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"portash/internal/invite"
	"portash/internal/tokens"
	"portash/internal/totp"
)

const (
	JoinPath     = "/v1/join"
	JoinTarget   = "portash-join" // what the device key signs for a join
	InviteHeader = "Portash-Invite"
	DeviceHeader = "Portash-Device"
)

// serveJoin handles POST /v1/join: an invite secret plus a device key (and
// that key's signature, to show the laptop holds it) registers the laptop as
// pending. The laptop gets its token, its TOTP link and its confirmation
// code; the token works once an admin approves that code.
func (g *Gateway) serveJoin(w http.ResponseWriter, r *http.Request, ip string) {
	if g.cfg.InviteDir == "" || r.TLS == nil {
		g.notFound(w, r, ip)
		return
	}
	dev, err := tokens.ParseDevice(r.Header.Get(DeviceHeader))
	sig, err2 := base64.RawURLEncoding.DecodeString(r.Header.Get(SigHeader))
	ekm, err3 := r.TLS.ExportKeyingMaterial(ExporterLabel, nil, 32)
	if err != nil || err2 != nil || err3 != nil || !ed25519.Verify(dev, SignedMessage(ekm, JoinTarget), sig) {
		g.cfg.Log.Printf("deny %s: join with bad device signature", r.RemoteAddr)
		g.notFound(w, r, ip)
		return
	}
	inv, err := invite.Redeem(g.cfg.InviteDir, r.Header.Get(InviteHeader), time.Now())
	if err != nil {
		g.cfg.Log.Printf("deny %s: join: %v", r.RemoteAddr, err)
		if errors.Is(err, invite.ErrExpired) {
			http.Error(w, "this invite has expired; ask for a new one", http.StatusGone)
			g.fails.fail(ip)
			return
		}
		g.notFound(w, r, ip)
		return
	}
	if tokens.Exists(g.cfg.Tokens.Path(), inv.Name) {
		g.cfg.Log.Printf("deny %s: join as %s: token exists", r.RemoteAddr, inv.Name)
		http.Error(w, fmt.Sprintf("a laptop is already set up as %q here; the admin must remove it first", inv.Name), http.StatusConflict)
		return
	}
	tok, err := tokens.New()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := sha256.Sum256([]byte(tok))
	p := invite.Pending{Name: inv.Name, Device: dev, TokenHash: hex.EncodeToString(h[:]), TokenTTL: inv.TokenTTL,
		Joined: time.Now().UTC(), Expires: time.Now().Add(invite.PendingTTL).UTC()}
	uri := "-"
	if g.cfg.Unlock != nil && !g.cfg.Unlock.TOTP.Has(inv.Name) {
		if p.TOTP, err = totp.NewSecret(); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		uri = totp.URI(p.TOTP, inv.Name, "portash "+inv.Host)
	}
	if err := invite.AddPending(g.cfg.InviteDir, p); err != nil {
		g.cfg.Log.Printf("fail %s: join as %s: %v", r.RemoteAddr, inv.Name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	code := invite.ConfirmCode(dev)
	g.cfg.Log.Printf("join %s token=%s device=%s code=%s: waiting for approval", r.RemoteAddr, inv.Name, tokens.FormatDevice(dev), code)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s\n%s\n%s\n%s\n", tok, uri, code, inv.Name)
}
