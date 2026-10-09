package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"portash/internal/dial"
	"portash/internal/gateway"
	"portash/internal/invite"
	"portash/internal/tokens"
	"portash/internal/totp"
)

type joinEnv struct {
	env
	invDir string
	st     totp.Store
}

func setupJoin(t *testing.T) joinEnv {
	dir := t.TempDir()
	je := joinEnv{invDir: filepath.Join(dir, "invites"), st: totp.Store{Dir: filepath.Join(dir, "unlock"), ValidName: tokens.ValidName}}
	je.env = setupWith(t, func(c *gateway.Config) {
		c.InviteDir = je.invDir
		c.Unlock = &gateway.Unlock{TOTP: je.st, TicketTTL: time.Hour, File: filepath.Join(dir, "tickets")}
	})
	return je
}

func (je joinEnv) invite(t *testing.T, name string, ttl time.Duration) string {
	t.Helper()
	s, err := invite.Create(je.invDir, invite.Invite{Name: name, Host: "vm1.example.com", Expires: time.Now().Add(ttl), TokenTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// approve does what `portash invite approve` does.
func (je joinEnv) approve(t *testing.T, name string) {
	t.Helper()
	p, err := invite.TakePending(je.invDir, name, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var h [32]byte
	b, _ := hex.DecodeString(p.TokenHash)
	copy(h[:], b)
	if err := tokens.AddHash(je.tokPath, p.Name, h, p.Device, p.TokenTTL); err != nil {
		t.Fatal(err)
	}
	if p.TOTP != "" {
		if err := je.st.Import(p.Name, p.TOTP); err != nil {
			t.Fatal(err)
		}
	}
}

func newDevice() ed25519.PrivateKey {
	_, d, _ := ed25519.GenerateKey(rand.Reader)
	return d
}

func codeFrom(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if err != nil {
		t.Fatal(err)
	}
	return totp.Code(raw, totp.Step(time.Now()))
}

// The whole flow: join, nothing works until approval, then unlock and connect.
func TestJoinApproveConnect(t *testing.T) {
	je := setupJoin(t)
	secret := je.invite(t, "alice-laptop", time.Hour)
	dev := newDevice()
	o := dial.Options{Gateway: je.gwAddr, Pins: []string{je.pin}, Device: dev}
	res, err := dial.Join(context.Background(), o, secret)
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "alice-laptop" || !tokens.ValidFormat(res.Token) || !strings.HasPrefix(res.TOTPURI, "otpauth://totp/portash%20vm1.example.com:alice-laptop?") {
		t.Fatalf("join result %+v", res)
	}
	if res.Code != invite.ConfirmCode(dev.Public().(ed25519.PublicKey)) {
		t.Fatalf("code %s doesn't match the device", res.Code)
	}

	o.Token = res.Token
	if _, _, err := dial.Unlock(context.Background(), o, codeFrom(t, res.TOTPURI)); err == nil {
		t.Fatal("unlocked before approval")
	}
	je.approve(t, "alice-laptop")
	if o.Ticket, _, err = dial.Unlock(context.Background(), o, codeFrom(t, res.TOTPURI)); err != nil {
		t.Fatalf("unlock after approval: %v", err)
	}
	s, err := dial.Connect(context.Background(), o, je.echo)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s)
	s.Close()
}

func TestInviteWorksOnce(t *testing.T) {
	je := setupJoin(t)
	secret := je.invite(t, "alice-laptop", time.Hour)
	o := dial.Options{Gateway: je.gwAddr, Pins: []string{je.pin}, Device: newDevice()}
	if _, err := dial.Join(context.Background(), o, secret); err != nil {
		t.Fatal(err)
	}
	o.Device = newDevice()
	if _, err := dial.Join(context.Background(), o, secret); err == nil {
		t.Fatal("second join with the same invite worked")
	}
}

func TestExpiredInvite(t *testing.T) {
	je := setupJoin(t)
	secret := je.invite(t, "alice-laptop", time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	o := dial.Options{Gateway: je.gwAddr, Pins: []string{je.pin}, Device: newDevice()}
	if _, err := dial.Join(context.Background(), o, secret); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired invite: %v", err)
	}
}

func TestMadeUpInvite(t *testing.T) {
	je := setupJoin(t)
	o := dial.Options{Gateway: je.gwAddr, Pins: []string{je.pin}, Device: newDevice()}
	if _, err := dial.Join(context.Background(), o, "pshi_"+strings.Repeat("A", 43)); err == nil {
		t.Fatal("made-up invite worked")
	}
}

// An existing laptop of that name isn't replaced.
func TestJoinDoesNotReplaceToken(t *testing.T) {
	je := setupJoin(t)
	secret := je.invite(t, "laptop", time.Hour) // setup made a token "laptop"
	o := dial.Options{Gateway: je.gwAddr, Pins: []string{je.pin}, Device: newDevice()}
	if _, err := dial.Join(context.Background(), o, secret); err == nil || !strings.Contains(err.Error(), "already set up") {
		t.Fatalf("join over an existing token: %v", err)
	}
}

func TestJoinNeedsInvitesEnabled(t *testing.T) {
	e := setup(t)
	o := dial.Options{Gateway: e.gwAddr, Pins: []string{e.pin}, Device: newDevice()}
	if _, err := dial.Join(context.Background(), o, "pshi_"+strings.Repeat("A", 43)); err == nil {
		t.Fatal("join on a gateway without invites")
	}
}

func TestJoinThroughTunnel(t *testing.T) {
	je := setupJoin(t)
	secret := je.invite(t, "alice-laptop", time.Hour)
	o := je.tunnel(t)
	o.Token, o.Device = "", newDevice()
	if _, err := dial.Join(context.Background(), o, secret); err != nil {
		t.Fatal(err)
	}
}

// A gateway that has a TOTP secret for the name keeps it (one authenticator
// entry for several VMs) and sends no link.
func TestJoinKeepsExistingTOTP(t *testing.T) {
	je := setupJoin(t)
	if err := je.st.Import("alice-laptop", testSecret); err != nil {
		t.Fatal(err)
	}
	secret := je.invite(t, "alice-laptop", time.Hour)
	res, err := dial.Join(context.Background(), dial.Options{Gateway: je.gwAddr, Pins: []string{je.pin}, Device: newDevice()}, secret)
	if err != nil {
		t.Fatal(err)
	}
	if res.TOTPURI != "" {
		t.Fatalf("got a new TOTP link: %s", res.TOTPURI)
	}
}

func TestConfirmCode(t *testing.T) {
	a, b := newDevice().Public().(ed25519.PublicKey), newDevice().Public().(ed25519.PublicKey)
	ca := invite.ConfirmCode(a)
	if len(ca) != 9 || ca[4] != '-' || ca == invite.ConfirmCode(b) || ca != invite.ConfirmCode(a) {
		t.Fatalf("codes %s %s", ca, invite.ConfirmCode(b))
	}
	if !invite.SameCode(ca, strings.ToLower(strings.ReplaceAll(ca, "-", " "))) || invite.SameCode(ca, "") {
		t.Fatal("SameCode")
	}
	if !errors.Is(invite.ErrNotFound, invite.ErrNotFound) {
		t.Fatal()
	}
}
