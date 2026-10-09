package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"portash/internal/invite"
	"portash/internal/tokens"
	"portash/internal/totp"
)

func TestInviteApprove(t *testing.T) {
	dir := t.TempDir()
	invDir := filepath.Join(dir, "invites")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tok, _ := tokens.New()
	h := sha256.Sum256([]byte(tok))
	sec, _ := totp.NewSecret()
	p := invite.Pending{Name: "alice", Device: pub, TokenHash: hex.EncodeToString(h[:]), TOTP: sec,
		TokenTTL: time.Hour, Joined: time.Now(), Expires: time.Now().Add(time.Hour)}
	if err := invite.AddPending(invDir, p); err != nil {
		t.Fatal(err)
	}
	if err := inviteApprove(dir, invDir, "alice", "AAAA-BBBB"); err == nil {
		t.Fatal("approved with the wrong code")
	}
	if err := inviteApprove(dir, invDir, "alice", invite.ConfirmCode(pub)); err != nil {
		t.Fatal(err)
	}
	if !tokens.Exists(filepath.Join(dir, "tokens"), "alice") {
		t.Fatal("no token after approve")
	}
	if !(totp.Store{Dir: filepath.Join(dir, "unlock"), ValidName: tokens.ValidName}).Has("alice") {
		t.Fatal("no TOTP secret after approve")
	}
	if err := inviteApprove(dir, invDir, "alice", invite.ConfirmCode(pub)); err == nil {
		t.Fatal("approved twice")
	}
}
