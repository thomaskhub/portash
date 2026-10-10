package invite

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"portash/internal/tokens"
)

func testGrant(t *testing.T) Grant {
	t.Helper()
	tok, err := tokens.New()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	h := make([]byte, 32)
	rand.Read(h)
	secret := make([]byte, 20)
	rand.Read(secret)
	return Grant{
		Gateway: "https://vm1.example.com",
		Name:    "vm1",
		Pin:     "sha256:" + base64.RawURLEncoding.EncodeToString(h),
		Token:   tok,
		Device:  tokens.FormatDevice(pub),
		HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		User:    "alice",
		TOTP:    base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret),
	}
}

func TestGrantRoundTrip(t *testing.T) {
	g := testGrant(t)
	s := g.String()
	if !strings.HasPrefix(s, GrantPrefix) {
		t.Fatalf("grant %q has no prefix", s)
	}
	got, err := ParseGrant("  " + s + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != g {
		t.Fatalf("round trip changed it:\n%+v\n%+v", got, g)
	}
	// optional parts may be absent
	min := g
	min.HostKey, min.User, min.TOTP = "", "", ""
	if got, err := ParseGrant(min.String()); err != nil || got != min {
		t.Fatalf("minimal grant: %+v, %v", got, err)
	}
}

func TestGrantRejectsEveryBadField(t *testing.T) {
	base := testGrant(t)
	cases := map[string]func(*Grant){
		"empty name":      func(g *Grant) { g.Name = "" },
		"upper name":      func(g *Grant) { g.Name = "VM1" },
		"slash name":      func(g *Grant) { g.Name = "a/b" },
		"empty gateway":   func(g *Grant) { g.Gateway = "" },
		"http gateway":    func(g *Grant) { g.Gateway = "http://evil" },
		"user in url":     func(g *Grant) { g.Gateway = "https://a@evil.example" },
		"space gateway":   func(g *Grant) { g.Gateway = "vm1 example.com" },
		"path gateway":    func(g *Grant) { g.Gateway = "vm1.example.com/x" },
		"bad pin":         func(g *Grant) { g.Pin = "sha256:short" },
		"no pin prefix":   func(g *Grant) { g.Pin = strings.TrimPrefix(g.Pin, "sha256:") },
		"bad token":       func(g *Grant) { g.Token = "psh_short" },
		"empty token":     func(g *Grant) { g.Token = "" },
		"bad device":      func(g *Grant) { g.Device = "pshd_nope" },
		"empty device":    func(g *Grant) { g.Device = "" },
		"bad user":        func(g *Grant) { g.User = "Root User" },
		"bad host key":    func(g *Grant) { g.HostKey = "rsa AAAA" },
		"newline in key":  func(g *Grant) { g.HostKey = "ssh-ed25519 AAAA\nevil" },
		"short totp":      func(g *Grant) { g.TOTP = "ABCDEFGH" },
		"non-base32 totp": func(g *Grant) { g.TOTP = strings.Repeat("1", 32) },
	}
	for name, mutate := range cases {
		g := base
		mutate(&g)
		if _, err := ParseGrant(g.String()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGrantRejectsTamperingAndJunk(t *testing.T) {
	g := testGrant(t)
	s := g.String()
	for name, bad := range map[string]string{
		"no prefix":     strings.TrimPrefix(s, GrantPrefix),
		"invite prefix": CodePrefix + strings.TrimPrefix(s, GrantPrefix),
		"not base64":    GrantPrefix + "!!!",
		"not json":      GrantPrefix + base64.RawURLEncoding.EncodeToString([]byte("nope")),
		"empty":         "",
		"truncated":     s[:len(s)-10],
		"too long":      GrantPrefix + strings.Repeat("A", maxGrantSize+1),
	} {
		if _, err := ParseGrant(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// unknown fields are refused, so a future field is not silently dropped
	var m map[string]any
	b, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, GrantPrefix))
	json.Unmarshal(b, &m)
	m["x"] = "surprise"
	b, _ = json.Marshal(m)
	if _, err := ParseGrant(GrantPrefix + base64.RawURLEncoding.EncodeToString(b)); err == nil {
		t.Error("a grant with an unknown field was accepted")
	}
	// two JSON values in a row
	b2 := append(append([]byte(nil), b[:0]...), []byte(`{"g":"a"}{"g":"b"}`)...)
	if _, err := ParseGrant(GrantPrefix + base64.RawURLEncoding.EncodeToString(b2)); err == nil {
		t.Error("trailing data was accepted")
	}
}
