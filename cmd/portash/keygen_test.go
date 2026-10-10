package main

import (
	"strings"
	"testing"

	"portash/internal/pin"
)

func TestKeygenPrintsOnlyThePinTheGatewayWillUse(t *testing.T) {
	dir := t.TempDir()
	out, err := capture(t, func() error { return cmdKeygen([]string{"--name", "vm1", "--dir", dir}) })
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(out)
	if !pin.Valid(got) || strings.Count(out, "\n") != 1 {
		t.Fatalf("keygen printed %q, want one pin and nothing else", out)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("keygen printed key material")
	}
	fp, err := capture(t, func() error { return cmdFingerprint([]string{"--dir", dir}) })
	if err != nil || strings.TrimSpace(fp) != got {
		t.Fatalf("fingerprint %q (%v) differs from keygen %q", fp, err, got)
	}
	// The way the gateway loads its certificate gives the same pin.
	cert, err := loadCert(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pin.Leaf(cert)
	if pin.Of(leaf) != got {
		t.Fatal("the gateway would log another pin")
	}
}

func TestKeygenNeedsAName(t *testing.T) {
	if _, err := capture(t, func() error { return cmdKeygen([]string{"--dir", t.TempDir()}) }); err == nil {
		t.Fatal("keygen without --name worked")
	}
}

func TestKeygenRefusesToReplace(t *testing.T) {
	dir := t.TempDir()
	if _, err := capture(t, func() error { return cmdKeygen([]string{"--name", "vm1", "--dir", dir}) }); err != nil {
		t.Fatal(err)
	}
	if _, err := capture(t, func() error { return cmdKeygen([]string{"--name", "vm1", "--dir", dir}) }); err == nil {
		t.Fatal("second keygen replaced the key")
	}
}
