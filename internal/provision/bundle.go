// Package provision prepares everything a VM needs for portash before the VM
// exists, and applies it on the VM. The admin's laptop makes a Bundle
// (portash provision create); a first-boot script, Terraform or Ansible hands
// it to the VM (portash provision apply). Nobody logs in to create access.
//
// A Bundle holds the gateway's private key, so it is a secret: keep it in a
// secrets store and fetch it on the VM; do not template it into user_data.
// It never holds the token or the device's private key, only the hash of the token
// (and the device's public key that the token line names).
package provision

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"portash/internal/pin"
	"portash/internal/tokens"
)

const (
	// Prefix starts a bundle string.
	Prefix = "pshp1."
	// Version is the bundle format.
	Version = 1
	// MaxSize is the longest bundle accepted, in bytes of text.
	MaxSize = 64 << 10
)

var totpB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Bundle is what a VM needs: the gateway's identity, one token's hash, and the
// unlock secret of the same person.
type Bundle struct {
	Version int    `json:"v"`
	VM      string `json:"vm"`   // label of the VM (in the certificate)
	Pin     string `json:"pin"`  // sha256:... of the certificate's key
	Key     string `json:"key"`  // gateway private key, PEM
	Cert    string `json:"cert"` // gateway certificate, PEM
	Name    string `json:"name"` // name of the token (and of its unlock secret)
	Line    string `json:"line"` // the token's line for tokens.d (its hash, never the token)
	TOTP    string `json:"totp"` // base32 unlock secret
}

func (b Bundle) String() string {
	j, _ := json.Marshal(b)
	return Prefix + base64.RawURLEncoding.EncodeToString(j)
}

// Parse reads a bundle made by Bundle.String and checks it completely.
func Parse(s string) (Bundle, error) {
	var b Bundle
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), Prefix)
	if !ok {
		return b, errors.New("not a portash provisioning bundle (it starts with " + Prefix + ")")
	}
	if len(rest) > MaxSize {
		return b, errors.New("the bundle is too long to be a bundle")
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return b, errors.New("the bundle is damaged; copy it again in full")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		return Bundle{}, errors.New("the bundle is damaged; copy it again in full")
	}
	if err := b.Validate(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// Validate checks every field and that the pieces belong together: the key
// matches the certificate, the pin is the certificate's, the line is a single
// token line of the named token.
func (b Bundle) Validate() error {
	if b.Version != Version {
		return fmt.Errorf("bundle version %d: this portash reads version %d", b.Version, Version)
	}
	if !tokens.ValidName(b.VM) || !tokens.ValidName(b.Name) {
		return errors.New("bundle: bad VM or token name")
	}
	if !pin.Valid(b.Pin) {
		return errors.New("bundle: bad pin")
	}
	priv, err := ParseKey(b.Key)
	if err != nil {
		return err
	}
	cert, err := ParseCert(b.Cert)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&priv.PublicKey) {
		return errors.New("bundle: the key does not belong to the certificate")
	}
	if pin.Of(cert) != b.Pin {
		return errors.New("bundle: the pin is not the certificate's pin")
	}
	entries, err := tokens.Parse([]byte(b.Line), "bundle")
	if err != nil || len(entries) != 1 || strings.Contains(strings.TrimSpace(b.Line), "\n") {
		return errors.New("bundle: the token line must be exactly one valid line")
	}
	if entries[0].Name != b.Name {
		return errors.New("bundle: the token line is for another name")
	}
	if entries[0].Expired(time.Now()) {
		return errors.New("bundle: the token has already expired")
	}
	raw, err := totpB32.DecodeString(strings.ToUpper(b.TOTP))
	if err != nil || len(raw) < 16 {
		return errors.New("bundle: the unlock secret is not base32 of at least 128 bits")
	}
	return nil
}

// ParseKey reads an ECDSA private key in PKCS#8 PEM.
func ParseKey(pemText string) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(pemText))
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("bundle: the gateway key is not a PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("bundle: the gateway key does not parse")
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("bundle: the gateway key is not an ECDSA key")
	}
	return priv, nil
}

// ParseCert reads a certificate in PEM.
func ParseCert(pemText string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(pemText))
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("bundle: the gateway certificate is not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, errors.New("bundle: the gateway certificate does not parse")
	}
	return c, nil
}
