// Package pin handles the gateway's TLS key and public-key pinning.
//
// The pin is sha256 over the certificate's SubjectPublicKeyInfo, so a
// certificate can be renewed with the same key without changing the pin.
package pin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const prefix = "sha256:"

// Of returns the pin string for a certificate.
func Of(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return prefix + base64.RawURLEncoding.EncodeToString(sum[:])
}

func Valid(p string) bool {
	if !strings.HasPrefix(p, prefix) {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(p[len(prefix):])
	return err == nil && len(b) == 32
}

// LoadOrCreate returns the gateway certificate in dir, generating a
// self-signed P-256 key and certificate on first use.
func LoadOrCreate(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "gateway.crt"), filepath.Join(dir, "gateway.key")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "portash gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// Leaf returns the parsed leaf certificate.
func Leaf(c tls.Certificate) (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	if len(c.Certificate) == 0 {
		return nil, errors.New("empty certificate")
	}
	return x509.ParseCertificate(c.Certificate[0])
}

// Verifier returns a VerifyConnection func that accepts only the pinned
// keys. More than one pin lets a gateway rotate its key without breaking
// clients: pin the current and the next key, then switch.
func Verifier(pins []string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("gateway sent no certificate")
		}
		got := Of(cs.PeerCertificates[0])
		for _, want := range pins {
			if got == want {
				return nil
			}
		}
		return fmt.Errorf("gateway key mismatch: got %s, pinned %s", got, strings.Join(pins, ","))
	}
}
