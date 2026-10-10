package provision

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"portash/internal/fsown"
	"portash/internal/pin"
	"portash/internal/secretfile"
	"portash/internal/tokens"
	"portash/internal/totp"
)

// Options for Prepare.
type Options struct {
	Dir    string            // where everything is kept (made if needed, mode 0700)
	VM     string            // label of the VM; goes into the gateway certificate
	User   string            // token name, e.g. "admin"
	Device ed25519.PublicKey // this laptop's device key
	TTL    time.Duration     // token lifetime on first creation (0 = never expires)
	Days   int               // gateway certificate validity on first creation
}

// Prepared is the outcome of Prepare. Token is the secret the admin keeps.
type Prepared struct {
	Bundle    Bundle
	Pin       string
	TokenFile string // the token (secret), kept on the laptop
	LineFile  string // the token line (hash)
	TOTPFile  string // the unlock secret, base32
	BundleOut string // the bundle for the VM
	NewTOTP   bool   // the unlock secret was made just now: show its QR code
	NewKey    bool
	NewToken  bool
}

// Prepare makes, or finds again, everything one VM needs: the gateway key, the
// token for this laptop's device key, the unlock secret, and the bundle. Run
// it again in the same folder and nothing is made twice: the same key, token and
// secret come out. A folder that was prepared for another device key is refused.
// Everything is written from values in memory, so no output of any command can
// leave a file half empty.
func Prepare(o Options) (Prepared, error) {
	var p Prepared
	if !tokens.ValidName(o.VM) || !tokens.ValidName(o.User) {
		return p, errors.New("the VM name and the user name use letters, digits and . _ @ -")
	}
	if len(o.Device) != ed25519.PublicKeySize {
		return p, errors.New("a device key is required")
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return p, err
	}
	gw := filepath.Join(o.Dir, "gw")
	keyPath, certPath := filepath.Join(gw, "gateway.key"), filepath.Join(gw, "gateway.crt")

	// 1. gateway key
	switch _, kerr := os.Stat(keyPath); {
	case kerr == nil:
		// reuse; Validate below checks that key and certificate belong together
	case errors.Is(kerr, os.ErrNotExist):
		days := o.Days
		if days == 0 {
			days = 365
		}
		if _, err := pin.Generate(gw, o.VM, days); err != nil {
			return p, err
		}
		p.NewKey = true
	default:
		return p, kerr
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return p, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return p, err
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return p, fmt.Errorf("%s: key and certificate do not belong together: %w", gw, err)
	}
	cert, err := ParseCert(string(certPEM))
	if err != nil {
		return p, err
	}
	p.Pin = pin.Of(cert)
	if err := fsown.WriteFile(filepath.Join(o.Dir, "pin"), []byte(p.Pin+"\n"), 0o600); err != nil {
		return p, err
	}

	// 2. token and its line
	p.TokenFile = filepath.Join(o.Dir, o.User+".token")
	p.LineFile = filepath.Join(o.Dir, o.User+".line")
	line, isNew, err := ensureToken(p.TokenFile, p.LineFile, o)
	if err != nil {
		return p, err
	}
	p.NewToken = isNew

	// 3. unlock secret
	p.TOTPFile = filepath.Join(o.Dir, o.User+".totp")
	secret, isNew, err := ensureTOTP(p.TOTPFile)
	if err != nil {
		return p, err
	}
	p.NewTOTP = isNew

	// 4. the bundle
	p.Bundle = Bundle{Version: Version, VM: o.VM, Pin: p.Pin, Key: string(keyPEM), Cert: string(certPEM),
		Name: o.User, Line: line, TOTP: secret}
	if err := p.Bundle.Validate(); err != nil {
		return p, err
	}
	p.BundleOut = filepath.Join(o.Dir, "provision.bundle")
	if err := fsown.WriteFile(p.BundleOut, []byte(p.Bundle.String()+"\n"), 0o600); err != nil {
		return p, err
	}
	return p, nil
}

// ensureToken returns the token's line, making the token (in tokenFile, a new
// 0600 file) and the line (in lineFile) only if neither exists.
func ensureToken(tokenFile, lineFile string, o Options) (line string, created bool, err error) {
	rawTok, tokErr := os.ReadFile(tokenFile)
	rawLine, lineErr := os.ReadFile(lineFile)
	switch {
	case tokErr == nil && lineErr == nil:
		entries, err := tokens.Parse(rawLine, lineFile)
		if err != nil || len(entries) != 1 {
			return "", false, fmt.Errorf("%s is not a token line; remove both %s and %s to start the token again", lineFile, tokenFile, lineFile)
		}
		e := entries[0]
		if !e.Device.Equal(o.Device) {
			return "", false, fmt.Errorf("%s was prepared for another device key (%s); use a new folder, or remove the files to start again", o.Dir, tokens.FormatDevice(e.Device))
		}
		tok := strings.TrimSpace(string(rawTok))
		if !tokens.ValidFormat(tok) || sha256.Sum256([]byte(tok)) != e.Hash {
			return "", false, fmt.Errorf("%s is not the token of the line in %s", tokenFile, lineFile)
		}
		return strings.TrimSpace(string(rawLine)), false, nil
	case errors.Is(tokErr, os.ErrNotExist) && errors.Is(lineErr, os.ErrNotExist):
		tok, e, err := tokens.NewEntry(o.User, o.Device, o.TTL)
		if err != nil {
			return "", false, err
		}
		line := tokens.FormatEntry(e)
		if err := secretfile.WriteNew(tokenFile, []byte(tok+"\n")); err != nil {
			return "", false, err
		}
		if err := secretfile.WriteNew(lineFile, []byte(line+"\n")); err != nil {
			os.Remove(tokenFile) // a token whose line was lost cannot be used
			return "", false, err
		}
		return line, true, nil
	}
	return "", false, fmt.Errorf("only one of %s and %s exists; remove it to start the token again", tokenFile, lineFile)
}

// ensureTOTP returns the unlock secret, making it (a new 0600 file) if needed.
func ensureTOTP(path string) (secret string, created bool, err error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		s := strings.ToUpper(strings.TrimSpace(string(raw)))
		b, derr := totpB32.DecodeString(s)
		if derr != nil || len(b) < 16 {
			return "", false, fmt.Errorf("%s is not an unlock secret", path)
		}
		return s, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	s, err := totp.NewSecret()
	if err != nil {
		return "", false, err
	}
	if err := secretfile.WriteNew(path, []byte(s+"\n")); err != nil {
		return "", false, err
	}
	return s, true, nil
}
