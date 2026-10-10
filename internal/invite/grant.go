package invite

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"portash/internal/pin"
	"portash/internal/tokens"
)

// GrantPrefix starts a grant string.
const GrantPrefix = "pshg1."

const maxGrantSize = 8 << 10

var (
	grantNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	grantUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	totpB32     = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// Grant is everything a person needs for one VM, in one string, when the
// admin already made their token (portash token new): where the gateway is,
// its pin, the token, the device key the token is bound to, and optionally the
// VM's SSH host key, the login name and the unlock (TOTP) secret. There is
// nothing to approve: the token works only with that device key.
//
// A grant holds the token, so it is a secret. Anyone who reads it still needs
// the laptop's private device key to get in, but treat it like a password.
type Grant struct {
	Gateway string `json:"g"`           // host:port or https://host
	Name    string `json:"n"`           // what the laptop calls the VM (ssh Host)
	Pin     string `json:"p"`           // sha256:...
	Token   string `json:"t"`           // psh_...
	Device  string `json:"d"`           // pshd_...: the key the token is bound to
	HostKey string `json:"k,omitempty"` // "ssh-ed25519 AAAA..."
	User    string `json:"u,omitempty"` // ssh login name
	TOTP    string `json:"s,omitempty"` // base32 unlock secret
}

func (g Grant) String() string {
	b, _ := json.Marshal(g)
	return GrantPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// ParseGrant reads a grant made by Grant.String and checks every field.
func ParseGrant(s string) (Grant, error) {
	var g Grant
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), GrantPrefix)
	if !ok {
		return g, errors.New("not a portash grant (they start with " + GrantPrefix + ")")
	}
	if len(rest) > maxGrantSize {
		return g, errors.New("the grant is too long to be a grant")
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return g, errors.New("the grant is damaged; copy it again in full")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil || dec.More() {
		return Grant{}, errors.New("the grant is damaged; copy it again in full")
	}
	if err := g.Validate(); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// Validate checks every field; a grant is built from files and strings an
// admin typed, and read on a laptop from a message.
func (g Grant) Validate() error {
	if !grantNameRe.MatchString(g.Name) {
		return fmt.Errorf("grant: name %q must be lowercase letters, digits, . _ -", g.Name)
	}
	if err := checkGateway(g.Gateway); err != nil {
		return fmt.Errorf("grant for %s: %w", g.Name, err)
	}
	if !pin.Valid(g.Pin) {
		return fmt.Errorf("grant for %s: the pin must look like sha256:<43 chars>", g.Name)
	}
	if !tokens.ValidFormat(g.Token) {
		return fmt.Errorf("grant for %s: that is not a psh_ token", g.Name)
	}
	if _, err := tokens.ParseDevice(g.Device); err != nil {
		return fmt.Errorf("grant for %s: %w", g.Name, err)
	}
	if g.User != "" && !grantUserRe.MatchString(g.User) {
		return fmt.Errorf("grant for %s: bad ssh user %q", g.Name, g.User)
	}
	if g.HostKey != "" {
		f := strings.Fields(g.HostKey)
		if len(f) != 2 || !(strings.HasPrefix(f[0], "ssh-") || strings.HasPrefix(f[0], "ecdsa-")) || strings.ContainsAny(g.HostKey, "\r\n") {
			return fmt.Errorf("grant for %s: the SSH host key is damaged", g.Name)
		}
	}
	if g.TOTP != "" {
		raw, err := totpB32.DecodeString(strings.ToUpper(g.TOTP))
		if err != nil || len(raw) < 16 {
			return fmt.Errorf("grant for %s: the unlock secret is not base32 of at least 128 bits", g.Name)
		}
	}
	return nil
}

// checkGateway accepts https://host[:port][/path] or host[:port], with no
// spaces or control characters.
func checkGateway(gw string) error {
	if gw == "" || len(gw) > 255 || strings.ContainsAny(gw, " \t\r\n\x00") {
		return errors.New("bad gateway address")
	}
	if rest, ok := strings.CutPrefix(gw, "https://"); ok {
		u, err := url.Parse(gw)
		if err != nil || u.Hostname() == "" || rest == "" || u.User != nil {
			return errors.New("the gateway must look like https://host or https://host/path")
		}
		return nil
	}
	if strings.Contains(gw, "://") || strings.ContainsAny(gw, "/@?#") {
		return errors.New("the gateway must be HOST[:PORT] or https://HOST")
	}
	return nil
}
