package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"portash/internal/dial"
	"portash/internal/invite"
	"portash/internal/pin"
	"portash/internal/qr"
	"portash/internal/tokens"
	"portash/internal/totp"
)

// cmdJoin sets this laptop up from invites (files or pasted codes): it makes
// the device key if needed, registers it with each VM, saves the gateway,
// trusts the VM's SSH host key, writes the ssh config and shows the TOTP QR
// code. The VM's admin then approves the confirmation code it prints.
func cmdJoin(ctx context.Context, args []string) error {
	replace := false
	var rest []string
	for _, a := range args {
		if a == "--replace" {
			replace = true
			continue
		}
		rest = append(rest, a)
	}
	args = rest
	if len(args) == 0 {
		return errors.New("usage: portash join FILE|CODE|GRANT... [--replace] (the invite or grant your admin sent)")
	}
	var codes []invite.Code
	var grants []invite.Grant
	for _, a := range args {
		if strings.HasPrefix(a, invite.CodePrefix) {
			c, err := invite.ParseCode(a)
			if err != nil {
				return err
			}
			codes = append(codes, c)
			continue
		}
		if strings.HasPrefix(a, invite.GrantPrefix) {
			g, err := invite.ParseGrant(a)
			if err != nil {
				return err
			}
			grants = append(grants, g)
			continue
		}
		f, err := os.Open(a)
		if err != nil {
			return err
		}
		n := 0
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 64<<10)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			switch {
			case strings.HasPrefix(line, invite.CodePrefix):
				c, err := invite.ParseCode(line)
				if err != nil {
					f.Close()
					return fmt.Errorf("%s: %w", a, err)
				}
				codes = append(codes, c)
				n++
			case strings.HasPrefix(line, invite.GrantPrefix):
				g, err := invite.ParseGrant(line)
				if err != nil {
					f.Close()
					return fmt.Errorf("%s: %w", a, err)
				}
				grants = append(grants, g)
				n++
			}
		}
		f.Close()
		if n == 0 {
			return fmt.Errorf("%s has no invite code or grant in it", a)
		}
	}
	if len(grants) > 0 {
		if err := joinGrants(grants, replace); err != nil {
			return err
		}
	}
	if len(codes) == 0 {
		return nil
	}
	for _, c := range codes {
		if !profileRe.MatchString(c.Name) || !pin.Valid(c.Pin) || (c.User != "" && !sshUserRe.MatchString(c.User)) {
			return fmt.Errorf("the invite for %q is damaged", c.Name)
		}
	}
	dev, err := deviceKey(true)
	if err != nil {
		return err
	}
	var approve []string
	failed := 0
	for _, c := range codes {
		o := dial.Options{Gateway: c.Gateway, Pins: []string{c.Pin}, Device: dev}
		jctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		res, err := dial.Join(jctx, o, c.Secret)
		cancel()
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "%s: %v\n", c.Name, err)
			continue
		}
		if err := saveProfile(c.Name, &profile{Gateway: c.Gateway, Pins: []string{c.Pin}, Token: res.Token, User: c.User}, c.HostKey); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\n%s: joined as %s.\n", c.Name, res.Name)
		if res.TOTPURI != "" {
			if term(os.Stderr) {
				if q, err := qr.Encode(res.TOTPURI); err == nil {
					fmt.Fprintln(os.Stderr, "Scan this with your authenticator app (the code it shows is for `portash unlock`):")
					q.WriteTerminal(os.Stderr)
				}
			}
			fmt.Fprintf(os.Stderr, "Authenticator link: %s\n", res.TOTPURI)
		} else {
			fmt.Fprintln(os.Stderr, "Your existing authenticator entry for this VM keeps working.")
		}
		approve = append(approve, fmt.Sprintf("  %-28s %s", c.Name, res.Code))
	}
	if len(approve) > 0 {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if err := writeSSHConfig(cfg); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\nTell your admin this confirmation code, so they can approve this laptop:\n%s\n", strings.Join(approve, "\n"))
		fmt.Fprintf(os.Stderr, "Once they have: portash unlock, then ssh %s\n", strings.SplitN(strings.TrimSpace(approve[0]), " ", 2)[0])
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d invites not used", failed, len(codes))
	}
	return nil
}

// saveProfile stores the gateway under name and trusts the VM's SSH host key:
// the steps every way of joining ends with.
func saveProfile(name string, p *profile, hostKey string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	cfg.Gateways[name] = p
	if err := saveConfig(cfg); err != nil {
		return err
	}
	if hostKey != "" {
		return trustHostKey(name, hostKey)
	}
	return nil
}

// joinGrants sets this laptop up from grants: no network, no approval. The
// token in a grant works only with the device key it was made for, so the
// laptop must already have that key (portash device); a grant never makes a
// new one, which would give a setup that silently does not work. A grant also
// never replaces a gateway you already have under that name with a different
// one (a wrong or hostile grant would redirect you), unless you say --replace.
func joinGrants(grants []invite.Grant, replace bool) error {
	dev, err := deviceKey(false)
	if err != nil {
		return fmt.Errorf("%w\nA grant is made for your device key: run `portash device`, give that key to your admin, and use the grant they make for it", err)
	}
	mine := tokens.FormatDevice(dev.Public().(ed25519.PublicKey))
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	for _, g := range grants {
		if g.Device != mine {
			return fmt.Errorf("the grant for %s was made for another laptop (device key %s...), not this one (%s...)", g.Name, g.Device[:14], mine[:14])
		}
		if old := cfg.Gateways[g.Name]; old != nil && !replace && (old.Gateway != g.Gateway || len(old.Pins) != 1 || old.Pins[0] != g.Pin) {
			return fmt.Errorf("%s is already set up with another gateway or pin; if the grant is really meant to replace it, run again with --replace", g.Name)
		}
	}
	for _, g := range grants {
		if err := saveProfile(g.Name, &profile{Gateway: g.Gateway, Pins: []string{g.Pin}, Token: g.Token, User: g.User}, g.HostKey); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\n%s: ready.\n", g.Name)
		if g.TOTP == "" {
			fmt.Fprintln(os.Stderr, "Your existing authenticator entry for this VM keeps working.")
			continue
		}
		uri := totp.URI(strings.ToUpper(g.TOTP), g.Name, "portash "+g.Name)
		if term(os.Stderr) {
			if q, err := qr.Encode(uri); err == nil {
				fmt.Fprintln(os.Stderr, "Scan this with your authenticator app (the code it shows is for `portash unlock`):")
				q.WriteTerminal(os.Stderr)
			}
		}
		fmt.Fprintf(os.Stderr, "Authenticator link: %s\n", uri)
	}
	cfg, err = loadConfig()
	if err != nil {
		return err
	}
	if err := writeSSHConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nNo approval needed. Next: portash unlock, then ssh %s\n", grants[0].Name)
	return nil
}

// trustHostKey adds "NAME TYPE KEY" to ~/.ssh/known_hosts unless it's there.
func trustHostKey(name, key string) error {
	f := strings.Fields(key)
	if len(f) != 2 || !strings.HasPrefix(f[0], "ssh-") && !strings.HasPrefix(f[0], "ecdsa-") {
		return fmt.Errorf("the invite's host key for %s is damaged", name)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "known_hosts")
	line := name + " " + f[0] + " " + f[1]
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, l := range strings.Split(string(old), "\n") {
		if strings.TrimSpace(l) == line {
			return nil
		}
	}
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if len(old) > 0 && !strings.HasSuffix(string(old), "\n") {
		line = "\n" + line
	}
	if _, err := fh.WriteString(line + "\n"); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}
