package main

import (
	"bufio"
	"context"
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
)

// cmdJoin sets this laptop up from invites (files or pasted codes): it makes
// the device key if needed, registers it with each VM, saves the gateway,
// trusts the VM's SSH host key, writes the ssh config and shows the TOTP QR
// code. The VM's admin then approves the confirmation code it prints.
func cmdJoin(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: portash join FILE|CODE... (the invite your admin sent)")
	}
	var codes []invite.Code
	for _, a := range args {
		if strings.HasPrefix(a, invite.CodePrefix) {
			c, err := invite.ParseCode(a)
			if err != nil {
				return err
			}
			codes = append(codes, c)
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
			if !strings.HasPrefix(line, invite.CodePrefix) {
				continue
			}
			c, err := invite.ParseCode(line)
			if err != nil {
				f.Close()
				return fmt.Errorf("%s: %w", a, err)
			}
			codes = append(codes, c)
			n++
		}
		f.Close()
		if n == 0 {
			return fmt.Errorf("%s has no invite code in it", a)
		}
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
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		cfg.Gateways[c.Name] = &profile{Gateway: c.Gateway, Pins: []string{c.Pin}, Token: res.Token, User: c.User}
		if err := saveConfig(cfg); err != nil {
			return err
		}
		if c.HostKey != "" {
			if err := trustHostKey(c.Name, c.HostKey); err != nil {
				return err
			}
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
