package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"portash/internal/invite"
	"portash/internal/secretfile"
	"portash/internal/tokens"
)

const maxGrantFile = 4 << 10

// cmdGrant builds the one string a person needs for a VM whose token the
// admin already made (portash token new): gateway, pin, token, the device key
// the token is bound to, and optionally the SSH host key, login name and
// unlock secret. The token and the secret are read from files, never from
// arguments, and the grant is a secret too: it goes to --out (a new file,
// mode 0600) or, without --out, to stdout.
func cmdGrant(args []string) error {
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	device := fs.String("device", "", "the device key (pshd_...) the token was made for")
	tokenFile := fs.String("token-file", "", "file holding the token (portash token new --out)")
	gw := fs.String("gateway", "", "how laptops reach the VM: https://HOST or HOST[:443]")
	pinFlag := fs.String("pin", "", "the gateway's key pin (sha256:...)")
	user := fs.String("ssh-user", "", "login name to put in the laptop's ssh config")
	hostKey := fs.String("host-key", "", "the VM's SSH host public key file, for the laptop to trust")
	totpFile := fs.String("totp-file", "", "file holding the unlock (TOTP) secret in base32")
	out := fs.String("out", "", "write the grant to this new file (mode 0600) instead of stdout")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("usage: portash grant [NAME] --device KEY --token-file FILE --gateway URL --pin PIN [--ssh-user U] [--host-key FILE] [--totp-file FILE] [--out FILE]")
	}
	addr, host, err := gatewayAddr(*gw)
	if err != nil {
		return err
	}
	g := invite.Grant{Gateway: addr, Name: host, Pin: *pinFlag, Device: *device, User: *user}
	if len(pos) == 1 {
		g.Name = pos[0]
	}
	if *tokenFile == "" {
		return errors.New("--token-file is required: the token is read from a file, never from an argument")
	}
	if g.Token, err = readOneLine(*tokenFile); err != nil {
		return err
	}
	if *totpFile != "" {
		if g.TOTP, err = readOneLine(*totpFile); err != nil {
			return err
		}
		g.TOTP = strings.ToUpper(strings.ReplaceAll(g.TOTP, " ", ""))
	}
	if *hostKey != "" {
		b, err := os.ReadFile(*hostKey)
		if err != nil {
			return fmt.Errorf("reading the SSH host key: %w", err)
		}
		f := strings.Fields(string(b))
		if len(f) < 2 {
			return fmt.Errorf("%s doesn't look like an SSH public key", *hostKey)
		}
		g.HostKey = f[0] + " " + f[1]
	}
	if err := g.Validate(); err != nil {
		return err
	}
	if _, err := tokens.ParseDevice(g.Device); err != nil {
		return err
	}
	s := g.String() + "\n"
	if *out != "" {
		if err := secretfile.WriteNew(*out, []byte(s)); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Grant for %s written to %s (mode 0600). It holds the token: send it to the person over a channel you trust, then delete it.\n", g.Name, *out)
		return nil
	}
	fmt.Fprintf(os.Stderr, "Grant for %s. It holds the token: send it over a channel you trust, then delete it.\n", g.Name)
	fmt.Print(s)
	return nil
}

// readOneLine reads a small file that must hold exactly one non-empty line.
func readOneLine(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) > maxGrantFile {
		return "", fmt.Errorf("%s is too big", path)
	}
	line := strings.TrimRight(string(b), "\r\n")
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return "", fmt.Errorf("%s must hold exactly one line", path)
	}
	return strings.TrimSpace(line), nil
}
