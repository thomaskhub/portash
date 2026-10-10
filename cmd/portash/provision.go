package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"portash/internal/fsown"
	"portash/internal/invite"
	"portash/internal/provision"
	"portash/internal/qr"
	"portash/internal/tokens"
	"portash/internal/totp"
)

const provisionUsage = "usage: portash provision create VMNAME [--dir DIR] [--user admin] [--ttl 2160h] [--days 365] [--gateway URL] [--ssh-user U] [--show-totp]\n" +
	"       portash provision apply [BUNDLE|-] [--dir /var/lib/portash] [--dry-run] [--json]"

// cmdProvision prepares a VM's access on the admin's laptop (create) and puts
// it in place on the VM (apply), so nobody has to log in to the VM to create
// access, and nothing is assembled by hand.
func cmdProvision(args []string) error {
	if len(args) == 0 {
		return errors.New(provisionUsage)
	}
	switch args[0] {
	case "create":
		return provisionCreate(args[1:])
	case "apply":
		return provisionApply(args[1:])
	}
	return errors.New(provisionUsage)
}

func provisionCreate(args []string) error {
	fs := flag.NewFlagSet("provision create", flag.ContinueOnError)
	dir := fs.String("dir", "", "where everything is kept (default ./portash-VMNAME)")
	user := fs.String("user", "admin", "name of the token (and its unlock secret)")
	ttl := fs.Duration("ttl", 90*24*time.Hour, "token lifetime on first creation (0 = never expires)")
	days := fs.Int("days", 365, "gateway certificate validity on first creation")
	gw := fs.String("gateway", "", "how laptops reach the VM: https://HOST (also makes the grant)")
	sshUser := fs.String("ssh-user", "", "login name on the VM, for the grant")
	showTOTP := fs.Bool("show-totp", false, "show the unlock QR code and link again")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(provisionUsage)
	}
	vm := pos[0]
	if *dir == "" {
		*dir = "portash-" + vm
	}
	if *ttl == 0 {
		fmt.Fprintln(os.Stderr, "warning: this token never expires")
	}
	priv, err := deviceKey(true)
	if err != nil {
		return err
	}
	dev := priv.Public().(ed25519.PublicKey)
	p, err := provision.Prepare(provision.Options{Dir: *dir, VM: vm, User: *user, Device: dev, TTL: *ttl, Days: *days})
	if err != nil {
		return err
	}
	say := func(what string, isNew bool) string {
		if isNew {
			return what + ": made now"
		}
		return what + ": reused from " + *dir
	}
	fmt.Fprintf(os.Stderr, "Prepared %s in %s\n", vm, *dir)
	fmt.Fprintf(os.Stderr, "  %s\n  %s\n  %s\n", say("gateway key", p.NewKey), say("token "+*user, p.NewToken), say("unlock secret", p.NewTOTP))
	fmt.Fprintf(os.Stderr, "  device key: %s (this laptop)\n  pin: %s\n", tokens.FormatDevice(dev), p.Pin)
	if p.NewTOTP || *showTOTP {
		uri := totp.URI(p.Bundle.TOTP, *user, "portash "+vm)
		if term(os.Stderr) {
			if q, err := qr.Encode(uri); err == nil {
				fmt.Fprintln(os.Stderr, "\nScan this with your authenticator app (its code is for `portash unlock`):")
				q.WriteTerminal(os.Stderr)
			}
		}
		fmt.Fprintf(os.Stderr, "Authenticator link (same secret as the QR code): %s\n", uri)
	}
	if *gw != "" {
		file, err := writeGrant(*dir, p, *user, *gw, *sshUser, dev)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\nGrant for you: %s\n  on this laptop: portash join %s ; portash unlock ; ssh ...\n", file, file)
	} else {
		fmt.Fprintf(os.Stderr, "\nNo --gateway yet: run this command again with --gateway https://HOST when the tunnel's address is known (nothing is made twice).\n")
	}
	fmt.Fprintf(os.Stderr, "\nThe bundle is a SECRET (it holds the gateway's private key and the unlock secret). Keep it in a secrets store;\n"+
		"do not put it in user_data. On the VM: portash provision apply %s\n", filepath.Base(p.BundleOut))
	fmt.Println(p.BundleOut)
	return nil
}

// writeGrant makes the laptop's own grant from the files provision keeps.
func writeGrant(dir string, p provision.Prepared, user, gw, sshUser string, dev ed25519.PublicKey) (string, error) {
	addr, host, err := gatewayAddr(gw)
	if err != nil {
		return "", err
	}
	tok, err := readOneLine(p.TokenFile)
	if err != nil {
		return "", err
	}
	g := invite.Grant{Gateway: addr, Name: host, Pin: p.Pin, Token: tok, Device: tokens.FormatDevice(dev), User: sshUser}
	if err := g.Validate(); err != nil {
		return "", err
	}
	file := filepath.Join(dir, user+".grant")
	if err := fsown.WriteFile(file, []byte(g.String()+"\n"), 0o600); err != nil {
		return "", err
	}
	return file, nil
}

func provisionApply(args []string) error {
	fs := flag.NewFlagSet("provision apply", flag.ContinueOnError)
	dir := fs.String("dir", "/var/lib/portash", "gateway state directory")
	dry := fs.Bool("dry-run", false, "show what would happen; write nothing")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	var text string
	switch {
	case len(pos) > 1:
		return errors.New(provisionUsage)
	case len(pos) == 1:
		text, err = readBundleText(pos[0])
	case os.Getenv("PORTASH_PROVISION") != "":
		text = os.Getenv("PORTASH_PROVISION")
	default:
		return errors.New("give the bundle file (or - for stdin), or set PORTASH_PROVISION\n" + provisionUsage)
	}
	if err != nil {
		return err
	}
	b, err := provision.Parse(text)
	if err != nil {
		return err
	}
	res, err := provision.Apply(*dir, b, *dry)
	if err != nil {
		return err
	}
	if *asJSON {
		out, err := json.Marshal(struct {
			DryRun bool               `json:"dryRun"`
			Pin    string             `json:"pin"`
			Items  []provision.Result `json:"items"`
		}{*dry, b.Pin, res})
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}
	verb := ""
	if *dry {
		verb = "would be "
	}
	for _, r := range res {
		fmt.Printf("%-28s %s%s\n", r.Item, verb, r.Status)
	}
	fmt.Printf("pin %s\n", b.Pin)
	return nil
}

// readBundleText reads a bundle from a file, or from stdin for "-": the first
// line that starts like a bundle, at most provision.MaxSize bytes.
func readBundleText(src string) (string, error) {
	var r io.Reader = os.Stdin
	if src != "-" {
		f, err := os.Open(src)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, provision.MaxSize+4096))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, provision.Prefix) {
			return line, nil
		}
	}
	return "", errors.New("no provisioning bundle (a line starting with " + provision.Prefix + ") in " + src)
}
