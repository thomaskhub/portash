package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"
	"time"

	"portash/internal/invite"
	"portash/internal/pin"
	"portash/internal/tokens"
	"portash/internal/totp"
)

var sshUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// cmdInvite runs on the VM, as root: make an invite, list them, approve a
// laptop that joined, or remove one.
func cmdInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	dir := fs.String("dir", "/var/lib/portash", "gateway state directory")
	gw := fs.String("gateway", "", "how laptops reach this VM: https://HOST behind Cloudflare Tunnel or a proxy, or HOST[:443] direct (required for a new invite)")
	user := fs.String("ssh-user", "", "login name to put in the laptop's ssh config")
	ttl := fs.Duration("ttl", time.Hour, "how long the invite can be used")
	tokenTTL := fs.Duration("token-ttl", 90*24*time.Hour, "token lifetime once approved (0 = never expires)")
	hostKey := fs.String("host-key", "/etc/ssh/ssh_host_ed25519_key.pub", "SSH host key the laptop should trust (\"\" = none)")
	quiet := fs.Bool("quiet", false, "approve: print nothing on success (errors are always shown)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	invDir := filepath.Join(*dir, "invites")
	usage := errors.New("usage: portash invite NAME --gateway https://HOST [--ssh-user USER] [--ttl 1h] | ls | approve NAME CODE | rm NAME")
	switch {
	case len(pos) == 1 && pos[0] == "ls":
		return inviteList(invDir)
	case len(pos) == 3 && pos[0] == "approve":
		if err := inviteApprove(*dir, invDir, pos[1], pos[2]); err != nil {
			return err
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "Approved %s. They can now run `portash unlock` and ssh in.\n", pos[1])
		}
		return nil
	case len(pos) == 2 && pos[0] == "rm":
		n := invite.Remove(invDir, pos[1])
		fmt.Fprintf(os.Stderr, "Removed %d invite(s) or pending laptop(s) for %s\n", n, pos[1])
		return nil
	case len(pos) == 1:
		return inviteCreate(*dir, invDir, pos[0], *gw, *user, *hostKey, *ttl, *tokenTTL)
	}
	return usage
}

func inviteCreate(dir, invDir, name, gw, user, hostKeyFile string, ttl, tokenTTL time.Duration) error {
	if !tokens.ValidName(name) {
		return errors.New("NAME must be 1-64 chars of letters, digits, . _ @ - (it names the laptop's token)")
	}
	if tokens.Exists(filepath.Join(dir, "tokens"), name) {
		return fmt.Errorf("a token named %q already exists (portash token rm %s, or pick another name)", name, name)
	}
	if user != "" && !sshUserRe.MatchString(user) {
		return errors.New("--ssh-user must be a plain login name")
	}
	if ttl <= 0 {
		return errors.New("--ttl must be positive")
	}
	addr, host, err := gatewayAddr(gw)
	if err != nil {
		return err
	}
	cert, err := pin.LoadOrCreate(dir)
	if err != nil {
		return err
	}
	leaf, err := pin.Leaf(cert)
	if err != nil {
		return err
	}
	code := invite.Code{Gateway: addr, Name: host, Pin: pin.Of(leaf), User: user}
	if hostKeyFile != "" {
		b, err := os.ReadFile(hostKeyFile)
		if err != nil {
			return fmt.Errorf("reading the SSH host key: %w (or --host-key \"\")", err)
		}
		f := strings.Fields(string(b))
		if len(f) < 2 {
			return fmt.Errorf("%s doesn't look like an SSH public key", hostKeyFile)
		}
		code.HostKey = f[0] + " " + f[1]
	}
	exp := time.Now().Add(ttl).UTC().Truncate(time.Second)
	if code.Secret, err = invite.Create(invDir, invite.Invite{Name: name, Host: host, Expires: exp, TokenTTL: tokenTTL}); err != nil {
		return err
	}
	fmt.Printf("# portash invite: %s on %s. Works once, until %s.\n", name, host, exp.Format("2006-01-02 15:04 MST"))
	fmt.Printf("# On the laptop, run:  portash join FILE  (with this file), or paste the code:  portash join CODE\n")
	fmt.Println(code.String())
	fmt.Fprintf(os.Stderr, "Send that to the user. When they've joined, they tell you the code their laptop shows; then:\n")
	fmt.Fprintf(os.Stderr, "  sudo portash invite approve %s CODE\n", name)
	return nil
}

// gatewayAddr turns --gateway into what laptops dial and the name they
// call the VM by.
func gatewayAddr(gw string) (addr, host string, err error) {
	if gw == "" {
		return "", "", errors.New("--gateway is required: https://HOST (Cloudflare Tunnel, proxy) or HOST (direct on 443)")
	}
	if strings.HasPrefix(gw, "https://") {
		u, err := url.Parse(gw)
		if err != nil || u.Hostname() == "" {
			return "", "", errors.New("--gateway must look like https://host")
		}
		addr, host = gw, u.Hostname()
	} else {
		addr = gw
		if _, _, err := net.SplitHostPort(gw); err != nil {
			addr = net.JoinHostPort(gw, "443")
		}
		host, _, _ = net.SplitHostPort(addr)
	}
	host = strings.ToLower(host)
	if !profileRe.MatchString(host) {
		return "", "", fmt.Errorf("%q can't be used as an ssh host name", host)
	}
	return addr, host, nil
}

func inviteList(invDir string) error {
	invs, pend := invite.List(invDir, time.Now())
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATE\tUNTIL")
	for _, i := range invs {
		fmt.Fprintf(w, "%s\tinvited\t%s\n", i.Name, i.Expires.Local().Format("Mon 15:04"))
	}
	for _, p := range pend {
		fmt.Fprintf(w, "%s\tjoined, waiting for approval\t%s\n", p.Name, p.Expires.Local().Format("Mon 15:04"))
	}
	return w.Flush()
}

func inviteApprove(dir, invDir, name, code string) error {
	_, pend := invite.List(invDir, time.Now())
	var found *invite.Pending
	for i := range pend {
		if pend[i].Name == name {
			found = &pend[i]
		}
	}
	if found == nil {
		return fmt.Errorf("no laptop is waiting for approval as %q (portash invite ls)", name)
	}
	if !invite.SameCode(invite.ConfirmCode(found.Device), code) {
		return fmt.Errorf("that code doesn't match the laptop that joined as %q. If your user's laptop really shows %s, "+
			"someone else used the invite: run `portash invite rm %s` and make a new one", name, code, name)
	}
	var h [32]byte
	if b, err := hex.DecodeString(found.TokenHash); err != nil || len(b) != len(h) {
		return errors.New("damaged pending entry")
	} else {
		copy(h[:], b)
	}
	p, err := invite.TakePending(invDir, name, time.Now())
	if err != nil {
		return err
	}
	if p.TokenHash != found.TokenHash {
		return errors.New("the pending laptop changed while approving; run it again")
	}
	if err := tokens.AddHash(filepath.Join(dir, "tokens"), p.Name, h, p.Device, p.TokenTTL); err != nil {
		return err
	}
	if p.TOTP != "" {
		st := totp.Store{Dir: filepath.Join(dir, "unlock"), ValidName: tokens.ValidName}
		if err := st.Import(p.Name, p.TOTP); err != nil {
			return err
		}
	}
	return nil
}
