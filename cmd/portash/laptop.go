package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"portash/internal/dial"
	"portash/internal/pin"
	"portash/internal/resume"
	"portash/internal/tokens"
)

// profile is one gateway this laptop can use: one per VM in per-VM mode, or
// one for a whole VPN.
type profile struct {
	Gateway       string    `json:"gateway"`
	Pins          []string  `json:"pins,omitempty"`
	Network       string    `json:"network,omitempty"`
	Token         string    `json:"token"`
	Ticket        string    `json:"ticket,omitempty"`
	TicketExpires time.Time `json:"ticketExpires,omitempty"`
}

type clientConfig struct {
	Gateways map[string]*profile `json:"gateways"`
}

var profileRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func configPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

func loadConfig() (clientConfig, error) {
	c := clientConfig{Gateways: map[string]*profile{}}
	path, err := configPath()
	if err != nil {
		return c, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.Gateways == nil {
		// Single-gateway config from before named gateways.
		var old profile
		if json.Unmarshal(b, &old) == nil && old.Gateway != "" {
			c.Gateways = map[string]*profile{"default": &old}
		} else {
			c.Gateways = map[string]*profile{}
		}
	}
	return c, nil
}

func saveConfig(c clientConfig) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writePrivate(path, append(b, '\n'))
}

func (c clientConfig) names() []string {
	var n []string
	for k := range c.Gateways {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// pick returns the named gateway, or the only one there is.
func (c clientConfig) pick(name string) (string, *profile, error) {
	if name != "" {
		p := c.Gateways[name]
		if p == nil {
			return "", nil, fmt.Errorf("no gateway named %q (portash status lists them)", name)
		}
		return name, p, nil
	}
	switch len(c.Gateways) {
	case 0:
		return "", nil, nil
	case 1:
		n := c.names()[0]
		return n, c.Gateways[n], nil
	}
	if p := c.Gateways["default"]; p != nil {
		return "default", p, nil
	}
	return "", nil, errors.New("several gateways are set up; pass --gateway NAME (portash ssh-config does)")
}

func (p *profile) options() dial.Options {
	o := dial.Options{Gateway: p.Gateway, Pins: p.Pins, Token: p.Token}
	if p.Network != "" {
		o.Network, _ = netip.ParsePrefix(p.Network)
	}
	if p.Ticket != "" && time.Now().Before(p.TicketExpires) {
		o.Ticket = p.Ticket
	}
	return o
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	gw := fs.String("gateway", "", "gateway host[:port] (default: NAME, port 443), or https://HOST behind Cloudflare Tunnel or a reverse proxy")
	pins := fs.String("pin", "", "gateway key pin(s) from `portash fingerprint`, comma-separated (omit only for a CA-signed --cert)")
	network := fs.String("network", "", "VPN CIDR (only for a gateway into a Vabbit VPN)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	name := "default"
	if len(pos) == 1 {
		name = pos[0]
	} else if len(pos) > 1 {
		return errors.New("usage: portash login [NAME] [--gateway HOST:443] --pin sha256:PIN")
	}
	if !profileRe.MatchString(name) {
		return errors.New("NAME must be lowercase letters, digits, '.', '_' or '-' (it becomes the ssh Host name)")
	}
	addr := *gw
	if addr == "" {
		if len(pos) == 0 {
			return errors.New("--gateway is required")
		}
		addr = name
	}
	if strings.HasPrefix(addr, "https://") {
		// Behind Cloudflare Tunnel or a reverse proxy.
		if u, err := url.Parse(addr); err != nil || u.Hostname() == "" {
			return errors.New("--gateway must look like https://host or https://host/path")
		}
	} else if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}
	var pinList []string
	for _, p := range strings.Split(*pins, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !pin.Valid(p) {
			return errors.New("--pin must look like sha256:<43 chars>")
		}
		pinList = append(pinList, p)
	}
	if strings.HasPrefix(addr, "https://") && len(pinList) == 0 {
		// The proxy in front holds a public certificate for this name, so
		// without a pin it could pose as the gateway.
		return errors.New("--pin is required for a gateway behind a tunnel or proxy (portash fingerprint on the VM prints it)")
	}
	if *network != "" {
		if _, err := netip.ParsePrefix(*network); err != nil {
			return errors.New("--network must be a CIDR")
		}
	}
	if _, err := deviceKey(false); err != nil {
		return err
	}
	// The token is never a flag, so it stays out of shell history and ps.
	if term(os.Stdin) {
		fmt.Fprintf(os.Stderr, "Token for %s: ", name)
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	t := strings.TrimSpace(line)
	if !tokens.ValidFormat(t) {
		return errors.New("that doesn't look like an psh_ token")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	c.Gateways[name] = &profile{Gateway: addr, Pins: pinList, Network: *network, Token: t}
	if err := saveConfig(c); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Saved gateway %q. Next: portash ssh-config >> ~/.ssh/config\n", name)
	return nil
}

func cmdLogout(args []string) error {
	if len(args) == 0 {
		path, err := configPath()
		if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	for _, n := range args {
		if c.Gateways[n] == nil {
			return fmt.Errorf("no gateway named %q", n)
		}
		delete(c.Gateways, n)
	}
	return saveConfig(c)
}

func cmdStatus() error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if len(c.Gateways) == 0 {
		fmt.Fprintln(os.Stderr, "No gateways yet: portash login NAME --pin sha256:PIN")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tGATEWAY\tUNLOCKED")
	for _, n := range c.names() {
		p := c.Gateways[n]
		st := "no"
		if p.Ticket != "" && time.Now().Before(p.TicketExpires) {
			st = "until " + p.TicketExpires.Local().Format("Mon 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", n, p.Gateway, st)
	}
	return tw.Flush()
}

// cmdUnlock asks for one TOTP code and unlocks every gateway (or the named
// ones) with it. Each gateway checks the code itself, so one code from one
// authenticator entry works for all of them.
func cmdUnlock(ctx context.Context, args []string) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	names := args
	if len(names) == 0 {
		names = c.names()
	}
	if len(names) == 0 {
		return errors.New("no gateways yet: portash login NAME --pin sha256:PIN")
	}
	for _, n := range names {
		if c.Gateways[n] == nil {
			return fmt.Errorf("no gateway named %q", n)
		}
	}
	dev, err := deviceKey(false)
	if err != nil {
		return err
	}
	if term(os.Stdin) {
		fmt.Fprint(os.Stderr, "TOTP code: ")
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	code := strings.TrimSpace(line)
	failed := 0
	for _, n := range names {
		p := c.Gateways[n]
		o := p.options()
		o.Device = dev
		uctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		t, exp, err := dial.Unlock(uctx, o, code)
		cancel()
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "%s: %v\n", n, err)
			continue
		}
		p.Ticket, p.TicketExpires = t, exp
		fmt.Fprintf(os.Stderr, "%s: unlocked until %s\n", n, exp.Local().Format("Mon 15:04"))
	}
	// The network round trips above can take a while; re-read the file so a
	// `portash login` made meanwhile isn't overwritten, and apply only the
	// tickets we got.
	fresh, err := loadConfig()
	if err != nil {
		return err
	}
	mergeTickets(fresh, c)
	if err := saveConfig(fresh); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d gateways not unlocked", failed, len(names))
	}
	return nil
}

// mergeTickets copies newer tickets from src into dst, and nothing else.
func mergeTickets(dst, src clientConfig) {
	for n, p := range src.Gateways {
		if f := dst.Gateways[n]; f != nil && p.Ticket != "" && p.TicketExpires.After(f.TicketExpires) {
			f.Ticket, f.TicketExpires = p.Ticket, p.TicketExpires
		}
	}
}

func cmdDial(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dial", flag.ContinueOnError)
	gwName := fs.String("gateway", "", "which gateway to use (from portash login NAME)")
	verbose := fs.Bool("v", false, "print which path was used to stderr")
	direct := fs.Duration("direct-timeout", 1500*time.Millisecond, "how long to try the VPN directly (0 = gateway only)")
	noResume := fs.Bool("no-resume", false, "don't reconnect and resume when the network drops")
	window := fs.Duration("resume-window", 10*time.Minute, "give up reconnecting after this long")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return errors.New("usage: portash dial [--gateway NAME] HOST PORT")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	_, p, err := cfg.pick(*gwName)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(pos[1])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("bad port %q", pos[1])
	}
	ip, err := resolve(ctx, pos[0])
	if err != nil {
		return err
	}
	var o dial.Options
	if p != nil {
		o = p.options()
		if o.Device, err = deviceKey(false); err != nil {
			return err
		}
	}
	o.DirectTimeout, o.Resume, o.ResumeWindow = *direct, !*noResume, *window
	if *verbose {
		o.Verbose = os.Stderr
	}
	c, err := dial.Connect(ctx, o, netip.AddrPortFrom(ip, uint16(port)).String())
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- dial.Stdio(c) }()
	select {
	case err := <-done:
		return err // includes "could not reconnect" when resuming failed
	case <-ctx.Done():
		// ssh sends SIGHUP when it gives up (say, on a bad host key). Tell the
		// gateway the session is over, so it doesn't wait for a resume.
		if rc, ok := c.(*resume.Conn); ok {
			rc.Shutdown(0)
		}
		c.Close()
		return nil
	}
}

const sshCommon = `    # portash dial reconnects by itself for up to 10 minutes; these keepalives
    # stop the gateway's idle timeout, and give up only after that window.
    ServerAliveInterval 30
    ServerAliveCountMax 20
    # Never trust a host key on first sight; trust your host CA (README, "Host keys").
    StrictHostKeyChecking yes
    ForwardAgent no
    PasswordAuthentication no
`

// quoteExe makes the program path safe to put at the start of a ProxyCommand
// line, which ssh hands to a shell (sh -c, or cmd.exe on Windows). A path with
// a space, such as C:\Program Files\portash\portash.exe, would otherwise be
// split. Double quotes work for both shells; characters the Unix shell would
// still expand inside them are escaped.
func quoteExe(exe string) string {
	if runtime.GOOS == "windows" {
		// Backslashes are path separators here.
		if !strings.ContainsAny(exe, " \t&|;<>()^%!") {
			return exe
		}
		return `"` + exe + `"`
	}
	if !strings.ContainsAny(exe, " \t\\\"'$`&|;<>()*?[]{}!#~") {
		return exe
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`").Replace(exe) + `"`
}

func cmdSSHConfig(args []string) error {
	var names []string
	write := false
	for _, a := range args {
		if a == "--write" || a == "-write" {
			write = true
		} else {
			names = append(names, a)
		}
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if write {
		if len(names) > 0 {
			return errors.New("--write always writes every gateway; leave out the names")
		}
		return writeSSHConfig(c)
	}
	if len(names) == 0 {
		names = c.names()
	}
	text, err := sshConfigText(c, names)
	if err != nil {
		return err
	}
	fmt.Print(text)
	return nil
}

func sshConfigText(c clientConfig, names []string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		exe = "portash"
	}
	exe = quoteExe(exe)
	if len(names) == 0 {
		return "", errors.New("no gateways yet: portash login NAME --pin sha256:PIN")
	}
	var b strings.Builder
	for _, n := range names {
		p := c.Gateways[n]
		if p == nil {
			return "", fmt.Errorf("no gateway named %q", n)
		}
		if p.Network == "" {
			// Per-VM gateway: it only forwards to its own sshd on localhost.
			// HostKeyAlias keeps each VM's host key apart even though they
			// are all 127.0.0.1; sign host certificates with -n NAME.
			fmt.Fprintf(&b, "Host %s\n    HostName 127.0.0.1\n    HostKeyAlias %s\n    ProxyCommand %s dial --gateway %s %%h %%p\n%s\n",
				n, n, exe, n, sshCommon)
			continue
		}
		fmt.Fprintf(&b, `# Gateway %q into the VPN %s: add one Host block per machine with its
# VPN IP, e.g.
#   Host myvm
#       HostName 100.92.0.7
Host %s
    ProxyCommand %s dial --gateway %s %%h %%p
%s
`, n, p.Network, vpnPattern(p.Network), exe, n, sshCommon)
	}
	return b.String(), nil
}

// writeSSHConfig keeps every gateway's Host block in ~/.ssh/portash.conf,
// replaced on each run, and makes ~/.ssh/config include it once, at the top
// (an Include further down would only apply inside the Host block above
// it). Your own settings for a host (User, IdentityFile, ...) stay in
// ~/.ssh/config, in a Host block of their own: ssh combines both.
func writeSSHConfig(c clientConfig) error {
	text, err := sshConfigText(c, c.names())
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	const header = "# Written by `portash ssh-config --write`; changes here are overwritten.\n" +
		"# Put your own settings (User, IdentityFile, ...) in ~/.ssh/config.\n\n"
	if err := writeAtomic(filepath.Join(dir, "portash.conf"), []byte(header+text), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Wrote %s (gateways: %d)\n", filepath.Join(dir, "portash.conf"), len(c.names()))

	cfgPath := filepath.Join(dir, "config")
	old, err := os.ReadFile(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if includesPortash(string(old)) {
		return nil
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(cfgPath); err == nil {
		mode = fi.Mode().Perm()
	}
	nl := "\n"
	if strings.Contains(string(old), "\r\n") {
		nl = "\r\n"
	}
	inc := "# Host blocks for portash gateways (portash ssh-config --write)" + nl + "Include portash.conf" + nl + nl
	if err := writeAtomic(cfgPath, append([]byte(inc), old...), mode); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Added \"Include portash.conf\" at the top of %s\n", cfgPath)
	return nil
}

var includeRe = regexp.MustCompile(`(?im)^\s*include\s+.*portash\.conf\s*$`)

func includesPortash(cfg string) bool { return includeRe.MatchString(cfg) }

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// vpnPattern turns 100.92.0.0/16 into the ssh Host pattern 100.92.*.
func vpnPattern(cidr string) string {
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil || !pfx.Addr().Is4() {
		return "*"
	}
	parts := strings.Split(pfx.Masked().Addr().String(), ".")
	keep := pfx.Bits() / 8
	if keep == 0 {
		return "*"
	}
	return strings.Join(parts[:keep], ".") + ".*"
}
