// Command portash gets SSH past port-22 and UDP blocks: it is an OpenSSH
// ProxyCommand that goes direct over the Vabbit VPN when it can and through
// a TLS gateway on port 443 when it can't.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"portash/internal/authd"
	"portash/internal/gateway"
	"portash/internal/pin"
	"portash/internal/restrict"
	"portash/internal/tokens"
	"portash/internal/totp"
)

var version = "dev"

const usage = `portash - a door to your shells: SSH over TLS on port 443

Gateway (on each VM, or one host in front of a Vabbit VPN):
  portash gateway --network CIDR [--listen :443] [--ports 22] [--dir /var/lib/portash]
          [--tunnel-listen 127.0.0.1:8080 [--tunnel-ip-header CF-Connecting-IP]]
          [--cert FILE --key FILE] [--max-streams 16] [--max-conns 512]
          [--idle-timeout 10m] [--max-session 24h] [--resume-window 10m]
          [--require-unlock] [--ticket-ttl 12h]
  portash fingerprint [--dir DIR]
          print the key pin laptops need
  portash token add NAME --device pshd_... [--ttl 2160h] [--dir DIR]
          print a new psh_ token bound to that device (shown once)
  portash token ls|rm NAME [--dir DIR]

Server (Linux; in authorized_keys or sshd ForceCommand; see README):
  portash shell [--sandbox] [--write DIR]... [--record=true] [--fail-open]
          login shell for full users: recorded, optionally sandboxed
  portash restrict --policy FILE [--name LABEL]
          run SSH_ORIGINAL_COMMAND only if FILE allows it
  portash restrict --policy FILE --check 'CMD'
          show whether CMD would be allowed
  portash authd [--socket PATH] [--totp-dir DIR] [--log-dir DIR]
          root daemon: TOTP checks, audit log, recordings
  portash totp enroll|rm USER [--totp-dir DIR]
          a user's TOTP secret for sudo and !totp rules (root)
  portash totp enroll|import|rm TOKEN --unlock [--dir /var/lib/portash]
          TOTP for the daily unlock; import reads an existing secret from
          stdin, so one phone entry unlocks every VM
  portash pam-totp
          TOTP check for sudo via pam_exec (see README)

Laptop:
  portash device
          print this laptop's device key (send it to the admin)
  portash login [NAME] [--gateway HOST:443|https://HOST] --pin sha256:...[,...] [--network CIDR]
          add a gateway (one per VM; NAME defaults to the host); the token
          is read from stdin or a prompt
  portash logout [NAME...]
          forget one gateway, or all
  portash unlock [NAME...]
          one TOTP code unlocks every gateway for 12 hours
  portash status
          list gateways and how long they stay unlocked
  portash dial [--gateway NAME] [-v] [--direct-timeout 1.5s] [--no-resume] HOST PORT
          stdio bridge; use as ssh ProxyCommand
  portash ssh-config [NAME...]
          print ~/.ssh/config blocks for your gateways
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "gateway":
		err = cmdGateway(ctx, args)
	case "fingerprint":
		err = cmdFingerprint(args)
	case "token":
		err = cmdToken(args)
	case "restrict":
		err = cmdRestrict(args)
	case "shell":
		err = cmdShell(args)
	case "authd":
		err = cmdAuthd(ctx, args)
	case "totp":
		err = cmdTOTP(args)
	case "pam-totp":
		err = cmdPAMTOTP(args)
	case "device":
		err = cmdDevice()
	case "login":
		err = cmdLogin(args)
	case "logout":
		err = cmdLogout(args)
	case "unlock":
		err = cmdUnlock(ctx, args)
	case "status":
		err = cmdStatus()
	case "dial":
		err = cmdDial(ctx, args)
	case "ssh-config":
		err = cmdSSHConfig(args)
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "portash:", err)
		os.Exit(1)
	}
}

// parse lets flags appear before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// ---- gateway side ----

func cmdGateway(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "address for direct TLS connections (\"\" = none)")
	tunnelListen := fs.String("tunnel-listen", "", "plain-HTTP address for Cloudflare Tunnel or a reverse proxy (e.g. 127.0.0.1:8080)")
	tunnelIP := fs.String("tunnel-ip-header", "", "header carrying the client's IP from the tunnel (CF-Connecting-IP, X-Real-IP)")
	network := fs.String("network", "", "VPN CIDR targets must be in (e.g. 100.92.0.0/16)")
	ports := fs.String("ports", "22", "comma-separated target ports allowed")
	dir := fs.String("dir", "/var/lib/portash", "state directory (tokens, TLS key)")
	certFile := fs.String("cert", "", "TLS certificate (default: self-signed key in --dir, pinned by clients)")
	keyFile := fs.String("key", "", "TLS key for --cert")
	maxStreams := fs.Int("max-streams", 16, "concurrent streams per token")
	maxConns := fs.Int("max-conns", 512, "concurrent connections in total")
	idle := fs.Duration("idle-timeout", 10*time.Minute, "close streams with no traffic for this long")
	maxSession := fs.Duration("max-session", 24*time.Hour, "close any stream after this long")
	resumeWindow := fs.Duration("resume-window", 10*time.Minute, "how long a dropped client may take to reconnect and resume")
	requireUnlock := fs.Bool("require-unlock", false, "every stream needs a ticket from `portash unlock` (a TOTP code once a day)")
	ticketTTL := fs.Duration("ticket-ttl", 12*time.Hour, "how long an unlock lasts")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(*network)
	if err != nil {
		return errors.New("--network must be a CIDR such as 100.92.0.0/16")
	}
	prefix = prefix.Masked()
	if prefix.Bits() < 8 {
		return errors.New("--network is too broad; use the VPN's CIDR")
	}
	allowed, err := gateway.ParsePorts(*ports)
	if err != nil {
		return err
	}
	store, err := tokens.NewStore(filepath.Join(*dir, "tokens"))
	if err != nil {
		return fmt.Errorf("%w (create one with: portash token add NAME --device KEY)", err)
	}
	cert, err := loadCert(*dir, *certFile, *keyFile)
	if err != nil {
		return err
	}
	leaf, err := pin.Leaf(cert)
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	gcfg := gateway.Config{Network: prefix, Ports: allowed, Tokens: store, MaxStreams: *maxStreams,
		MaxConns: *maxConns, IdleTimeout: *idle, MaxSession: *maxSession, ResumeWindow: *resumeWindow, Log: logger}
	if *requireUnlock {
		gcfg.Unlock = &gateway.Unlock{
			TOTP:      totp.Store{Dir: filepath.Join(*dir, "unlock"), ValidName: tokens.ValidName},
			TicketTTL: *ticketTTL,
			File:      filepath.Join(*dir, "tickets"),
		}
	}
	g, err := gateway.New(gcfg)
	if err != nil {
		return err
	}
	if *listen == "" && *tunnelListen == "" {
		return errors.New("nothing to listen on: set --listen and/or --tunnel-listen")
	}
	logger.Printf("portash gateway %s, network %s, ports %s, pin %s", version, prefix, *ports, pin.Of(leaf))
	var servers []*http.Server
	errc := make(chan error, 3)
	if *listen != "" {
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		srv := g.Server(*listen, cert)
		servers = append(servers, srv)
		logger.Printf("direct TLS on %s", *listen)
		go func() { errc <- srv.ServeTLS(g.Listener(ln), "", "") }()
	}
	if *tunnelListen != "" {
		ln, err := net.Listen("tcp", *tunnelListen)
		if err != nil {
			return err
		}
		tl := gateway.NewTunnelListener(*tunnelIP)
		front := &http.Server{Handler: tl, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10,
			ErrorLog: log.New(io.Discard, "", 0)}
		inner := g.Server("", cert)
		servers = append(servers, front, inner)
		logger.Printf("tunnel (WebSocket at %s) on %s", gateway.TunnelPath, *tunnelListen)
		go func() { errc <- front.Serve(g.Listener(ln)) }()
		go func() { errc <- inner.ServeTLS(g.Listener(tl), "", "") }()
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, s := range servers {
			s.Shutdown(sctx)
		}
		return nil
	}
}

func loadCert(dir, certFile, keyFile string) (cert tls.Certificate, err error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return cert, errors.New("--cert and --key go together")
		}
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	return pin.LoadOrCreate(dir)
}

func cmdFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	dir := fs.String("dir", "/var/lib/portash", "state directory")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	cert, err := pin.LoadOrCreate(*dir)
	if err != nil {
		return err
	}
	leaf, err := pin.Leaf(cert)
	if err != nil {
		return err
	}
	fmt.Println(pin.Of(leaf))
	return nil
}

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	dir := fs.String("dir", "/var/lib/portash", "state directory")
	device := fs.String("device", "", "the laptop's device key from `portash device` (required for add)")
	ttl := fs.Duration("ttl", 90*24*time.Hour, "token lifetime for add (0 = never expires)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	path := filepath.Join(*dir, "tokens")
	usage := errors.New("usage: portash token add NAME --device KEY [--ttl 2160h] | ls | rm NAME")
	if len(pos) == 0 {
		return usage
	}
	switch {
	case pos[0] == "add" && len(pos) == 2:
		pub, err := tokens.ParseDevice(*device)
		if err != nil {
			return err
		}
		tok, err := tokens.Add(path, pos[1], pub, *ttl)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Token for %s (shown once; only its hash is stored; works only from that device):\n", pos[1])
		fmt.Println(tok)
		return nil
	case pos[0] == "ls" && len(pos) == 1:
		entries, err := tokens.Load(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tEXPIRES\tDEVICE")
		now := time.Now()
		for _, e := range entries {
			exp := "never"
			if !e.Expires.IsZero() {
				exp = e.Expires.Format(time.RFC3339)
				if e.Expired(now) {
					exp += " (expired)"
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", e.Name, exp, tokens.FormatDevice(e.Device))
		}
		w.Flush()
		return err
	case pos[0] == "rm" && len(pos) == 2:
		return tokens.Remove(path, pos[1])
	}
	return usage
}

func cmdRestrict(args []string) error {
	fs := flag.NewFlagSet("restrict", flag.ContinueOnError)
	policy := fs.String("policy", "", "allowlist file")
	name := fs.String("name", "", "label for this key in the auth log")
	check := fs.String("check", "", "test a command line against the policy and exit")
	allowPTY := fs.Bool("allow-pty", false, "run even though the key has a PTY (i.e. lacks the restrict option)")
	socket := fs.String("socket", authd.DefaultSocket, "portash authd socket, for !totp rules")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) != 0 {
		return errors.New("unexpected arguments; the command comes from SSH_ORIGINAL_COMMAND")
	}
	if *policy == "" {
		return errors.New("--policy is required")
	}
	if *check == "" {
		return restrict.Run(*policy, restrict.Options{Name: *name, AllowPTY: *allowPTY,
			VerifyTOTP: func(code string) error { return authd.VerifyTOTP(*socket, code) }})
	}
	p, err := restrict.Load(*policy)
	if err != nil {
		return err
	}
	argv, err := restrict.Split(*check)
	if err != nil {
		return fmt.Errorf("denied: %v", err)
	}
	r, d := p.Check(argv)
	if d != nil {
		return fmt.Errorf("denied by line %d (%s)", d.Line, d.Text)
	}
	if r == nil {
		return errors.New("denied: no rule matches")
	}
	prog, err := restrict.Resolve(argv[0])
	if err != nil {
		return fmt.Errorf("allowed by line %d, but %v", r.Line, err)
	}
	extra := ""
	if r.TOTP {
		extra = " after a TOTP code"
	}
	fmt.Printf("allowed by line %d (%s), runs %s%s\n", r.Line, r.Text, prog, extra)
	return nil
}

// ---- laptop side ----

func configDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "portash"), nil
}

func writePrivate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// deviceKey loads this laptop's Ed25519 device key, creating it on first use.
// TODO: keep it in the OS keychain / Secure Enclave / TPM instead of a file.
func deviceKey(create bool) (ed25519.PrivateKey, error) {
	d, err := configDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(d, "device.key")
	b, err := os.ReadFile(path)
	if err == nil {
		seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s is corrupt", path)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, fmt.Errorf("no device key yet; run `portash device` (%v)", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := writePrivate(path, []byte(base64.RawURLEncoding.EncodeToString(priv.Seed())+"\n")); err != nil {
		return nil, err
	}
	return priv, nil
}

func cmdDevice() error {
	priv, err := deviceKey(true)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Send this device key to your gateway admin (it is public):")
	fmt.Println(tokens.FormatDevice(priv.Public().(ed25519.PublicKey)))
	return nil
}

func term(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// resolve turns a name into an IP locally (e.g. /etc/hosts), because the
// gateway only accepts literal VPN addresses.
func resolve(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("can't resolve %q; use the VPN IP (HostName in ~/.ssh/config)", host)
	}
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			return ip.Unmap(), nil
		}
	}
	return ips[0].Unmap(), nil
}
