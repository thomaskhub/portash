//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"portash/internal/authd"
	"portash/internal/sandbox"
	"portash/internal/session"
	"portash/internal/tokens"
	"portash/internal/totp"
)

const defaultTOTPDir = "/var/lib/portash/totp"

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func cmdAuthd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("authd", flag.ContinueOnError)
	socket := fs.String("socket", authd.DefaultSocket, "Unix socket to listen on")
	totpDir := fs.String("totp-dir", defaultTOTPDir, "TOTP secrets (root only)")
	logDir := fs.String("log-dir", "/var/log/portash", "audit log and session recordings")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("portash authd must run as root")
	}
	s := &authd.Server{TOTP: totp.Store{Dir: *totpDir}, LogDir: *logDir, Log: log.New(os.Stderr, "", 0)}
	log.Printf("portash authd %s on %s", version, *socket)
	return s.ListenAndServe(ctx, *socket)
}

func cmdTOTP(args []string) error {
	fs := flag.NewFlagSet("totp", flag.ContinueOnError)
	dir := fs.String("totp-dir", defaultTOTPDir, "TOTP secrets (root only)")
	unlock := fs.Bool("unlock", false, "manage the gateway's daily-unlock secret for a token NAME instead of a user's")
	gwDir := fs.String("dir", "/var/lib/portash", "gateway state directory (with --unlock)")
	issuer := fs.String("issuer", "", "name shown in the authenticator app (default: hostname)")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 || (pos[0] != "enroll" && pos[0] != "rm" && pos[0] != "import") {
		return errors.New("usage: portash totp enroll|import|rm NAME [--unlock]")
	}
	st := totp.Store{Dir: *dir}
	if *unlock {
		st = totp.Store{Dir: filepath.Join(*gwDir, "unlock"), ValidName: tokens.ValidName}
	}
	switch pos[0] {
	case "rm":
		return st.Remove(pos[1])
	case "import":
		// The same secret on every VM means one authenticator entry, and
		// one code from `portash unlock` opens them all.
		if term(os.Stdin) {
			fmt.Fprint(os.Stderr, "Secret (base32 or otpauth:// URI): ")
		}
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if err := st.Import(pos[1], line); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Imported TOTP secret for %s\n", pos[1])
		return nil
	}
	if *issuer == "" {
		h, _ := os.Hostname()
		*issuer = "portash " + h
		if *unlock {
			*issuer = "portash"
		}
	}
	uri, err := st.Enroll(pos[1], *issuer)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Add this to %s's authenticator app (paste it, or make a QR code with `qrencode -t ansiutf8`):\n", pos[1])
	if *unlock {
		fmt.Fprintf(os.Stderr, "To use the same entry on other VMs: echo 'URI' | sudo portash totp import %s --unlock\n", pos[1])
	}
	fmt.Println(uri)
	return nil
}

// cmdPAMTOTP is run by pam_exec during sudo:
//
//	auth required pam_exec.so expose_authtok quiet /usr/local/bin/portash pam-totp
//
// PAM puts the user name in PAM_USER and what they typed on stdin.
func cmdPAMTOTP(args []string) error {
	fs := flag.NewFlagSet("pam-totp", flag.ContinueOnError)
	dir := fs.String("totp-dir", defaultTOTPDir, "TOTP secrets (root only)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if t := os.Getenv("PAM_TYPE"); t != "" && t != "auth" {
		return nil // only authentication is ours to decide
	}
	user := os.Getenv("PAM_USER")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	code := strings.TrimSpace(strings.TrimRight(line, "\x00"))
	err := totp.Store{Dir: *dir}.Check(user, code)
	if w, lerr := syslogWriter(); lerr == nil {
		res := "ok"
		if err != nil {
			res = "fail: " + err.Error()
		}
		fmt.Fprintf(w, "sudo totp user=%s ruser=%s %s", user, os.Getenv("PAM_RUSER"), res)
		w.Close()
	}
	return err
}

// cmdShell is the ForceCommand for full (non-allowlisted) users. It records
// interactive sessions through authd, logs every command, and with --sandbox
// confines all writes to the listed directories (Landlock).
func cmdShell(args []string) error {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	sb := fs.Bool("sandbox", false, "only allow writes beneath --write directories (Landlock); sudo stops working")
	var writable multiFlag
	fs.Var(&writable, "write", "directory the session may write to (repeatable; ~ is the user's home)")
	record := fs.Bool("record", true, "record interactive sessions through portash authd")
	failOpen := fs.Bool("fail-open", false, "allow the session even if authd can't log or record it")
	socket := fs.String("socket", authd.DefaultSocket, "portash authd socket")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	paths := append([]string{}, sandbox.DefaultWritable...)
	for _, w := range writable {
		if w == "~" || strings.HasPrefix(w, "~/") {
			w = filepath.Join(home, strings.TrimPrefix(w, "~"))
		}
		paths = append(paths, w)
	}
	if *sb {
		// Landlock and no_new_privs apply to the calling thread only. Keep
		// this goroutine on one thread from here on, so the restricted thread
		// is the one that execs or forks the shell.
		runtime.LockOSThread()
	}
	confine := func(extra ...string) error {
		if !*sb {
			return nil
		}
		if err := sandbox.Restrict(append(paths, extra...)); err != nil {
			return fmt.Errorf("sandbox: %w", err)
		}
		return nil
	}
	shell := loginShell()
	cmdline, hasCmd := os.LookupEnv("SSH_ORIGINAL_COMMAND")
	hasCmd = hasCmd && cmdline != ""
	tty := session.IsTerminal(os.Stdin)
	mode := "interactive"
	switch {
	case hasCmd && tty:
		mode = "exec-pty" // ssh -t host cmd: recorded like a login
	case hasCmd:
		mode = "exec"
	}
	detail := fmt.Sprintf("mode=%s sandbox=%v from=%q cmd=%q", mode, *sb, os.Getenv("SSH_CONNECTION"), cmdline)
	if *sb {
		detail += fmt.Sprintf(" landlock_abi=%d", sandbox.ABI())
	}
	if err := authd.Log(*socket, "session", detail); err != nil && !*failOpen {
		return fmt.Errorf("refusing session: can't write the audit log (%v)", err)
	}

	if !tty {
		// scp, rsync, ansible, `ssh host cmd`: logged above, not recorded.
		if err := confine(); err != nil {
			return err
		}
		argv := []string{filepath.Base(shell)}
		if hasCmd {
			argv = append(argv, "-c", cmdline)
		}
		return syscall.Exec(shell, argv, os.Environ())
	}

	var rec interface {
		Write([]byte) (int, error)
		Close() error
	}
	if *record {
		r, err := authd.Record(*socket, fmt.Sprintf("%s %s", os.Getenv("USER"), os.Getenv("SSH_CONNECTION")))
		if err != nil && !*failOpen {
			return fmt.Errorf("refusing session: can't start the recording (%v)", err)
		}
		if err == nil {
			rec = r
			defer r.Close()
		}
	}
	cmd := exec.Command(shell)
	cmd.Args = []string{"-" + filepath.Base(shell)} // login shell
	if hasCmd {
		cmd.Args = []string{filepath.Base(shell), "-c", cmdline}
	}
	cmd.Env = os.Environ()
	var w interface{ Write([]byte) (int, error) }
	if rec != nil {
		w = rec
	}
	code, err := session.RunPTY(cmd, w, func(tty string) error { return confine(tty) })
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}

// loginShell returns the user's shell from /etc/passwd (sshd also sets SHELL).
func loginShell() string {
	if sh := os.Getenv("SHELL"); strings.HasPrefix(sh, "/") {
		return sh
	}
	uid := fmt.Sprint(os.Getuid())
	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) == 7 && f[2] == uid && strings.HasPrefix(f[6], "/") {
				return f[6]
			}
		}
	}
	return "/bin/sh"
}
