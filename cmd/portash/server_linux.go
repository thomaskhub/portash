//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"portash/internal/authd"
	"portash/internal/sandbox"
	"portash/internal/session"
	"portash/internal/tokens"
	"portash/internal/totp"
)

// defaultTOTPDir holds the sudo and session TOTP secrets. It is outside the
// gateway's /var/lib/portash, which the gateway's own user owns.
const defaultTOTPDir = "/var/lib/portash-authd/totp"

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
//
// For a password and a code, the code needs its own prompt: PAM hands the
// first answer to every module, so pam_unix would get the code as the
// password. With --tty (and without expose_authtok), after common-auth:
//
//	@include common-auth
//	auth required pam_exec.so quiet /usr/local/bin/portash pam-totp --tty
//
// asks for the code on the user's terminal once the password was right.
func cmdPAMTOTP(args []string) error {
	fs := flag.NewFlagSet("pam-totp", flag.ContinueOnError)
	dir := fs.String("totp-dir", defaultTOTPDir, "TOTP secrets (root only)")
	tty := fs.Bool("tty", false, "ask for the code on the terminal instead of reading it from PAM")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if t := os.Getenv("PAM_TYPE"); t != "" && t != "auth" {
		return nil // only authentication is ours to decide
	}
	user := os.Getenv("PAM_USER")
	in := io.Reader(os.Stdin)
	if *tty {
		// pam_exec starts us in a new session, so /dev/tty is gone; sudo
		// names the user's terminal in PAM_TTY.
		name := os.Getenv("PAM_TTY")
		if !strings.HasPrefix(name, "/dev/") {
			name = "/dev/" + name
		}
		if name == "/dev/" || strings.Contains(name, "..") {
			return errors.New("no terminal to ask for the TOTP code on")
		}
		f, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
		if err != nil {
			return errors.New("no terminal to ask for the TOTP code on")
		}
		defer f.Close()
		fmt.Fprint(f, "TOTP code: ")
		defer fmt.Fprint(f, "\n")
		defer noEcho(f)()
		in = f
	}
	line, _ := bufio.NewReader(in).ReadString('\n')
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

// noEcho hides what is typed on the terminal f and returns the undo.
func noEcho(f *os.File) func() {
	var t syscall.Termios
	fd := f.Fd()
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&t))); e != 0 {
		return func() {}
	}
	old := t
	t.Lflag &^= syscall.ECHO
	syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&t)))
	return func() { syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&old))) }
}

// cmdShell is the ForceCommand for full (non-allowlisted) users. It records
// interactive sessions through authd, logs every command, and with --sandbox
// confines all writes to the listed directories (Landlock).
func cmdShell(args []string) error {
	fs := flag.NewFlagSet("shell", flag.ContinueOnError)
	sb := fs.Bool("sandbox", false, "only allow writes beneath --write directories (Landlock); sudo stops working")
	oldKernel := fs.Bool("allow-old-landlock", false, "with --sandbox: accept Landlock before ABI 3 (Linux 6.2), which can't stop truncating files")
	userManager := fs.Bool("allow-user-manager", false, "with --sandbox: allow a session whose user has a systemd --user or D-Bus session manager, which can start processes outside the sandbox")
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
		if sock := sandbox.UserManager(os.Getuid()); sock != "" && !*userManager {
			fmt.Fprintf(os.Stderr, "portash: %s can start programs outside the sandbox; an admin must turn off the user manager for this account (README, Sandbox)\n", sock)
			return errors.New("refusing a sandboxed session: user service manager running")
		}
	}
	confine := func(extra ...string) error {
		if !*sb {
			return nil
		}
		min := sandbox.MinABI
		if *oldKernel {
			min = 1
		}
		if err := sandbox.Restrict(append(paths, extra...), min); err != nil {
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

	if !tty && !hasCmd {
		// `ssh -T host`: a shell with no terminal would not be recorded, so
		// "interactive" in the audit log always means there is a recording.
		fmt.Fprintln(os.Stderr, "portash: a shell needs a terminal (ssh -t), or give a command")
		return errors.New("refusing a shell without a terminal")
	}
	if !tty {
		// scp, rsync, ansible, `ssh host cmd`: logged above with the command,
		// not recorded.
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
