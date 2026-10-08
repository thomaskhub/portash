//go:build !windows

package restrict

import (
	"fmt"
	"log/syslog"
	"os"
	"strings"
	"syscall"
)

// Run is the forced-command entry point. name labels the key in logs.
// Options for Run beyond the policy file.
type Options struct {
	Name     string // labels the key in logs
	AllowPTY bool   // run even though the key has a PTY
	// VerifyTOTP checks a code for !totp rules (authd in production).
	VerifyTOTP func(code string) error
}

func Run(policyFile string, o Options) error {
	name := o.Name
	logw, _ := syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "portash-restrict")
	logf := func(format string, args ...any) {
		if logw != nil {
			logw.Info(fmt.Sprintf(format, args...))
		}
	}
	from := os.Getenv("SSH_CONNECTION")
	p, err := Load(policyFile)
	if err != nil {
		logf("error key=%s from=%q: %v", name, from, err)
		return fmt.Errorf("policy error, nothing allowed (see the server's auth log)")
	}
	// The authorized_keys "restrict" option disables the PTY, so a PTY means
	// "restrict" was left off and port/agent forwarding are probably on too.
	if os.Getenv("SSH_TTY") != "" && !o.AllowPTY {
		logf("deny key=%s from=%q: PTY allocated; add the restrict option to this key", name, from)
		return fmt.Errorf("this key is missing the \"restrict\" option in authorized_keys; refusing")
	}
	raw, ok := os.LookupEnv("SSH_ORIGINAL_COMMAND")
	if !ok || raw == "" {
		logf("deny key=%s from=%q: interactive shell", name, from)
		msg := "this key can't open a shell; it may only run:\n"
		for _, r := range p.Rules {
			msg += "  " + r.Text + "\n"
		}
		return fmt.Errorf("%s", msg)
	}
	args, err := Split(raw)
	if err != nil {
		logf("deny key=%s from=%q cmd=%q: %v", name, from, raw, err)
		return fmt.Errorf("command not allowed: %v", err)
	}
	rule, denied := p.Check(args)
	if denied != nil {
		logf("deny key=%s from=%q cmd=%q deny-rule=%d", name, from, raw, denied.Line)
		return fmt.Errorf("command not allowed: %s", raw)
	}
	if rule == nil {
		logf("deny key=%s from=%q cmd=%q", name, from, raw)
		return fmt.Errorf("command not allowed: %s", raw)
	}
	if rule.TOTP {
		if o.VerifyTOTP == nil {
			return fmt.Errorf("this command needs a TOTP code, but TOTP isn't set up on this server")
		}
		fmt.Fprint(os.Stderr, "TOTP code for "+args[0]+": ")
		code, err := readLine(os.Stdin)
		if err != nil {
			return fmt.Errorf("no TOTP code given")
		}
		if err := o.VerifyTOTP(code); err != nil {
			logf("deny key=%s from=%q cmd=%q: totp: %v", name, from, raw, err)
			return fmt.Errorf("TOTP: %v", err)
		}
		logf("totp ok key=%s from=%q cmd=%q", name, from, raw)
	}
	prog, err := Resolve(args[0])
	if err != nil {
		logf("deny key=%s from=%q cmd=%q: %v", name, from, raw, err)
		return err
	}
	logf("allow key=%s from=%q cmd=%q rule=%d", name, from, raw, rule.Line)
	if logw != nil {
		logw.Close()
	}
	return syscall.Exec(prog, args, Env(os.Environ()))
}

// readLine reads one line a byte at a time, so the rest of stdin is left for
// the command that runs next.
func readLine(f *os.File) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for len(b) < 64 {
		n, err := f.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return strings.TrimSpace(string(b)), nil
			}
			b = append(b, one[0])
		}
		if err != nil {
			if len(b) > 0 {
				return strings.TrimSpace(string(b)), nil
			}
			return "", err
		}
	}
	return "", fmt.Errorf("line too long")
}
