// Package restrict limits which commands an SSH key may run. sshd runs
// `portash restrict` as a forced command; it reads SSH_ORIGINAL_COMMAND, checks it
// against an allowlist, and execs the program directly (never through a
// shell), so ; | $() and friends are just literal characters.
package restrict

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const (
	maxCommand = 4096
	maxArgs    = 64
	// Rest at the end of a rule matches any number of further arguments.
	Rest = "..."
)

// SafePath is the only PATH used to find programs.
var SafePath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

type Rule struct {
	Line   int
	Text   string
	Tokens []string
	Unsafe bool // "!unsafe": the linter was overridden
	TOTP   bool // "!totp": the user must enter a TOTP code first
	Deny   bool // "!deny": matching commands are refused even if another rule allows them
}

// alwaysUnsafe programs hand the user a shell or arbitrary code however
// they are invoked.
var alwaysUnsafe = set("sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "busybox",
	"env", "sudo", "su", "doas", "pkexec", "vi", "vim", "nvim", "view", "vimdiff", "ex", "nano",
	"emacs", "ed", "less", "more", "most", "man", "python", "python2", "python3", "perl", "ruby",
	"node", "php", "lua", "awk", "gawk", "mawk", "nawk", "find", "xargs", "script", "expect",
	"ssh", "nsenter", "chroot", "unshare", "gdb", "strace", "ltrace", "crontab", "at", "watch",
	"nice", "nohup", "timeout", "stdbuf", "setsid", "flock", "time", "socat", "nc", "ncat", "telnet",
	"ash", "mksh", "rbash", "yash", "tclsh", "wish", "pwsh", "R", "Rscript", "julia", "irb", "jshell",
	"deno", "bun", "taskset", "ionice", "chrt", "setpriv", "runuser", "machinectl", "sudoedit",
	"firejail", "bwrap", "capsh", "systemd-nspawn", "ssh-agent", "openssl", "vipe", "rlwrap")

// unsafePrefixes catch versioned interpreters (python3.12, perl5.36, lua5.4).
var unsafePrefixes = []string{"python", "perl", "ruby", "lua", "php", "node", "tclsh", "pypy"}

// unsafeWithWildcards are fine with fixed arguments (docker ps) but give
// code execution once the user picks the arguments.
var unsafeWithWildcards = set("docker", "podman", "kubectl", "git", "tar", "zip", "unzip",
	"rsync", "scp", "sftp", "systemd-run", "tmux", "screen", "make", "npm", "pip", "apt", "apt-get",
	"dnf", "yum", "cp", "mv", "tee", "dd", "install", "ln", "chmod", "chown", "sed", "curl", "wget")

// wildSubcommand programs are fine with a fixed subcommand (systemctl status
// ...) but not with a user-chosen one (systemctl edit, ip netns exec).
var wildSubcommand = set("systemctl", "ip", "service")

func set(names ...string) map[string]bool {
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

// lint refuses rules that would give back a shell. "!unsafe" before a rule
// overrides it for an admin who has checked the program.
func lint(toks []string) error {
	prog := path.Base(toks[0])
	unsafe := alwaysUnsafe[prog]
	for _, p := range unsafePrefixes {
		unsafe = unsafe || strings.HasPrefix(prog, p)
	}
	if unsafe {
		return fmt.Errorf("%s can start a shell or run code; refusing it (prefix the rule with !unsafe to override)", prog)
	}
	if wildSubcommand[prog] && len(toks) > 1 && (toks[1] == Rest || strings.ContainsAny(toks[1], "*?[")) {
		return fmt.Errorf("%s with a user-chosen subcommand can run code; spell the subcommand out (or prefix the rule with !unsafe)", prog)
	}
	if unsafeWithWildcards[prog] {
		for _, t := range toks[1:] {
			if t == Rest || strings.ContainsAny(t, "*?[") {
				return fmt.Errorf("%s with user-chosen arguments can run code; list exact arguments (or prefix the rule with !unsafe)", prog)
			}
		}
	}
	return nil
}

type Policy struct {
	Rules []Rule
}

// Load reads one rule per line. Blank lines and # comments are ignored.
func Load(file string) (*Policy, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s must not be writable by group/other", file)
	}
	return Parse(f, file)
}

func Parse(f io.Reader, name string) (*Policy, error) {
	p := &Policy{}
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var unsafe, needTOTP, deny bool
		for strings.HasPrefix(line, "!") {
			word, rest, _ := strings.Cut(line, " ")
			switch word {
			case "!unsafe":
				unsafe = true
			case "!totp":
				needTOTP = true
			case "!deny":
				deny = true
			default:
				return nil, fmt.Errorf("%s:%d: unknown flag %s (use !unsafe, !totp or !deny)", name, n, word)
			}
			line = strings.TrimSpace(rest)
		}
		if deny && (unsafe || needTOTP) {
			return nil, fmt.Errorf("%s:%d: !deny can't be combined with other flags", name, n)
		}
		toks, err := Split(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %v", name, n, err)
		}
		if !deny && strings.ContainsAny(toks[0], `*?[\`) {
			return nil, fmt.Errorf("%s:%d: the program name can't be a pattern", name, n)
		}
		for i, t := range toks {
			if t == Rest && i != len(toks)-1 {
				return nil, fmt.Errorf("%s:%d: %s must be last", name, n, Rest)
			}
			if _, err := path.Match(t, ""); err != nil {
				return nil, fmt.Errorf("%s:%d: bad pattern %q", name, n, t)
			}
		}
		if !unsafe && !deny {
			if err := lint(toks); err != nil {
				return nil, fmt.Errorf("%s:%d: %v", name, n, err)
			}
		}
		p.Rules = append(p.Rules, Rule{Line: n, Text: line, Tokens: toks, Unsafe: unsafe, TOTP: needTOTP, Deny: deny})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	allows := 0
	for _, r := range p.Rules {
		if !r.Deny {
			allows++
		}
	}
	if allows == 0 {
		return nil, fmt.Errorf("%s: no allow rules (a policy of only !deny rules would allow nothing)", name)
	}
	return p, nil
}

// Split breaks a command line into arguments with shell-like quoting
// ('single', "double", backslash) but no expansion of any kind.
func Split(s string) ([]string, error) {
	if len(s) > maxCommand {
		return nil, errors.New("command too long")
	}
	var args []string
	var cur strings.Builder
	inArg := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' || c == 0x7f {
			return nil, errors.New("control characters are not allowed")
		}
		switch {
		case c == ' ' || c == '\t':
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		case c == '\'':
			inArg = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("unterminated '")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inArg = true
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
					i++
				}
				if s[i] < 0x20 && s[i] != '\t' {
					return nil, errors.New("control characters are not allowed")
				}
				cur.WriteByte(s[i])
			}
			if i >= len(s) {
				return nil, errors.New(`unterminated "`)
			}
		case c == '\\':
			if i+1 >= len(s) {
				return nil, errors.New("trailing backslash")
			}
			i++
			cur.WriteByte(s[i])
			inArg = true
		default:
			cur.WriteByte(c)
			inArg = true
		}
	}
	if inArg {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, errors.New("empty command")
	}
	if len(args) > maxArgs {
		return nil, errors.New("too many arguments")
	}
	return args, nil
}

// matchArg matches one argument. A pattern that doesn't itself start with
// "-" never matches an argument that does, so wildcards can't smuggle in
// options like --upload-pack= or -o ProxyCommand=; flags must be spelled out.
//
// In a !deny rule the opposite holds: wildcards match anything, flags
// included, and the program matches by base name too, because refusing too
// much is the safe direction.
func matchArg(pattern, arg string, deny bool) bool {
	if !deny && strings.HasPrefix(arg, "-") && !strings.HasPrefix(pattern, "-") {
		return false
	}
	if !deny && pattern != arg {
		// A wildcard never stands for a ".." path segment, or for a hidden
		// file unless the pattern itself starts that segment with a dot:
		// /srv/app/* must not reach /srv/app/../etc or ~/.ssh.
		for _, seg := range strings.Split(arg, "/") {
			if seg == ".." {
				return false
			}
		}
		if hiddenNotInPattern(pattern, arg) {
			return false
		}
	}
	ok, _ := path.Match(pattern, arg)
	return ok
}

// hiddenNotInPattern reports whether arg has a dot-led path segment that the
// pattern's segment at the same position doesn't spell with a dot.
func hiddenNotInPattern(pattern, arg string) bool {
	ps, as := strings.Split(pattern, "/"), strings.Split(arg, "/")
	for i, a := range as {
		if !strings.HasPrefix(a, ".") || a == "." {
			continue
		}
		if i >= len(ps) || !strings.HasPrefix(ps[i], ".") {
			return true
		}
	}
	return false
}

func (r Rule) Match(args []string) bool {
	toks := r.Tokens
	if r.Deny {
		full, _ := path.Match(toks[0], args[0])
		base, _ := path.Match(path.Base(toks[0]), path.Base(args[0]))
		if !full && !base {
			return false
		}
		return denySubsequence(toks[1:], args[1:])
	} else if args[0] != toks[0] {
		return false
	}
	for i := 1; i < len(toks); i++ {
		if toks[i] == Rest {
			if !r.Deny {
				for _, a := range args[i:] {
					if strings.HasPrefix(a, "-") {
						return false
					}
				}
			}
			return true
		}
		if i >= len(args) || !matchArg(toks[i], args[i], r.Deny) {
			return false
		}
	}
	return len(args) == len(toks)
}

// denySubsequence reports whether the deny rule's words appear in args in
// order, with any other arguments before, between and after them: a deny
// rule must not be dodged by adding or moving an argument
// (systemctl restart --force nginx against "!deny * --force").
func denySubsequence(toks, args []string) bool {
	i := 0
	for _, t := range toks {
		if t == Rest {
			return true
		}
		for i < len(args) && !matchArg(t, args[i], true) {
			i++
		}
		if i == len(args) {
			return false
		}
		i++
	}
	return true
}

// Check returns the first allow rule that matches args, or nil. Any
// matching !deny rule wins over every allow rule; it is returned as the
// second value.
func (p *Policy) Check(args []string) (*Rule, *Rule) {
	for i := range p.Rules {
		if p.Rules[i].Deny && p.Rules[i].Match(args) {
			return nil, &p.Rules[i]
		}
	}
	for i := range p.Rules {
		if !p.Rules[i].Deny && p.Rules[i].Match(args) {
			return &p.Rules[i], nil
		}
	}
	return nil, nil
}

// Resolve finds the program for argv[0] on SafePath (or uses it as given if
// it is absolute). The user's PATH is never consulted.
func Resolve(prog string) (string, error) {
	if strings.HasPrefix(prog, "/") {
		return prog, nil
	}
	if strings.Contains(prog, "/") {
		return "", fmt.Errorf("%q: use a bare program name or an absolute path", prog)
	}
	for _, dir := range SafePath {
		p := dir + "/" + prog
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in %s", prog, strings.Join(SafePath, ":"))
}

// Env is the environment the allowed program gets: a fixed PATH plus a few
// harmless variables. Things like LD_PRELOAD never get through.
func Env(environ []string) []string {
	keep := map[string]bool{"HOME": true, "USER": true, "LOGNAME": true, "LANG": true, "LC_ALL": true,
		"TERM": true, "TZ": true, "SSH_CLIENT": true, "SSH_CONNECTION": true}
	out := []string{"PATH=" + strings.Join(SafePath, ":")}
	for _, kv := range environ {
		if k, _, ok := strings.Cut(kv, "="); ok && keep[k] {
			out = append(out, kv)
		}
	}
	return out
}
