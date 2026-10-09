package restrict

import (
	"reflect"
	"strings"
	"testing"
)

const testPolicy = `
# comment
uptime
systemctl status ...
systemctl restart nginx
journalctl -u nginx -n *
!unsafe docker logs --tail * *
git -C /srv/app pull
`

func load(t *testing.T) *Policy {
	t.Helper()
	p, err := Parse(strings.NewReader(testPolicy), "test")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSplit(t *testing.T) {
	cases := map[string][]string{
		`uptime`:                     {"uptime"},
		`  a   b  `:                  {"a", "b"},
		`a 'b c' "d e"`:              {"a", "b c", "d e"},
		`a "x\"y" 'it''s'`:           {"a", `x"y`, "its"},
		`a b\ c`:                     {"a", "b c"},
		`echo $(id); rm -rf / | cat`: {"echo", "$(id);", "rm", "-rf", "/", "|", "cat"},
		`a ""`:                       {"a", ""},
	}
	for in, want := range cases {
		got, err := Split(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("Split(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{``, `   `, `a 'b`, `a "b`, `a\`, "a\nb", "a\x00b", `a "b` + "\n" + `"`} {
		if _, err := Split(bad); err == nil {
			t.Errorf("Split(%q) should fail", bad)
		}
	}
}

func TestCheck(t *testing.T) {
	p := load(t)
	allow := []string{
		"uptime",
		"systemctl status",
		"systemctl status nginx",
		"systemctl status nginx postgres",
		"systemctl restart nginx",
		"journalctl -u nginx -n 50",
		"docker logs --tail 100 web",
		"git -C /srv/app pull",
	}
	deny := []string{
		"uptime --help",                        // extra arg
		"bash",                                 // not listed
		"/bin/sh -c uptime",                    // not listed
		"systemctl restart postgres",           // only nginx
		"systemctl restart nginx; reboot",      // ';' is literal: arg "nginx;" doesn't match
		"systemctl status --no-pager",          // ... never matches flags
		"journalctl -u nginx -n --output=json", // * never matches flags
		"journalctl -u nginx -n 50 extra",      // too many args
		"docker logs --tail 100 -f",            // * never matches flags
		"git -C /srv/app pull --upload-pack=x", // extra flag
		"/usr/bin/uptime",                      // program must match exactly
		"Uptime",                               // case sensitive
	}
	for _, c := range allow {
		args, _ := Split(c)
		if r, _ := p.Check(args); r == nil {
			t.Errorf("%q should be allowed", c)
		}
	}
	for _, c := range deny {
		args, err := Split(c)
		if r, _ := p.Check(args); err == nil && r != nil {
			t.Errorf("%q should be denied", c)
		}
	}
}

func TestWildcardDoesNotCrossSlash(t *testing.T) {
	p, _ := Parse(strings.NewReader("cat /var/log/app/*\n"), "t")
	for c, want := range map[string]bool{
		"cat /var/log/app/today.log":        true,
		"cat /var/log/app/../../etc/shadow": false,
		"cat /var/log/app/x/y":              false,
		"cat /var/log/app/..":               false,
		"cat /var/log/app/.secret":          false,
	} {
		args, _ := Split(c)
		if r, _ := p.Check(args); (r != nil) != want {
			t.Errorf("%q: allowed=%v, want %v", c, !want, want)
		}
	}
}

func TestBadPolicies(t *testing.T) {
	for _, bad := range []string{
		"",                   // empty policy
		"# only comments\n",  // still empty
		"sys* status\n",      // pattern as program
		"ls ... -l\n",        // ... not last
		"ls [\n",             // bad glob
		"ls 'unterminated\n", // bad quoting
	} {
		if _, err := Parse(strings.NewReader(bad), "t"); err == nil {
			t.Errorf("policy %q should be rejected", bad)
		}
	}
}

func TestEnvDropsDangerousVariables(t *testing.T) {
	env := Env([]string{"HOME=/root", "LD_PRELOAD=/tmp/x.so", "PATH=/tmp/evil", "TERM=xterm", "BASH_ENV=/tmp/x"})
	want := []string{"PATH=" + strings.Join(SafePath, ":"), "HOME=/root", "TERM=xterm"}
	if !reflect.DeepEqual(env, want) {
		t.Fatalf("got %q", env)
	}
}

func TestResolve(t *testing.T) {
	if _, err := Resolve("../bin/sh"); err == nil {
		t.Error("relative path accepted")
	}
	if p, err := Resolve("sh"); err != nil || !strings.HasSuffix(p, "/sh") {
		t.Errorf("Resolve(sh) = %q, %v", p, err)
	}
}

func TestLinterRefusesShellEscapes(t *testing.T) {
	for _, bad := range []string{
		"bash\n", "/bin/sh -c uptime\n", "vim /etc/hosts\n", "less /var/log/syslog\n",
		"python3 ...\n", "sudo systemctl restart nginx\n", "find /var/log ...\n", "env\n",
		"docker run *\n", "git ...\n", "tar -xf *\n",
		"python3.12 ...\n", "perl5.36 -e *\n", "taskset 1 *\n", "systemctl * nginx\n", "ip ...\n",
	} {
		if _, err := Parse(strings.NewReader(bad), "t"); err == nil {
			t.Errorf("linter accepted %q", bad)
		}
	}
	for _, ok := range []string{"docker ps\n", "git -C /srv/app pull\n", "systemctl status ...\n", "!unsafe less /var/log/app.log\n"} {
		p, err := Parse(strings.NewReader(ok), "t")
		if err != nil {
			t.Errorf("linter refused %q: %v", ok, err)
			continue
		}
		if strings.HasPrefix(ok, "!unsafe") && !p.Rules[0].Unsafe {
			t.Errorf("%q not marked unsafe", ok)
		}
	}
}

func TestDenyAndTOTPRules(t *testing.T) {
	p, err := Parse(strings.NewReader(`
systemctl status ...
!totp systemctl restart *
!deny systemctl * sshd
!deny * --force
`), "t")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		cmd           string
		allowed, totp bool
	}{
		{"systemctl status nginx", true, false},
		{"systemctl restart nginx", true, true},
		{"systemctl restart sshd", false, false},          // deny wins over the totp rule
		{"/usr/bin/systemctl status sshd", false, false},  // deny matches by base name
		{"systemctl status --force", false, false},        // deny wildcards match flags
		{"systemctl restart --force nginx", false, false}, // deny words match anywhere
		{"systemctl restart sshd --now", false, false},    // extra arguments don't dodge a deny
		{"systemctl status nginx sshd", false, false},
	}
	for _, c := range cases {
		args, _ := Split(c.cmd)
		r, d := p.Check(args)
		if (r != nil) != c.allowed || (r != nil && r.TOTP != c.totp) || (d != nil) == c.allowed {
			t.Errorf("%q: allow=%v deny=%v", c.cmd, r, d)
		}
	}
	if _, err := Parse(strings.NewReader("!deny rm ...\n"), "t"); err == nil {
		t.Error("policy with only deny rules accepted")
	}
	if _, err := Parse(strings.NewReader("!sudo ls\n"), "t"); err == nil {
		t.Error("unknown flag accepted")
	}
}

func TestHiddenNeedsADotInThePattern(t *testing.T) {
	p, _ := Parse(strings.NewReader("cat /home/deploy/*\ncat /home/deploy/.*\n"), "t")
	args, _ := Split("cat /home/deploy/.profile")
	if r, _ := p.Check(args); r == nil || r.Tokens[1] != "/home/deploy/.*" {
		t.Fatalf("dotfile should match only the rule that spells the dot, got %v", r)
	}
	p, _ = Parse(strings.NewReader("cat /home/deploy/*\n"), "t")
	args, _ = Split("cat /home/deploy/.ssh")
	if r, _ := p.Check(args); r != nil {
		t.Fatal("* matched a hidden file")
	}
}
