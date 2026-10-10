package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"portash/internal/invite"
	"portash/internal/pin"
	"portash/internal/tokens"
)

// statusCheck is one thing about the state directory that is right or wrong.
type statusCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// gatewayStatus is everything `portash gateway-status` reports. It is a fixed
// list of counts and facts on purpose: no tokens, hashes, TOTP data, device
// keys, tickets or log contents can get into it, because nothing of that kind
// is ever copied into a field. The pin is public.
type gatewayStatus struct {
	Version        string        `json:"version"`
	Dir            string        `json:"dir"`
	Pin            string        `json:"pin,omitempty"`
	Tokens         int           `json:"tokens"`        // all usable entries: tokens file and tokens.d
	TokensExpired  int           `json:"tokensExpired"` // of those, already expired
	DropinTokens   int           `json:"dropinTokens"`  // of those, from tokens.d
	DropinRefused  int           `json:"dropinRefused"` // files or lines in tokens.d that are ignored
	OpenInvites    int           `json:"openInvites"`
	PendingLaptops int           `json:"pendingLaptops"`
	UnlockSecrets  int           `json:"unlockSecrets"` // TOTP secrets enrolled for the daily unlock
	Checks         []statusCheck `json:"checks"`
}

// collectStatus looks at the state directory of a gateway. It only reads, needs
// no running gateway and opens no connection. A file it cannot read is a
// failed check, not an error.
func collectStatus(dir string, now time.Time) (gatewayStatus, error) {
	st := gatewayStatus{Version: version, Dir: dir, Checks: []statusCheck{}}
	fi, err := os.Stat(dir)
	if err != nil {
		return st, err
	}
	if !fi.IsDir() {
		return st, fmt.Errorf("%s is not a folder", dir)
	}
	add := func(name string, ok bool, detail string) {
		st.Checks = append(st.Checks, statusCheck{Name: name, OK: ok, Detail: detail})
	}
	add("state folder", noGroupOtherWrite(fi), modeDetail(fi, "must not be writable by group or others"))

	tokPath := filepath.Join(dir, "tokens")
	entries, refused, err := tokens.LoadAll(tokPath)
	switch {
	case err != nil:
		add("tokens file", false, "cannot be read or parsed: "+shortErr(err))
	default:
		for _, e := range entries {
			st.Tokens++
			if e.Expired(now) {
				st.TokensExpired++
			}
			if e.Source != "" {
				st.DropinTokens++
			}
		}
		if tfi, err := os.Stat(tokPath); err == nil {
			add("tokens file", tfi.Mode().Perm()&0o077 == 0, modeDetail(tfi, "must not be readable by group or others (chmod 600)"))
		} else {
			add("tokens file", true, "none yet: nobody can connect with a token from it")
		}
	}
	st.DropinRefused = len(refused)
	if len(refused) == 0 {
		add("tokens.d", true, "")
	} else {
		reasons := make([]string, 0, len(refused))
		for _, r := range refused {
			reasons = append(reasons, r.String())
		}
		add("tokens.d", false, strings.Join(reasons, "; "))
	}

	st.Pin, st.Checks = certPin(dir, st.Checks)
	if t, err := os.Stat(filepath.Join(dir, "tickets")); err == nil {
		add("tickets file", t.Mode().Perm()&0o077 == 0, modeDetail(t, "must not be readable by group or others (chmod 600)"))
	}
	st.UnlockSecrets, st.Checks = unlockState(filepath.Join(dir, "unlock"), st.Checks)
	st.OpenInvites, st.PendingLaptops = invite.Count(filepath.Join(dir, "invites"), now)
	return st, nil
}

// certPin reads the pin from gateway.crt (public) and checks the key file.
func certPin(dir string, checks []statusCheck) (string, []statusCheck) {
	crt, key := filepath.Join(dir, "gateway.crt"), filepath.Join(dir, "gateway.key")
	b, err := os.ReadFile(crt)
	if err != nil {
		return "", append(checks, statusCheck{Name: "gateway key", OK: true, Detail: "not made yet: the gateway makes it on first start, or run portash keygen"})
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "", append(checks, statusCheck{Name: "gateway key", Detail: "gateway.crt is not a certificate"})
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return "", append(checks, statusCheck{Name: "gateway key", Detail: "gateway.crt does not parse"})
	}
	kfi, err := os.Stat(key)
	if err != nil {
		return pin.Of(cert), append(checks, statusCheck{Name: "gateway key", Detail: "gateway.key: " + shortErr(err)})
	}
	return pin.Of(cert), append(checks, statusCheck{Name: "gateway key", OK: kfi.Mode().Perm()&0o077 == 0,
		Detail: modeDetail(kfi, "gateway.key must not be readable by group or others (chmod 600)")})
}

// unlockState counts the TOTP secret files and checks the folder and files.
func unlockState(dir string, checks []statusCheck) (int, []statusCheck) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, checks
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		return 0, append(checks, statusCheck{Name: "unlock folder", Detail: "cannot be read: " + shortErr(err)})
	}
	n, loose := 0, 0
	for _, de := range names {
		if !strings.HasSuffix(de.Name(), ".secret") {
			continue
		}
		n++
		if info, err := de.Info(); err == nil && info.Mode().Perm()&0o077 != 0 {
			loose++
		}
	}
	ok := fi.Mode().Perm()&0o077 == 0 && loose == 0
	detail := ""
	if !ok {
		detail = "the folder and its .secret files must not be accessible by group or others"
	}
	return n, append(checks, statusCheck{Name: "unlock folder", OK: ok, Detail: detail})
}

func noGroupOtherWrite(fi os.FileInfo) bool {
	return runtime.GOOS == "windows" || fi.Mode().Perm()&0o022 == 0
}

func modeDetail(fi os.FileInfo, rule string) string {
	if runtime.GOOS == "windows" || fi.Mode().Perm()&0o077 == 0 || fi.IsDir() && fi.Mode().Perm()&0o022 == 0 {
		return ""
	}
	return fmt.Sprintf("mode %04o: %s", fi.Mode().Perm(), rule)
}

// shortErr is an error without the path, which would only repeat the check's name.
func shortErr(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// cmdGatewayStatus prints the state of a gateway's folder, for people and for
// tools. Exit code 0 means it could read the folder, even when some checks
// failed: those are data, in the output. 1 means it could not look.
func cmdGatewayStatus(args []string) error {
	fs := flag.NewFlagSet("gateway-status", flag.ContinueOnError)
	dir := fs.String("dir", "/var/lib/portash", "gateway state directory")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, err := parse(fs, args); err != nil {
		return err
	} else if len(pos) != 0 {
		return errors.New("usage: portash gateway-status [--dir DIR] [--json]")
	}
	st, err := collectStatus(*dir, time.Now())
	if err != nil {
		return err
	}
	if *asJSON {
		b, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "version\t%s\ndir\t%s\npin\t%s\n", st.Version, st.Dir, orDash(st.Pin))
	fmt.Fprintf(w, "tokens\t%d (%d expired, %d from tokens.d, %d ignored in tokens.d)\n", st.Tokens, st.TokensExpired, st.DropinTokens, st.DropinRefused)
	fmt.Fprintf(w, "invites\t%d open, %d laptops waiting for approval\nunlock secrets\t%d\n", st.OpenInvites, st.PendingLaptops, st.UnlockSecrets)
	for _, c := range st.Checks {
		res := "ok"
		if !c.OK {
			res = "FAIL"
		}
		fmt.Fprintf(w, "check %s\t%s %s\n", c.Name, res, c.Detail)
	}
	return w.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
