package provision

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"portash/internal/fsown"
	"portash/internal/tokens"
	"portash/internal/totp"
)

// Item statuses in a Result.
const (
	Created   = "created"
	Updated   = "updated"
	Unchanged = "unchanged"
)

// Result says what Apply did (or would do) to one item. It names things, it
// never holds a secret.
type Result struct {
	Item   string `json:"item"`
	Status string `json:"status"`
}

// Apply puts a bundle into a gateway's state folder dir. It checks the whole
// bundle first and writes nothing if anything is wrong. Every item is safe to
// repeat: a gateway key that is already there is never replaced (a different
// one is an error), the token line is rewritten only if it differs, and an
// unlock secret that exists is kept with its replay and lockout state. With
// dry set nothing is written.
func Apply(dir string, b Bundle, dry bool) ([]Result, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	keyPath, certPath := filepath.Join(dir, "gateway.key"), filepath.Join(dir, "gateway.crt")
	keyStatus, err := checkKeyFile(keyPath, b.Key, true)
	if err != nil {
		return nil, err
	}
	certStatus, err := checkKeyFile(certPath, b.Cert, false)
	if err != nil {
		return nil, err
	}
	if keyStatus == Created && certStatus != Created {
		return nil, fmt.Errorf("%s exists but %s does not: restore the key or remove the certificate by hand", certPath, keyPath)
	}
	lineDir := filepath.Join(dir, tokens.DropinName)
	linePath := filepath.Join(lineDir, b.Name)
	lineStatus := Created
	if old, err := os.ReadFile(linePath); err == nil {
		lineStatus = Updated
		if string(old) == b.Line+"\n" {
			lineStatus = Unchanged
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	st := totp.Store{Dir: filepath.Join(dir, "unlock"), ValidName: tokens.ValidName}
	have, err := st.Exists(b.Name)
	if err != nil {
		return nil, err
	}
	totpStatus := Created
	if have {
		totpStatus = Unchanged
	}
	res := []Result{
		{"gateway key", keyStatus},
		{"gateway certificate", certStatus},
		{"token " + b.Name, lineStatus},
		{"unlock secret " + b.Name, totpStatus},
	}
	if dry {
		return res, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if keyStatus == Created {
		if err := createNew(keyPath, []byte(b.Key), 0o600); err != nil {
			return nil, err
		}
	}
	if certStatus == Created {
		if err := createNew(certPath, []byte(b.Cert), 0o644); err != nil {
			if keyStatus == Created {
				os.Remove(keyPath) // no key without its certificate
			}
			return nil, err
		}
	}
	if lineStatus != Unchanged {
		if err := os.MkdirAll(lineDir, 0o700); err != nil {
			return nil, err
		}
		if err := fsown.WriteFile(linePath, []byte(b.Line+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	if totpStatus == Created {
		if err := os.MkdirAll(st.Dir, 0o700); err != nil {
			return nil, err
		}
		if err := st.Import(b.Name, b.TOTP); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// checkKeyFile compares a file that may exist with what the bundle says it
// should hold. Same content (or, for the key, the same key) is unchanged; a
// file with other content is an error, never replaced; a missing file is created.
func checkKeyFile(path, want string, isKey bool) (string, error) {
	got, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Created, nil
	}
	if err != nil {
		return "", err
	}
	if bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace([]byte(want))) {
		return Unchanged, nil
	}
	if isKey {
		if a, err := ParseKey(string(got)); err == nil {
			if b, err := ParseKey(want); err == nil && a.Equal(b) {
				return Unchanged, nil
			}
		}
		return "", fmt.Errorf("%s is a different gateway key. Not replacing it (every user's pin would change): remove it by hand if you mean it", path)
	}
	if a, err := ParseCert(string(got)); err == nil {
		if b, err := ParseCert(want); err == nil && bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo) {
			return Unchanged, nil // the same key in another certificate: the pin is the same
		}
	}
	return "", fmt.Errorf("%s is another certificate (another key). Not replacing it: remove it by hand if you mean it", path)
}

// createNew writes a file that must not exist, owned like its folder.
func createNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	if err := fsown.LikeParent(path); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}
